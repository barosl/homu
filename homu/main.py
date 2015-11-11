import argparse
import github3
import toml
import json
import re
from . import utils
import logging
from threading import Thread, Lock
import time
import traceback
import sqlite3
import requests
from contextlib import contextmanager
from itertools import chain
from queue import Queue
import os
import subprocess
from .git_helper import SSH_KEY_FILE

STATUS_TO_PRIORITY = {
    'success': 0,
    'pending': 1,
    'approved': 2,
    '': 3,
    'error': 4,
    'failure': 5,
}

INTERRUPTED_BY_HOMU_FMT = 'Interrupted by Homu ({})'
INTERRUPTED_BY_HOMU_RE = re.compile(r'Interrupted by Homu \((.+?)\)')

@contextmanager
def buildbot_sess(repo_cfg):
    sess = requests.Session()

    sess.post(repo_cfg['buildbot']['url'] + '/login', allow_redirects=False, data={
        'username': repo_cfg['buildbot']['username'],
        'passwd': repo_cfg['buildbot']['password'],
    })

    yield sess

    sess.get(repo_cfg['buildbot']['url'] + '/logout', allow_redirects=False)

db_query_lock = Lock()
def db_query(db, *args):
    with db_query_lock:
        db.execute(*args)

class PullReqState:
    num = 0
    priority = 0
    rollup = False
    title = ''
    body = ''
    head_ref = ''
    base_ref = ''
    assignee = ''
    delegate = ''

    def __init__(self, num, head_sha, status, db, repo_label, mergeable_que, gh, owner, name, repos):
        self.head_advanced('', use_db=False)

        self.num = num
        self.head_sha = head_sha
        self.status = status
        self.db = db
        self.repo_label = repo_label
        self.mergeable_que = mergeable_que
        self.gh = gh
        self.owner = owner
        self.name = name
        self.repos = repos

    def head_advanced(self, head_sha, *, use_db=True):
        self.head_sha = head_sha
        self.approved_by = ''
        self.status = ''
        self.merge_sha = ''
        self.build_res = {}
        self.try_ = False
        self.mergeable = None

        if use_db:
            self.set_status('')
            self.set_mergeable(None)
            self.init_build_res([])

    def __repr__(self):
        return 'PullReqState:{}/{}#{}(approved_by={}, priority={}, status={})'.format(
            self.owner,
            self.name,
            self.num,
            self.approved_by,
            self.priority,
            self.status,
        )

    def sort_key(self):
        return [
            STATUS_TO_PRIORITY.get(self.get_status(), -1),
            1 if self.mergeable is False else 0,
            0 if self.approved_by else 1,
            1 if self.rollup else 0,
            -self.priority,
            self.num,
        ]

    def __lt__(self, other):
        return self.sort_key() < other.sort_key()

    def add_comment(self, text):
        issue = getattr(self, 'issue', None)
        if not issue:
            issue = self.issue = self.get_repo().issue(self.num)

        issue.create_comment(text)

    def set_status(self, status):
        self.status = status

        db_query(self.db, 'UPDATE pull SET status = ? WHERE repo = ? AND num = ?', [self.status, self.repo_label, self.num])

        # FIXME: self.try_ should also be saved in the database
        if not self.try_:
            db_query(self.db, 'UPDATE pull SET merge_sha = ? WHERE repo = ? AND num = ?', [self.merge_sha, self.repo_label, self.num])

    def get_status(self):
        return 'approved' if self.status == '' and self.approved_by and self.mergeable is not False else self.status

    def set_mergeable(self, mergeable, *, cause=None, que=True):
        if mergeable is not None:
            self.mergeable = mergeable

            db_query(self.db, 'INSERT OR REPLACE INTO mergeable (repo, num, mergeable) VALUES (?, ?, ?)', [self.repo_label, self.num, self.mergeable])
        else:
            if que:
                self.mergeable_que.put([self, cause])
            else:
                self.mergeable = None

            db_query(self.db, 'DELETE FROM mergeable WHERE repo = ? AND num = ?', [self.repo_label, self.num])

    def init_build_res(self, builders, *, use_db=True):
        self.build_res = {x: {
            'res': None,
            'url': '',
        } for x in builders}

        if use_db:
            db_query(self.db, 'DELETE FROM build_res WHERE repo = ? AND num = ?', [self.repo_label, self.num])

    def set_build_res(self, builder, res, url):
        if builder not in self.build_res:
            raise Exception('Invalid builder: {}'.format(builder))

        self.build_res[builder] = {
            'res': res,
            'url': url,
        }

        db_query(self.db, 'INSERT OR REPLACE INTO build_res (repo, num, builder, res, url, merge_sha) VALUES (?, ?, ?, ?, ?, ?)', [
            self.repo_label,
            self.num,
            builder,
            res,
            url,
            self.merge_sha,
        ])

    def build_res_summary(self):
        return ', '.join('{}: {}'.format(builder, data['res'])
                         for builder, data in self.build_res.items())

    def get_repo(self):
        repo = self.repos[self.repo_label]
        if not repo:
            self.repos[self.repo_label] = repo = self.gh.repository(self.owner, self.name)

            assert repo.owner.login == self.owner
            assert repo.name == self.name
        return repo

    def save(self):
        db_query(self.db, 'INSERT OR REPLACE INTO pull (repo, num, status, merge_sha, title, body, head_sha, head_ref, base_ref, assignee, approved_by, priority, try_, rollup, delegate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [
            self.repo_label,
            self.num,
            self.status,
            self.merge_sha,
            self.title,
            self.body,
            self.head_sha,
            self.head_ref,
            self.base_ref,
            self.assignee,
            self.approved_by,
            self.priority,
            self.try_,
            self.rollup,
            self.delegate,
        ])

    def refresh(self):
        issue = self.get_repo().issue(self.num)

        self.title = issue.title
        self.body = issue.body

    def fake_merged(self, repo_cfg):
        if repo_cfg.get('linear', False) or repo_cfg.get('autosquash', False):
            msg = '!!! Temporary commit !!!\n\nThis commit is artifically made up to mark PR {} as merged.\n\nIf this commit remained in the history, you may reset HEAD to {}\n\n[ci skip]'.format(self.num, self.merge_sha)

            # `merge()` will return `None` if the `head_sha` commit is already part of the `base_ref` branch, which means rebasing didn't have to modify the original commit
            if self.get_repo().merge(self.base_ref, self.head_sha, msg):
                self.rebased = True

def sha_cmp(short, full):
    return len(short) >= 4 and short == full[:len(short)]

def sha_or_blank(sha):
    return sha if re.match(r'^[0-9a-f]+$', sha) else ''

def parse_commands(body, username, repo_cfg, state, my_username, db, *, realtime=False, sha=''):
    try_only = False
    if username not in repo_cfg['reviewers'] and username != my_username:
        if username == state.delegate:
            pass # Allow users who have been delegated review powers
        elif username in repo_cfg.get('try_users', []):
            try_only = True
        else:
            return False

    state_changed = False

    words = list(chain.from_iterable(re.findall(r'\S+', x) for x in body.splitlines() if '@' + my_username in x))
    for i, word in reversed(list(enumerate(words))):
        found = True

        if word == 'r+' or word.startswith('r='):
            if try_only:
                if realtime: state.add_comment(':key: Insufficient privileges')
                continue

            if not sha and i+1 < len(words):
                cur_sha = sha_or_blank(words[i+1])
            else:
                cur_sha = sha

            approver = word[len('r='):] if word.startswith('r=') else username

            # Ignore "r=me"
            if approver == 'me':
                continue

            # Sometimes, GitHub sends the head SHA of a PR as 0000000 through the webhook. This is
            # called a "null commit", and seems to happen when GitHub internally encounters a race
            # condition. Last time, it happened when squashing commits in a PR. In this case, we
            # just try to retrieve the head SHA manually.
            if all(x == '0' for x in state.head_sha):
                state.add_comment(':bangbang: Invalid head SHA found, retrying: `{}`'.format(state.head_sha))

                state.head_sha = state.get_repo().pull_request(state.num).head.sha
                state.save()

                assert any(x != '0' for x in state.head_sha)

            if sha_cmp(cur_sha, state.head_sha):
                state.approved_by = approver

                state.save()
            elif realtime and username != my_username:
                if cur_sha:
                    msg = '`{}` is not a valid commit SHA.'.format(cur_sha)
                    state.add_comment(':scream_cat: {} Please try again with `{:.7}`.'.format(msg, state.head_sha))
                else:
                    state.add_comment(':pushpin: Commit {:.7} has been approved by `{}`\n\n<!-- @{} r={} {} -->'.format(state.head_sha, approver, my_username, approver, state.head_sha))

        elif word == 'r-':
            if try_only:
                if realtime: state.add_comment(':key: Insufficient privileges')
                continue

            state.approved_by = ''

            state.save()

        elif word.startswith('p='):
            try: state.priority = int(word[len('p='):])
            except ValueError: pass

            state.save()

        elif word.startswith('delegate='):
            if try_only:
                if realtime: state.add_comment(':key: Insufficient privileges')
                continue

            state.delegate = word[len('delegate='):]
            state.save()

            if realtime: state.add_comment(':v: @{} can now approve this pull request'.format(state.delegate))

        elif word == 'delegate-':
            state.delegate = ''
            state.save()

        elif word == 'delegate+':
            if try_only:
                if realtime: state.add_comment(':key: Insufficient privileges')
                continue

            state.delegate = state.get_repo().pull_request(state.num).user.login
            state.save()

            if realtime: state.add_comment(':v: @{} can now approve this pull request'.format(state.delegate))

        elif word == 'retry' and realtime:
            state.set_status('')

        elif word in ['try', 'try-'] and realtime:
            state.try_ = word == 'try'

            state.merge_sha = ''
            state.init_build_res([])

            state.save()

        elif word in ['rollup', 'rollup-']:
            state.rollup = word == 'rollup'

            state.save()

        elif word == 'force' and realtime:
            with buildbot_sess(repo_cfg) as sess:
                res = sess.post(repo_cfg['buildbot']['url'] + '/builders/_selected/stopselected', allow_redirects=False, data={
                    'selected': repo_cfg['buildbot']['builders'],
                    'comments': INTERRUPTED_BY_HOMU_FMT.format(int(time.time())),
                })

            if 'authzfail' in res.text:
                err = 'Authorization failed'
            else:
                mat = re.search('(?s)<div class="error">(.*?)</div>', res.text)
                if mat:
                    err = mat.group(1).strip()
                    if not err: err = 'Unknown error'
                else:
                    err = ''

            if err:
                state.add_comment(':bomb: Buildbot returned an error: `{}`'.format(err))

        elif word == 'clean' and realtime:
            state.merge_sha = ''
            state.init_build_res([])

            state.save()

        else:
            found = False

        if found:
            state_changed = True

            words[i] = ''

    return state_changed

def create_merge(state, repo_cfg, branch, git_cfg):
    base_sha = state.get_repo().ref('heads/' + state.base_ref).object.sha

    state.refresh()

    merge_msg = 'Auto merge of #{} - {}, r={}\n\n{}\n\n{}'.format(
        state.num,
        state.head_ref,
        '<try>' if state.try_ else state.approved_by,
        state.title,
        state.body,
    )

    desc = 'Merge conflict'

    if git_cfg['local_git']:
        pull = state.get_repo().pull_request(state.num)

        fpath = 'cache/{}/{}'.format(repo_cfg['owner'], repo_cfg['name'])
        url = 'git@github.com:{}/{}.git'.format(repo_cfg['owner'], repo_cfg['name'])
        head_repo_url = 'https://github.com/{}/{}.git'.format(*pull.head.repo)
        head_branch = state.head_ref.split(':')[1]

        os.makedirs(os.path.dirname(SSH_KEY_FILE), exist_ok=True)
        with open(SSH_KEY_FILE, 'w') as fp:
            fp.write(git_cfg['ssh_key'])
        os.chmod(SSH_KEY_FILE, 0o600)

        if os.path.exists(fpath):
            utils.logged_call(['git', '-C', fpath, 'fetch', '--no-tags', 'origin', state.base_ref])
        else:
            utils.logged_call(['git', 'clone', url, fpath])

        utils.silent_call(['git', '-C', fpath, 'remote', 'remove', 'head_repo'])
        utils.logged_call(['git', '-C', fpath, 'remote', 'add', '-f', '--no-tags'] + (['-t', head_branch] if head_branch else []) + ['head_repo', head_repo_url])

        utils.silent_call(['git', '-C', fpath, 'rebase', '--abort'])
        utils.silent_call(['git', '-C', fpath, 'merge', '--abort'])

        if repo_cfg.get('linear', False):
            utils.logged_call(['git', '-C', fpath, 'checkout', '-B', branch, state.head_sha])
            try:
                utils.logged_call(['git', '-C', fpath, '-c', 'user.name=' + git_cfg['name'], '-c', 'user.email=' + git_cfg['email'], 'rebase'] + (['-i', '--autosquash'] if repo_cfg.get('autosquash', False) else []) + [base_sha])
            except subprocess.CalledProcessError:
                if repo_cfg.get('autosquash', False):
                    utils.silent_call(['git', '-C', fpath, 'rebase', '--abort'])
                    if utils.silent_call(['git', '-C', fpath, 'rebase', base_sha]) == 0:
                        desc = 'Auto-squashing failed'
            else:
                utils.logged_call(['git', '-C', fpath, '-c', 'user.name=' + git_cfg['name'], '-c', 'user.email=' + git_cfg['email'], 'commit', '-m', merge_msg, '--allow-empty'])
                utils.logged_call(['git', '-C', fpath, 'push', '-f', 'origin', branch])

                return subprocess.check_output(['git', '-C', fpath, 'rev-parse', 'HEAD']).decode('ascii').strip()
        else:
            utils.logged_call(['git', '-C', fpath, 'checkout', '-B', 'homu-tmp', state.head_sha])

            ok = True
            if repo_cfg.get('autosquash', False):
                try:
                    merge_base_sha = subprocess.check_output(['git', '-C', fpath, 'merge-base', base_sha, state.head_sha]).decode('ascii').strip()
                    utils.logged_call(['git', '-C', fpath, '-c', 'user.name=' + git_cfg['name'], '-c', 'user.email=' + git_cfg['email'], 'rebase', '-i', '--autosquash', '--onto', merge_base_sha, base_sha])
                except subprocess.CalledProcessError:
                    desc = 'Auto-squashing failed'
                    ok = False

            if ok:
                utils.logged_call(['git', '-C', fpath, 'checkout', '-B', branch, base_sha])
                try:
                    utils.logged_call(['git', '-C', fpath, '-c', 'user.name=' + git_cfg['name'], '-c', 'user.email=' + git_cfg['email'], 'merge', 'heads/homu-tmp', '-m', merge_msg])
                except subprocess.CalledProcessError:
                    pass
                else:
                    utils.logged_call(['git', '-C', fpath, 'push', '-f', 'origin', branch])

                    return subprocess.check_output(['git', '-C', fpath, 'rev-parse', 'HEAD']).decode('ascii').strip()
    else:
        if repo_cfg.get('linear', False) or repo_cfg.get('autosquash', False):
            raise RuntimeError('local_git must be turned on to use this feature')

        if branch != state.base_ref:
            utils.github_set_ref(
                state.get_repo(),
                'heads/' + branch,
                base_sha,
                force=True,
            )

        try: merge_commit = state.get_repo().merge(branch, state.head_sha, merge_msg)
        except github3.models.GitHubError as e:
            if e.code != 409: raise
        else:
            return merge_commit.sha if merge_commit else ''

    state.set_status('error')
    utils.github_create_status(state.get_repo(), state.head_sha, 'error', '', desc, context='homu')

    state.add_comment(':lock: ' + desc)

    return ''

def start_build(state, repo_cfgs, buildbot_slots, logger, db, git_cfg):
    if buildbot_slots[0]:
        return True

    assert state.head_sha == state.get_repo().pull_request(state.num).head.sha

    repo_cfg = repo_cfgs[state.repo_label]

    if 'buildbot' in repo_cfg:
        branch = 'try' if state.try_ else 'auto'
        branch = repo_cfg.get('branch', {}).get(branch, branch)
        builders = repo_cfg['buildbot']['try_builders' if state.try_ else 'builders']
    elif 'travis' in repo_cfg:
        branch = repo_cfg.get('branch', {}).get('auto', 'auto')
        builders = ['travis']
    elif 'status' in repo_cfg:
        branch = repo_cfg.get('branch', {}).get('auto', 'auto')
        builders = ['status']
    else:
        raise RuntimeError('Invalid configuration')

    if state.approved_by and builders == ['status'] and repo_cfg['status']['context'] == 'continuous-integration/travis-ci/push':
        for info in utils.github_iter_statuses(state.get_repo(), state.head_sha):
            if info.context == 'continuous-integration/travis-ci/pr':
                if info.state == 'success':
                    mat = re.search('/builds/([0-9]+)$', info.target_url)
                    if mat:
                        url = 'https://api.travis-ci.org/{}/{}/builds/{}'.format(state.owner, state.name, mat.group(1))
                        res = requests.get(url)
                        travis_sha = json.loads(res.text)['commit']
                        travis_commit = state.get_repo().commit(travis_sha)
                        base_sha = state.get_repo().ref('heads/' + state.base_ref).object.sha
                        if [travis_commit.parents[0]['sha'], travis_commit.parents[1]['sha']] == [base_sha, state.head_sha]:
                            merge_sha = create_merge(state, repo_cfg, state.base_ref, git_cfg)
                            if merge_sha:
                                desc = 'Test exempted'
                                url = info.target_url

                                state.set_status('success')
                                utils.github_create_status(state.get_repo(), state.head_sha, 'success', url, desc, context='homu')
                                state.add_comment(':zap: {} - [{}]({})'.format(desc, 'status', url))

                                state.merge_sha = merge_sha
                                state.save()

                                state.fake_merged(repo_cfg)
                                return True
                break

    merge_sha = create_merge(state, repo_cfg, branch, git_cfg)
    if not merge_sha:
        return False

    state.init_build_res(builders)
    state.merge_sha = merge_sha

    state.save()

    if 'buildbot' in repo_cfg:
        buildbot_slots[0] = state.merge_sha

    logger.info('Starting build of {}/{}#{} on {}: {}'.format(state.owner,
                                                              state.name,
                                                              state.num, branch, state.merge_sha))

    state.set_status('pending')
    desc = '{} commit {:.7} with merge {:.7}...'.format('Trying' if state.try_ else 'Testing', state.head_sha, state.merge_sha)
    utils.github_create_status(state.get_repo(), state.head_sha, 'pending', '', desc, context='homu')

    state.add_comment(':hourglass: ' + desc)

    return True

def start_rebuild(state, repo_cfgs):
    repo_cfg = repo_cfgs[state.repo_label]

    if 'buildbot' not in repo_cfg or not state.build_res:
        return False

    builders = []
    succ_builders = []

    for builder, info in state.build_res.items():
        if not info['url']:
            return False

        if info['res']:
            succ_builders.append([builder, info['url']])
        else:
            builders.append([builder, info['url']])

    if not builders or not succ_builders:
        return False

    base_sha = state.get_repo().ref('heads/' + state.base_ref).object.sha
    parent_shas = [x['sha'] for x in state.get_repo().commit(state.merge_sha).parents]

    if base_sha not in parent_shas:
        return False

    utils.github_set_ref(state.get_repo(), 'tags/homu-tmp', state.merge_sha, force=True)

    builders.sort()
    succ_builders.sort()

    with buildbot_sess(repo_cfg) as sess:
        for builder, url in builders:
            res = sess.post(url + '/rebuild', allow_redirects=False, data={
                'useSourcestamp': 'exact',
                'comments': 'Initiated by Homu',
            })

            if 'authzfail' in res.text:
                err = 'Authorization failed'
            elif builder in res.text:
                err = ''
            else:
                mat = re.search('<title>(.+?)</title>', res.text)
                err = mat.group(1) if mat else 'Unknown error'

            if err:
                state.add_comment(':bomb: Failed to start rebuilding: `{}`'.format(err))
                return False

    state.set_status('pending')

    msg_1 = 'Previous build results'
    msg_2 = ' for {}'.format(', '.join('[{}]({})'.format(builder, url) for builder, url in succ_builders))
    msg_3 = ' are reusable. Rebuilding'
    msg_4 = ' only {}'.format(', '.join('[{}]({})'.format(builder, url) for builder, url in builders))

    utils.github_create_status(state.get_repo(), state.head_sha, 'pending', '', '{}{}...'.format(msg_1, msg_3), context='homu')

    state.add_comment(':zap: {}{}{}{}...'.format(msg_1, msg_2, msg_3, msg_4))

    return True

def start_build_or_rebuild(state, repo_cfgs, *args):
    if start_rebuild(state, repo_cfgs):
        return True

    return start_build(state, repo_cfgs, *args)

def process_queue(states, repos, repo_cfgs, logger, buildbot_slots, db, git_cfg):
    for repo_label, repo in repos.items():
        repo_states = sorted(states[repo_label].values())

        for state in repo_states:
            if state.status == 'pending' and not state.try_:
                break

            elif state.status == '' and state.approved_by:
                if start_build_or_rebuild(state, repo_cfgs, buildbot_slots, logger, db, git_cfg):
                    return

            elif state.status == 'success' and state.try_ and state.approved_by:
                state.try_ = False

                state.save()

                if start_build(state, repo_cfgs, buildbot_slots, logger, db, git_cfg):
                    return

        for state in repo_states:
            if state.status == '' and state.try_:
                if start_build(state, repo_cfgs, buildbot_slots, logger, db, git_cfg):
                    return

def fetch_mergeability(mergeable_que):
    re_pull_num = re.compile('(?i)merge (?:of|pull request) #([0-9]+)')

    while True:
        try:
            state, cause = mergeable_que.get()

            mergeable = state.get_repo().pull_request(state.num).mergeable
            if mergeable is None:
                time.sleep(5)
                mergeable = state.get_repo().pull_request(state.num).mergeable

            if state.mergeable is True and mergeable is False:
                if cause:
                    mat = re_pull_num.search(cause['title'])

                    if mat: issue_or_commit = '#' + mat.group(1)
                    else: issue_or_commit = cause['sha'][:7]
                else:
                    issue_or_commit = ''

                state.add_comment(':umbrella: The latest upstream changes{} made this pull request unmergeable. Please resolve the merge conflicts.'.format(
                    ' (presumably {})'.format(issue_or_commit) if issue_or_commit else '',
                ))

            state.set_mergeable(mergeable, que=False)

        except:
            traceback.print_exc()

        finally:
            mergeable_que.task_done()

def synchronize(repo_label, repo_cfg, logger, gh, states, repos, db, mergeable_que, my_username, repo_labels):
    logger.info('Synchronizing {}...'.format(repo_label))

    repo = gh.repository(repo_cfg['owner'], repo_cfg['name'])

    db_query(db, 'DELETE FROM pull WHERE repo = ?', [repo_label])
    db_query(db, 'DELETE FROM build_res WHERE repo = ?', [repo_label])
    db_query(db, 'DELETE FROM mergeable WHERE repo = ?', [repo_label])

    states[repo_label] = {}
    repos[repo_label] = repo

    for pull in repo.iter_pulls(state='open'):
        db_query(db, 'SELECT status FROM pull WHERE repo = ? AND num = ?', [repo_label, pull.number])
        row = db.fetchone()
        if row:
            status = row[0]
        else:
            status = ''
            for info in utils.github_iter_statuses(repo, pull.head.sha):
                if info.context == 'homu':
                    status = info.state
                    break

        state = PullReqState(pull.number, pull.head.sha, status, db, repo_label, mergeable_que, gh, repo_cfg['owner'], repo_cfg['name'], repos)
        state.title = pull.title
        state.body = pull.body
        state.head_ref = pull.head.repo[0] + ':' + pull.head.ref
        state.base_ref = pull.base.ref
        state.set_mergeable(None)
        state.assignee = pull.assignee.login if pull.assignee else ''

        for comment in pull.iter_comments():
            if comment.original_commit_id == pull.head.sha:
                parse_commands(
                    comment.body,
                    comment.user.login,
                    repo_cfg,
                    state,
                    my_username,
                    db,
                    sha=comment.original_commit_id,
                )

        for comment in pull.iter_issue_comments():
            parse_commands(
                comment.body,
                comment.user.login,
                repo_cfg,
                state,
                my_username,
                db,
            )

        state.save()

        states[repo_label][pull.number] = state

    logger.info('Done synchronizing {}!'.format(repo_label))

def arguments():
    parser = argparse.ArgumentParser(description =
                                     'A bot that integrates with GitHub and '
                                     'your favorite continuous integration service')
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='Enable more verbose logging')

    return parser.parse_args()

def main():
    args = arguments()

    logger = logging.getLogger('homu')
    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    logger.addHandler(logging.StreamHandler())

    try:
        with open('cfg.toml') as fp:
            cfg = toml.loads(fp.read())
    except FileNotFoundError:
        with open('cfg.json') as fp:
            cfg = json.loads(fp.read())

    gh = github3.login(token=cfg['github']['access_token'])
    user = gh.user()
    try: user_email = [x for x in gh.iter_emails() if x['primary']][0]['email']
    except IndexError:
        raise RuntimeError('Primary email not set, or "user" scope not granted')

    states = {}
    repos = {}
    repo_cfgs = {}
    buildbot_slots = ['']
    my_username = user.login
    repo_labels = {}
    mergeable_que = Queue()
    git_cfg = {
        'name': user.name if user.name else user.login,
        'email': user_email,
        'ssh_key': cfg.get('git', {}).get('ssh_key', ''),
        'local_git': cfg.get('git', {}).get('local_git', False),
    }

    db_conn = sqlite3.connect('main.db', check_same_thread=False, isolation_level=None)
    db = db_conn.cursor()

    db_query(db, '''CREATE TABLE IF NOT EXISTS pull (
        repo TEXT NOT NULL,
        num INTEGER NOT NULL,
        status TEXT NOT NULL,
        merge_sha TEXT,
        title TEXT,
        body TEXT,
        head_sha TEXT,
        head_ref TEXT,
        base_ref TEXT,
        assignee TEXT,
        approved_by TEXT,
        priority INTEGER,
        try_ INTEGER,
        rollup INTEGER,
        delegate TEXT,
        UNIQUE (repo, num)
    )''')

    db_query(db, '''CREATE TABLE IF NOT EXISTS build_res (
        repo TEXT NOT NULL,
        num INTEGER NOT NULL,
        builder TEXT NOT NULL,
        res INTEGER,
        url TEXT NOT NULL,
        merge_sha TEXT NOT NULL,
        UNIQUE (repo, num, builder)
    )''')

    db_query(db, '''CREATE TABLE IF NOT EXISTS mergeable (
        repo TEXT NOT NULL,
        num INTEGER NOT NULL,
        mergeable INTEGER NOT NULL,
        UNIQUE (repo, num)
    )''')

    for repo_label, repo_cfg in cfg['repo'].items():
        repo_cfgs[repo_label] = repo_cfg
        repo_labels[repo_cfg['owner'], repo_cfg['name']] = repo_label

        repo_states = {}
        repos[repo_label] = None

        db_query(db, 'SELECT num, head_sha, status, title, body, head_ref, base_ref, assignee, approved_by, priority, try_, rollup, delegate, merge_sha FROM pull WHERE repo = ?', [repo_label])
        for num, head_sha, status, title, body, head_ref, base_ref, assignee, approved_by, priority, try_, rollup, delegate, merge_sha in db.fetchall():
            state = PullReqState(num, head_sha, status, db, repo_label, mergeable_que, gh, repo_cfg['owner'], repo_cfg['name'], repos)
            state.title = title
            state.body = body
            state.head_ref = head_ref
            state.base_ref = base_ref
            state.assignee = assignee

            state.approved_by = approved_by
            state.priority = int(priority)
            state.try_ = bool(try_)
            state.rollup = bool(rollup)
            state.delegate = delegate

            if merge_sha:
                if 'buildbot' in repo_cfg:
                    builders = repo_cfg['buildbot']['builders']
                elif 'travis' in repo_cfg:
                    builders = ['travis']
                elif 'status' in repo_cfg:
                    builders = ['status']
                else:
                    raise RuntimeError('Invalid configuration')

                state.init_build_res(builders, use_db=False)
                state.merge_sha = merge_sha

            elif state.status == 'pending':
                # FIXME: There might be a better solution
                state.status = ''

                state.save()

            repo_states[num] = state

        states[repo_label] = repo_states

    db_query(db, 'SELECT repo, num, builder, res, url, merge_sha FROM build_res')
    for repo_label, num, builder, res, url, merge_sha in db.fetchall():
        try:
            state = states[repo_label][num]
            if builder not in state.build_res: raise KeyError
            if state.merge_sha != merge_sha: raise KeyError
        except KeyError:
            db_query(db, 'DELETE FROM build_res WHERE repo = ? AND num = ? AND builder = ?', [repo_label, num, builder])
            continue

        state.build_res[builder] = {
            'res': bool(res) if res is not None else None,
            'url': url,
        }

    db_query(db, 'SELECT repo, num, mergeable FROM mergeable')
    for repo_label, num, mergeable in db.fetchall():
        try: state = states[repo_label][num]
        except KeyError:
            db_query(db, 'DELETE FROM mergeable WHERE repo = ? AND num = ?', [repo_label, num])
            continue

        state.mergeable = bool(mergeable) if mergeable is not None else None

    queue_handler_lock = Lock()
    def queue_handler():
        with queue_handler_lock:
            return process_queue(states, repos, repo_cfgs, logger, buildbot_slots, db, git_cfg)

    os.environ['GIT_SSH'] = os.path.join(os.path.dirname(__file__), 'git_helper.py')
    os.environ['GIT_EDITOR'] = 'cat'

    from . import server
    Thread(target=server.start, args=[cfg, states, queue_handler, repo_cfgs, repos, logger, buildbot_slots, my_username, db, repo_labels, mergeable_que, gh]).start()

    Thread(target=fetch_mergeability, args=[mergeable_que]).start()

    queue_handler()

if __name__ == '__main__':
    main()
