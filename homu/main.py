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

    def __init__(self, num, head_sha, status, repo, db, repo_label, mergeable_que):
        self.head_advanced('', use_db=False)

        self.num = num
        self.head_sha = head_sha
        self.status = status
        self.repo = repo
        self.db = db
        self.repo_label = repo_label
        self.mergeable_que = mergeable_que

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
        return 'PullReqState#{}(approved_by={}, priority={}, status={})'.format(
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
            issue = self.issue = self.repo.issue(self.num)

        issue.create_comment(text)

    def set_status(self, status):
        self.status = status

        db_query(self.db, 'INSERT OR REPLACE INTO state (repo, num, status) VALUES (?, ?, ?)', [self.repo_label, self.num, self.status])

        # FIXME: self.try_ should also be saved in the database
        if not self.try_:
            db_query(self.db, 'UPDATE state SET merge_sha = ? WHERE repo = ? AND num = ?', [self.merge_sha, self.repo_label, self.num])

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

def sha_cmp(short, full):
    return len(short) >= 4 and short == full[:len(short)]

def sha_or_blank(sha):
    return sha if re.match(r'^[0-9a-f]+$', sha) else ''

def parse_commands(body, username, repo_cfg, state, my_username, db, *, realtime=False, sha=''):
    if username not in repo_cfg['reviewers'] and username != my_username:
        return False

    state_changed = False

    words = list(chain.from_iterable(re.findall(r'\S+', x) for x in body.splitlines() if '@' + my_username in x))
    for i, word in reversed(list(enumerate(words))):
        found = True

        if word == 'r+' or word.startswith('r='):
            if not sha and i+1 < len(words):
                cur_sha = sha_or_blank(words[i+1])
            else:
                cur_sha = sha

            approver = word[len('r='):] if word.startswith('r=') else username

            if sha_cmp(cur_sha, state.head_sha):
                state.approved_by = approver
            elif realtime and username != my_username:
                if cur_sha:
                    msg = '`{}` is not a valid commit SHA.'.format(cur_sha)
                    state.add_comment(':scream_cat: {} Please try again with `{:.7}`.'.format(msg, state.head_sha))
                else:
                    state.add_comment(':pushpin: Commit {:.7} has been approved by `{}`\n\n<!-- @{} r={} {} -->'.format(state.head_sha, approver, my_username, approver, state.head_sha))

        elif word == 'r-':
            state.approved_by = ''

        elif word.startswith('p='):
            try: state.priority = int(word[len('p='):])
            except ValueError: pass

        elif word == 'retry' and realtime:
            state.set_status('')

        elif word in ['try', 'try-'] and realtime:
            state.try_ = word == 'try'

            state.merge_sha = ''
            state.init_build_res([])

        elif word in ['rollup', 'rollup-']:
            state.rollup = word == 'rollup'

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

        else:
            found = False

        if found:
            state_changed = True

            words[i] = ''

    return state_changed

def create_merge(state, repo_cfg):
    master_sha = state.repo.ref('heads/' + repo_cfg.get('branch', {}).get('master', 'master')).object.sha
    utils.github_set_ref(
        state.repo,
        'heads/' + repo_cfg.get('branch', {}).get('tmp', 'tmp'),
        master_sha,
        force=True,
    )

    merge_msg = 'Auto merge of #{} - {}, r={}\n\n{}'.format(
        state.num,
        state.head_ref,
        '<try>' if state.try_ else state.approved_by,
        state.body,
    )
    try: merge_commit = state.repo.merge(repo_cfg.get('branch', {}).get('tmp', 'tmp'), state.head_sha, merge_msg)
    except github3.models.GitHubError as e:
        if e.code != 409: raise

        state.set_status('error')
        desc = 'Merge conflict'
        utils.github_create_status(state.repo, state.head_sha, 'error', '', desc, context='homu')

        state.add_comment(':lock: ' + desc)

        return None

    return merge_commit

def start_build(state, repo_cfgs, buildbot_slots, logger, db):
    if buildbot_slots[0]:
        return True

    assert state.head_sha == state.repo.pull_request(state.num).head.sha

    repo_cfg = repo_cfgs[state.repo_label]

    merge_commit = create_merge(state, repo_cfg)
    if not merge_commit:
        return False

    if 'buildbot' in repo_cfg:
        branch = 'try' if state.try_ else 'auto'
        branch = repo_cfg.get('branch', {}).get(branch, branch)
        builders = repo_cfg['buildbot']['try_builders' if state.try_ else 'builders']
    elif 'travis' in repo_cfg:
        branch = repo_cfg.get('branch', {}).get('auto', 'auto')
        builders = ['travis']
    else:
        raise RuntimeError('Invalid configuration')

    utils.github_set_ref(state.repo, 'heads/' + branch, merge_commit.sha, force=True)

    state.init_build_res(builders)
    state.merge_sha = merge_commit.sha

    if 'buildbot' in repo_cfg:
        buildbot_slots[0] = state.merge_sha

    logger.info('Starting build of #{} on {}: {}'.format(state.num, branch, state.merge_sha))

    state.set_status('pending')
    desc = '{} commit {:.7} with merge {:.7}...'.format('Trying' if state.try_ else 'Testing', state.head_sha, state.merge_sha)
    utils.github_create_status(state.repo, state.head_sha, 'pending', '', desc, context='homu')

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

    master_sha = state.repo.ref('heads/' + repo_cfg.get('branch', {}).get('master', 'master')).object.sha
    parent_shas = [x['sha'] for x in state.repo.commit(state.merge_sha).parents]

    if master_sha not in parent_shas:
        return False

    utils.github_set_ref(state.repo, 'tags/homu-tmp', state.merge_sha, force=True)

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

    utils.github_create_status(state.repo, state.head_sha, 'pending', '', '{}{}...'.format(msg_1, msg_3), context='homu')

    state.add_comment(':zap: {}{}{}{}...'.format(msg_1, msg_2, msg_3, msg_4))

    return True

def start_build_or_rebuild(state, repo_cfgs, *args):
    if start_rebuild(state, repo_cfgs):
        return True

    return start_build(state, repo_cfgs, *args)

def process_queue(states, repos, repo_cfgs, logger, buildbot_slots, db):
    for repo_label, repo in repos.items():
        repo_states = sorted(states[repo_label].values())

        for state in repo_states:
            if state.status == 'pending' and not state.try_:
                break

            elif state.status == '' and state.approved_by:
                if start_build_or_rebuild(state, repo_cfgs, buildbot_slots, logger, db):
                    return

            elif state.status == 'success' and state.try_ and state.approved_by:
                state.try_ = False

                if start_build(state, repo_cfgs, buildbot_slots, logger, db):
                    return

        for state in repo_states:
            if state.status == '' and state.try_:
                if start_build(state, repo_cfgs, buildbot_slots, logger, db):
                    return

def fetch_mergeability(mergeable_que):
    re_pull_num = re.compile('(?i)merge (?:of|pull request) #([0-9]+)')

    while True:
        try:
            state, cause = mergeable_que.get()

            mergeable = state.repo.pull_request(state.num).mergeable
            if mergeable is None:
                time.sleep(5)
                mergeable = state.repo.pull_request(state.num).mergeable

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

def main():
    logger = logging.getLogger('homu')
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())

    with open('cfg.toml') as fp:
        cfg = toml.loads(fp.read())

    gh = github3.login(token=cfg['github']['access_token'])

    states = {}
    repos = {}
    repo_cfgs = {}
    buildbot_slots = ['']
    my_username = gh.user().login
    repo_labels = {}
    mergeable_que = Queue()

    db_conn = sqlite3.connect('main.db', check_same_thread=False, isolation_level=None)
    db = db_conn.cursor()

    db_query(db, '''CREATE TABLE IF NOT EXISTS state (
        repo TEXT NOT NULL,
        num INTEGER NOT NULL,
        status TEXT NOT NULL,
        merge_sha TEXT,
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

    logger.info('Retrieving pull requests...')

    for repo_label, repo_cfg in cfg['repo'].items():
        repo = gh.repository(repo_cfg['owner'], repo_cfg['name'])

        states[repo_label] = {}
        repos[repo_label] = repo
        repo_cfgs[repo_label] = repo_cfg

        for pull in repo.iter_pulls(state='open'):
            db_query(db, 'SELECT status FROM state WHERE repo = ? AND num = ?', [repo_label, pull.number])
            row = db.fetchone()
            if row:
                status = row[0]
            else:
                status = ''
                for info in utils.github_iter_statuses(repo, pull.head.sha):
                    if info.context == 'homu':
                        status = info.state
                        break

                db_query(db, 'INSERT INTO state (repo, num, status) VALUES (?, ?, ?)', [repo_label, pull.number, status])

            state = PullReqState(pull.number, pull.head.sha, status, repo, db, repo_label, mergeable_que)
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

            states[repo_label][pull.number] = state

        repo_labels[repo.owner.login, repo.name] = repo_label

    db_query(db, 'SELECT repo, num, merge_sha FROM state')
    for repo_label, num, merge_sha in db.fetchall():
        try: state = states[repo_label][num]
        except KeyError:
            db_query(db, 'DELETE FROM state WHERE repo = ? AND num = ?', [repo_label, num])
            continue

        if merge_sha:
            if 'buildbot' in repo_cfgs[repo_label]:
                builders = repo_cfgs[repo_label]['buildbot']['builders']
            else:
                builders = ['travis']

            state.init_build_res(builders, use_db=False)
            state.merge_sha = merge_sha

        elif state.status == 'pending':
            # FIXME: There might be a better solution
            state.status = ''

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

    logger.info('Done!')

    queue_handler_lock = Lock()
    def queue_handler():
        with queue_handler_lock:
            return process_queue(states, repos, repo_cfgs, logger, buildbot_slots, db)

    from . import server
    Thread(target=server.start, args=[cfg, states, queue_handler, repo_cfgs, repos, logger, buildbot_slots, my_username, db, repo_labels, mergeable_que]).start()

    Thread(target=fetch_mergeability, args=[mergeable_que]).start()

    queue_handler()

if __name__ == '__main__':
    main()
