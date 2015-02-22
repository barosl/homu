import github3
import toml
import json
import re
from . import utils
import logging
from threading import Thread
import time
import traceback
import sqlite3
import requests

STATUS_TO_PRIORITY = {
    'success': 0,
    'pending': 1,
    'approved': 2,
    '': 3,
    'error': 4,
    'failure': 5,
}

class PullReqState:
    num = 0
    priority = 0
    rollup = False
    title = ''
    body = ''
    head_ref = ''
    base_ref = ''
    assignee = ''

    def __init__(self, num, head_sha, status, repo, db, repo_label):
        self.head_advanced('', use_db=False)

        self.num = num
        self.head_sha = head_sha
        self.status = status
        self.repo = repo
        self.db = db
        self.repo_label = repo_label

    def head_advanced(self, head_sha, *, use_db=True):
        self.head_sha = head_sha
        self.approved_by = ''
        self.status = ''
        self.merge_sha = ''
        self.build_res = {}
        self.try_ = False
        self.mergeable = None

        if use_db: self.set_status('')

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

        self.db.execute('INSERT OR REPLACE INTO state (repo, num, status) VALUES (?, ?, ?)', [self.repo_label, self.num, self.status])

    def get_status(self):
        return 'approved' if self.status == '' and self.approved_by and self.mergeable is not False else self.status

def sha_cmp(short, full):
    return len(short) >= 4 and short == full[:len(short)]

def parse_commands(body, username, repo_cfg, state, my_username, db, *, realtime=False, sha=''):
    if username not in repo_cfg['reviewers']:
        return False

    mentioned = '@' + my_username in body
    if not mentioned: return False

    state_changed = False

    words = re.findall(r'\S+', body)
    for i, word in enumerate(words):
        found = True

        if word == 'r+' or word.startswith('r='):
            if not sha and i+1 < len(words):
                sha = words[i+1]

            if sha_cmp(sha, state.head_sha):
                state.approved_by = word[len('r='):] if word.startswith('r=') else username
            elif realtime:
                msg = '`{}` is not a valid commit SHA.'.format(sha) if sha else 'No commit SHA found.'
                state.add_comment(':scream_cat: {} Please try again with `{:.7}`.'.format(msg, state.head_sha))

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
            state.build_res = {}

        elif word in ['rollup', 'rollup-']:
            state.rollup = word == 'rollup'

        elif word == 'force' and realtime:
            sess = requests.Session()

            sess.post(repo_cfg['buildbot']['url'] + '/login', allow_redirects=False, data={
                'username': repo_cfg['buildbot']['username'],
                'passwd': repo_cfg['buildbot']['password'],
            })

            res = sess.post(repo_cfg['buildbot']['url'] + '/builders/_selected/stopselected', allow_redirects=False, data={
                'selected': repo_cfg['buildbot']['builders'],
                'comments': 'Interrupted by Homu',
            })

            sess.get(repo_cfg['buildbot']['url'] + '/logout', allow_redirects=False)

            err = ''
            if 'authzfail' in res.text:
                err = 'Authorization failed'
            else:
                mat = re.search('(?s)<div class="error">(.*?)</div>', res.text)
                if mat: err = mat.group(1).strip()

            if err:
                state.add_comment(':bomb: Buildbot returned an error: `{}`'.format(err))

        else:
            found = False

        if found:
            state_changed = True

    return state_changed

def start_build(state, repo, repo_cfgs, buildbot_slots, logger, db):
    if buildbot_slots[0]:
        return True

    assert state.head_sha == repo.pull_request(state.num).head.sha

    repo_cfg = repo_cfgs[state.repo_label]

    master_sha = repo.ref('heads/' + repo_cfg.get('branch', {}).get('master', 'master')).object.sha
    try:
        utils.github_set_ref(
            repo,
            'heads/' + repo_cfg.get('branch', {}).get('tmp', 'tmp'),
            master_sha,
            force=True,
        )
    except github3.models.GitHubError:
        repo.create_ref(
            'refs/heads/' + repo_cfg.get('branch', {}).get('tmp', 'tmp'),
            master_sha,
        )

    merge_msg = 'Auto merge of #{} - {}, r={}\n\n{}'.format(
        state.num,
        state.head_ref,
        '<try>' if state.try_ else state.approved_by,
        state.body,
    )
    try: merge_commit = repo.merge(repo_cfg.get('branch', {}).get('tmp', 'tmp'), state.head_sha, merge_msg)
    except github3.models.GitHubError as e:
        if e.code != 409: raise

        desc = 'Merge conflict'
        utils.github_create_status(repo, state.head_sha, 'error', '', desc, context='homu')
        state.set_status('error')

        state.add_comment(':umbrella: ' + desc)

        return False
    else:
        if 'buildbot' in repo_cfg:
            branch = 'try' if state.try_ else 'auto'
            branch = repo_cfg.get('branch', {}).get(branch, branch)
            builders = repo_cfg['buildbot']['try_builders' if state.try_ else 'builders']
        elif 'travis' in repo_cfg:
            branch = repo_cfg.get('branch', {}).get('auto', 'auto')
            builders = ['travis']
        else:
            raise RuntimeError('Invalid configuration')

        utils.github_set_ref(repo, 'heads/' + branch, merge_commit.sha, force=True)

        state.build_res = {x: None for x in builders}
        state.merge_sha = merge_commit.sha

        if 'buildbot' in repo_cfg:
            buildbot_slots[0] = state.merge_sha

        logger.info('Starting build of #{} on {}: {}'.format(state.num, branch, state.merge_sha))

        desc = '{} commit {:.7} with merge {:.7}...'.format('Trying' if state.try_ else 'Testing', state.head_sha, state.merge_sha)
        utils.github_create_status(repo, state.head_sha, 'pending', '', desc, context='homu')
        state.set_status('pending')

        state.add_comment(':hourglass: ' + desc)

        # FIXME: state.try_ should also be saved in the database
        if not state.try_:
            db.execute('UPDATE state SET merge_sha = ? WHERE repo = ? AND num = ?', [state.merge_sha, state.repo_label, state.num])

    return True

def process_queue(states, repos, repo_cfgs, logger, buildbot_slots, db):
    for repo_label, repo in repos.items():
        repo_states = sorted(states[repo_label].values())

        for state in repo_states:
            if state.status == 'pending' and not state.try_:
                break

            elif state.status == '' and state.approved_by:
                if start_build(state, repo, repo_cfgs, buildbot_slots, logger, db):
                    return

            elif state.status == 'success' and state.try_ and state.approved_by:
                state.try_ = False

                if start_build(state, repo, repo_cfgs, buildbot_slots, logger, db):
                    return

        for state in repo_states:
            if state.status == '' and state.try_:
                if start_build(state, repo, repo_cfgs, buildbot_slots, logger, db):
                    return

def fetch_mergeability(states, repos):
    while True:
        try:
            for repo_label, repo in repos.items():
                for state in states[repo_label].values():
                    if state.mergeable is None:
                        state.mergeable = repo.pull_request(state.num).mergeable
        except:
            traceback.print_exc()

        time.sleep(60)

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

    db_conn = sqlite3.connect('main.db', check_same_thread=False, isolation_level=None)
    db = db_conn.cursor()

    db.execute('''CREATE TABLE IF NOT EXISTS state (
        repo TEXT NOT NULL,
        num INTEGER NOT NULL,
        status TEXT NOT NULL,
        merge_sha TEXT,
        UNIQUE (repo, num)
    )''')

    db.execute('''CREATE TABLE IF NOT EXISTS build_res (
        repo TEXT NOT NULL,
        num INTEGER NOT NULL,
        builder TEXT NOT NULL,
        res TEXT NOT NULL,
        UNIQUE (repo, num, builder)
    )''')

    logger.info('Retrieving pull requests...')

    for repo_label, repo_cfg in cfg['repo'].items():
        repo = gh.repository(repo_cfg['owner'], repo_cfg['name'])

        states[repo_label] = {}
        repos[repo_label] = repo
        repo_cfgs[repo_label] = repo_cfg

        for pull in repo.iter_pulls(state='open'):
            db.execute('SELECT status FROM state WHERE repo = ? AND num = ?', [repo_label, pull.number])
            row = db.fetchone()
            if row:
                status = row[0]
            else:
                status = ''
                for info in utils.github_iter_statuses(repo, pull.head.sha):
                    if info.context == 'homu':
                        status = info.state
                        break

                db.execute('INSERT INTO state (repo, num, status) VALUES (?, ?, ?)', [repo_label, pull.number, status])

            state = PullReqState(pull.number, pull.head.sha, status, repo, db, repo_label)
            state.title = pull.title
            state.body = pull.body
            state.head_ref = pull.head.repo[0] + ':' + pull.head.ref
            state.base_ref = pull.base.ref
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

    db.execute('SELECT repo, num, merge_sha FROM state')
    for repo_label, num, merge_sha in db.fetchall():
        try: state = states[repo_label][num]
        except KeyError:
            db.execute('DELETE FROM state WHERE repo = ? AND num = ?', [repo_label, num])
            continue

        if merge_sha:
            if 'buildbot' in repo_cfgs[repo_label]:
                builders = repo_cfgs[repo_label]['buildbot']['builders']
            else:
                builders = ['travis']

            state.build_res = {x: None for x in builders}
            state.merge_sha = merge_sha

        elif state.status == 'pending':
            # FIXME: There might be a better solution
            state.status = ''

    db.execute('SELECT repo, num, builder, res FROM build_res')
    for repo_label, num, builder, res in db.fetchall():
        try: state = states[repo_label][num]
        except KeyError:
            db.execute('DELETE FROM build_res WHERE repo = ? AND num = ? AND builder = ?', [repo_label, num, builder])
            continue

        if builder in state.build_res:
            state.build_res[builder] = json.loads(res)

    logger.info('Done!')

    queue_handler = lambda: process_queue(states, repos, repo_cfgs, logger, buildbot_slots, db)

    from . import server
    Thread(target=server.start, args=[cfg, states, queue_handler, repo_cfgs, repos, logger, buildbot_slots, my_username, db, repo_labels]).start()

    Thread(target=fetch_mergeability, args=[states, repos]).start()

    queue_handler()

if __name__ == '__main__':
    main()
