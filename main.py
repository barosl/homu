#!/usr/bin/env python3

import github3
import toml
import json
import re
import server
import utils
import logging
from threading import Thread
import time
import traceback

class PullReqState:
    num = 0
    priority = 0
    rollup = False
    title = ''
    body = ''
    head_ref = ''
    base_ref = ''
    assignee = ''

    def __init__(self, num, head_sha, status):
        self.head_advanced('')

        self.num = num
        self.head_sha = head_sha
        self.status = status

    def head_advanced(self, head_sha):
        self.head_sha = head_sha
        self.approved_by = ''
        self.status = ''
        self.merge_sha = ''
        self.build_res = {}
        self.try_ = False
        self.mergeable = None

    def __repr__(self):
        return 'PullReqState#{}(approved_by={}, priority={}, status={})'.format(
            self.num,
            self.approved_by,
            self.priority,
            self.status,
        )

    def sort_key(self):
        return [
            1 if self.mergeable is False else 0,
            0 if self.approved_by else 1,
            1 if self.rollup else 0,
            -self.priority,
            self.num,
        ]

    def __lt__(self, other):
        return self.sort_key() < other.sort_key()

def sha_cmp(short, full):
    return len(short) >= 4 and short == full[:len(short)]

def parse_commands(body, username, reviewers, state, my_username, *, realtime=False, sha=''):
    if username not in reviewers:
        return False

    mentioned = '@' + my_username in body
    if not mentioned: return False

    state_changed = False

    words = re.findall(r'\S+', body)
    for i, word in enumerate(words):
        found = True

        if word in ['r+', 'r=me']:
            if not sha and i+1 < len(words):
                sha = words[i+1]

            if sha_cmp(sha, state.head_sha):
                state.approved_by = username

        elif word.startswith('r='):
            if not sha and i+1 < len(words):
                sha = words[i+1]

            if sha_cmp(sha, state.head_sha):
                state.approved_by = word[len('r='):]

        elif word == 'r-':
            state.approved_by = ''

        elif word.startswith('p='):
            try: state.priority = int(word[len('p='):])
            except ValueError: pass

        elif word == 'retry' and realtime:
            state.status = ''

        elif word == 'try' and realtime:
            state.try_ = True

        elif word == 'rollup':
            state.rollup = True

        elif word == 'rollup-':
            state.rollup = False

        else:
            found = False

        if found:
            state_changed = True

    return state_changed

def start_build(state, repo, repo_cfgs, buildbot_slots, logger):
    if buildbot_slots[0]:
        return True

    assert state.head_sha == repo.pull_request(state.num).head.sha

    repo_cfg = repo_cfgs[repo.name]

    master_sha = repo.ref('heads/' + repo_cfg['master_branch']).object.sha
    try:
        utils.github_set_ref(
            repo,
            'heads/' + repo_cfg['tmp_branch'],
            master_sha,
            force=True,
        )
    except github3.models.GitHubError:
        repo.create_ref(
            'refs/heads/' + repo_cfg['tmp_branch'],
            master_sha,
        )

    merge_msg = 'Auto merge of #{} - {}, r={}\n\n{}'.format(
        state.num,
        state.head_ref,
        state.approved_by,
        state.body,
    )
    try: merge_commit = repo.merge(repo_cfg['tmp_branch'], state.head_sha, merge_msg)
    except github3.models.GitHubError as e:
        if e.code != 409: raise

        desc = 'Merge conflict'
        utils.github_create_status(repo, state.head_sha, 'error', '', desc, context='homu')
        state.status = 'error'

        repo.issue(state.num).create_comment(':umbrella: ' + desc)

        return False
    else:
        utils.github_set_ref(repo, 'heads/' + repo_cfg['buildbot_branch'], merge_commit.sha, force=True)

        state.build_res = {x: None for x in repo_cfgs[repo.name]['builders']}
        state.merge_sha = merge_commit.sha

        buildbot_slots[0] = state.merge_sha

        logger.info('Starting build of #{}: {}'.format(state.num, state.merge_sha))

        desc = 'Testing commit {:.7} with merge {:.7}...'.format(state.head_sha, state.merge_sha)
        utils.github_create_status(repo, state.head_sha, 'pending', '', desc, context='homu')
        state.status = 'pending'

        repo.issue(state.num).create_comment(':hourglass: ' + desc)

    return True

def process_queue(states, repos, repo_cfgs, logger, cfg, buildbot_slots):
    for repo in repos.values():
        repo_states = sorted(states[repo.name].values())

        for state in repo_states:
            if state.status == 'pending' and not state.try_:
                break

            elif state.status == '' and state.approved_by:
                if start_build(state, repo, repo_cfgs, buildbot_slots, logger):
                    return

            elif state.status == 'success' and state.try_ and state.approved_by:
                state.try_ = False

                if start_build(state, repo, repo_cfgs, buildbot_slots, logger):
                    return

        for state in repo_states:
            if state.status == '' and state.try_:
                if start_build(state, repo, repo_cfgs, buildbot_slots, logger):
                    return

def fetch_mergeability(states, repos):
    while True:
        try:
            for repo in repos.values():
                for state in states[repo.name].values():
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

    gh = github3.login(token=cfg['main']['token'])

    states = {}
    repos = {}
    repo_cfgs = {}
    buildbot_slots = ['']
    my_username = gh.user().login

    queue_handler = lambda: process_queue(states, repos, repo_cfgs, logger, cfg, buildbot_slots)

    logger.info('Retrieving pull requests...')

    for repo_cfg in cfg['repo']:
        repo = gh.repository(repo_cfg['owner'], repo_cfg['repo'])

        states[repo.name] = {}
        repos[repo.name] = repo
        repo_cfgs[repo.name] = repo_cfg

        for pull in repo.iter_pulls(state='open'):
            status = ''
            for info in utils.github_iter_statuses(repo, pull.head.sha):
                if info.context == 'homu':
                    status = info.state
                    break

            state = PullReqState(pull.number, pull.head.sha, status)
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
                        repo_cfg['reviewers'],
                        state,
                        my_username,
                        sha=comment.original_commit_id,
                    )

            for comment in pull.iter_issue_comments():
                parse_commands(
                    comment.body,
                    comment.user.login,
                    repo_cfg['reviewers'],
                    state,
                    my_username,
                )

            states[repo.name][pull.number] = state

    logger.info('Done!')

    server.start(cfg, states, queue_handler, repo_cfgs, repos, logger, buildbot_slots, my_username)

    Thread(target=fetch_mergeability, args=[states, repos]).start()

    queue_handler()

if __name__ == '__main__':
    main()
