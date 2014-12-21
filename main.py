#!/usr/bin/env python3

import github3
import toml
import json
import re
import server
import utils
import logging

class PullReqState:
    num = 0
    title = ''
    head_ref = ''

    def __init__(self, num, head_sha, status):
        self.head_advanced('')

        self.num = num
        self.head_sha = head_sha
        self.status = status

    def head_advanced(self, head_sha):
        self.head_sha = head_sha
        self.approved_by = ''
        self.priority = 0
        self.status = ''
        self.merge_sha = ''
        self.build_res = {}
        self.try_ = False
        self.rollup = False

    def __repr__(self):
        return 'PullReqState#{}(approved_by={}, priority={}, status={})'.format(
            self.num,
            self.approved_by,
            self.priority,
            self.status,
        )

    def sort_key(self):
        return [
            0 if self.approved_by else 1,
            -self.priority,
            self.num,
        ]

    def __lt__(self, other):
        return self.sort_key() < other.sort_key()

def parse_commands(body, username, reviewers, state, *, realtime=False):
    if username not in reviewers:
        return

    state_changed = False

    for word in re.findall(r'\S+', body):
        found = True

        if word in ['r+', 'r=me']:
            state.approved_by = username

        elif word.startswith('r='):
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

    merge_msg = 'Merge {:.7} into {}\n\nApproved-by: {}'.format(
        state.head_sha,
        repo_cfg['tmp_branch'],
        state.approved_by,
    )
    try: merge_commit = repo.merge(repo_cfg['tmp_branch'], state.head_sha, merge_msg)
    except github3.models.GitHubError as e:
        if e.code != 409: raise

        utils.github_create_status(repo, state.head_sha, 'error', '', 'Merge conflict', context='homu')
        state.status = 'error'

        return False
    else:
        utils.github_set_ref(repo, 'heads/' + repo_cfg['buildbot_branch'], merge_commit.sha, force=True)

        state.build_res = {x: None for x in repo_cfgs[repo.name]['builders']}
        state.merge_sha = merge_commit.sha

        buildbot_slots[0] = state.merge_sha

        logger.info('Starting build: {}'.format(state.merge_sha))

        desc = 'Testing candidate {}...'.format(state.merge_sha)
        utils.github_create_status(repo, state.head_sha, 'pending', '', desc, context='homu')
        state.status = 'pending'

    return True

def process_queue(states, repos, repo_cfgs, logger, cfg, buildbot_slots):
    for repo in repos.values():
        repo_states = sorted(states[repo.name].values())

        for state in repo_states:
            if state.status == 'pending':
                break

            elif state.status == '' and state.approved_by:
                if start_build(state, repo, repo_cfgs, buildbot_slots, logger):
                    break

            elif state.status == 'success' and state.try_:
                state.try_ = False

                if start_build(state, repo, repo_cfgs, buildbot_slots, logger):
                    break

        for state in repo_states:
            if state.status == '' and state.try_:
                start_build(state, repo, repo_cfgs, buildbot_slots, logger)

def main():
    logger = logging.getLogger('homu')

    with open('cfg.toml') as fp:
        cfg = toml.loads(fp.read())

    gh = github3.login(token=cfg['main']['token'])

    states = {}
    repos = {}
    repo_cfgs = {}
    buildbot_slots = ['']

    queue_handler = lambda: process_queue(states, repos, repo_cfgs, logger, cfg, buildbot_slots)

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
            state.head_ref = pull.head.repo[0] + ':' + pull.head.ref

            for comment in pull.iter_comments():
                if comment.original_commit_id == pull.head.sha:
                    parse_commands(
                        comment.body,
                        comment.user.login,
                        repo_cfg['reviewers'],
                        state,
                    )

            states[repo.name][pull.number] = state

    server.start(cfg, states, queue_handler, repo_cfgs, repos, logger, buildbot_slots)

    queue_handler()

if __name__ == '__main__':
    main()
