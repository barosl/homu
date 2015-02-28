import hmac
import json
import urllib.parse
from .main import PullReqState, parse_commands, db_query, INTERRUPTED_BY_HOMU_RE
from . import utils
import github3
import jinja2
import requests
import pkg_resources
from bottle import get, post, run, request, redirect, abort, response
import hashlib

import bottle; bottle.BaseRequest.MEMFILE_MAX = 1024 * 1024 * 10

class G: pass
g = G()

def find_state(sha):
    for repo_label, repo_states in g.states.items():
        for state in repo_states.values():
            if state.merge_sha == sha:
                return state, repo_label

    raise ValueError('Invalid SHA')

@get('/')
def index():
    return g.tpls['index'].render(repos=sorted(g.repos))

@get('/queue/<repo_label>')
def queue(repo_label):
    if repo_label == 'all':
        labels = g.repos.keys()
    else:
        labels = repo_label.split('+')

    states = []
    for label in labels:
        states += g.states[label].values()

    pull_states = sorted(states)

    rows = []
    for state in pull_states:
        rows.append({
            'status': state.get_status(),
            'status_ext': ' (try)' if state.try_ else '',
            'priority': 'rollup' if state.rollup else state.priority,
            'url': 'https://github.com/{}/{}/pull/{}'.format(state.repo.owner.login, state.repo.name, state.num),
            'num': state.num,
            'approved_by': state.approved_by,
            'title': state.title,
            'head_ref': state.head_ref,
            'mergeable': 'yes' if state.mergeable is True else 'no' if state.mergeable is False else '',
            'assignee': state.assignee,
        })

    return g.tpls['queue'].render(
        repo_label = repo_label,
        states = rows,
        oauth_client_id = g.cfg['github']['app_client_id'],
        total = len(pull_states),
        approved = len([x for x in pull_states if x.approved_by]),
        rolled_up = len([x for x in pull_states if x.rollup]),
        failed = len([x for x in pull_states if x.status == 'failure' or x.status == 'error']),
    )

@get('/rollup')
def rollup():
    response.content_type = 'text/plain'

    code = request.query.code
    state = json.loads(request.query.state)

    res = requests.post('https://github.com/login/oauth/access_token', data={
        'client_id': g.cfg['github']['app_client_id'],
        'client_secret': g.cfg['github']['app_client_secret'],
        'code': code,
    })
    args = urllib.parse.parse_qs(res.text)
    token = args['access_token'][0]

    repo_label = state['repo_label']
    repo = g.repos[repo_label]
    repo_cfg = g.repo_cfgs[repo_label]

    user_gh = github3.login(token=token)
    user_repo = user_gh.repository(user_gh.user().login, repo.name)
    base_repo = user_gh.repository(repo.owner.login, repo.name)

    nums = state.get('nums', [])
    if nums:
        try: rollup_states = [g.states[repo_label][num] for num in nums]
        except KeyError as e: return 'Invalid PR number: {}'.format(e.args[0])
    else:
        rollup_states = [x for x in g.states[repo_label].values() if x.rollup]
    rollup_states = [x for x in rollup_states if x.approved_by]
    rollup_states.sort(key=lambda x: x.num)

    if not rollup_states:
        return 'No pull requests are marked as rollup'

    master_sha = repo.ref('heads/' + repo_cfg.get('branch', {}).get('master', 'master')).object.sha
    utils.github_set_ref(
        user_repo,
        'heads/' + repo_cfg.get('branch', {}).get('rollup', 'rollup'),
        master_sha,
        force=True,
    )

    successes = []
    failures = []

    for state in rollup_states:
        merge_msg = 'Rollup merge of #{} - {}, r={}\n\n{}'.format(
            state.num,
            state.head_ref,
            state.approved_by,
            state.body,
        )

        try: user_repo.merge(repo_cfg.get('branch', {}).get('rollup', 'rollup'), state.head_sha, merge_msg)
        except github3.models.GitHubError as e:
            if e.code != 409: raise

            failures.append(state.num)
        else:
            successes.append(state.num)

    title = 'Rollup of {} pull requests'.format(len(successes))
    body = '- Successful merges: {}\n- Failed merges: {}'.format(
        ', '.join('#{}'.format(x) for x in successes),
        ', '.join('#{}'.format(x) for x in failures),
    )

    try:
        pull = base_repo.create_pull(
            title,
            repo_cfg.get('branch', {}).get('master', 'master'),
            user_repo.owner.login + ':' + repo_cfg.get('branch', {}).get('rollup', 'rollup'),
            body,
        )
    except github3.models.GitHubError as e:
        return e.response.text
    else:
        redirect(pull.html_url)

@post('/github')
def github():
    response.content_type = 'text/plain'

    payload = request.body.read()
    info = request.json

    owner_info = info['repository']['owner']
    owner = owner_info.get('login') or owner_info['name']
    repo_label = g.repo_labels[owner, info['repository']['name']]
    repo_cfg = g.repo_cfgs[repo_label]

    hmac_method, hmac_sig = request.headers['X-Hub-Signature'].split('=')
    if hmac_sig != hmac.new(
        repo_cfg['github']['secret'].encode('utf-8'),
        payload,
        hmac_method,
    ).hexdigest():
        abort(400, 'Invalid signature')

    event_type = request.headers['X-Github-Event']

    if event_type == 'pull_request_review_comment':
        action = info['action']
        original_commit_id = info['comment']['original_commit_id']
        head_sha = info['pull_request']['head']['sha']

        if action == 'created' and original_commit_id == head_sha:
            pull_num = info['pull_request']['number']
            body = info['comment']['body']
            username = info['sender']['login']

            if parse_commands(
                body,
                username,
                repo_cfg,
                g.states[repo_label][pull_num],
                g.my_username,
                g.db,
                realtime=True,
                sha=original_commit_id,
            ):
                g.queue_handler()

    elif event_type == 'pull_request':
        action = info['action']
        pull_num = info['number']
        head_sha = info['pull_request']['head']['sha']

        if action == 'synchronize':
            state = g.states[repo_label][pull_num]
            state.head_advanced(head_sha)

        elif action in ['opened', 'reopened']:
            state = PullReqState(pull_num, head_sha, '', g.repos[repo_label], g.db, repo_label, g.mergeable_que)
            state.title = info['pull_request']['title']
            state.body = info['pull_request']['body']
            state.head_ref = info['pull_request']['head']['repo']['owner']['login'] + ':' + info['pull_request']['head']['ref']
            state.base_ref = info['pull_request']['base']['ref']
            state.set_mergeable(info['pull_request']['mergeable'])
            state.assignee = info['pull_request']['assignee']['login'] if info['pull_request']['assignee'] else ''

            found = False

            if action == 'reopened':
                # FIXME: Review comments are ignored here
                for comment in g.repos[repo_label].issue(pull_num).iter_comments():
                    found = parse_commands(
                        comment.body,
                        comment.user.login,
                        repo_cfg,
                        state,
                        g.my_username,
                        g.db,
                    ) or found

            g.states[repo_label][pull_num] = state

            if found:
                g.queue_handler()

        elif action == 'closed':
            del g.states[repo_label][pull_num]

            db_query(g.db, 'DELETE FROM state WHERE repo = ? AND num = ?', [repo_label, pull_num])
            db_query(g.db, 'DELETE FROM build_res WHERE repo = ? AND num = ?', [repo_label, pull_num])
            db_query(g.db, 'DELETE FROM mergeable WHERE repo = ? AND num = ?', [repo_label, pull_num])

            g.queue_handler()

        elif action in ['assigned', 'unassigned']:
            state = g.states[repo_label][pull_num]
            state.assignee = info['pull_request']['assignee']['login'] if info['pull_request']['assignee'] else ''

        else:
            g.logger.debug('Invalid pull_request action: {}'.format(action))

    elif event_type == 'push':
        ref = info['ref'][len('refs/heads/'):]

        for state in list(g.states[repo_label].values()):
            if state.base_ref == ref:
                state.set_mergeable(None, cause={
                    'sha': info['head_commit']['id'],
                    'title': info['head_commit']['message'].splitlines()[0],
                })

            if state.head_sha == info['before']:
                state.head_advanced(info['after'])

    elif event_type == 'issue_comment':
        body = info['comment']['body']
        username = info['comment']['user']['login']
        pull_num = info['issue']['number']

        state = g.states[repo_label].get(pull_num)

        if 'pull_request' in info['issue'] and state:
            state.title = info['issue']['title']
            state.body = info['issue']['body']

            if parse_commands(
                body,
                username,
                repo_cfg,
                state,
                g.my_username,
                g.db,
                realtime=True,
            ):
                g.queue_handler()

    return 'OK'

def report_build_res(succ, url, builder, repo_label, state):
    state.set_build_res(builder, succ, url)

    if succ:
        if all(x['res'] for x in state.build_res.values()):
            state.set_status('success')
            desc = 'Test successful'
            utils.github_create_status(state.repo, state.head_sha, 'success', url, desc, context='homu')

            urls = ', '.join('[{}]({})'.format(builder, x['url']) for builder, x in sorted(state.build_res.items()))
            state.add_comment(':sunny: {} - {}'.format(desc, urls))

            if state.approved_by and not state.try_:
                try:
                    utils.github_set_ref(
                        state.repo,
                        'heads/' + g.repo_cfgs[repo_label].get('branch', {}).get('master', 'master'),
                        state.merge_sha,
                    )
                except github3.models.GitHubError as e:
                    state.set_status('error')
                    desc = 'Test was successful, but fast-forwarding failed: {}'.format(e)
                    utils.github_create_status(state.repo, state.head_sha, 'error', url, desc, context='homu')

                    state.add_comment(':eyes: ' + desc)

    else:
        if state.status == 'pending':
            state.set_status('failure')
            desc = 'Test failed'
            utils.github_create_status(state.repo, state.head_sha, 'failure', url, desc, context='homu')

            state.add_comment(':broken_heart: {} - [{}]({})'.format(desc, builder, url))

    g.queue_handler()

@post('/buildbot')
def buildbot():
    response.content_type = 'text/plain'

    for row in json.loads(request.forms.packets):
        if row['event'] == 'buildFinished':
            info = row['payload']['build']
            props = dict(x[:2] for x in info['properties'])

            if 'retry' in info['text']: continue

            if not props['revision']: continue

            try: state, repo_label = find_state(props['revision'])
            except ValueError:
                g.logger.debug('Invalid commit ID from Buildbot: {}'.format(props['revision']))
                continue

            if info['builderName'] not in state.build_res:
                g.logger.debug('Invalid builder from Buildbot: {}'.format(info['builderName']))
                continue

            repo_cfg = g.repo_cfgs[repo_label]

            if request.forms.secret != repo_cfg['buildbot']['secret']:
                abort(400, 'Invalid secret')

            build_succ = 'successful' in info['text'] or info['results'] == 0

            url = '{}/builders/{}/builds/{}'.format(
                repo_cfg['buildbot']['url'],
                info['builderName'],
                props['buildnumber'],
            )

            if 'interrupted' in info['text']:
                step_name = ''
                for step in reversed(info['steps']):
                    if 'interrupted' in step.get('text', []):
                        step_name = step['name']
                        break

                if step_name:
                    res = requests.get('{}/builders/{}/builds/{}/steps/{}/logs/interrupt'.format(
                        repo_cfg['buildbot']['url'],
                        info['builderName'],
                        props['buildnumber'],
                        step_name,
                    ))

                    mat = INTERRUPTED_BY_HOMU_RE.search(res.text)
                    if mat:
                        interrupt_token = mat.group(1)
                        if getattr(state, 'interrupt_token', '') != interrupt_token:
                            state.interrupt_token = interrupt_token

                            if state.status == 'pending':
                                state.set_status('')

                                desc = ':snowman: The build was interrupted to prioritize another pull request.'
                                state.add_comment(desc)
                                utils.github_create_status(state.repo, state.head_sha, 'error', url, desc, context='homu')

                                g.queue_handler()

                        continue

                else:
                    g.logger.error('Corrupt payload from Buildbot')

            report_build_res(build_succ, url, info['builderName'], repo_label, state)

        elif row['event'] == 'buildStarted':
            info = row['payload']['build']
            props = dict(x[:2] for x in info['properties'])

            if not props['revision']: continue

            try: state, repo_label = find_state(props['revision'])
            except ValueError: pass
            else:
                if info['builderName'] in state.build_res:
                    repo_cfg = g.repo_cfgs[repo_label]

                    if request.forms.secret != repo_cfg['buildbot']['secret']:
                        abort(400, 'Invalid secret')

                    url = '{}/builders/{}/builds/{}'.format(
                        repo_cfg['buildbot']['url'],
                        info['builderName'],
                        props['buildnumber'],
                    )

                    state.set_build_res(info['builderName'], None, url)

            if g.buildbot_slots[0] == props['revision']:
                g.buildbot_slots[0] = ''

                g.queue_handler()

    return 'OK'

@post('/travis')
def travis():
    info = json.loads(request.forms.payload)

    try: state, repo_label = find_state(info['commit'])
    except ValueError:
        g.logger.debug('Invalid commit ID from Travis: {}'.format(info['commit']))
        return 'OK'

    if 'travis' not in state.build_res:
        return 'OK'

    token = g.repo_cfgs[repo_label]['travis']['token']
    code = hashlib.sha256(('{}/{}{}'.format(state.repo.owner.login, state.repo.name, token)).encode('utf-8')).hexdigest()
    if request.headers['Authorization'] != code:
        abort(400, 'Authorization failed')

    succ = info['result'] == 0

    report_build_res(succ, info['build_url'], 'travis', repo_label, state)

    return 'OK'

def start(cfg, states, queue_handler, repo_cfgs, repos, logger, buildbot_slots, my_username, db, repo_labels, mergeable_que):
    env = jinja2.Environment(
        loader = jinja2.FileSystemLoader(pkg_resources.resource_filename(__name__, 'html')),
        autoescape = True,
    )
    tpls = {}
    tpls['index'] = env.get_template('index.html')
    tpls['queue'] = env.get_template('queue.html')

    g.cfg = cfg
    g.states = states
    g.queue_handler = queue_handler
    g.repo_cfgs = repo_cfgs
    g.repos = repos
    g.logger = logger
    g.buildbot_slots = buildbot_slots
    g.tpls = tpls
    g.my_username = my_username
    g.db = db
    g.repo_labels = repo_labels
    g.mergeable_que = mergeable_que

    run(host='', port=cfg['web']['port'], server='waitress')
