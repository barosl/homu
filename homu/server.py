import hmac
import json
import urllib.parse
from .main import PullReqState, parse_commands
from . import utils
import github3
import jinja2
import requests
import pkg_resources
from bottle import get, post, run, request, redirect, abort, response

class G: pass
g = G()

@get('/')
def index():
    return g.tpls['index'].render(repos=sorted(g.repos))

@get('/queue/<repo_name>')
def queue(repo_name):
    repo = g.repos[repo_name]
    pull_states = sorted(g.states[repo_name].values())

    rows = []
    for state in pull_states:
        rows.append({
            'status': state.get_status(),
            'status_ext': ' (try)' if state.try_ else '',
            'priority': 'rollup' if state.rollup else state.priority,
            'url': 'https://github.com/{}/{}/pull/{}'.format(repo.owner, repo.name, state.num),
            'num': state.num,
            'approved_by': state.approved_by,
            'title': state.title,
            'head_ref': state.head_ref,
            'mergeable': 'yes' if state.mergeable is True else 'no' if state.mergeable is False else '',
            'assignee': state.assignee,
        })

    return g.tpls['queue'].render(
        repo_name = repo.name,
        states = rows,
        oauth_client_id = g.cfg['main']['oauth_client_id'],
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
        'client_id': g.cfg['main']['oauth_client_id'],
        'client_secret': g.cfg['main']['oauth_client_secret'],
        'code': code,
    })
    args = urllib.parse.parse_qs(res.text)
    token = args['access_token'][0]

    repo = g.repos[state['repo']]
    repo_cfg = g.repo_cfgs[repo.name]

    user_gh = github3.login(token=token)
    user_repo = user_gh.repository(user_gh.user().login, repo.name)
    base_repo = user_gh.repository(repo.owner.login, repo.name)

    rollup_states = [x for x in g.states[repo.name].values() if x.rollup and x.approved_by]
    rollup_states.sort(key=lambda x: x.num)

    if not rollup_states:
        return 'No pull requests are marked as rollup'

    master_sha = repo.ref('heads/' + repo_cfg['master_branch']).object.sha
    try:
        utils.github_set_ref(
            user_repo,
            'heads/' + repo_cfg['rollup_branch'],
            master_sha,
            force=True,
        )
    except github3.models.GitHubError:
        user_repo.create_ref(
            'refs/heads/' + repo_cfg['rollup_branch'],
            master_sha,
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

        try: user_repo.merge(repo_cfg['rollup_branch'], state.head_sha, merge_msg)
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
            repo_cfg['master_branch'],
            user_repo.owner.login + ':' + repo_cfg['rollup_branch'],
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

    hmac_method, hmac_sig = request.headers['X-Hub-Signature'].split('=')
    if hmac_sig != hmac.new(
        g.hmac_key,
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
            repo_name = info['repository']['name']
            pull_num = info['pull_request']['number']
            body = info['comment']['body']
            username = info['sender']['login']

            repo_cfg = g.repo_cfgs[repo_name]

            if parse_commands(
                body,
                username,
                repo_cfg['reviewers'],
                g.states[repo_name][pull_num],
                g.my_username,
                g.db,
                realtime=True,
                sha=original_commit_id,
            ):
                g.queue_handler()

    elif event_type == 'pull_request':
        action = info['action']
        pull_num = info['number']
        repo_name = info['repository']['name']
        head_sha = info['pull_request']['head']['sha']

        if action == 'synchronize':
            state = g.states[repo_name][pull_num]
            state.head_advanced(head_sha)

        elif action in ['opened', 'reopened']:
            state = PullReqState(pull_num, head_sha, '', g.repos[repo_name], g.db)
            state.title = info['pull_request']['title']
            state.body = info['pull_request']['body']
            state.head_ref = info['pull_request']['head']['repo']['owner']['login'] + ':' + info['pull_request']['head']['ref']
            state.base_ref = info['pull_request']['base']['ref']
            state.mergeable = info['pull_request']['mergeable']

            if action == 'reopened':
                # FIXME: Review comments are ignored here
                for comment in g.repos[repo_name].issue(pull_num).iter_comments():
                    parse_commands(
                        comment.body,
                        comment.user.login,
                        g.repo_cfgs[repo_name]['reviewers'],
                        state,
                        g.my_username,
                        g.db,
                    )

            g.states[repo_name][pull_num] = state

        elif action == 'closed':
            del g.states[repo_name][pull_num]

        elif action in ['assigned', 'unassigned']:
            assignee = info['pull_request']['assignee']['login'] if info['pull_request']['assignee'] else ''

            state = g.states[repo_name][pull_num]
            state.assignee = assignee

        else:
            g.logger.debug('Invalid pull_request action: {}'.format(action))

    elif event_type == 'push':
        repo_name = info['repository']['name']
        ref = info['ref'][len('refs/heads/'):]

        for state in g.states[repo_name].values():
            if state.base_ref == ref:
                state.mergeable = None

            if state.head_sha == info['before']:
                state.head_advanced(info['after'])

    elif event_type == 'issue_comment':
        body = info['comment']['body']
        username = info['comment']['user']['login']
        repo_name = info['repository']['name']
        pull_num = info['issue']['number']

        repo_cfg = g.repo_cfgs[repo_name]

        state = g.states[repo_name].get(pull_num)

        if 'pull_request' in info['issue'] and state:
            state.title = info['issue']['title']
            state.body = info['issue']['body']

            if parse_commands(
                body,
                username,
                repo_cfg['reviewers'],
                state,
                g.my_username,
                g.db,
                realtime=True,
            ):
                g.queue_handler()

    return 'OK'

@post('/buildbot')
def buildbot():
    response.content_type = 'text/plain'

    if request.forms.key != g.cfg['main']['buildbot_key']:
        abort(400, 'Invalid key')

    for row in json.loads(request.forms.packets):
        if row['event'] == 'buildFinished':
            info = row['payload']['build']

            found = False
            rev = [x[1] for x in info['properties'] if x[0] == 'revision'][0]
            if rev:
                for repo in g.repos.values():
                    for state in g.states[repo.name].values():
                        if state.merge_sha == rev:
                            found = True
                            break

                    if found: break

            if found and info['builderName'] in state.build_res:
                builder = info['builderName']
                build_num = info['number']
                build_succ = 'successful' in info['text'] or info['results'] == 0

                url = '{}/builders/{}/builds/{}'.format(
                    g.repo_cfgs[repo.name]['buildbot_url'],
                    builder,
                    build_num,
                )

                if build_succ:
                    state.build_res[builder] = url

                    if all(state.build_res.values()):
                        desc = 'Test successful'
                        utils.github_create_status(repo, state.head_sha, 'success', url, desc, context='homu')
                        state.set_status('success')

                        urls = ', '.join('[{}]({})'.format(builder, url) for builder, url in sorted(state.build_res.items()))
                        state.add_comment(':sunny: {} - {}'.format(desc, urls))

                        if state.approved_by and not state.try_:
                            try:
                                utils.github_set_ref(
                                    repo,
                                    'heads/' + g.repo_cfgs[repo.name]['master_branch'],
                                    state.merge_sha
                                )
                            except github3.models.GitHubError:
                                desc = 'Test was successful, but fast-forwarding failed'
                                utils.github_create_status(repo, state.head_sha, 'error', url, desc, context='homu')
                                state.set_status('error')

                                state.add_comment(':eyes: ' + desc)

                        g.queue_handler()

                else:
                    state.build_res[builder] = False

                    if state.status == 'pending':
                        desc = 'Test failed'
                        utils.github_create_status(repo, state.head_sha, 'failure', url, desc, context='homu')
                        state.set_status('failure')

                        state.add_comment(':broken_heart: {} - [{}]({})'.format(desc, builder, url))

                        g.queue_handler()

            else:
                g.logger.debug('Invalid commit from Buildbot: {}'.format(rev))

        elif row['event'] == 'buildStarted':
            info = row['payload']['build']
            rev = [x[1] for x in info['properties'] if x[0] == 'revision'][0]

            if rev and g.buildbot_slots[0] == rev:
                g.buildbot_slots[0] = ''

                g.queue_handler()

    return 'OK'

def start(cfg, states, queue_handler, repo_cfgs, repos, logger, buildbot_slots, my_username, db):
    env = jinja2.Environment(
        loader = jinja2.FileSystemLoader(pkg_resources.resource_filename(__name__, 'html')),
        autoescape = True,
    )
    tpls = {}
    tpls['index'] = env.get_template('index.html')
    tpls['queue'] = env.get_template('queue.html')

    g.hmac_key = cfg['main']['hmac_key'].encode('utf-8')
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

    run(host='', port=cfg['main']['port'], server='waitress')
