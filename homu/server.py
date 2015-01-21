from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import hmac
import json
import urllib.parse
from .main import PullReqState, parse_commands
from . import utils
from socketserver import ThreadingMixIn
import github3
import jinja2
import requests
import pkg_resources

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            resp_status = 200
            resp_text = self.server.tpls['index'].render(repos=sorted(self.server.repos))

        elif self.path.startswith('/queue/'):
            repo_name = self.path.split('/', 2)[2]

            repo = self.server.repos[repo_name]
            pull_states = sorted(self.server.states[repo_name].values())

            rows = []
            for state in pull_states:
                rows.append({
                    'status': 'approved' if state.status == '' and state.approved_by and state.mergeable else state.status,
                    'priority': 'rollup' if state.rollup else state.priority,
                    'url': 'https://github.com/{}/{}/pull/{}'.format(repo.owner, repo.name, state.num),
                    'num': state.num,
                    'approved_by': state.approved_by,
                    'title': state.title,
                    'head_ref': state.head_ref,
                    'mergeable': 'yes' if state.mergeable is True else 'no' if state.mergeable is False else '',
                    'assignee': state.assignee,
                })

            resp_status = 200
            resp_text = self.server.tpls['queue'].render(
                repo_name = repo.name,
                states = rows,
                oauth_client_id = self.server.cfg['main']['oauth_client_id'],
                total = len(pull_states),
                approved = len([x for x in pull_states if x.approved_by]),
                rolled_up = len([x for x in pull_states if x.rollup]),
                failed = len([x for x in pull_states if x.status == 'failure' or x.status == 'error']),
            )

        elif self.path.startswith('/rollup'):
            args = urllib.parse.parse_qs(self.path[self.path.index('?')+1:])
            code = args['code'][0]
            state = json.loads(args['state'][0])

            res = requests.post('https://github.com/login/oauth/access_token', data={
                'client_id': self.server.cfg['main']['oauth_client_id'],
                'client_secret': self.server.cfg['main']['oauth_client_secret'],
                'code': code,
            })
            args = urllib.parse.parse_qs(res.text)
            token = args['access_token'][0]

            repo = self.server.repos[state['repo']]
            repo_cfg = self.server.repo_cfgs[repo.name]

            user_gh = github3.login(token=token)
            user_repo = user_gh.repository(user_gh.user().login, repo.name)
            base_repo = user_gh.repository(repo.owner.login, repo.name)

            rollup_states = [x for x in self.server.states[repo.name].values() if x.rollup and x.approved_by]
            rollup_states.sort(key=lambda x: x.num)

            if not rollup_states:
                resp_status = 200
                resp_text = 'No pull requests are marked as rollup'
            else:
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
                    resp_status = 200
                    resp_text = e.response.text
                else:
                    resp_status = 302
                    resp_text = pull.html_url

        else:
            resp_status = 404
            resp_text = ''

        self.send_response(resp_status)
        if resp_status == 302:
            self.send_header('Location', resp_text)
        else:
            self.send_header('Content-type', 'text/html')
        self.end_headers()

        self.wfile.write(resp_text.encode('utf-8'))

    def do_POST(self):
        payload = self.rfile.read(int(self.headers['Content-Length']))

        if self.path == '/github':
            info = json.loads(payload.decode('utf-8'))

            event_type = self.headers['X-Github-Event']

            hmac_method, hmac_sig = self.headers['X-Hub-Signature'].split('=')
            if hmac_sig != hmac.new(
                self.server.hmac_key,
                payload,
                hmac_method,
            ).hexdigest():
                return

            if event_type == 'pull_request_review_comment':
                action = info['action']
                original_commit_id = info['comment']['original_commit_id']
                head_sha = info['pull_request']['head']['sha']

                if action == 'created' and original_commit_id == head_sha:
                    repo_name = info['repository']['name']
                    pull_num = info['pull_request']['number']
                    body = info['comment']['body']
                    username = info['sender']['login']

                    repo_cfg = self.server.repo_cfgs[repo_name]

                    if parse_commands(
                        body,
                        username,
                        repo_cfg['reviewers'],
                        self.server.states[repo_name][pull_num],
                        self.server.my_username,
                        self.server.db,
                        realtime=True,
                        sha=original_commit_id,
                    ):
                        self.server.queue_handler()

            elif event_type == 'pull_request':
                action = info['action']
                pull_num = info['number']
                repo_name = info['repository']['name']
                head_sha = info['pull_request']['head']['sha']

                if action == 'synchronize':
                    state = self.server.states[repo_name][pull_num]
                    state.head_advanced(head_sha)

                elif action in ['opened', 'reopened']:
                    state = PullReqState(pull_num, head_sha, '', self.server.repos[repo_name], self.server.db)
                    state.title = info['pull_request']['title']
                    state.body = info['pull_request']['body']
                    state.head_ref = info['pull_request']['head']['repo']['owner']['login'] + ':' + info['pull_request']['head']['ref']
                    state.base_ref = info['pull_request']['base']['ref']
                    state.mergeable = info['pull_request']['mergeable']

                    # FIXME: Needs to retrieve the status and the comments if the action is reopened

                    self.server.states[repo_name][pull_num] = state

                elif action == 'closed':
                    del self.server.states[repo_name][pull_num]

                elif action == 'assigned':
                    assignee = info['pull_request']['assignee']['login']

                    state = self.server.states[repo_name][pull_num]
                    state.assignee = assignee

                elif action == 'unassigned':
                    assignee = info['pull_request']['assignee']['login']

                    state = self.server.states[repo_name][pull_num]
                    if state.assignee == assignee:
                        state.assignee = ''

                else:
                    self.server.logger.debug('Invalid pull_request action: {}'.format(action))

            elif event_type == 'push':
                repo_name = info['repository']['name']
                ref = info['ref'][len('refs/heads/'):]

                for state in self.server.states[repo_name].values():
                    if state.base_ref == ref:
                        state.mergeable = None

                    if state.head_sha == info['before']:
                        state.head_advanced(info['after'])

            elif event_type == 'issue_comment':
                body = info['comment']['body']
                username = info['comment']['user']['login']
                repo_name = info['repository']['name']
                pull_num = info['issue']['number']

                repo_cfg = self.server.repo_cfgs[repo_name]

                if 'pull_request' in info['issue'] and pull_num in self.server.states[repo_name]:
                    if parse_commands(
                        body,
                        username,
                        repo_cfg['reviewers'],
                        self.server.states[repo_name][pull_num],
                        self.server.my_username,
                        self.server.db,
                        realtime=True,
                    ):
                        self.server.queue_handler()

            resp_status = 200
            resp_text = ''

        elif self.path == '/buildbot':
            info = urllib.parse.parse_qs(payload.decode('utf-8'))

            if info['key'][0] != self.server.cfg['main']['buildbot_key']:
                return

            for row in json.loads(info['packets'][0]):
                if row['event'] == 'buildFinished':
                    info = row['payload']['build']

                    found = False
                    rev = [x[1] for x in info['properties'] if x[0] == 'revision'][0]
                    if rev:
                        for repo in self.server.repos.values():
                            for state in self.server.states[repo.name].values():
                                if state.merge_sha == rev:
                                    found = True
                                    break

                            if found: break

                    if found and info['builderName'] in state.build_res:
                        builder = info['builderName']
                        build_num = info['number']
                        build_succ = 'successful' in info['text'] or info['results'] == 0

                        url = '{}/builders/{}/builds/{}'.format(
                            self.server.repo_cfgs[repo.name]['buildbot_url'],
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
                                            'heads/' + self.server.repo_cfgs[repo.name]['master_branch'],
                                            state.merge_sha
                                        )
                                    except github3.models.GitHubError:
                                        desc = 'Test was successful, but fast-forwarding failed'
                                        utils.github_create_status(repo, state.head_sha, 'error', url, desc, context='homu')
                                        state.set_status('error')

                                        state.add_comment(':eyes: ' + desc)

                                self.server.queue_handler()

                        else:
                            state.build_res[builder] = False

                            if state.status == 'pending':
                                desc = 'Test failed'
                                utils.github_create_status(repo, state.head_sha, 'failure', url, desc, context='homu')
                                state.set_status('failure')

                                state.add_comment(':broken_heart: {} - [{}]({})'.format(desc, builder, url))

                                self.server.queue_handler()

                    else:
                        self.server.logger.debug('Invalid commit from Buildbot: {}'.format(rev))

                elif row['event'] == 'buildStarted':
                    info = row['payload']['build']
                    rev = [x[1] for x in info['properties'] if x[0] == 'revision'][0]

                    if rev and self.server.buildbot_slots[0] == rev:
                        self.server.buildbot_slots[0] = ''

                        self.server.queue_handler()

            resp_status = 200
            resp_text = ''

        else:
            resp_status = 404
            resp_text = ''

        self.send_response(resp_status)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        self.wfile.write(resp_text.encode('utf-8'))

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

def start(cfg, states, queue_handler, repo_cfgs, repos, logger, buildbot_slots, my_username, db):
    server = ThreadedHTTPServer(('', cfg['main']['port']), RequestHandler)

    tpls = {}
    env = jinja2.Environment(
        loader = jinja2.FileSystemLoader(pkg_resources.resource_filename(__name__, 'html')),
        autoescape = True,
    )
    tpls['index'] = env.get_template('index.html')
    tpls['queue'] = env.get_template('queue.html')

    server.hmac_key = cfg['main']['hmac_key'].encode('utf-8')
    server.cfg = cfg
    server.states = states
    server.queue_handler = queue_handler
    server.repo_cfgs = repo_cfgs
    server.repos = repos
    server.logger = logger
    server.buildbot_slots = buildbot_slots
    server.tpls = tpls
    server.my_username = my_username
    server.db = db

    Thread(target=server.serve_forever).start()
