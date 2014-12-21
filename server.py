from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import hmac
import json
import urllib.parse
from main import PullReqState, parse_commands
import utils
from socketserver import ThreadingMixIn
import github3
import jinja2

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
                    'status': state.status if state.status else 'undecided',
                    'priority': state.priority,
                    'url': 'https://github.com/{}/{}/pull/{}'.format(repo.owner, repo.name, state.num),
                    'num': state.num,
                    'approved_by': state.approved_by if state.approved_by else '(empty)',
                    'title': state.title,
                    'head_ref': state.head_ref,
                })

            resp_status = 200
            resp_text = self.server.tpls['queue'].render(
                repo_name = repo.name,
                states = rows,
            )

        elif self.path.startswith('/rollup/'):
            repo_name = self.path[len('/rollup/'):]
            repo = self.server.repos[repo_name]
            repo_cfg = self.server.repo_cfgs[repo.name]

            rollup_states = [x for x in self.server.states[repo.name].values() if x.rollup and x.approved_by]

            if not rollup_states:
                resp_status = 200
                resp_text = 'No pull requests are marked as rollup'
            else:
                master_sha = repo.ref('heads/' + repo_cfg['master_branch']).object.sha
                try:
                    utils.github_set_ref(
                        repo,
                        'heads/' + repo_cfg['rollup_branch'],
                        master_sha,
                        force=True,
                    )
                except github3.models.GitHubError:
                    repo.create_ref(
                        'refs/heads/' + repo_cfg['rollup_branch'],
                        master_sha,
                    )


                successes = []
                failures = []

                for state in rollup_states:
                    merge_msg = 'Merge {:.7} into {}\n\nApproved-by: {}'.format(
                        state.head_sha,
                        repo_cfg['rollup_branch'],
                        state.approved_by,
                    )

                    try: repo.merge(repo_cfg['rollup_branch'], state.head_sha, merge_msg)
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

                [x.close() for x in repo.iter_pulls(head='{}:{}'.format(repo.owner, repo_cfg['rollup_branch']))]

                pull = repo.create_pull(
                    title,
                    repo_cfg['master_branch'],
                    repo_cfg['rollup_branch'],
                    body,
                )

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
                        realtime=True,
                    ):
                        self.server.queue_handler()

            elif event_type == 'pull_request':
                action = info['action']
                pull_num = info['number']
                repo_name = info['repository']['name']
                head_sha = info['pull_request']['head']['sha']

                if action == 'synchronize':
                    self.server.states[repo_name][pull_num].head_advanced(head_sha)
                elif action in ['opened', 'reopened']:
                    state = PullReqState(pull_num, head_sha, '') # FIXME: status, comments
                    state.title = info['pull_request']['title']
                    state.head_ref = info['pull_request']['head']['repo']['owner']['login'] + ':' + info['pull_request']['head']['ref']

                    self.server.states[repo_name][pull_num] = state
                elif action == 'closed':
                    del self.server.states[repo_name][pull_num]
                else:
                    self.server.logger.debug('Invalid pull_request action: {}'.format(action))

            elif event_type == 'push':
                repo_name = info['repository']['name']

                for state in self.server.states[repo_name].values():
                    if state.head_sha == info['before']:
                        state.head_advanced(info['after'])

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
                    for repo in self.server.repos.values():
                        for state in self.server.states[repo.name].values():
                            if state.merge_sha == rev:
                                found = True
                                break

                        if found: break

                    if found:
                        builder = info['builderName']
                        build_num = info['number']
                        build_res = info.get('results', 0)

                        url = '{}/builders/{}/builds/{}'.format(
                            self.server.repo_cfgs[repo.name]['buildbot_url'],
                            builder,
                            build_num,
                        )

                        if build_res == 0:
                            state.build_res[builder] = True

                            if all(state.build_res.values()):
                                desc = 'Test successful'
                                utils.github_create_status(repo, state.head_sha, 'success', url, desc, context='homu')
                                state.status = 'success'

                                repo.issue(state.num).create_comment(':sunny: ' + desc)

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
                                        state.status = 'error'

                                        repo.issue(state.num).create_comment(':eyes: ' + desc)

                                self.server.queue_handler()

                        else:
                            state.build_res[builder] = False

                            if state.status == 'pending':
                                desc = 'Test failed'
                                utils.github_create_status(repo, state.head_sha, 'failure', url, desc, context='homu')
                                state.status = 'failure'

                                repo.issue(state.num).create_comment(':broken_heart: ' + desc)

                                self.server.queue_handler()

                    else:
                        self.server.logger.debug('Invalid commit from Buildbot: {}'.format(rev))

                elif row['event'] == 'buildStarted':
                    info = row['payload']['build']
                    rev = [x[1] for x in info['properties'] if x[0] == 'revision'][0]

                    if self.server.buildbot_slots[0] == rev:
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

def start(cfg, states, queue_handler, repo_cfgs, repos, logger, buildbot_slots):
    server = ThreadedHTTPServer(('', cfg['main']['port']), RequestHandler)

    tpls = {}
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('html'))
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

    Thread(target=server.serve_forever).start()
