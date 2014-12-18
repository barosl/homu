from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import hmac
import json
import urllib.parse
from main import PullReqState, parse_commands
import utils
from socketserver import ThreadingMixIn
import github3

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            res = []

            res.append('''<style>
                table { border-collapse: collapse; }
                td, th { border: 1px solid black; padding: 5px; font-size: 13px; }
                button { display: block; margin: 15px 0; }
                h1 { font-size: 20px; }
                h2 { font-size: 16px; }
            </style>\n''')
            res.append('<h1>Homu queue</h1>\n')

            for repo_name in self.server.states:
                pull_states = sorted(self.server.states[repo_name].values())

                res.append('<h2>{}</h2>\n'.format(repo_name))
                res.append('<button type="button" onclick="if (confirm(\'A new pull request will be created. Continue?\')) location = \'/rollup/{}\';">Create a rollup</button>\n'.format(repo_name))
                res.append('<table>\n')
                res.append('<tr><th>Status</th><th>Priority</th><th>Number</th><th>Approved by</th></tr>\n')

                for state in pull_states:
                    res.append('<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n'.format(
                        state.status if state.status else '(Undecided)',
                        state.priority,
                        state.num,
                        state.approved_by if state.approved_by else '(None)',
                    ))

                res.append('</table>\n')

            resp_status = 200
            resp_text = ''.join(res)

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

                    if parse_commands(
                        body,
                        username,
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
                    self.server.states[repo_name][pull_num] = PullReqState(pull_num, head_sha, '') # FIXME: status, comments
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
                                state.status = 'success'
                                repo.create_status(state.head_sha, 'success', url, 'Test successful')

                                if state.approved_by and not state.try_:
                                    try:
                                        utils.github_set_ref(
                                            repo,
                                            'heads/' + self.server.repo_cfgs[repo.name]['master_branch'],
                                            state.merge_sha
                                        )
                                    except github3.models.GitHubError:
                                        state.status = 'error'
                                        repo.create_status(state.head_sha, 'error', url, 'Test was successful, but fast-forwarding failed')

                                self.server.queue_handler()

                        else:
                            state.build_res[builder] = False

                            if state.status == 'pending':
                                repo.create_status(state.head_sha, 'failure', url, 'Test failed')

                                state.status = 'failure'

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

    server.hmac_key = cfg['main']['hmac_key'].encode('utf-8')
    server.cfg = cfg
    server.states = states
    server.queue_handler = queue_handler
    server.repo_cfgs = repo_cfgs
    server.repos = repos
    server.logger = logger
    server.buildbot_slots = buildbot_slots

    Thread(target=server.serve_forever).start()
