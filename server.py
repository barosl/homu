from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import hmac
import json
import urllib.parse
from main import PullReqState, parse_commands
import utils
from socketserver import ThreadingMixIn

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            res = []

            for repo_name in self.server.states:
                pull_states = sorted(self.server.states[repo_name].values())

                res.append('<style>table { border-collapse: collapse; } td, th { border: 1px solid black; padding: 5px; }</style>\n')
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

        else:
            resp_status = 404
            resp_text = ''

        self.send_response(resp_status)
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
                    self.server.states[repo_name][pull_num].approved_by = ''
                elif action in ['opened', 'reopened']:
                    self.server.states[repo_name][pull_num] = PullReqState(pull_num, head_sha, '') # FIXME: status, comments
                elif action == 'closed':
                    del self.server.states[repo_name][pull_num]
                else:
                    self.server.logger.debug('Invalid pull_request action: {}'.format(action))

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
                    for repo in self.server.repos:
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
                                repo.create_status(state.head_sha, 'success', url, desc)

                                state.status = 'success'

                                utils.github_set_ref(repo, 'heads/' + self.server.repo_cfgs[repo.name]['master_branch'], state.merge_sha)

                                self.server.queue_handler()

                        else:
                            state.build_res[builder] = False

                            if state.status == 'pending':
                                desc = 'Test failed'
                                repo.create_status(state.head_sha, 'failure', url, desc)

                                state.status = 'failure'

                                self.server.queue_handler()

                    else:
                        self.server.logger.debug('Invalid commit from Buildbot: {}'.format(rev))

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

def start(cfg, states, queue_handler, repo_cfgs, repos, logger):
    server = ThreadedHTTPServer(('', cfg['main']['port']), RequestHandler)

    server.hmac_key = cfg['main']['hmac_key'].encode('utf-8')
    server.cfg = cfg
    server.states = states
    server.queue_handler = queue_handler
    server.repo_cfgs = repo_cfgs
    server.repos = repos
    server.logger = logger

    Thread(target=server.serve_forever).start()
