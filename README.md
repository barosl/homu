Homu is a continuous integration service bot that works with GitHub and
[Buildbot](http://buildbot.net/). It is largely inspired by
[bors](https://github.com/graydon/bors).

## What differentiates it from bors?

1. **Stateful**. Unlike bors, which intends to be stateless, Homu is stateful.
   It means that Homu does not need to retrieve all the information again and
   again from GitHub at every run. This is essential because of the GitHub's
   rate limiting. Once it downloads the initial state, the following changes
   are delivered with the [Webhooks](https://developer.github.com/webhooks/)
   API.
2. **Pushing over polling**. Homu prefers pushing wherever possible. The pull
   requests from GitHub are retrieved using Webhooks, as stated above. The
   test results from Buildbot are pushed back to Homu with the
   [HttpStatusPush](http://docs.buildbot.net/current/manual/cfg-statustargets.html#httpstatuspush)
   feature. This approach improves the overall performance and the response
   time, because the bot is informed about the status changes immediately.

## Additional features

1. `try`: Test a pull request without blocking the queue.
2. `rollup`: Mark a pull request as part of a rollup.

You should specify the commands in the "files changed" tab.

## Configurations

1. Add a Webhook to your repository:

 - Payload URL: http://HOST:PORT/github
 - Content type: application/json
 - Secret: The same as `hmac_key` in cfg.toml

2. Insert the following code to the Buildbot configuration:

```python
from buildbot.status.status_push import HttpStatusPush

c['status'].append(HttpStatusPush(
    serverUrl='http://HOST:PORT/buildbot',
    extra_post_params={'key': 'buildbot_key in cfg.toml'},
))
```

## How to install

```sh
sudo apt-get install python3-venv

pyvenv .venv
.venv/bin/pip install -r requirements.txt
```

## How to run

```sh
.venv/bin/python main.py
```
