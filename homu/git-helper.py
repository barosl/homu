#!/usr/bin/env python3

import toml
import sys
import subprocess
import json
import os

KEY_FILE = 'cache/key'

def main():
    os.chdir(os.path.join(os.path.dirname(__file__), '..'))

    try:
        with open('cfg.toml') as fp:
            cfg = toml.loads(fp.read())
    except FileNotFoundError:
        with open('cfg.json') as fp:
            cfg = json.loads(fp.read())

    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    with open(KEY_FILE, 'w') as fp:
        fp.write(cfg['github']['ssh_key'])
    os.chmod(KEY_FILE, 0o600)

    args = ['ssh', '-i', KEY_FILE] + sys.argv[1:]
    os.execvp('ssh', args)

if __name__ == '__main__':
    main()
