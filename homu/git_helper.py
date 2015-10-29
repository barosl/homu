#!/usr/bin/env python3

import sys
import subprocess
import os

SSH_KEY_FILE = os.path.join(os.path.dirname(__file__), '../cache/key')

def main():
    args = ['ssh', '-i', SSH_KEY_FILE] + sys.argv[1:]
    os.execvp('ssh', args)

if __name__ == '__main__':
    main()
