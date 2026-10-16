#!/usr/bin/env python3
"""Disposable THREE-QEMU Maât signed-registry laboratory (no host changes).

Runs the real OpenSSH protocol between isolated Ubuntu kernels. All authority
private material remains on disposable node A. Requires the Ubuntu 22.04
cloud qcow2 image previously used by tests/qemu/run-e2e.sh.
"""
import hashlib
import os
from pathlib import Path
import random
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
PRIVATE_NET = '192.168.177.'
MARKER = '/etc/maat-disposable-p2p-lab'


def need(command):
    if not shutil.which(command):
        raise RuntimeError('missing required host command: ' + command)


def run(args, *, input=None, timeout=120, output=True, check=True):
    result = subprocess.run(args, input=input, text=True, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if output and result.stdout:
        print(result.stdout, end='', flush=True)
    if check and result.returncode:
        raise RuntimeError('exit %s: %s\n%s' %
                           (result.returncode, ' '.join(map(str, args)), result.stdout[-2500:]))
    return result


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def bbs_artifacts():
    # check/full builds with BBS enabled in build/, while standalone P2P
    # instructions historically used build-bbs/. Accept either build layout.
    fixture = ROOT/'libs/maat-bbs/target/release/maat_bbs_fixture'
    candidates = (ROOT/'build/maat-bbs-p2p-gate',
                  ROOT/'build-bbs/maat-bbs-p2p-gate')
    executable = next((path for path in candidates if path.is_file()), None)
    require(executable is not None and fixture.is_file(),
            'missing host BBS artifacts (gate in build/ or build-bbs/, '
            'fixture in libs/maat-bbs/target/release/). Build with '
            'cmake -S . -B build -DMAAT_BUILD_BBS_BRIDGE=ON '
            '&& cmake --build build -j4')
    return executable, fixture


class Laboratory:
    def __init__(self, image, temporary, ports, multicast_port):
        self.image = image
        self.tmp = Path(temporary)
        self.ports = ports
        self.mcast = multicast_port
        self.processes = []
        self.ssh_key = self.tmp / 'admin_key'
        self.peer_key = self.tmp / 'sync_key'
        self.known_hosts = self.tmp / 'bootstrap_known_hosts'
        self.known_hosts.touch(mode=0o600)
        self.base_size = int(__import__('json').loads(
            run(['qemu-img', 'info', '--output=json', str(image)],
                output=False).stdout)['virtual-size'])
        for key in (self.ssh_key, self.peer_key):
            run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], output=False)

    def ssh(self, index, command, *, input=None, timeout=120, output=True, check=True):
        common = ['ssh', '-T', '-i', str(self.ssh_key), '-p', str(self.ports[index]),
                  '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                  '-o', 'StrictHostKeyChecking=accept-new',
                  '-o', 'UserKnownHostsFile=' + str(self.known_hosts),
                  '-o', 'ConnectTimeout=5', '-o', 'LogLevel=ERROR',
                  'maatci@127.0.0.1']
        return run(common + [command], input=input, timeout=timeout,
                   output=output, check=check)

    def scp_to(self, index, source, destination):
        run(['scp', '-q', '-i', str(self.ssh_key), '-P', str(self.ports[index]),
             '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
             '-o', 'StrictHostKeyChecking=yes',
             '-o', 'UserKnownHostsFile=' + str(self.known_hosts),
             str(source), 'maatci@127.0.0.1:' + destination], output=False)

    def scp_from(self, index, source, destination):
        run(['scp', '-q', '-i', str(self.ssh_key), '-P', str(self.ports[index]),
             '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
             '-o', 'StrictHostKeyChecking=yes',
             '-o', 'UserKnownHostsFile=' + str(self.known_hosts),
             'maatci@127.0.0.1:' + source, str(destination)], output=False)

    def boot(self):
        public = (self.ssh_key.with_suffix('.pub')).read_text().strip()
        for i in range(3):
            name = ['a', 'b', 'c'][i]
            user_data = self.tmp / ('user-%s' % name)
            meta_data = self.tmp / ('meta-%s' % name)
            seed = self.tmp / ('seed-%s.img' % name)
            overlay = self.tmp / ('overlay-%s.qcow2' % name)
            console = self.tmp / ('console-%s.log' % name)
            qemu_log = (self.tmp / ('qemu-%s.log' % name)).open('wb')
            user_data.write_text('#cloud-config\nhostname: maat-p2p-%s\nssh_pwauth: false\n'
                'disable_root: true\nusers:\n'
                '  - name: maatci\n    shell: /bin/bash\n    groups: [sudo]\n'
                '    lock_passwd: true\n    sudo: "ALL=(ALL) NOPASSWD:ALL"\n'
                "    ssh_authorized_keys:\n      - '%s'\n" % (name, public) +
                'write_files:\n'
                '  - path: ' + MARKER + '\n    permissions: "0444"\n'
                '    owner: root:root\n    content: "ephemeral qemu-only"\n'
                'growpart:\n  mode: auto\n  devices: ["/"]\nresize_rootfs: true\n')
            meta_data.write_text('instance-id: maat-p2p-%s-%d\nlocal-hostname: maat-p2p-%s\n'
                                 % (name, os.getpid(), name))
            run(['cloud-localds', str(seed), str(user_data), str(meta_data)], output=False)
            run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2',
                 '-b', str(self.image), str(overlay)], output=False)
            disk_gb = int(os.environ.get('MAAT_P2P_DISK_GB', '8'))
            require(8 <= disk_gb <= 32, 'MAAT_P2P_DISK_GB must be in [8,32]')
            if self.base_size < disk_gb * 1024**3:
                run(['qemu-img', 'resize', '-f', 'qcow2', str(overlay),
                     str(disk_gb) + 'G'], output=False)
            accelerator = os.environ.get('MAAT_P2P_ACCEL', 'auto')
            if accelerator == 'auto':
                accelerator = 'kvm' if os.access('/dev/kvm', os.R_OK | os.W_OK) else 'tcg'
            if accelerator == 'tcg' and i == 0:
                print('WARNING: KVM unavailable; running 3 QEMU under TCG will be slow',
                      file=sys.stderr)
            require(accelerator in ('tcg', 'kvm'), 'invalid QEMU accelerator')
            memory = 2048 if i == 0 else 768
            mac = '52:54:00:7a:10:%02x' % (i + 1)
            command = ['qemu-system-x86_64', '-machine', 'q35,accel=' + accelerator,
                       '-m', str(memory), '-smp', '2' if i == 0 else '1',
                       '-drive', 'file=%s,format=qcow2,if=virtio' % overlay,
                       '-drive', 'file=%s,format=raw,if=virtio,readonly=on' % seed,
                       '-nic', 'user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:%d-:22' % self.ports[i],
                       '-netdev', 'socket,id=maatlan,mcast=230.0.0.1:%d,localaddr=127.0.0.1' % self.mcast,
                       '-device', 'virtio-net-pci,netdev=maatlan,mac=' + mac,
                       '-display', 'none', '-serial', 'file:' + str(console),
                       '-monitor', 'none', '-no-reboot']
            self.processes.append(subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                                    stdout=qemu_log, stderr=subprocess.STDOUT))
            qemu_log.close()
            print('BOOT QEMU %s SSH localhost:%d / LAN %s%d' %
                  (name.upper(), self.ports[i], PRIVATE_NET, 11+i), flush=True)
        deadline = time.monotonic() + 420
        pending = {0, 1, 2}
        while pending and time.monotonic() < deadline:
            for i in tuple(pending):
                require(self.processes[i].poll() is None, 'QEMU %d terminated during boot' % i)
                if self.ssh(i, 'test -f '+ MARKER, timeout=8, output=False, check=False).returncode == 0:
                    self.ssh(i, 'cloud-init status --wait >/dev/null; test -f '+ MARKER,
                             timeout=180, output=False)
                    print('READY QEMU %s' % 'ABC'[i], flush=True)
                    pending.remove(i)
            if pending:
                time.sleep(3)
        require(not pending, 'QEMU bootstrap timed out: %r' % pending)

    def provision(self):
        for i in range(3):
            print('INSTALL OS DEPS %s' % 'ABC'[i], flush=True)
            packages = 'openssh-server iproute2 libsqlite3-0 libssl3'
            if i == 0:
                packages += ' g++ libsqlite3-dev libssl-dev'
            command = ('sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && '
                       'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq '
                       '--no-install-recommends ' + packages)
            self.ssh(i, command, timeout=1600, output=False)
            setup = r'''set -Eeuo pipefail
id="$1"
net="192.168.177.$((11+id))"
mac="52:54:00:7a:10:0$((id+1))"
iface=""
for item in /sys/class/net/*; do
  if [ "$(cat "$item/address")" = "$mac" ]; then iface="${item##*/}"; fi
done
[ -n "$iface" ] || { echo 'No private LAN NIC'; exit 1; }
sudo ip link set "$iface" up
sudo ip addr add "$net/24" dev "$iface"
getent passwd maatsync >/dev/null || sudo useradd -m -U -s /bin/sh -p NP maatsync
sudo install -d -m 0755 -o root -g root /etc/maat /opt/maat/bin
sudo install -d -m 0700 -o maatsync -g maatsync /var/lib/maat
sudo install -m 0644 -o root -g root /dev/null /etc/maat/authorized_keys
sudo ssh-keygen -q -t ed25519 -N '' -f /etc/maat/sync_host_ed25519
sudo tee /etc/maat/sshd_config >/dev/null <<EOF
Port 2223
ListenAddress $net
HostKey /etc/maat/sync_host_ed25519
PidFile /run/maat-sync-sshd.pid
AuthorizedKeysFile /etc/maat/authorized_keys
AllowUsers maatsync
ForceCommand /usr/local/bin/maat-trust-lab-force
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin no
PermitTTY no
DisableForwarding yes
PermitUserRC no
X11Forwarding no
PermitUserEnvironment no
PrintMotd no
LogLevel ERROR
EOF
sudo tee /usr/local/bin/maat-trust-lab-force >/dev/null <<'EOF_FORCE'
#!/bin/sh
set -eu
if [ -e /etc/maat/poison ]; then
  exec /opt/maat/bin/maat-trust-lab poison
fi
set -- $(cat /var/lib/maat/root.txt)
exec /opt/maat/bin/maat-trust-sync serve /var/lib/maat/trust.sqlite "$1" "$2"
EOF_FORCE
sudo chmod 0755 /usr/local/bin/maat-trust-lab-force
sudo /usr/sbin/sshd -t -f /etc/maat/sshd_config
sudo /usr/sbin/sshd -f /etc/maat/sshd_config
'''
            self.ssh(i, 'bash -s -- %d' % i, input=setup, timeout=80)
        # Confirm real, isolated guest-to-guest TCP over QEMU multicast LAN.
        # A working host-side admin SSH forward does not prove P2P reachability.
        for src,dst in ((1,0),(2,1)):
            self.ssh(src, 'timeout 8 bash -c \"true </dev/tcp/%s%d/2223\"' %
                     (PRIVATE_NET,dst+11), timeout=18, output=False)
        print('PASS independent QEMU kernels can reach dedicated peer SSH ports',flush=True)

    def build_and_distribute(self):
        with tarfile.open(self.tmp/'trust-source.tar.gz', 'w:gz') as archive:
            for relative in ['src/identity/replicated_trust.hpp',
                             'src/identity/replicated_trust.cpp',
                             'src/identity/trust_sync.hpp',
                             'src/identity/trust_sync.cpp',
                             'src/identity/trust_peers.hpp',
                             'src/identity/trust_peers.cpp',
                             'src/identity/trust_sync_main.cpp',
                             'tests/qemu/trust_p2p_fixture.cpp']:
                archive.add(ROOT/relative, arcname=relative)
        self.scp_to(0, self.tmp/'trust-source.tar.gz', 'trust-source.tar.gz')
        build = r'''set -Eeuo pipefail
test -f /etc/maat-disposable-p2p-lab
mkdir -p "$HOME/trust-src"
tar xzf "$HOME/trust-source.tar.gz" -C "$HOME/trust-src"
cd "$HOME/trust-src"
g++ -std=c++17 -O2 -Wall -Wextra -Werror -pthread -Isrc \
  src/identity/replicated_trust.cpp src/identity/trust_sync.cpp \
  src/identity/trust_peers.cpp src/identity/trust_sync_main.cpp \
  -lsqlite3 -lcrypto -o "$HOME/maat-trust-sync"
g++ -std=c++17 -O2 -Wall -Wextra -Werror -pthread -Isrc \
  src/identity/replicated_trust.cpp src/identity/trust_sync.cpp \
  tests/qemu/trust_p2p_fixture.cpp \
  -lsqlite3 -lcrypto -o "$HOME/maat-trust-lab"
'''
        print('BUILD trusted sync binaries INSIDE QEMU A', flush=True)
        self.ssh(0, 'bash -se', input=build, timeout=400)
        for tool in ['maat-trust-sync', 'maat-trust-lab']:
            self.scp_from(0, tool, self.tmp/tool)
        for i in range(3):
            for tool in ['maat-trust-sync', 'maat-trust-lab']:
                self.scp_to(i, self.tmp/tool, tool)
                self.ssh(i, 'sudo install -o root -g root -m 0755 '+tool+
                         ' /opt/maat/bin/'+tool, output=False)
        print('PASS single native guest build, 3 isolated deployments', flush=True)

    def distribute_bbs_verifier(self):
        # Reuse the host's offline Rust/C++ build artifacts. The signed trust
        # protocol binaries above are still compiled natively in guest A.
        # No cargo/rustup installation or network fetch inside the guests.
        executable, fixture = bbs_artifacts()
        for i in range(3):
            for file,name in ((executable,'maat-bbs-p2p-gate'),
                              (fixture,'maat-bbs-fixture')):
                self.scp_to(i,file,name)
                self.ssh(i,'sudo install -o root -g root -m 0755 '+name+
                         ' /opt/maat/bin/'+name,output=False)
        print('PASS BBS Rust fixture and C++ gate deployed to 3 guests',flush=True)

    def bbs_gate(self,index,expected):
        require(expected in ('allow','deny'),'invalid gate expectation')
        result=self.ssh(index,'sudo -u maatsync /opt/maat/bin/maat-bbs-p2p-gate '
                        '/var/lib/maat '+expected,output=True)
        require('PASS BBS gate decision '+expected in result.stdout,
                'missing BBS decision marker on node '+ 'ABC'[index])

    def bbs_issuer_hex(self):
        probe=self.ssh(0,'/opt/maat/bin/maat-bbs-fixture forum.example '+
                       '00'*32+' 42 9',output=False).stdout
        values=re.findall(r'^PK=([0-9a-f]{192})$',probe,re.MULTILINE)
        require(len(values)==1,'invalid BBS fixture public key')
        return values[0]

    def configure_authentication(self):
        pub = self.peer_key.with_suffix('.pub').read_text()
        hosts = []
        for i in range(3):
            result = self.ssh(i, 'sudo cat /etc/maat/sync_host_ed25519.pub',
                              output=False).stdout.strip().split()
            require(len(result)>=2 and result[0]=='ssh-ed25519', 'invalid SSH host pin')
            hosts.append('[%s%d]:2223 %s %s\n' %
                         (PRIVATE_NET, i+11, result[0], result[1]))
        (self.tmp/'peer_known_hosts').write_text(''.join(hosts))
        (self.tmp/'peer_authorized').write_text(pub)
        for i in range(3):
            self.scp_to(i, self.peer_key, 'sync_client_key')
            self.scp_to(i, self.tmp/'peer_known_hosts', 'sync_known_hosts')
            self.scp_to(i, self.tmp/'peer_authorized', 'sync_authorized')
            self.ssh(i, '''set -eu
sudo install -o maatsync -g maatsync -m 0600 sync_client_key /etc/maat/sync_client
sudo install -o maatsync -g maatsync -m 0600 sync_known_hosts /etc/maat/known_hosts.sync
sudo install -o root -g root -m 0644 sync_authorized /etc/maat/authorized_keys
''', output=False)
        print('PASS SSH server keys pinned over authenticated bootstrap links', flush=True)

    def install_root(self):
        self.ssh(0, 'sudo -u maatsync /opt/maat/bin/maat-trust-lab init /var/lib/maat')
        data = self.ssh(0, 'sudo cat /var/lib/maat/root.txt', output=False).stdout
        public = data.split()
        require(len(public)==3 and all(re.fullmatch('[0-9a-f]{64}', x) for x in public),
                'malformed fixture root, refusing propagation')
        (self.tmp/'root.txt').write_text(data)
        for i in (1,2):
            self.scp_to(i, self.tmp/'root.txt', 'root.txt')
            self.ssh(i, 'sudo install -o maatsync -g maatsync -m 0600 root.txt '
                     '/var/lib/maat/root.txt', output=False)
        print('PASS official test authority root distributed out of band', flush=True)

    def peers(self, index, peers, max_pages=256):
        require(1 <= max_pages <= 4096, 'invalid P2P page limit')
        lines = ['maatsync@%s%d 2223 /etc/maat/sync_client '
                 '/etc/maat/known_hosts.sync %d\n' %
                 (PRIVATE_NET,p+11,max_pages) for p in peers]
        conf = self.tmp/'peers.conf'
        conf.write_text(''.join(lines))
        self.scp_to(index, conf, 'peers.conf')
        self.ssh(index,'sudo install -o maatsync -g maatsync -m 0600 peers.conf '
                 '/etc/maat/peers.conf', output=False)

    def sync(self, index, success=True):
        # The root file is intentionally 0600 and owned by maatsync. Read it
        # inside that account, rather than under the administrative SSH login.
        # It contains three newline-separated 32-byte hex values.
        command = '''set -eu
sudo -u maatsync bash -se <<'MAAT_SYNC_ROUND'
set -euo pipefail
mapfile -t roots < /var/lib/maat/root.txt
[ "${#roots[@]}" -eq 3 ] || {
  echo 'Maât P2P lab: expected 3 pinned trust roots' >&2
  exit 2
}
for value in "${roots[@]}"; do
  [[ "$value" =~ ^[0-9a-f]{64}$ ]] || {
    echo 'Maât P2P lab: invalid pinned trust root' >&2
    exit 2
  }
done
exec /opt/maat/bin/maat-trust-sync round /var/lib/maat/trust.sqlite \
  "${roots[0]}" "${roots[1]}" /etc/maat/peers.conf
MAAT_SYNC_ROUND
'''
        result=self.ssh(index, 'bash -se', input=command, timeout=200,
                        output=True, check=False)
        require((result.returncode==0)==success,
                'QEMU %s: sync exit=%d, expected %s; remote output: %s' %
                ('ABC'[index], result.returncode,
                 'success' if success else 'failure', result.stdout[-1200:]))

    def state(self,index,sequence,active, fresh=1):
        result=self.ssh(index,'sudo -u maatsync /opt/maat/bin/maat-trust-lab '
                        'status /var/lib/maat',output=False)
        print('STATE %s: %s' % ('ABC'[index], result.stdout.strip()),flush=True)
        require('sequence=%d fresh=%d active=%d forked=0' % (sequence,fresh,active)
                in result.stdout, 'unexpected signed trust state in %s' % 'ABC'[index])

    def tests(self):
        self.install_root()
        # C receives all 171 events from A via SSH to the *independent* 2223 service.
        self.peers(2,[0]);self.sync(2);self.state(2,171,1)
        # INTENTIONAL interruption: B is allowed just ONE signed page of A.
        # The CLI reports the unfinished session as failure, but SQLite has
        # committed a verified prefix (64 events), still too stale for use.
        self.peers(1,[0],max_pages=1)
        self.sync(1,success=False);self.state(1,64,0,fresh=0)
        print('PASS interrupted SSH page budget retained 64 signed events',flush=True)
        # C now becomes malicious: its SSH transport is legitimate and pinned,
        # but its protocol response contains a forged Ed25519 delta.
        self.ssh(2,'sudo touch /etc/maat/poison',output=False)
        self.peers(1,[2]);self.sync(1,success=False);self.state(1,64,0,fresh=0)
        print('PASS forged SSH peer did not poison committed 64-event prefix',flush=True)
        # Retry via A in a NEW SSH process: resume from committed cursor 64.
        self.peers(1,[2,0]);self.sync(1);self.state(1,171,1)
        print('PASS real SSH resume and fallback completed 171 signed events',flush=True)
        # BBS issuer signed by A and received over the real SSH peer link.
        issuer=self.bbs_issuer_hex()
        self.bbs_gate(1,'deny')
        self.ssh(0,'sudo -u maatsync /opt/maat/bin/maat-trust-lab '
                 'bbs-add /var/lib/maat '+issuer)
        self.peers(1,[0]);self.sync(1);self.state(1,172,1)
        self.bbs_gate(1,'allow')
        print('PASS real BBS proof authorized by SSH-replicated issuer',flush=True)
        # A revokes the issuer; B MUST reject authentic BBS after SSH update.
        self.ssh(0,'sudo -u maatsync /opt/maat/bin/maat-trust-lab '
                 'bbs-revoke /var/lib/maat '+issuer)
        self.peers(1,[0]);self.sync(1);self.state(1,173,1)
        self.bbs_gate(1,'deny')
        print('PASS authentic BBS proof denied after issuer revocation',flush=True)
        # Citizen revocation on A, replicated to B. C stays at 171.
        self.ssh(0,'sudo -u maatsync /opt/maat/bin/maat-trust-lab revoke /var/lib/maat')
        self.peers(1,[0]);self.sync(1);self.state(1,174,0)
        # C's stale (but still validly signed) state must not roll B back.
        self.ssh(2,'sudo rm -f /etc/maat/poison',output=False)
        self.peers(1,[2]);self.sync(1);self.state(1,174,0)
        print('PASS valid but lagging peer cannot erase revocation',flush=True)
        # Stop ONLY A's dedicated sync SSH server. The admin SSH and the VM
        # remain alive. C must still recover the revocation exclusively from B.
        self.ssh(0, "sudo sh -c 'kill \"$(cat /run/maat-sync-sshd.pid)\"'",
                 output=False)
        unreachable = self.ssh(2,
            'timeout 5 bash -c "true </dev/tcp/%s11/2223"' % PRIVATE_NET,
            timeout=12, output=False, check=False)
        require(unreachable.returncode != 0,
                'authority sync SSH still online during offline relay test')
        self.peers(2,[1]);self.sync(2);self.state(2,174,0)
        self.bbs_gate(2,'deny')
        print('PASS revoked key relayed B -> C with NO query to authority',flush=True)
        print('PASS QEMU three-kernel Maât trust P2P laboratory',flush=True)

    def close(self,failed):
        for p in self.processes:
            if p.poll() is None:
                p.terminate()
        for p in self.processes:
            try:p.wait(timeout=8)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        if failed:
            for i in range(3):
                for prefix in ('console','qemu'):
                    path=self.tmp/('%s-%s.log' % (prefix, 'abc'[i]))
                    if path.exists():
                        print('--- %s ---' % path.name, file=sys.stderr)
                        print('\n'.join(path.read_text(errors='replace').splitlines()[-35:]),
                              file=sys.stderr)


def main():
    if len(sys.argv)!=2:
        print('usage: tests/qemu/run-trust-p2p.py /path/to/ubuntu-22.04-cloudimg.qcow2',
              file=sys.stderr)
        return 2
    for command in ('qemu-system-x86_64','qemu-img','cloud-localds','ssh',
                    'scp','ssh-keygen'):
        need(command)
    image=Path(sys.argv[1]).resolve()
    require(image.is_file(),'QEMU base image missing')
    meta=__import__('json').loads(run(['qemu-img','info','--output=json',str(image)],
                                   output=False).stdout)
    require(meta.get('format')=='qcow2','disposable overlay requires qcow2 base')
    expected=os.environ.get('MAAT_P2P_IMAGE_SHA256')
    if expected:
        require(re.fullmatch('[0-9a-fA-F]{64}',expected) is not None,
                'invalid pinned image SHA-256')
        h=hashlib.sha256()
        with image.open('rb') as source:
            for block in iter(lambda:source.read(1<<20),b''):h.update(block)
        require(h.hexdigest()==expected.lower(),'QEMU base image SHA-256 mismatch')
    base=int(os.environ.get('MAAT_P2P_PORT_BASE','22521'))
    require(1024<=base<=65532,'invalid host port base')
    for port in range(base,base+3):
        with socket.socket() as s:
            s.bind(('127.0.0.1',port))
    # Fail before starting three costly disposable VMs if artifacts are absent.
    bbs_artifacts()
    # A unique multicast UDP port per invocation, local to this host.
    group_port=random.SystemRandom().randint(20000,55000)
    with tempfile.TemporaryDirectory(prefix='maat-qemu-p2p-') as tmp:
        os.chmod(tmp,0o700)
        lab=Laboratory(image,tmp,[base,base+1,base+2],group_port)
        failed=True
        try:
            lab.boot()
            lab.provision()
            lab.build_and_distribute()
            lab.distribute_bbs_verifier()
            lab.configure_authentication()
            lab.tests()
            failed=False
        finally:
            lab.close(failed)
    return 0


if __name__=='__main__':
    try:sys.exit(main())
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
        print('FAIL QEMU P2P:',str(error),file=sys.stderr)
        sys.exit(1)
