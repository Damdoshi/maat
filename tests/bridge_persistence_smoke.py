#!/usr/bin/env python3
"""Unprivileged bridge E2E against fake seqpacket broker and HTTP backend.

This verifies actual FD3 capability reuse and the bridge's HTTP/1.1 frames.
It deliberately does NOT claim authenticated Apache identity verification.
"""
import array
import socket
import struct
import subprocess
import sys
import threading


def check(ok, msg):
    if not ok:
        raise AssertionError(msg)


def packet(word):
    encoded = word.encode()
    return struct.pack('!I', len(encoded)) + encoded + struct.pack('!I', 0)


def parse_replies(wire):
    result = []
    while wire:
        n = wire.find(b'\r\n\r\n')
        check(n >= 0, 'response headers complete')
        header = wire[:n]
        check(header.startswith(b'HTTP/1.1 200 OK\r\n'), 'response status')
        check(b'Connection: keep-alive\r\n' in header + b'\r\n', 'keepalive')
        length = [int(line.split(b':', 1)[1].strip())
                  for line in header.split(b'\r\n')
                  if line.lower().startswith(b'content-length:')]
        check(len(length) == 1, 'one Content-Length')
        end = n + 4 + length[0]
        check(end <= len(wire), 'body complete')
        result.append(wire[n + 4:end])
        wire = wire[end:]
    return result


def main():
    check(len(sys.argv) == 2, 'usage: bridge_persistence_smoke.py BRIDGE')
    broker, bridge = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(('127.0.0.1', 18081))
    except OSError as exc:
        print('SKIP: test backend port 18081 occupied:', exc)
        return 77
    listener.listen(5)
    listener.settimeout(10)
    failures = []
    counts = {'broker': 0, 'http': 0}
    messages = [b'alpha', b'beta', b'gamma']

    def broker_worker():
        try:
            broker.settimeout(10)
            for _ in messages:
                data, ancillary, _, _ = broker.recvmsg(128, socket.CMSG_SPACE(4))
                check(data == packet('MAATLINK1'), 'broker link wire')
                passed = [array.array('i', value) for level, kind, value in ancillary
                          if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS]
                check(len(passed) == 1 and len(passed[0]) == 1, 'SCM_RIGHTS FD exact')
                with socket.socket(fileno=passed[0][0]) as fd:
                    check(fd.getpeername()[1] == 18081, 'real TCP backend FD')
                broker.sendall(packet('MAATREADY1'))
                counts['broker'] += 1
        except BaseException as exc:
            failures.append(exc)
        finally:
            broker.close()

    def http_worker():
        try:
            for payload in messages:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(10)
                    data = bytearray()
                    while True:
                        part = connection.recv(4096)
                        if not part:
                            break
                        data.extend(part)
                    check(data.startswith(b'GET /whoami.php HTTP/1.1\r\n'), 'forwarded request')
                    check(b'Connection: close\r\n' in data, 'private upstream connection closed')
                    check(b'X-Maat-User:' not in data, 'forge stripped')
                    connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n'
                                       b'Connection: close\r\n\r\n' + payload)
                    counts['http'] += 1
        except BaseException as exc:
            failures.append(exc)
        finally:
            listener.close()

    threads = [threading.Thread(target=broker_worker),
               threading.Thread(target=http_worker)]
    for worker in threads:
        worker.start()
    # Forced command expects the capability on FD3 (not a regular environment
    # string). Copy before exec while preserving its inheritable flag.
    def bridge_setup():
        if bridge.fileno() != 3:
            import os
            os.dup2(bridge.fileno(), 3, inheritable=True)
    try:
        with subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              pass_fds=(3, bridge.fileno()), preexec_fn=bridge_setup,
                              env={'MAAT_BIND_FD': '3'}) as child:
            bridge.close()
            requests = (b'GET /whoami.php HTTP/1.1\r\nHost: localhost\r\n'
                        b'X-Maat-User: forged\r\n\r\n') * 3
            output, errors = child.communicate(input=requests, timeout=20)
            check(child.returncode == 0,
                  'bridge failed: ' + repr((child.returncode, errors[-500:])))
            check(parse_replies(output) == messages, 'three properly framed replies')
    finally:
        for worker in threads:
            worker.join(timeout=12)
        check(not any(worker.is_alive() for worker in threads), 'workers completed')
    check(not failures, 'fake backend/broker failed: ' + repr(failures))
    check(counts == {'broker': 3, 'http': 3}, 'one new registration per request')
    print('PASS bridge FD3 reused safely for 3 HTTP messages, 3 fresh TCP FDs')
    return 0


if __name__ == '__main__':
    sys.exit(main())
