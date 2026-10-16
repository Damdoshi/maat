#!/usr/bin/env python3
"""Adversarial Maât native E2E cases. Run from disposable-root E2E ONLY.

One fresh broker proof and one separate backend socket per HTTP request.
"""
import concurrent.futures
import json
import os
import select
import socket
import subprocess
import sys
import time


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def main():
    if len(sys.argv) != 6:
        raise SystemExit("usage: adversarial_http.py SSH PORT KEY_A KEY_B SSH_USER")
    executable, port, first, second, user = sys.argv[1:]
    common = [executable, "-F", "/dev/null", "-o", "BatchMode=yes",
              "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
              "-o", "LogLevel=ERROR", "-o", "IdentitiesOnly=yes",
              "-o", "PreferredAuthentications=publickey", "-o", "ConnectTimeout=5",
              "-p", port]
    keys = [open(first + ".pub").read().split()[1],
            open(second + ".pub").read().split()[1]]
    require(keys[0] != keys[1], "two SSH identities must differ")

    def run_ssh(which, wire, timeout=12):
        cmd = common + ["-i", (first, second)[which], "-T", user + "@127.0.0.1", "ignored"]
        return subprocess.run(cmd, input=wire, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)

    def request(index):
        which = index % 2
        forged = b"X-Maat-User: fake\r\nX-Maat-Ticket: " + b"e" * 64 + b"\r\n"
        payload = b"GET /whoami.php HTTP/1.1\r\nHost: localhost\r\n" + forged + b"\r\n"
        result = run_ssh(which, payload, timeout=20)
        require(result.returncode == 0 and b"200 OK" in result.stdout,
                "authorized SSH failed at request " + str(index) + ": " +
                repr((result.returncode, result.stderr[-600:], result.stdout[-400:])))
        body = result.stdout.split(b"\r\n\r\n", 1)[1]
        data = json.loads(body)
        require(data["authenticated"] is True and data["identity_verified"] is False,
                "SSH was confused with citizenship verification")
        require(data["public_key"].split()[1] == keys[which], "CROSS-IDENTITY LEAK")
        return True

    # Bounded concurrency: 32 requests across 8 workers (preserves pids-limit).
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for value in pool.map(request, range(32)):
            require(value, "concurrent authenticated request failed")
    print("PASS 32 authenticated requests / 8 workers, both keys exact", flush=True)

    def direct_http(index):
        with socket.create_connection(("127.0.0.1", 18081), timeout=4) as s:
            s.settimeout(4)
            fake_headers = (
                b"X-Maat-User: fake\r\nX-Maat-Principal: forged\r\n"
                b"X-Maat-Ticket: " + b"0" * 64 + b"\r\n")
            wire = b"GET /whoami.php HTTP/1.1\r\nHost: localhost\r\n" + (
                fake_headers if index % 2 else b"") + b"Connection: close\r\n\r\n"
            s.sendall(wire)
            status = s.recv(1024).split(b"\r\n", 1)[0]
            require(b" 403 " in status, "unregistered direct TCP succeeded: " + repr(status))
            return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for result in pool.map(direct_http, range(32)):
            require(result, "direct HTTP rejection failed")
    print("PASS 32 unbound/forged direct TCP connections denied", flush=True)

    def split_responses(data):
        messages = []
        while data:
            marker = data.find(b"\r\n\r\n")
            require(marker != -1, "truncated HTTP response header")
            header = data[:marker].split(b"\r\n")
            require(header[0].startswith(b"HTTP/1.1 200"), "non-200 response: " + repr(header[0]))
            lengths = [line.split(b":", 1)[1].strip() for line in header[1:]
                       if line.lower().startswith(b"content-length:")]
            require(len(lengths) == 1, "no single framing length")
            length = int(lengths[0])
            body = data[marker + 4:marker + 4 + length]
            require(len(body) == length, "truncated persistent body")
            messages.append(json.loads(body))
            data = data[marker + 4 + length:]
        return messages

    one = b"GET /whoami.php HTTP/1.1\r\nHost: localhost\r\n\r\n"
    for which in range(2):
        # Real pipelining: 3 requests arrive in a single SSH stream. Each one
        # MUST use its own backend TCP connection and single-use broker proof.
        result = run_ssh(which, one * 3, timeout=20)
        require(result.returncode == 0, "pipelined request failed: " + repr(result.stderr[-600:]))
        responses = split_responses(result.stdout)
        require(len(responses) == 3, "wrong number of pipelined responses")
        for response in responses:
            require(response["authenticated"] is True and
                    response["public_key"].split()[1] == keys[which],
                    "pipelined SSH request changed identity")
    print("PASS three pipelined requests per SSH connection, fresh per-request proof", flush=True)

    # Real keep-alive: deliver the second request ONLY AFTER the first response
    # has been fully received. Do not rely on pipe pre-buffering.
    for which in range(2):
        cmd = common + ["-i", (first, second)[which], "-T", user + "@127.0.0.1", "ignored"]
        child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        pending = b""
        def read_response():
            nonlocal pending
            deadline = time.monotonic() + 12
            while True:
                header_end = pending.find(b"\r\n\r\n")
                if header_end != -1:
                    head = pending[:header_end].split(b"\r\n")
                    lengths = [x.split(b":", 1)[1].strip() for x in head[1:]
                               if x.lower().startswith(b"content-length:")]
                    require(len(lengths) == 1, "no Content-Length for live keep-alive")
                    required = header_end + 4 + int(lengths[0])
                    if len(pending) >= required:
                        result = pending[:required]
                        pending = pending[required:]
                        return split_responses(result)[0]
                remain = deadline - time.monotonic()
                require(remain > 0, "timeout waiting for persistent response")
                readable, _, _ = select.select([child.stdout], [], [], remain)
                require(bool(readable), "response not readable")
                chunk = os.read(child.stdout.fileno(), 4096)
                require(bool(chunk), "SSH closed before persistent response")
                pending += chunk
        try:
            for _ in range(2):
                child.stdin.write(one)
                child.stdin.flush()
                response = read_response()
                require(response["public_key"].split()[1] == keys[which],
                        "live keep-alive changed identity")
            child.stdin.close()
            require(child.wait(timeout=12) == 0, "SSH failed after keep-alive")
            require(not pending and not child.stdout.read(), "unexpected extra response data")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
    print("PASS sequential live keep-alive SSH requests for both identities", flush=True)

    negatives = [
        b"GET /whoami.php HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        b"GET /whoami.php HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"GET /whoami.php HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\n\r\n",
        b"GET /whoami.php HTTP/1.1\r\nHost: localhost\r\n" + b"A" * 17000 + b": b\r\n\r\n",
        b"POST /whoami.php HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nab",
    ]
    for index, payload in enumerate(negatives):
        result = run_ssh(index % 2, payload)
        require(result.returncode != 0 and b'"authenticated":true' not in result.stdout.lower(),
                "invalid HTTP request was accepted: " + str(index))
    print("PASS ambiguous framing / truncation / oversized headers rejected", flush=True)

    # The bridge must tolerate fragmented valid input (no assumption of a
    # single read containing a whole header), and never reuse another session.
    cmd = common + ["-i", first, "-T", user + "@127.0.0.1", "ignored"]
    child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    try:
        child.stdin.write(b"GET /whoami.php HTTP/1.1\r\nHost: local")
        child.stdin.flush()
        time.sleep(0.1)
        output, errors = child.communicate(input=b"host\r\n\r\n", timeout=12)
        require(child.returncode == 0 and b"200 OK" in output,
                "valid fragmented header failed: " + repr(errors[-300:]))
        require(json.loads(output.split(b"\r\n\r\n", 1)[1])["public_key"].split()[1] == keys[0],
                "fragmented header switched identity")
    finally:
        if child.poll() is None:
            child.kill(); child.communicate()
    print("PASS fragmented SSH HTTP request remains bound to original key", flush=True)

    # Kill the SSH client while the server-side bridge is waiting for headers.
    child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    try:
        child.stdin.write(b"GET /whoami.php HTTP/1.1\r\nHost: ")
        child.stdin.flush()
        time.sleep(0.1)
    finally:
        child.kill()
        child.communicate(timeout=5)
    # A later fresh SSH connection must still carry its OWN Ed25519 identity.
    require(request(1), "new session after abort failed")
    print("PASS abandoned partial SSH request cannot contaminate following session", flush=True)


if __name__ == "__main__":
    main()
