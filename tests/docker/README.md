# Maât 0.19.0-rc1 — disposable Docker integration environment

This directory adds an executable integration environment for the existing
`tests/e2e_native_apache_direct.sh`. It **does not** change host SSH, Apache,
accounts, or `/etc`. The container does not mount host files, publish ports,
share the host network or PID namespace, or use `--privileged`.

## Launch on Ubuntu/Linux

Install Docker Engine / `docker.io` if necessary, start the Docker daemon,
then from the Maât repository root:

```sh
./tests/docker/run-e2e.sh
```

If Docker requires administrator access, run `sudo ./tests/docker/run-e2e.sh`.
Membership in the `docker` Unix group grants access comparable to root: grant
it only to trusted users. The image build downloads Ubuntu 22.04 packages and
therefore needs network connectivity; the **test container runs with
`--network none`**, using only its own loopback interface.

Use `./tests/docker/run-e2e.sh --build-only` to compile without performing
privileged tests, or `--run-only` to repeat E2E without rebuilding. By default
Docker builds C++, the OpenSSH fork, the PHP 8.1 module and `mod_maat`, and
runs CTest/PHPT/Apache smoke tests **during image construction**. Any failure
stops the build.

The runtime test exercises the native 0.19 path: real Ed25519 SSH keys,
privileged OpenSSH monitor, broker + SQLite, descriptor pairing, Apache with
`mod_maat`, and native PHP `$_AUTH`. Since the build context is copied under
`maatbuild` ownership, the test **installs a root-owned (0600) UID-range
configuration in its disposable temporary directory** and validates it with
`maat-check-config` before starting the broker. Do not relax the broker's
ownership check to accommodate Docker build-time ownership.

Cases covered in `e2e_apache.sh` include:

- two different keys using the same SSH account; twelve alternating requests
- concurrent authenticated HTTP requests, each mapped to the correct key
- raw HTTP and spoofed identity headers rejected on the private Maât ingress
- untrusted SSH keys, untrusted local UID, and broker failure refused
- two live ephemeral session UIDs isolated via `/proc`
- indicative timing of five complete SSH-to-PHP requests

The user supplied a passing Docker E2E trace for 0.19-alpha3. This release
candidate source archive still needs its own full Docker run. The authoring
environment has no Docker engine. Retain full failure logs.

## Deliberate boundaries

* Multiple sequential and pipelined **HTTP/1.1** requests share one SSH
  session, with a new kernel TCP descriptor proof **per HTTP request**.
  HTTP/2, HTTP/3 and TLS have not been validated by this test suite.
* Docker shares the host kernel, so also run QEMU on an independent kernel.
* Civil identity is not established; `identity_verified` stays false.
* Ubuntu packages are not pinned for byte-for-byte reproducible builds.
* The UID range must be reserved on any real deployment host.
* Never execute the privileged E2E directly on your normal workstation.

The launcher intentionally drops all Linux capabilities and adds back only
CHOWN, DAC_OVERRIDE, FOWNER, KILL, SETGID, SETUID and SYS_CHROOT. If the
actual SSH monitor needs more, treat this as a failure to understand before
changing the list. In particular, do not casually add `SYS_ADMIN` or use
`--privileged`.

## Maât 0.19 adversarial and persistence coverage

The native E2E runs `tests/adversarial_http.py`: 32 authenticated SSH requests
with two Ed25519 keys and eight workers, 32 direct HTTP spoofing attempts,
rejection of malformed and ambiguous framing, fragmented valid requests,
abandoned SSH clients and broker termination. Pipelined and sequential
HTTP/1.1 requests on the same SSH session must all obtain fresh per-request
proofs. The same native E2E suite runs inside QEMU.
