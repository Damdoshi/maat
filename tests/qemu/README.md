# Maât QEMU E2E — separate Linux kernel

The QEMU laboratory uses a separate Linux kernel and an official Ubuntu 22.04
QCOW2 cloud image. Install host packages (`qemu-system-x86`, `qemu-utils`,
`cloud-image-utils`, `openssh-client`), then run from the Maât repository root:

```sh
./check.sh full
```

`check.sh full` downloads `ubuntu-22.04-server-cloudimg-amd64.img` directly into
the repository root when absent and passes that exact path to both QEMU suites.
It verifies SHA-256 from Canonical's HTTPS manifest before use and refuses to
silently overwrite a mismatched existing image. `./check.sh unit` requires no
image and performs no network download. The image is a test fixture, not a
prebuild dependency. HTTPS checksum verification does not replace validation of
the publisher's signed checksum manifest; see the manual verification steps below.

For Ubuntu 22.04 use the official **released** AMD64 cloud image:

- https://cloud-images.ubuntu.com/releases/server/jammy/release/
- Download `ubuntu-22.04-server-cloudimg-amd64.img` (QCOW2) and the matching
  `SHA256SUMS` plus `SHA256SUMS.gpg` from the **same release**.
- Verify the signing key and `SHA256SUMS.gpg` using the publisher's trusted
  signing-key documentation, then verify the `.img` against that manifest.
  Do not trust a checksum copied from the same unverified web page in place
  of a signed manifest.

For example, with those verified files in the current directory:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

Then, from Maât's working tree, run the lightweight safety checks and
launch the disposable VM:

```sh
./tests/qemu/preflight-smoke.sh
./tests/qemu/run-e2e.sh /path/to/ubuntu-22.04-server-cloudimg-amd64.img
```

The image may consume roughly 700 MiB on the host, with several additional
GiB required for the **sparse** temporary overlay and package downloads.
This first run can take a while; subsequent invocations recreate the guest
from scratch and do not keep a writable VM state.

The script creates a temporary QCOW2 overlay and cloud-init seed; it never
writes to the base image. It expands only the overlay to **at least 12 GiB**
and asks cloud-init to grow the guest root filesystem. It verifies at least
4 GiB of free guest disk before installing build dependencies. The default
is **4 GiB RAM, two vCPUs, two compilation jobs**, with an optional
90-minute guest-operation timeout (QEMU boot time excluded). The VM gets a private Ed25519 SSH login key and a
localhost-only SSH forwarding port (default 22422, configurable through
`MAAT_QEMU_SSH_PORT`). The guest stages sources under `/opt/maat`
(owner `maatci`, directory mode 0755), installs dependencies and builds Maât
as an unprivileged user. It checks that unrelated unprivileged accounts can
execute the bridge and read the Apache/PHP test artifacts before running the
**same** privileged positive/negative E2E suite inside the disposable guest.
This matters because each SSH session runs under its own ephemeral UID and
cannot traverse the private `/home/maatci` directory. The user's home
permissions remain unchanged. No host path is mounted; source is copied
into the guest with SSH/SCP. Guest and keys are destroyed on completion.

KVM is used only if accessible; otherwise `tcg` is chosen, which may be very
slow. Set `MAAT_QEMU_ACCEL=tcg` to force emulation. Optional variables:
`MAAT_QEMU_MEMORY_MB` (3072–65536), `MAAT_QEMU_DISK_GB` (8–128),
`MAAT_QEMU_GUEST_TIMEOUT` (seconds, 300–21600), and
`MAAT_QEMU_IMAGE_SHA256` (the expected hash from your verified image
manifest, to have the launcher check the image once more). The guest can
reach Ubuntu package mirrors through QEMU user-mode networking but **no
public host ports** are published; guest SSH is forwarded only to
127.0.0.1:22422 by default. A failed test prints the
last 80 lines of the guest console and returns a nonzero status.

**Security boundary:** user-mode networking still gives the guest outbound
network access for Ubuntu package downloads, and exposes only guest SSH on
host loopback. Do not use a production disk image, real credentials, or a host
with untrusted users controlling the source tree. QEMU is a better kernel
isolation boundary than Docker, not an alternative to auditing Maât. Neither
proves an actual French citizen's identity or prevents compromise of a root
process inside the Maât server.

Status: the user-supplied 2026-10-13 trace shows complete positive and
adversarial guest E2E **PASS** on Ubuntu 22.04 (kernel 5.15.0-198-generic).
The authoring environment has no QEMU engine; see
`docs/VALIDATION-0.19-RC1.md` for actual observed evidence and limitations.
