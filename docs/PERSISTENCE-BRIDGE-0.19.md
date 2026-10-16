# Maât 0.19-alpha3 — bridge streaming changes

Apply only **after** the 0.19-alpha2 broker-capability patch and the earlier
SQLite/GCC11 Docker fixes. This patch is incremental. In particular it does
not modify `mod_maat` or relax any broker UID/security permissions.

From the repository root on Ubuntu 22.04:

```sh
# Check and apply the downloadable incremental patch.
git apply --check maat-0.19.0-alpha3-persistent-bridge.patch
git apply maat-0.19.0-alpha3-persistent-bridge.patch

cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
ctest --test-dir build --output-on-failure

# Full privileged E2E runs only INSIDE the disposable Docker image.
sudo ./tests/docker/run-e2e.sh
```

Do not run `tests/e2e_apache.sh` directly on a normal workstation: it alters
accounts, privileged SSH files, sockets and test credentials. The Docker
launcher has no bind mounts, published ports or `--privileged`.

New tests include `maat-http-stream-tests`, the unprivileged
`maat-bridge-persistence-smoke`, and real Docker assertions for both true
sequential HTTP requests and pipelined requests on a single SSH connection.
The native PHP extension still reads its request identity from the per-request
Apache context. No client identity header or HTTP bearer token is accepted.

The Docker benchmark uses one request per SSH connection for historical
comparison. Do not interpret it as a benchmark of persistent throughput.
