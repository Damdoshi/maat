# Validation Maât 0.15 — 2026-10-12

## Executed in the preparing Debian container

- `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug` — PASS
- `cmake --build build -j4` — PASS
- `ctest --test-dir build --output-on-failure` — PASS 5/5
- `cmake -S . -B build-asan ... -fsanitize=address,undefined` — PASS
- `ASAN_OPTIONS=detect_leaks=0 ctest --test-dir build-asan --output-on-failure` — PASS 5/5
- Corrupted Apache tarball — refused by pinned SHA-256 check
- Attempt to build Apache without verified sources — refused
- `dpkg-parsechangelog -S Version` — PASS, 0.15.0-1

## Not executed; should not be inferred as successful

- Apache upstream 2.4.69 checkout in `libs/apache-httpd/`: FAILED to
  obtain from preparing host (DNS unavailable). Official manifest pinned.
- Real Apache 2.4.69 compilation: NOT RUN.
- Real `mod_maat.so` compilation: NOT RUN (`apache2-dev`/`apxs` unavailable).
- Debian binary `libapache2-mod-maat`: NOT BUILT (missing build dependencies).
- Root-only SSH -> Apache -> **native** PHP positive E2E: NOT RUN.
- Performance/load benchmarks with `mod_maat`: NOT RUN.

The two new Apache module tests are for a dependency-free policy and a
simulated Apache hook respectively. They cannot replace an actual Apache
module ABI / process test. Tests of earlier 0.14 transport are regression
checks but do not independently constitute a new end-to-end validation.
