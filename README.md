# Maât 0.20-alpha14 — PHP example and safe site scaffolding

`tools/maat-site create NAME --root EXISTING_DIRECTORY` creates a demonstration
site and a review-only Apache fragment. No live Apache instance, SSH listener,
service, BBS grant or authorization state is configured. See
[`docs/ALPHA14-WEB-SITES.md`](docs/ALPHA14-WEB-SITES.md).

---

# Maât 0.20-alpha11 — Reprise P2P et non-révocation anonyme (conception)

Le protocole signé de synchronisation traite les pages incomplètes, les
annonces de tête non signées et le rattrapage après interruption. Le laboratoire
à trois QEMU vérifie une reprise après 64 événements sur une nouvelle
connexion SSH, puis le refus du pair falsificateur. La révocation individuelle
BBS anonyme n’est **pas** encore implémentée : les exigences de preuve et
d'absence de divulgation sont détaillées dans
[`docs/IDENTITY-0.20-ALPHA11.md`](docs/IDENTITY-0.20-ALPHA11.md).

---

# Maât 0.20-alpha10 — Trois QEMU pour le registre P2P (expérimental)

Nouveau banc opt-in `tests/qemu/run-trust-p2p.sh` : trois noyaux indépendants,
trois serveurs SSH dédiés, registre signé, attaque de pair falsificateur,
bascule et propagation d’une révocation sans interroger l’autorité.
**Aucun service ajouté automatiquement** et aucune modification du chemin
SSH → broker → Apache → PHP. Voir
[`docs/IDENTITY-0.20-ALPHA10.md`](docs/IDENTITY-0.20-ALPHA10.md).

---

# Maât 0.20-alpha9 — Scheduled P2P trust sync (experimental)

Adds a locally configured set of SSH peers with pinned host keys, bounded
failover sync rounds, an operator-only peer configuration file and optional
systemd timer examples. The legitimate registry authority remains the sole
source of signed public-trust changes; peers only relay signed deltas. No new
state governance or trust authority is introduced. Normal SSH/HTTP/PHP identity
authentication is unchanged. `identity_verified=false`.

See [`docs/IDENTITY-0.20-ALPHA9.md`](docs/IDENTITY-0.20-ALPHA9.md).

---
# Maât 0.20-alpha8 — Signed P2P trust sync (experimental)

Adds an append-only signed trust event history and bounded SSH-stdio
peer-to-peer synchronization with atomic catch-up, independent Ed25519
checks, persisted fork quarantine, and gossipable signed fork proofs.
Normal SSH/HTTP/PHP identity authentication remains unchanged; all trust root
pins must be provisioned out-of-band, no automatic peer discovery or SSH
service configuration is enabled. Individual BBS holder revocation and civil
identity verification are not implemented. See
[`docs/IDENTITY-0.20-ALPHA8.md`](docs/IDENTITY-0.20-ALPHA8.md).

---

# Maât 0.20-alpha7 — Public trust replication (experimental)

New node-local `ReplicatedTrust` verifies signed incremental Ed25519 trust
updates, enforces persistent sequence/hash chaining, key revocations and
strict freshness. `BbsReplicatedGate` additionally requires its BBS issuer
key to be locally authorized. **This is issuer-level revocation, NOT
unlinkable individual BBS credential revocation.** No gossip daemon or SSH /
PHP authentication integration is enabled; `identity_verified=false`.

See [`docs/IDENTITY-0.20-ALPHA7.md`](docs/IDENTITY-0.20-ALPHA7.md).

---

# Maât 0.20-alpha5 (experimental BBS bridge, disabled by default)

Added a narrowly scoped C++17 BBS presentation gate and optional **Rust
staticlib** wrapper around the user-provided Affinidi BBS sources. A verifier
creates and consumes challenges and fixes its own service scope and issuer key.
**Without the optional Rust build, the gate rejects EVERY presentation.**

The user-supplied clone does NOT include transitive crates. The Rust/BBS code
has NOT been compiled or tested here, due to unavailable Rust and crates.io.
Do NOT enable the backend on public endpoints until it is built and tested.
Even when enabled, this is a BBS proof gate, NOT a working citizen credential
issuer, anti-Sybil continuity guarantee, live revocation system, judicial
opening scheme, or proof of civil identity. SSH, the broker and PHP remain
unchanged (`identity_verified=false`).

See [`docs/IDENTITY-0.20-ALPHA5.md`](docs/IDENTITY-0.20-ALPHA5.md).

---

# Maât 0.20.0-alpha4 — Émission indépendante du service (étape préparatoire)

Nouvelle bibliothèque C++17 `src/identity/privacy_bootstrap.*` : le citoyen
possède un seul engagement de secret de pseudonyme épinglé durablement au
registre, conservé lors du renouvellement des clés. Un émetteur privé peut
signer un justificatif **sans connaître le nom du service de destination**.
Défis, autorisation préalable, clé signataire distincte, unicité, refus,
suspension, révocation, anti-rejeu et persistance sont testés.

**ATTENTION : ce n'est PAS ENCORE une authentification anonyme utilisable.**
Le justificatif expose l'engagement stable et **ne doit jamais être présenté
à un service**, faute de quoi toutes les visites pourraient être corrélées.
Le nullifier dérivé localement est **non vérifiable** sans une véritable
preuve ZK. Il n'existe aucun chemin de vérification de ce justificatif dans
OpenSSH, le broker, Apache ou PHP ; `identity_verified=false` reste inchangé.
La branche précédente, `ScopedCredentialIssuer`, reste disponible en tant
que mécanisme non anonyme de l'alpha3.

Le protocole étudié pour la suite est **BBS per Verifier Linkability** (CFRG,
Internet-Draft actif en juin 2026), avec blind BBS : voir
[`docs/IDENTITY-0.20-ALPHA4.md`](docs/IDENTITY-0.20-ALPHA4.md) pour
les propriétés garanties et non garanties, les références et les tests.
La 0.20-alpha4 est une **alpha préparatoire de sécurité**, et non une
prétendue solution ZK prête à déployer.

---

# Maât 0.20.0-alpha3 — Justificatifs vérifiables par service

La nouvelle bibliothèque C++17 `src/identity/scoped_credentials.*` délivre des
justificatifs signés Ed25519 et limités à cinq minutes. Chaque justificatif
contient un **nullifier stable propre à un service**, une clé éphémère et une
signature d'émetteur : le service peut le vérifier sans connaître l'identité
citoyenne ni sa clé SSH permanente. Les signatures de possession de clé, les
défis à usage unique, les refus et suspensions d'anonymat et les bannissements
survivant au renouvellement des clés sont testés.

**Ce n'est PAS un justificatif cryptographiquement anonyme.** L'émetteur voit
l'identité citoyenne et le service demandé. Le service ne voit qu'un pseudonyme
local, qui permet de reconnaître les visites dans son propre périmètre. Il
faudra un protocole de justificatifs anonymes éprouvé pour supprimer cette
connaissance de l'émetteur. Les justificatifs émis restent valides au plus
cinq minutes après une révocation ; une diffusion de révocations à durée de
fraîcheur bornée n'existe pas encore. Le transport SSH/PHP n'est pas modifié,
`identity_verified=false` reste en vigueur et aucun déploiement public n'est
approuvé.

Voir [`docs/IDENTITY-0.20-ALPHA3.md`](docs/IDENTITY-0.20-ALPHA3.md).

---


# Maât 0.20.0-alpha2 — Administration signée du registre citoyen

## Administration cryptographiquement authentifiée (hors transport)

Les mutations du registre citoyen doivent désormais passer par
`RegistryAuthority` : autorité Ed25519 préalablement provisionnée, commandes
signées avec namespace de registre, compteur anti-rejeu strict et journal
SQLite atomique. Les opérations directes de modification ne sont plus
publiques dans l'API C++. Aucun serveur d'administration n'est exposé.

Voir [`docs/IDENTITY-0.20-ALPHA2.md`](docs/IDENTITY-0.20-ALPHA2.md).

## Registre d'identité (non activé)

Le code C++ `src/identity/` introduit une première base administrative à
unicité de citoyen, un droit d'anonymat **refusé par défaut**, des clés
rotatives/révocables et des bannissements à identifiant propre à chaque
service. **Aucune vérification civile ni preuve anonyme ne sont encore
implémentées ; `identity_verified=false` reste inchangé dans SSH/PHP.**
Voir aussi le document historique
[`docs/IDENTITY-0.20-ALPHA1.md`](docs/IDENTITY-0.20-ALPHA1.md).

## Base de transport 0.19.0-rc1 — Intégration précédemment validée

Maât is an experimental identity transport prototype, **not** an operating
citizen registry and **not approved for Internet-facing production**.
The actual SSH Ed25519 key is authenticated but civil identity is not:
`identity_verified=false`. Registration, revocation, host UID reservation,
threat modeling, audit and hardening remain to be completed.

This release candidate combines the previously tested alpha3 implementation
with the Docker and QEMU harness fixes. The user-supplied Ubuntu 22.04 QEMU
run dated 2026-10-13 ended with `E2E HTTP PASS` and
`PASS QEMU isolated-kernel Maât native E2E`. Docker 0.19-alpha3 also passed.
The SSH bridge supports multiple HTTP/1.1 requests per authenticated SSH
session, always with a **fresh independently broker-validated TCP descriptor
proof for every HTTP request**. See `docs/VALIDATION-0.19-RC1.md`.

**Re-run this exact RC archive before promoting it:**

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
ctest --test-dir build --output-on-failure
sudo ./tests/docker/run-e2e.sh
./tests/qemu/run-e2e.sh /path/to/verified-ubuntu-22.04-server-cloudimg-amd64.img
```

## Earlier implementation history

# Maât 0.18 — Transport d’identité sans jeton HTTP

**Changement incompatible avec 0.17, non encore validé en bout-en-bout Apache réel.**

La requête HTTP ne transporte plus `X-Maat-Ticket` ni aucun autre jeton.
La passerelle SSH présente au broker un descripteur de sa connexion TCP,
via son canal Unix de session authentifié. Apache présente son propre
descripteur TCP au même broker, via SCM_RIGHTS depuis `mod_maat`.
Le broker apparie les deux extrémités de la **même connexion ouverte**,
retourne la clé SSH attestée et détruit cette autorisation à usage unique.
Le module PHP natif continue à lire l’identité de `request_config`.

* L’instance Apache privée utilise `MaatIngress On` et renvoie 403 si aucune
  liaison de descripteur ne correspond, y compris sur une requête locale.
* Une instance Apache ordinaire utilise `MaatIngress Off` ; `$_AUTH` y vaut NULL.
* Le port du backend privé demeure 127.0.0.1:18081, sans proxy TCP ou NAT.
* L’IPC n’est valable que sur Linux, avec `SO_PEERCRED` et `SCM_RIGHTS`.
* Ce prototype ne prouve toujours aucune appartenance au registre des citoyens.

La construction C++ et ses tests ne suffisent pas à démontrer la sécurité du
module Apache chargé dans une véritable installation. **Ne pas installer
cette version sur un service Maât existant** avant un test traversant en
VM/container jetable avec SSH, `mod_maat`, `php-maat` et Apache réels.

# Maât 0.18 — Native Apache request identity (single path)

**Experimental, not for production.** `mod_maat` now consumes the SSH-bound
one-use ticket, stores the broker-verified key in Apache `request_config`;
`php-maat` retrieves that context via Apache's optional function, never HTTP
headers. The old `MaatDirectVerify` switch and PHP->broker fallback are removed.

On Ubuntu with PHP 8.1: `./build.sh --skip-vendored-apache`, or run the
component steps in `docs/APACHE-0.17.md`. Do NOT install over services without
staging tests. A true positive SSH→Apache→`$_AUTH` test still requires a
throwaway root VM/container and is not yet validated in this build session.

# Maât 0.15 — Apache source integration (incremental)

**Security status: experimental / not for production.** This iteration adds
an optional Apache 2.4 ingress module and pinned upstream Apache vendoring.
It does **not** replace the trusted broker, SSH monitor, or native PHP
verification. Read `docs/APACHE-0.15.md` for build steps and limitations.

# Maât 0.14.0 — isolated Unix credentials per authenticated SSH/HTTP session

**Security research prototype; NOT approved for Internet-facing production.**

C++17, bundled OpenSSH Portable 10.6p1 (`libs/openssh-portable/`), a
privileged monitor receiver, a broker, a forced HTTP bridge, SQLite and a PHP
demonstrator. The 0.20 administrative registry is not yet connected to SSH;
`identity_verified` remains `false`.

## Security change in 0.13

Version 0.12 protected shared-UID processes with `PR_SET_DUMPABLE(0)`, but
`execve()` can reset dumpability. In 0.13, **each SSH connection** is given a
**distinct Linux kernel UID**, before OpenSSH's post-auth privilege drop.

1. The OpenSSH privileged monitor validates the real Ed25519 SSH key and
   records a `MAATMON2` assertion via a root-owned Unix socket.
2. Before dropping privileges, the post-auth child requests a `MAATBIND3`
   session capability via the privileged monitor. The monitor registers the
   session with the root broker using `SOCK_SEQPACKET` and `SCM_RIGHTS`.
3. Inside one SQLite `BEGIN IMMEDIATE` transaction, the broker binds that
   previously verified session and allocates an unused ephemeral UID from the
   **host-reserved range `1000000000..2099999999`**.
4. The privileged monitor receives the UID in an `MAATBOUND3` reply and
   conveys it to the post-auth child over OpenSSH's internal monitor IPC.
5. The post-auth child applies the assigned UID through OpenSSH's normal
   `do_setusercontext()` **before parsing further client session requests**.
   The login account must be `maatweb`; no shell or user-controlled command
   runs. An administrative `ForceCommand` launches `maat-http-bridge` directly.
6. The bridge holds only its inherited per-session socket descriptor (fd 3).
   It requests one use-once ticket over it. Apache/PHP redeems the ticket
   against a separate Unix verification socket. Web applications never get
   to declare the identity themselves.

The ledger `maat_ephemeral_uids` is durable. UIDs are **never reused**, even
if a session is abandoned, has ended, or the broker restarts. Collisions,
replays, SQLite failures and UID range exhaustion fail closed. The code
refuses an UID found by NSS (`getpwuid_r`) but **this is not a complete
host-wide collision check**.

### REQUIRED host-level UID reservation

**Do not deploy until the entire range `1000000000..2099999999` is
administratively reserved exclusively for Maât**, including every relevant
NSS source, systemd service, container, privileged runtime and UID allocator.
The package does **not** automatically enforce a reservation with all other
root processes. Linux does not offer a general exclusive UID allocator;
privileged software elsewhere can still adopt an overlapping UID. For a
production release, create an auditable machine-level reservation/preflight
policy or move sessions into separately controlled user namespaces.

The SQLite database is part of the security perimeter: never delete, truncate,
restore to an earlier version or copy it between independent active machines.
An attacker with host root access can forge this local chain.

## Build

Debian 13 amd64 requirements: g++, cmake, sqlite3 development headers,
OpenSSL and zlib development headers, autoconf/automake, OpenSSH build tools,
Apache 2.4 with mod_php and PHP 8.4 for Apache end-to-end tests.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
ctest --test-dir build --output-on-failure

cd libs/openssh-portable
./configure --prefix=/usr --sysconfdir=/etc/maat \
 --libexecdir=/usr/lib/maat --with-privsep-user=maatsshd \
 --with-privsep-path=/var/empty/maat --without-pam \
 --without-kerberos5 --without-selinux \
 --without-security-key-builtin CFLAGS='-O2 -g -DMAAT_MONITOR_SOCKET'
make -j4 sshd sshd-auth sshd-session ssh ssh-keygen
```

Build this with matching OpenSSL headers and libraries. The validation
container's system OpenSSL headers and shared library versions differ, so
**only for the test build** the `--without-openssl-header-check` override was
necessary. This mismatch must be fixed before production.

**Disposable root VM/container ONLY:**

```
tests/e2e_apache.sh
# Or for the PHP built-in server:
tests/e2e_http.sh
./build/maat-isolation-tests
```

The tests temporarily modify the `maatweb` test account's shell/password,
restore them on exit, and use dedicated local sockets, keys and ports.
Never run them on a production host. The Apache E2E verifies two concurrent
sessions sharing the same SSH account but assigned distinct UIDs, and probes
`/proc/<pid>/fd/3` from the original account and another session UID.

To build an amd64 Debian package from sources:

```
MAAT_OUTPUT_DIRECTORY=dist packaging/build-deb.sh
```

The build deliberately fails when OpenSSL headers/library don't match, unless
`MAAT_ALLOW_OPENSSL_HEADER_MISMATCH=1` is explicitly set for a test build.
The `.deb` never enables SSH or Apache services automatically. The included
SSH HTTP example configuration is loopback-only and denies all users until
an administrator explicitly permits appropriate test credentials.

## Remaining work / non-guarantees

- No citizen authority, birth records, unique-human identity, card, revocation
  or selective disclosure. The `maatweb` Unix account is NOT a civil identity.
- `_AUTH` native PHP extension is included in `php-ext/` but not compiled or
  runtime-tested (the test environment lacks `php8.4-dev` / `phpize`). Apache
  E2E still uses `php/maat_auth.php` bootstrap, not a PHP superglobal.
- HTTP proxy supports one bounded HTTP/1.1 GET/POST/HEAD request per SSH
  connection; not HTTP/2, WebSockets, streaming, or production browser use.
- Global UID reservation across root-managed services is NOT yet enforced.
  No independent security audit or penetration test has been done.
- Monitor and broker are root-trusted, and SQLite files are root-controlled.
  The UID ledger grows monotonically and needs operational limits/monitoring.
- No automatic database disaster recovery, secure upgrade/rollback policy,
  workload profiling beyond short local loopback measurements, or load testing.

See `docs/SECURITY-0.13.md` for the trust model and failure cases.

### 0.14: UID allocation configuration and PHP extension testing

See `docs/UID-RANGE.md` for the root-owned Dabsic-subset range configuration.
The PHP native module is not built into the `maat-sshd` package unless PHP development
headers are available and its compilation / PHPT tests have passed.

## Ubuntu/PHP 8.1 development + unprivileged test corrections

The `maat-bind-tests` positive test exercises the **root-only** OpenSSH to
broker trust boundary. Run its positive cases in a *disposable root CI/VM*,
not via `sudo ctest` on a real server. Under ordinary users it is reported
**Skipped** (CTest exit code 77), not wrongly reported as a failing function.

The HTTP repository's unit tests use a dependency-injected, deterministic UID
collision policy. The production broker **still consults NSS**, fails closed
for occupied UIDs and NSS lookup errors, and prints the NSS error to stderr.
This makes unit tests reproducible on hosts with LDAP/SSSD, without weakening
production UID isolation. Host integration testing is still required.

To build PHP on Ubuntu 22.04 (PHP 8.1):

```
sudo apt install php8.1-dev php8.1-cli
./php-ext/build.sh
```

The script detects `php`, `phpize`, and `php-config` automatically. It requires
matching major/minor PHP and development header versions, fails if `maat.so`
is not generated, and runs the PHPT suite. It does not replace the privileged
SSH → Apache native-extension E2E test: that test must happen on the target
host with isolated service accounts and sockets.

For a PHP 8.1 package, after a successful extension build and PHPT suite:

```
./packaging/build-php-deb.sh
```

It creates `php8.1-maat_0.14.0-1_<arch>.deb` for an 8.1 installation;
installing this does not automatically replace or enable the native module
in Apache. Verify the `maat-sshd` dependency is available on the target OS.

## Maât 0.16 experimental native Apache verification

This release introduces optional direct `mod_maat` → broker verification and
request-local Apache identity state. It is OFF by default. `php-maat` has a
PHP 8.1-only experimental Apache request API adapter, separately enabled
with `MAAT_EXPERIMENTAL_APACHE_ABI=yes` at build time. The working 0.15
PHP → broker path is untouched by default. **Do not enable these modes on
production sites.** See [docs/APACHE-0.16.md](docs/APACHE-0.16.md).

## HTTP persistence candidate (0.19-alpha3)

See `docs/HTTP-PERSISTENCE-PLAN.md` and `docs/PERSISTENCE-BRIDGE-0.19.md` for
the multi-request SSH bridge, fresh per-request TCP proofs, limits, and tests.
This candidate still requires positive Docker and QEMU validation.
