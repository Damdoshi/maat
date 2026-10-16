# Maât 0.20-alpha5 — Pont de vérification BBS (candidat, inactif par défaut)

## Ce que le code FAIT

- `BbsPresentationGate` impose un identifiant de service canonique et une clé
  BBS d'émetteur configurée par le **service**, jamais fournis par le client.
- Le défi est généré par OpenSSL `RAND_bytes`, lié à un seul service, valable
  60 secondes, consommé avant la vérification, y compris en cas d'échec. Au
  plus 1 024 défis en cours sont conservés en mémoire. Redémarrage = défis
  perdus = refus fermé.
- Si et seulement si `MAAT_BUILD_BBS_BRIDGE=ON`, le C++ appelle le vérificateur
  de preuve `proof_verify_with_nym` dans Affinidi via une ABI C de taille
  contrainte. La preuve vérifie la possession d'une signature BBS sur un message
  `MAAT-CITIZEN-ACTIVE-V1`, l'existence d'un secret nym masqué, le pseudonyme
  propre à la destination, et le défi fourni par le service.
- En l'absence de Rust, ou si la compilation BBS n'est pas activée : tous les
  présentations sont refusées. Aucun jeton Ed25519 alpha4 n'est converti
  en identité vérifiée.

**ATTENTION** : valider une signature BBS n'établit pas que l'émetteur est
réellement une autorité d'identité civile, ni que le titulaire est toujours
actif, ni qu'il est unique. Il n'y a pas encore de procédure d'émission BBS
reliée transactionnellement à `CitizenRegistry`. La valeur renvoyée par le
verificateur n'est JAMAIS injectée dans `$_AUTH` ni dans le broker. La
transmission d'un `ScopeFreeCredential` alpha4 à un service demeure interdite.

## Pourquoi les sources Git ne suffisent pas

Le clone `libs/affinidi-tdk-rs/crates/core/affinidi-bbs/` contient la crate
`affinidi-bbs` 0.4.0 et ses vecteurs de tests, sous licence Apache-2.0.
**Il ne contient pas ses dépendances transitives**, notamment `bls12_381_plus`,
`sha2`, `rand`, `zeroize`, etc. Le dossier initial `libs/libs/maat-bbs/vendor/`
est vide. Le workspace téléchargé exige Rust 1.95.0.

`libs/maat-bbs/Cargo.toml` utilise un chemin local vers la source copiée :
la bibliothèque BBS elle-même n'est plus téléchargée depuis crates.io. Mais
Cargo doit toujours résoudre et récupérer ses dépendances sur une machine
ayant accès au registre Cargo (ou un miroir d'entreprise) une fois :

```sh
cd libs/maat-bbs
cargo generate-lockfile
cargo test --locked
mkdir -p .cargo
cargo vendor --locked vendor > .cargo/config.toml
cargo test --locked --offline
cd ../..
cmake -S . -B build-bbs -DMAAT_BUILD_BBS_BRIDGE=ON
cmake --build build-bbs -j4
ctest --test-dir build-bbs --output-on-failure
```

**Important :** la commande `cargo vendor` doit être exécutée sur une machine
ayant déjà téléchargé les crates, puis il faut synchroniser `Cargo.lock`,
`.cargo/config.toml` et **tout** `vendor/` vers la machine hors réseau.
L'archive transmise par l'utilisateur ne contient aucun de ces téléchargements.
Le bridge est volontairement EXCLU du build Docker normal pour maintenir la
non-régression et empêcher toute activation implicite.

Une fois `cargo test --locked --offline` réussi, lancer les tests complets
Docker/QEMU ; ceux-ci ne constituent pas pour autant un test d'intégration
BBS sur le transport Maât.

## Propriété anti-Sybil qui RESTE À PROUVER

Le mécanisme décrit dans `nym.rs` calcule :

`nym_secret = prover_nym + signer_nym_entropy`.

Une même destination donne le même pseudonyme si ET SEULEMENT SI ce secret
nym reste le même. Les tests Rust du bridge démontrent délibérément qu'un
changement de la contribution du citoyen **ou** de celle de l'émetteur change
le pseudonyme. Il faudra lier l'émission aveugle à l'engagement unique du
registre avec une preuve cryptographique de cette continuité. La persistance
SQLite de l'engagement SHA-256 alpha4 ne suffit pas. Ne pas déclarer les
bannissements incontestables dans cette version.

La révocation en temps réel, le maintien des garanties lorsque les clés sont
compromises, l'ouverture judiciaire multipartite, la non-corrélation sous
métadonnées réseau et la vérification de la source civile de l'enregistrement
ne sont pas implémentés. Prototype de recherche uniquement.

## Offline dependency snapshot + real C++/Rust test (alpha5 verification update)

The independent Cargo dependency archive supplied by the user contains
`Cargo.lock`, `.cargo/config.toml` and 71 complete vendor directories.
For this checkout, the snapshot was checked against 2,761 SHA-256 file hashes
stored in Cargo's `.cargo-checksum.json` files (0 mismatches). The snapshot
contains no Rust toolchain; Rust/Cargo 1.95.0 is still needed to build BBS.
The Rust dependencies are **build-time** only and BBS remains OFF by default.

To populate an alpha5 checkout from the dependency archive, if not already done:

```sh
cd ~/maat
mkdir -p libs/maat-bbs
# The archive has paths relative to libs/maat-bbs; it must not be unpacked at ~/maat.
tar xzf /path/to/maat-bbs-deps.tar.gz -C libs/maat-bbs
```

Verify with a suitable Rust/Cargo 1.95.0 (beware an older `/usr/bin/cargo`
shadowing rustup's installation):

```sh
cd ~/maat/libs/maat-bbs
cargo test --locked --offline
cd ~/maat
cmake -S . -B build-bbs -DMAAT_BUILD_BBS_BRIDGE=ON
cmake --build build-bbs -j4
ctest --test-dir build-bbs --output-on-failure
```

When enabled, the build also compiles a **test-only fixture generator**
`target/release/maat_bbs_fixture`. It generates test BBS signatures and
proofs using a hard-coded public test key. Its output is fed to the native
`BbsPresentationGate` through the C ABI, ensuring that a valid proof is
accepted once and that changed challenges, scopes and proofs are refused.
This helper MUST NEVER be installed as a production issuer.

The positive test also demonstrates that changing the holder nym contribution
or issuer entropy yields a **different valid pseudonym for the same service**.
This is an explicit failure of the desired anti-Sybil issuance policy, NOT a
feature to enable for citizens. There is no production BBS issuer wired to
`CitizenRegistry`, nor an enforceable issuance continuity proof, independent
revocation freshness mechanism or authority chain. Until those exist, this
experimental BBS verifier must NOT grant authenticated access in the broker,
Apache, or `$_AUTH`. `identity_verified=false` continues to apply.

The default Docker/QEMU E2E paths exercise Maât SSH and PHP, NOT the optional
BBS cryptography, and are insufficient evidence of the positive BBS test.
