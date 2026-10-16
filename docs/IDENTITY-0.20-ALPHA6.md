# Maât 0.20-alpha6 — Émission aveugle BBS liée au registre (recherche)

**ATTENTION — PROTOTYPE CRYPTOGRAPHIQUE NON AUDITÉ.** Les tests BBS alpha5
sont réussis chez l'utilisateur. L'alpha6 introduit un **nouveau protocole
Schnorr de liaison** sur les générateurs du BBS blind ; contrairement aux
primitives standard sous-jacentes, cette composition n'a pas été auditée ni
éprouvée par une analyse formelle. Elle reste **exclue du transport Maât**.

## Propriété recherchée

Une personne peut renouveler ses clés d'accès et ses justificatifs BBS sans
changer de pseudonyme auprès d'un service, tant que le registre, le secret
personnel `prover_nym`, la clé maîtresse d'entropie de l'émetteur et la clé
publique BBS restent inchangés. Les services ne voient ni identité civile,
ni clé Ed25519 permanente, ni engagement privé.

Le registre est supposé relier *une seule* identité légale vérifiée à *un
seul* `citizen_id` ; cette hypothèse n'est **pas encore prouvée** par le
système. L'émission ne transforme PAS `identity_verified=false` en `true`.

## Schéma cryptographique et restrictions

- Le titulaire choisit initialement un scalaire privé `p` et le conserve de
  manière durable. Une première émission enregistre l'ancre **privée**
  `A = J_nym · p` (G1, 48 octets), sous son identifiant citoyen, dans SQLite.
  Unique et immuable, cette ancre n'est **jamais transmise aux sites**.
- Pour chaque émission, Affinidi produit `nym_commit(p)` donnant
  `C = Q_2 · r + J_nym · p` avec un nouveau `r` et un engagement opaque
  contenant sa propre preuve standard de connaissance.
- Une preuve Schnorr additionnelle démontre la connaissance de `r` telle
  que `C − A = Q_2 · r`. Son défi Fiat-Shamir est lié à la version du
  protocole, la namespace du registre, la clé Ed25519 citoyenne, le nonce
  serveur, l'ancre, l'engagement complet et l'engagement Schnorr. Le serveur
  vérifie **aussi** la preuve native contenue dans `nym_commit` lors du
  `blind_sign_with_nym`.
- Le citoyen signe avec sa clé Ed25519 inscrite une demande incluant le
  nonce serveur, `A`, `C`, et cette preuve. Le serveur refuse les clés
  révoquées, les citoyens révoqués et les permissions `denied/suspended`.
- L'émetteur utilise `e = HashToScalar(HMAC-SHA512(master, domaine ||
  registryId || citizenId))`. Seule la contribution de l'émetteur `e`
  et celle du titulaire `p` sont additionnées dans la signature BBS.
  La clé maîtresse HMAC et la clé privée BBS sont distinctes et fixées
  lors du bootstrap, avec empreinte d'identité persistante dans SQLite.
  Modifier silencieusement l'une des deux est refusé.
- Les mutations SQLite (nouvelle ancre et émission) s'effectuent dans une
  transaction `BEGIN IMMEDIATE`, avec restauration au moindre échec.
  Le serveur vérifie la continuité de l'ancre à chaque émission.
- Aucun service ID n'intervient dans l'émission : le détenteur choisit
  *ultérieurement* le contexte de la preuve anonyme lors de la présentation.
  Le service le fixe lui-même dans `BbsPresentationGate` et reçoit le
  pseudonyme dérivé de `p+e` ainsi qu'une preuve liée à son défi.

**Modèle de confiance :** l'autorité d'émission possède la clé BBS : une
émission volontairement malveillante ou un contournement de cette API par
l'opérateur disposant de la clé ne peuvent pas être empêchés par ce seul
composant. Il faut des clés protégées matériellement, un service d'émission
isolé, de l'audit, une gouvernance des autorités et une vérification civile
non implémentés à cette étape. L'ancre et ses métadonnées doivent rester
strictement internes à l'autorité, faute de quoi les demandes deviennent
corrélables. Les identifiants de réseaux, les timings et l'IP ne sont pas
masqués par BBS.

## État de l'intégration

- `libs/maat-bbs/src/bound_issue.rs` : preuve de liaison, vérification,
  dérivation de l'entropie et signature aveugle BBS. FFI C limitée à des
  tableaux de taille fixe, sans service web public.
- `src/identity/bbs_bound_issuer.*` : challenge à usage unique, identité
  Ed25519, contrôle du registre, ancrage SQLite, HMAC de l'émetteur.
- `tests/bbs_bound_issuer_test.cpp` : tests d'ancrage, rotation, refus de
  changement, reprise après redémarrage, suspensions, faux signatures,
  challenge rejoué et changement des secrets d'autorité.
- Les tests Rust vérifient les *vraies signatures BBS*, la liaison et le
  pseudonyme stable/différent selon le service.
- `MAAT_BUILD_BBS_BRIDGE` demeure **OFF par défaut**. Même ON, aucun
  `maatd`, `sshd`, Apache, PHP ou `$_AUTH` n'appelle ce composant.

## Reproduire les tests (Rust 1.95, sources vendoriées)

```
cd ~/maat
export PATH="$(dirname "$(rustup which cargo)"):$PATH"
hash -r
cd libs/maat-bbs
cargo test --locked --offline
cd ../..
cmake -S . -B build-bbs -DMAAT_BUILD_BBS_BRIDGE=ON
cmake --build build-bbs -j4
ctest --test-dir build-bbs --output-on-failure
```

Si Rust/Cargo ne sont pas accessibles, le build C++ par défaut continue de
fonctionner, mais cela **ne valide pas** l'émission BBS alpha6. Le patch est
construit à partir de l'archive alpha5 hors ligne et ne modifie ni l'instance
SSH d'administration ni le transport Maât dédié.

## Ce qui reste à faire

1. Revue cryptographique indépendante de la preuve de liaison et de sa
   combinaison avec BBS ; vecteurs interopérables et fuzzing FFI.
2. Sécurisation des secrets citoyens (carte / élément sécurisé, sauvegarde
   et protocole de récupération du secret stable), résistance à la cession
   volontaire de justificatifs et aux appareils compromis.
3. Émissions auditables ou à seuil ; revocation *des justificatifs déjà émis*
   sans oracle nominatif, gestion des epochs, changement contrôlé des clés
   d'autorité, séparation institutionnelle et ouverture judiciaire à seuil.
4. Tests d'intégration Linux isolé Docker/QEMU, modèle civil vérifié,
   et seulement ensuite liaison prudente au broker/Apache/PHP.
