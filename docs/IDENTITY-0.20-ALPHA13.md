# Maât 0.20-alpha13 — BBS/P2P sur trois QEMU (laboratoire)

## But

Relier la preuve BBS authentique au registre de confiance qui a réellement
voyagé sur les connexions SSH de trois noyaux indépendants.

* Sur A, un événement signé `add_bbs_issuer` autorise la clé BBS publique
  du générateur de preuves *de test*.
* B récupère cet événement via la commande SSH `maat-trust-sync round` et
  vérifie une preuve BBS fraîche avec `BbsReplicatedGate` et sa propre base.
* A signe `revoke_bbs_issuer`. B le récupère via SSH, puis rejette une
  **nouvelle preuve BBS authentique** du même émetteur.
* Après révocation de la clé citoyenne déjà exercée par le laboratoire, A
  devient injoignable sur son SSH de synchronisation ; C rattrape les événements
  depuis B et refuse aussi la présentation BBS.

Ces scénarios prouvent la révocation **de l'émetteur**, jamais la révocation
anonyme du titulaire individuel. Le code ne donne aucun accès SSH, PHP ou HTTP.

## Construction et exécution

```sh
cmake -S . -B build-bbs -DMAAT_BUILD_BBS_BRIDGE=ON
cmake --build build-bbs -j4
ctest --test-dir build-bbs --output-on-failure
./tests/qemu/run-trust-p2p.sh ./ubuntu-22.04-server-cloudimg-amd64.img
```

Attention : le banc compile nativement les outils de synchronisation dans A,
mais copie le nouveau vérificateur C++ et le générateur de preuves BBS depuis
les artefacts de `build-bbs` de l'hôte. Le banc suppose donc une architecture
AMD64 et une compatibilité des bibliothèques dynamiques **hôte → Ubuntu 22.04**.
Si le binaire est lié à une glibc hôte plus récente, le démarrage dans l'invité
peut échouer. Il faudrait alors construire aussi la partie BBS dans un
conteneur ou une VM Ubuntu 22.04 avec un toolchain Rust adéquat (hors de cette
itération). Les clés d'autorité restent exclusivement dans QEMU A.

Le banc est expérimental, jetable, non destiné à la production. Les preuves
BBS proviennent d'un générateur de test. Aucune identité civile n'est attestée
et `identity_verified` ne doit pas être changé.
