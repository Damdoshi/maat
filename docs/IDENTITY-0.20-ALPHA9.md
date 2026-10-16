# Maât 0.20-alpha9 — Synchronisation multi-pairs planifiée

## Gouvernance : autorité publique légitime, pairs non autoritaires

Maât considère le registre citoyen public et la signature de son autorité
légitime comme les sources de vérité. Il n'assimile **pas** l'État à une menace
et ne crée pas de mécanisme de consensus concurrent de l'autorité. La sécurité
visée est la résistance aux **faux registres**, aux pairs compromis, aux
accidents de réseau et aux bases obsolètes. Une rupture de confiance avec
l'autorité elle-même demeure un incident exceptionnel à traiter hors de ce
protocole, dans son cadre juridique et administratif.

Le pair est un **transporteur d'événements**, jamais un certificateur. Un
nœud connaît sa racine (ID registre + clé publique Ed25519) *avant* de se
synchroniser. Il vérifie **toutes** les signatures, séquences et chaînages
locaux. Aucun pair ne peut modifier cette racine. La réception reste atomique
par page et une preuve authentique de bifurcation maintient la quarantaine.

## Configuration de plusieurs pairs, sans découverte implicite

L'exécutable dispose maintenant d'un troisième mode :

```sh
maat-trust-sync round PUBLIC_DB REGISTRY_HEX AUTHORITY_ED25519_HEX /etc/maat/peers.conf
```

Le fichier `/etc/maat/peers.conf` (administrateur ou compte de service,
`0600` ou `0640`, non accessible en écriture au groupe ou au monde, pas de
lien symbolique) est **un fichier de configuration local**, et **pas** une
réponse du réseau. Exemple :

```text
# user@host   port   /absolute/client-private-key   /absolute/pinned-known_hosts   [max_pages]
maat-sync@node-a.example 2223 /etc/maat/keys/sync_ed25519 /etc/maat/known_hosts.sync 256
maat-sync@node-b.example 2223 /etc/maat/keys/sync_ed25519 /etc/maat/known_hosts.sync 256
```

Chaque clé hôte du serveur doit être mise dans le fichier `known_hosts`
**par un canal authentifié**, en format OpenSSH (`[node-a.example]:2223
ssh-ed25519 ...`), et jamais à l'aide de `StrictHostKeyChecking=accept-new`.
La clé privée SSH doit être un fichier propriétaire du compte local (ou de
root) avec permissions `0600` ou plus strictes. Le fichier `known_hosts` doit
être contrôlé par le compte local (ou root), non modifiable par le groupe ou
le monde. Protéger aussi **les répertoires parents**.

L'outil emploie `/usr/bin/ssh` via `/usr/bin/timeout` (GNU coreutils),
avec `-F /dev/null`, authentification par clé et vérification stricte de
l'hôte ; les fichiers de configuration SSH utilisateur n'ajoutent aucun
`ProxyCommand` ou autre comportement. Le serveur doit utiliser un `sshd`
**distinct de l'administration**, avec compte de service dédié et
`ForceCommand` fixe vers `maat-trust-sync serve` comme en alpha8.

## Cycle de synchronisation

1. Le client lit son état de confiance local (SQLite).
2. Il contacte successivement les pairs configurés, chacun sur sa propre
   session SSH non interactive avec un délai total de 30 secondes maximum.
3. Chaque page répond avec au maximum 64 événements. Ils sont vérifiés
   cryptographiquement avant leur application transactionnelle.
4. Si le pair est indisponible ou répond mal, le client en essaie un autre.
   Les événements valides déjà importés restent acquis, sans adoption d'une
   nouvelle branche.
5. Le cycle réussit lorsqu'au moins un contact a abouti et que
   `ReplicatedTrust::fresh()` est vrai. Une liste injoignable, un historique
   incomplet ou un état expiré provoquent un échec explicite du cycle.
6. Une **preuve de bifurcation authentiquement signée** provoque toujours
   une quarantaine persistante, jamais une simple bascule de pair.

Important : `fresh()` et la politique d'autorisation locale restent vérifiés
**à chaque authentification**, pas uniquement par le synchroniseur. Un timer
réussi ne constitue pas un certificat d'autorisation. Le protocole actuel
n'expose pas les clés civiles et ne garantit toujours pas de révocation
individuelle anonyme des titulaires BBS.

## Lancement périodique facultatif

Les fichiers d'exemple `packaging/systemd/maat-trust-sync.service.example`
et `maat-trust-sync.timer.example` servent de **modèles**, non installés.
Adapter le compte de service, les chemins, les racines hexadécimales et les
permissions avant activation. Le timer exécute environ un tour toutes les
cinq minutes avec une gigue de 30 secondes. Aucun daemon permanent n'est
nécessaire. Un nœud vérifie localement ses identités entre deux tournées.

Pour une première validation en laboratoire, ne pas activer systemd :

```sh
./build/maat-trust-sync round /var/lib/maat-sync/public.sqlite \
  REGISTRY_HEX AUTHORITY_HEX /etc/maat/peers.conf
```

## Limites et tests

Les 30 secondes incluent la connexion et le dialogue ; un très gros registre
nécessite plusieurs tournées et davantage de pairs/historique. Jusqu'à 8
pairs peuvent être configurés, chacun avec une limite de 1 à 4096 pages.
L'ordre statique n'est pas une découverte P2P automatique. La source
historique alpha7 reste incomplète : aucun pair ne peut recréer les
signatures qu'il n'a pas conservées.

Les tests `maat-trust-peers-tests` couvrent la grammaire hostile, les
injections en arguments SSH, les doublons, les quotas, les permissions et le
refus de symlink. `maat-trust-cli-tests` exécute réellement `serve` dans un processus distinct
et transmet 65 événements via stdin/stdout (pages de 64, 1, puis 0).
`maat-trust-sync-tests` vérifie toujours les signatures,
l'application atomique, le rattrapage et les vrais conflits signés. Un
laboratoire avec deux vraies instances `sshd` dédiées et clés hôtes vérifiées
reste nécessaire avant de qualifier le réseau réel.

Ce protocole n'est pas un mécanisme de disponibilité garantie (objectif
99,999 % non mesuré), pas une preuve de conformité réglementaire, pas une
identité civile vérifiée (`identity_verified=false`), ni une permission de
révéler les pseudonymes BBS.
