# Maât 0.20-alpha8 — Synchronisation du registre public par pairs

## Propriété prioritaire : le pair n'est JAMAIS une autorité

L'autorité citoyenne publie des événements **Ed25519 signés**. Un nœud
conserve localement les clés publiques et l'état de révocation, et ne demande
**aucune permission à l'autorité** lorsqu'il vérifie une authentification.
Un voisin Maât peut transporter des octets mais ne peut ni introduire sa clé
comme racine de confiance ni remplacer un historique local divergent.

**Ce que l'alpha8 fournit** : journal public append-only transactionnel,
reprise paginée (64 événements par page), rattrapage d'événements historiques
expirés, protocole binaire borné versionné, commandes `serve` et `pull` sur
canal SSH non interactif, quarantaine persistante avec propagation de preuves
cryptographiques d'équivocation. La vérification d'identité reste locale.

**Ce qui N'EST PAS fourni** : découverte automatique des voisins, planificateur
périodique, daemon de propagation push, distribution massive de snapshots,
validation d'identité civile, révocation individuelle anonyme BBS, garantie
mesurée « 99,999 % », quorum indépendant d'autorités, ancrage anti-rollback
matériel, intégration au SSH/Apache/PHP en production. `identity_verified=false`.

## Anti-empoisonnement : six frontières

1. **Racines épinglées hors bande.** L'identifiant du registre et la clé
   Ed25519 de l'autorité sont stockés dans la configuration locale. Les trames
   de pair ne peuvent jamais les réassigner. Le serveur SSH est authentifié
   séparément par une clé hôte épinglée (`StrictHostKeyChecking=yes`).
2. **Authentification des événements.** Signature Ed25519, domaine/version,
   registre, format canonique, durée bornée, séquence consécutive et SHA-256 du
   prédécesseur sont obligatoires. Les métadonnées `peerSequence/peerHead`
   sont de simples **indices non fiables**.
3. **Aucun changement partiel.** Un lot contenant une mutation corrompue,
   étrangère, falsifiée, réordonnée ou contradictoire est entièrement annulé
   dans une transaction SQLite, y compris son journal append-only.
4. **Pas d'adoption d'une branche distante.** En cas de divergence à la même
   séquence, aucun choix automatique du « meilleur pair », de la majorité des
   pairs ou du registre prétendument le plus avancé. Le registre reste
   immuable. Un événement concurrent AUTHENTIQUEMENT signé est enregistré
   comme indice de bifurcation et bloque la vérification.
5. **Preuve de bifurcation relayable.** Une paire de deux événements DISTINCTS
   à la MÊME séquence, tous deux signés par la même autorité épinglée,
   constitue une preuve indépendante d'équivocation. Les pairs peuvent
   diffuser cette paire ; le destinataire vérifie **les deux** signatures
   avant de placer sa base en quarantaine. Un simple « alerte, je suis
   empoisonné » ne suffit pas. La quarantaine est conservée au redémarrage.
6. **État local frais obligatoire.** Lorsqu'un nœud voit un événement signé
   en avance, un trou dans l'historique ou une date `validUntil` dépassée,
   `fresh()` refuse de valider des clés. Les événements vieux de plusieurs
   jours peuvent être rejoués **uniquement** dans une synchronisation
   historisée cryptographiquement vérifiée. Le dernier événement doit encore
   être frais pour restaurer la vérification locale.

**Limite de confiance fondamentale** : si la clé officielle de l'autorité
est compromise et publie une histoire malveillante mais cohérente, aucune
vérification Ed25519/P2P ne peut la distinguer d'une publication régulière.
Cette éventualité constitue une **rupture de confiance institutionnelle**,
exceptionnelle, dont le traitement relève des procédures administratives et
juridiques légitimes (notification, enquête, remplacement des clés et remise
en service authentifiée). Maât n'installe pas de gouvernance concurrente ni
ne présume l'État hostile. Une paire d'historiques concurrents établit une
anomalie de signature, mais ne juge pas la légalité de l'acte.

Une base SQLite locale administrativement compromise, un disque restauré à
un état ancien encore frais ou une horloge système manipulée demandent des
protections distinctes. Une attaque réseau peut retarder les révocations
jusqu'à la fin de la fenêtre de fraîcheur ; **aucune garantie de mise à jour
instantanée** n'est impliquée par la signature.

## Binaire `maat-trust-sync`

Compilation normale C++17 (Rust non requis) :

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build -j4
ctest --test-dir build --output-on-failure
./build/maat-trust-sync
```

Le binaire accepte deux modes ; les valeurs hexadécimales de la racine sont
32 octets, transmis comme 64 caractères hexadécimaux :

```text
maat-trust-sync serve DB REGISTRY_HEX AUTHORITY_ED25519_HEX
maat-trust-sync pull DB REGISTRY_HEX AUTHORITY_ED25519_HEX SSH_USER_AT_HOST SSH_PORT SSH_IDENTITY [MAX_PAGES]
```

`serve` traite des requêtes binaires sur stdin et écrit des réponses binaires
sur stdout, jusqu'à EOF ou un maximum de 4096 pages par connexion. Ne jamais
écrire de diagnostic sur stdout : stderr est réservé à cela. `pull` lance un
client OpenSSH sans shell, vérifie strictement l'identité du serveur via
`known_hosts`, et synchronise plusieurs pages dans **une seule session SSH**.
Aucun argument serveur ou racine n'est reçu du canal SSH. Le code n'est pas
branché au transport SSH existant des requêtes HTTP.

### Exemple de raccord sûr (non activé automatiquement)

Créer un **compte de service distinct** `maat-sync`, avec un shell utilisable
par OpenSSH pour son `ForceCommand` mais aucun accès libre (le `ForceCommand`
et `AllowUsers` sont imposés par le démon séparé). Le fichier de base SQLite
et son dossier WAL ne sont accessibles qu'à ce service. Utiliser une **instance
sshd séparée** de celle d'administration : sa propre configuration, son propre
port, sa clé hôte et son PID. Par exemple dans un fichier de configuration
dédié, adapté par l'administrateur :

```text
Port 2223
PidFile /run/maat-sync-sshd.pid
HostKey /etc/ssh/maat_sync_host_ed25519_key
AllowUsers maat-sync
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTTY no
ForceCommand /usr/local/libexec/maat-trust-sync serve /var/lib/maat-sync/public.sqlite REGISTRY_HEX AUTHORITY_ED25519_HEX
```

Ce fichier n'est **pas** fourni prêt à activer : il faut provisionner la clé
hôte, les utilisateurs, l'accès aux fichiers et l'authentification des pairs.
Ne pas réemployer les comptes administratifs ou le serveur SSH local standard.
L'exemple `2223` est arbitraire ; choisir un port réellement accessible. Les
clés SSH du client autorisé doivent être enregistrées explicitement.

Sur le nœud client (la clé hôte du serveur doit être vérifiée par un canal
indépendant, jamais acceptée automatiquement au premier contact) :

```sh
./build/maat-trust-sync pull /var/lib/maat-sync/public.sqlite \
  REGISTRY_HEX AUTHORITY_ED25519_HEX maat-sync@node-exemple 2223 \
  /etc/maat/keys/peer_sync_ed25519
```

L'outil réplique des événements publics de **pair à pair**, mais il ne lance
pas de sessions spontanées à intervalle régulier, et ne gère pas la découverte
et l'ordonnancement multi-voisins. Ces responsabilités appartiendront à un
service de synchronisation ultérieur.

### Bootstrap depuis une ancienne alpha7

L'alpha7 ne conservait **pas** l'historique des événements, seulement la tête
hashée du registre et l'état courant. Alpha8 ne fabrique pas de faux événements
anciens pour combler ce trou. Une ancienne base continue à vérifier ses clés,
et journalise les nouveaux événements, mais **ne peut pas donner un historique
complet à un nouveau nœud parti de zéro**. Il faut obtenir un historique
complet authentique depuis l'autorité ou un pair disposant réellement de
l'historique, puis le rejouer dans une nouvelle base : aucune remise à zéro
du curseur d'une base existante ou confiance implicite à un snapshot tiers.

### Concurrence et contrôle du stockage

Le protocole a une limite de 64 événements par page, de 512 octets par
événement, et de 4096 pages par connexion. Le serveur et le client refusent
les tailles excessives et les versions inconnues. Les transactions SQLite
mettent à jour ensemble clés, tombstones, tête et journal. Les lectures de
vérification restent locales, sans RPC ni appel à l'autorité. Une base
expérimentale avec journal complet grossit linéairement ; la compaction
nécessitera des checkpoints signés par une gouvernance indépendante et n'est
**pas** activée dans cette version.

## Tests

`maat-trust-sync-tests` couvre un rattrapage de 171 événements en 3 pages,
les événements historiques expirés, le refus pendant le rattrapage, les lots
corrompus sans application partielle, le rejet des métadonnées hostiles et des
mauvais registres, la propagation d'une révocation, la détection de fork
réellement signé, les fausses preuves de fork rejetées, la quarantaine
persistante après redémarrage et la propagation de la preuve à un troisième
nœud n'ayant accepté aucune branche. `maat-replicated-trust-tests` conserve
les protections alpha7. Un test avec de vrais démons SSH sur des machines
indépendantes doit encore être réalisé. **Aucun mécanisme cryptographique de
révocation anonyme individuelle BBS n'est implémenté.**
