# Maât 0.20-alpha7 — Réplication locale des clés publiques et révocations

## Objectif architectural

L'autorité citoyenne n'est **pas** un oracle interrogé à chaque connexion.
Chaque nœud Maât est censé disposer d'un **pool local de clés publiques** et
états de révocation, reçu par propagation entre pairs. Une vérification
ordinaire porte sur le pool local, sans accès réseau. L'autorité doit publier
les mutations et des signaux de fraîcheur, pas donner sa permission à chaque
connexion. Les propriétés de disponibilité (dont 99,999 % souhaités) restent
à mesurer, **pas à déduire de ces tests unitaires**.

L'alpha7 ajoute une brique autonome C++17, `ReplicatedTrust`, stockée en
SQLite et indépendante de Rust. Elle reçoit des deltas **Ed25519 signés par
l'autorité épinglée** et les applique localement. Aucun démon gossip, mécanisme
de découverte, bootstrap massif ni liaison au serveur SSH/PHP n'est activé à
cette étape. `identity_verified=false` demeure inchangé.

## Format des événements / synchronisation

`TrustDelta` utilise un encodage binaire canonique (octets en ordre réseau),
avec séparation de domaine `MAAT:REPLICATED-PUBLIC-TRUST:DELTA:V1\0` :

- ID de registre épinglé (32 octets), numéro global strictement consécutif
  (64 bits), date de publication et limite de validité (secondes Unix) ;
- empreinte SHA-256 du **précédent événement signé** (32 octets) ;
- opération, longueur explicite et clé publique cible, sans champ optionnel ;
- signature Ed25519 (64 octets) recouvrant tous les champs précédents.

Opérations : `heartbeat`, ajout/révocation d'une clé Ed25519 citoyenne (32
octets), ajout/révocation d'une clé publique d'émetteur BBS (96 octets).
Une clé révoquée crée un **tombstone** : l'ancien numéro de clé ne peut pas
être réactivé. Lors d'une rotation, publier une nouvelle clé distincte.

Les événements sont **incrémentaux** et peuvent être copiés par des pairs
sans leur accorder aucune autorité. Une signature valide, un ID de registre
correct, le chaînage et une séquence consécutive sont nécessaires pour les
appliquer atomiquement. Toute mutation refusée est annulée. Le compteur,
l'empreinte du dernier événement et les tombstones survivent au redémarrage.
Les clés publiques ont des index SQLite pour les vérifications locales.

### Événements manquants

Si un nœud reçoit un événement **authentique** de séquence supérieure à la
prochaine attendue, il persiste la plus haute séquence observée et entre en
**quarantaine** : son état local n'autorise plus de clés, même si son dernier
`heartbeat` est encore valide. Il en sort lorsque les événements consécutifs
manquants ont été appliqués. Un paquet forgé ne peut pas déclencher cette
quarantaine, car la signature est contrôlée d'abord. Un mécanisme futur de
récupération des deltas par gossip doit gérer les demandes de resynchronisation.

### Fraîcheur hors ligne

Chaque delta contient un `validUntil` **signé** ; la fenêtre entre
publication et échéance est limitée à 24 h dans cette alpha. Les `heartbeat`
signés renouvellent la période même en l'absence de révocations. En cas de
perte prolongée de mise à jour, la vérification locale **refuse** à
l'expiration. La sécurité dépend de l'horloge locale correctement gérée et de
la diffusion suffisamment rapide des événements. Jusqu'à l'expiration, un
nœud isolé peut ignorer une révocation publiée ailleurs. Le délai de
propagation réel n'est pas garanti par une preuve cryptographique.

La base SQLite ne protège pas contre l'administrateur de la machine qui la
remplacerait arbitrairement, et **ne constitue pas un ancrage anti-rollback
physique** : la restauration d'une ancienne copie complète de la base peut
restaurer un ancien numéro valide pendant sa fenêtre de fraîcheur. Pour le
réseau réel : protection des fichiers, ancrage monotone externe/TPM ou autre
mécanisme anti-rollback robuste, distribution authentifiée des checkpoints,
audit des éventuelles bifurcations de l'autorité et supervision de l'horloge.

## Lien avec les justificatifs BBS

`BbsReplicatedGate` entoure la vérification cryptographique BBS existante :

1. Le service choisit son ID canonique et un défi aléatoire à usage unique.
2. Le backend Rust vérifie la preuve BBS et le pseudonyme par service.
3. Le nœud vérifie **dans son pool local** que la clé de l'émetteur BBS est
   autorisée et que l'état n'est pas périmé/en quarantaine.
4. Si la clé est révoquée ou si le pool est périmé, même une preuve BBS
   authentique est refusée. Un défi est consommé dans tous les cas.

**ATTENTION : ceci révoque un ÉMETTEUR entier, pas une personne anonyme.**
Les preuves BBS alpha6 ne contiennent actuellement que le message public
statique `MAAT-CITIZEN-ACTIVE-V1`. Un service ne peut pas déterminer quelle clé
citoyenne cachée appartient au détenteur de la preuve. Révoquer une clé
Ed25519 de son pool ne révoque donc **PAS** automatiquement les anciens
justificatifs BBS de cette personne ; prétendre l'inverse compromettrait
l'anonymat ou la sécurité. La révocation individuelle anonyme nécessitera un
schéma vérifié de statut/non-révocation ZK, par exemple des accumulateurs ou
autres constructions étudiées, dont les témoins pourront être actualisés par
les publications gossip **sans interroger nominativement l'autorité**. Les
preuves doivent également engager l'état/epoch signé et le défi du service,
sans divulguer d'identifiant commun entre services.

Il reste par ailleurs à réaliser l'émission et la gouvernance effectives des
certificats d'identité civile, l'émetteur BBS et la mise en service du réseau
P2P. L'alpha6 lie expérimentalement le secret à un citoyen, mais cette
composition cryptographique nouvelle n'est pas auditée.

## Vérification

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build -j4
ctest --test-dir build --output-on-failure

# Sur machine équipée de Rust 1.95, vendoring en place :
cmake -S . -B build-bbs -DMAAT_BUILD_BBS_BRIDGE=ON
cmake --build build-bbs -j4
ctest --test-dir build-bbs --output-on-failure
```

`maat-replicated-trust-tests` teste le vrai Ed25519, l'encodage canonique,
les rejets de falsification, rejeu, mauvais registre, saut, fork, période,
les tombstones et la persistance SQLite, plus 256 mises à jour incrémentales.
`maat-bbs-real-proof-tests`, si Rust est activé, vérifie aussi une preuve BBS
réelle acceptée **seulement** lorsque son émetteur est présent et autorisé
localement, puis refusée après révocation ou expiration.

Ce code est **expérimental**, non audité, non intégré aux authentifications
production SSH/PHP, sans preuve de disponibilité opérationnelle.
