# Maât 0.20.0-alpha11 — Reprise P2P et frontière de révocation BBS

## But opérationnel

Une connexion à l'autorité citoyenne n'est **pas** nécessaire pour vérifier une clé
publique. L'autorité signe les changements, les pairs transportent des événements,
chaque nœud décide à partir de son pool local authentifié.

Cette version renforce la reprise sur une autre connexion SSH ou un autre pair.
Chaque page est validée intégralement (signature Ed25519, registre épinglé,
chaînage, séquence et dates), puis enregistrée atomiquement dans SQLite.
Une coupure avant application laisse le curseur inchangé ; une coupure après
application reprend au nouveau curseur durable. **Aucune donnée partielle ni
aucune annonce non signée n'autorise une identité.**

### Changements alpha11

* Une réponse `events` avec un numéro de tête non nul doit contenir un
  événement de tête **signé**. Une séquence annoncée sans preuve ne suffit pas.
* Une tête signée plus récente accompagnée d'une page vide est refusée comme
  rétention des événements. Le tour multi-pairs peut essayer le pair suivant.
* Une page **plus courte que 64 événements** ne signifie pas la fin du
  rattrapage si la tête signée du pair est encore devant notre curseur.
* Si la tête signée contredit le dernier événement signé d'une page à la même
  séquence, cette bifurcation attestée provoque la quarantaine persistante.
* Un budget de pages épuisé retourne une erreur, mais ne détruit pas les pages
  déjà validées. Un autre processus `round` reprend depuis le curseur SQLite.
* Le laboratoire existant de **trois QEMU** teste un arrêt volontaire au bout
  de 64 événements, puis une attaque de pair, puis une reprise depuis 65.

Cette version ne supprime pas la limite de fraîcheur du registre. Une
synchronisation incomplète peut laisser la dernière tête expirée ; la vérification
continue alors à refuser les clés. Le système n'affirme pas avoir reçu une
révocation instantanément si le réseau est partitionné. Le test QEMU ne prouve
pas encore la robustesse face à un arrêt électrique pendant `fsync`.

### Tester

```sh
cmake -S . -B build-bbs -DMAAT_BUILD_BBS_BRIDGE=ON
cmake --build build-bbs -j4
ctest --test-dir build-bbs --output-on-failure
./tests/qemu/run-trust-p2p.sh ./ubuntu-22.04-server-cloudimg-amd64.img
```

Le patch alpha10 → alpha11 est calculé sur l'alpha10 **avec les deux correctifs
QEMU** (`cloudinit` et `sync-permissions`) déjà appliqués, conformément à
l'état validé par le laboratoire de l'utilisateur. Ni `sshd` ni les timers ne
sont installés ou activés par ce patch.

## Révocation d'un titulaire BBS : état des garanties

**Non implémentée dans l'alpha11.** Une preuve de possession d'une signature
BBS valide et un émetteur actif dans le registre ne prouvent *pas* que son
porteur individuel n'a pas été révoqué depuis l'émission. Les clés citoyennes
publiques révoquées et les émetteurs BBS révoqués sont déjà traités localement,
mais ne doivent pas être présentés comme une révocation individuelle anonyme.

Les pseudonymes propres à chaque service peuvent servir aux bannissements
**locaux à ce service**, qui ne nécessitent pas de liste de révocation civile.
Ils ne suffisent pas à une révocation globale d'un titulaire anonyme.

### Contrat cryptographique envisagé (à évaluer et auditer)

1. À l'émission, un *identifiant de révocation secret* et stable doit être
   **lié par preuve** au même citoyen que la contribution de pseudonyme BBS,
   malgré les renouvellements de clés. Il ne doit pas être choisi librement à
   chaque nouvelle émission. La liaison cryptographique de cette construction
   avec les engagements BBS existants devra être auditée.
2. L'autorité publie les évolutions de révocation dans des états
   cryptographiques signés, distribués par le P2P déjà existant. Les nœuds
   n'interrogent pas l'autorité par visite.
3. Le porteur met à jour un témoin de non-révocation depuis ces **données
   publiques**, sans identification nominative ni requête ciblée à l'autorité.
4. Une présentation prouve en zéro connaissance que le porteur connaît
   **le même identifiant de révocation caché que celui attesté à l'émission**
   et qu'il n'appartient pas à l'ensemble des citoyens révoqués. Cette preuve
   doit être liée au défi unique du service et à l'époque du registre.
5. Le vérificateur vérifie localement le registre signé, la fraîcheur, la
   preuve de non-révocation, la preuve BBS, le pseudonyme par service et leurs
   liaisons. Il ne reçoit aucun identifiant de révocation ni engagement global.
6. Un nœud trop en retard pour vérifier le nouvel état de révocation ne doit
   pas se déclarer à jour à partir de sa seule dernière tête ancienne.

**La sélection de l'accumulateur / schéma de preuve de non-appartenance n'est
pas faite.** Ne pas inventer un accumulateur à signatures BBS ou un simple
hachage d'identité publiquement testable : cela compromettrait la confidentialité
ou la résistance aux contournements. Les critères d'évaluation incluent :
preuves d'un même secret pour BBS et non-révocation, mises à jour publiques des
témoins, suppression/ajout, coût par citoyen et par vérification, sécurité sous
corruption de pairs et propriétés d'absence de corrélation entre services.

**Compromission de l'autorité officielle :** une véritable rupture de confiance
institutionnelle relève des procédures légitimes, pas d'une présomption générale
d'hostilité de l'État ou de l'apparition d'autorités concurrentes.

## Limites et sécurité

`identity_verified=false` demeure le comportement du transport actuel tant
qu'une véritable attestation civile n'existe pas. La brique BBS reste
expérimentale et distincte du parcours SSH → Apache → PHP.

Des tests fonctionnels et des sanitizers ne remplacent ni revue indépendante
du protocole cryptographique ni tests prolongés en conditions réseau réelles.
