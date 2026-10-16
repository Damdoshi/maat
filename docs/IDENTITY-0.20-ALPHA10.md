# Maât 0.20.0-alpha10 — Laboratoire SSH P2P sur trois QEMU

## Périmètre

L'alpha10 ajoute un **banc de validation**, sans activer un nouveau réseau en
production ni changer le broker SSH, Apache ou `$_AUTH`.

L'autorité publique demeure la **seule source légitime de mutations signées**.
Les pairs transportent des données ; aucun d'eux n'a le pouvoir de réémettre
une clé citoyenne ou de remplacer la racine locale.

Trois machines virtuelles Ubuntu 22.04, chacune avec son propre noyau :

| VM | Rôle | Mémoire |
| --- | --- | ---: |
| A | Émetteur du registre **fictif de laboratoire** et pair source | 2 048 Mio |
| B | Récepteur, détection de falsification, bascule entre pairs | 768 Mio |
| C | Relais initialement sain, puis pair empoisonneur simulé | 768 Mio |

Consommation mémoire **configurée** : 3 584 Mio, sans les surcoûts QEMU et
hôte. Trois disques QCOW2 jetables de 8 Gio virtuels (sparse) utilisent
**la même image de base en lecture seule**. Les machines sont conservées
pendant tous les scénarios puis détruites ; jamais plus de trois à la fois.

La compilation du synchroniseur et de l'utilitaire d'essai est effectuée
**une fois dans A**, puis copiée aux deux autres machines Ubuntu identiques.
Aucune compilation BBS, OpenSSH modifié, Apache ou PHP n'est nécessaire
pour ce **banc spécifique de registre P2P**. Les tests Docker/QEMU antérieurs
restent utiles pour vérifier le transport applicatif distinct.

## Scénarios vérifiés par le script

1. Une clé Ed25519 d'**autorité fictive** et un ID de registre aléatoires
   sont créés à l'intérieur de A. Sa clé privée n'est jamais expédiée à B
   ou C. L'identifiant, sa clé **publique** et la clé citoyenne fictive sont
   distribués sur un canal d'administration initial distinct et authentifié.
2. A signe 171 événements (dont une clé citoyenne autorisée). C récupère
   l'historique depuis A au travers du véritable `sshd` **dédié**.
3. C devient hostile et transmet une mutation signée avec une signature
   **falsifiée**. B doit refuser toute la page, sans appliquer de mutation.
4. Le fichier local des pairs de B liste C, puis A : C échoue, A fournit
   les 171 événements valides. Les clés hôtes SSH sont épinglées hors bande.
5. A signe une révocation de la clé citoyenne fictive (séquence 172).
   B la récupère et refuse immédiatement cette clé à partir de sa base locale.
6. C est rétabli, mais reste en retard à la séquence 171 ; sa vieille copie
   authentique ne peut **pas** faire revenir B en arrière.
7. Le serveur SSH **dédié** de A est arrêté ; C récupère alors la
   révocation **depuis B**, sans pouvoir contacter A ni une autorité.
   La propagation entre nœuds est donc vérifiée sur trois noyaux différents.

Le banc préserve l'isolation entre le SSH d'administration de chaque invité
(port 22 dans les VM) et le `sshd` Maât de laboratoire (port 2223,
clé hôte distincte, utilisateur `maatsync`, `ForceCommand` fixe, transferts
et redirections interdits). Les clés de chaque serveur sont récupérées par
le canal d'amorçage initial **avant** toute synchronisation. Les `known_hosts`
ne sont pas appris automatiquement pendant le protocole Maât.

## Lancement

Prérequis hôte : `qemu-system-x86_64`, `qemu-img`, `cloud-localds`, `ssh`,
`scp`, `ssh-keygen`, Python 3. C'est la **même image officielle QCOW2 Jammy
22.04, préalablement vérifiée**, que dans `tests/qemu/run-e2e.sh`.
La récupération de paquets Ubuntu exige l'accès aux miroirs `apt` depuis
les trois invités. Le programme ne télécharge pas d'image système.

```bash
cd ~/maat
./tests/qemu/run-trust-p2p.sh ./ubuntu-22.04-server-cloudimg-amd64.img
```

En option, fournir la somme SHA-256 de cette image depuis un manifeste
**authentifié indépendamment** :

```bash
MAAT_P2P_IMAGE_SHA256=... \
  ./tests/qemu/run-trust-p2p.sh /chemin/vers/image.img
```

Le script utilise sur **l'hôte** uniquement les ports SSH locaux `22521`,
`22522`, `22523` (personnalisables avec `MAAT_P2P_PORT_BASE`). Les VM sont
reliées entre elles par une interface Ethernet privée émulée QEMU via
multicast local à l'hôte, sur le réseau `192.168.177.0/24`. Si la politique
de l'hôte interdit cette méthode de réseau QEMU, le test doit **échouer** :
il ne substitue pas silencieusement une simulation en processus.

Paramètres facultatifs : `MAAT_P2P_ACCEL=auto|kvm|tcg`,
`MAAT_P2P_DISK_GB=8..32`, `MAAT_P2P_PORT_BASE=22521`.
`tcg` fonctionne sans KVM mais peut être très lent pour trois invités.
Pour réduire le temps, le projet est compilé une seule fois dans A. Les
overlays, clés SSH et données de laboratoire sont supprimés en fin de test,
y compris en cas d'échec ; les derniers journaux console sont alors affichés.

**Ce test est destructeur exclusivement pour les disques invités temporaires.**
Il ne modifie ni l'image de base, ni `/etc/ssh` ou les services de l'hôte.
Les éventuels fichiers `tests/qemu/trust_p2p_fixture.cpp` sont des outils
**d'essai uniquement**. Ils refusent de signer si le marqueur de VM jetable
est absent. Ne pas les installer sur un serveur Maât réel, ni réutiliser
leurs clés fictives dans un réseau réel.

## Limites de sécurité

Le banc vérifie la **signature, les séquences, l'intégrité et la
révocation des clés publiques** à travers de vraies connexions SSH et trois
noyaux différents. Il ne prétend pas démontrer l'absence de toute attaque de
réseau ou l'intégrité d'une autorité officielle compromise.

L'individualisation d'une révocation **anonyme BBS** n'est pas implémentée
par ce registre public. `identity_verified=false` reste inchangé, et aucune
preuve BBS anonyme n'est autorisée par le test à entrer dans `$_AUTH`.
**La réplication est asynchrone** : C peut encore considérer l'ancienne tête
comme fraîche avant sa prochaine synchronisation. Ce banc démontre que la
révocation est respectée **après propagation**, pas qu'elle est instantanée
à tous les nœuds. Le délai de propagation et un objectif de disponibilité
99,999 % ne sont ni mesurés ni garantis.

Les précédentes suites Docker/QEMU de SSH → Apache → PHP restent séparées.

La réussite du banc n'est confirmée **qu'après son exécution réelle sous
QEMU**, sur une machine possédant QEMU et une image Jammy convenable. La
validation des sources et des tests locaux ne suffit pas à la déclarer.
