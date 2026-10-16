# Maât 0.20-alpha1 — Registre citoyen et périmètres de bannissement

## Statut

**Fondation métier C++17 / SQLite uniquement.** Le transport Maât 0.19 ne
consulte PAS ce registre et continue d'indiquer `identity_verified=false`.
Il n'existe ni émetteur de justificatifs anonymes, ni ZKP, ni signature de
groupe ouvrable, ni protocole d'ouverture judiciaire dans cette livraison.
Aucune API publique de création, d'administration ou de vérification d'identité
n'est activée. Ne pas déployer comme registre national.

## Modèle et invariants locaux

- `CitizenRegistry` est une base **réservée à l'autorité**. Elle associe un
  `subject_commitment` binaire de 256 bits, opaque, à un identifiant citoyen
  aléatoire de 256 bits. SQLite impose l'unicité du `subject_commitment` pour
  toute la durée de la base, **y compris après révocation** : la révocation
  n'efface pas la référence d'unicité.
- Le `subject_commitment` DOIT être calculé par une autorité compétente, de
  manière déterministe pour une même personne, à l'aide d'une primitive
  cryptographique *à clé secrète* et avec séparation de domaine. Ne pas
  stocker le numéro de sécurité sociale, le NIR, le nom ou un simple SHA-256
  du NIR : un identifiant civil à faible entropie se retrouve par dictionnaire.
  Le code ne fabrique ni ne valide cette preuve d'état civil. Une erreur ou
  une fraude de l'autorité peut toujours créer plusieurs engagements pour
  une même personne. L'unicité ici est une garantie **conditionnelle**.
- Une clé publique Ed25519 brute est unique dans le registre. Une clé révoquée
  reste interdite à la réaffectation. La rotation ajoute une nouvelle clé au
  même citoyen. La révocation du citoyen est définitive dans cette version,
  désactive toutes ses clés et rend l'anonymat indisponible.
- L'anonymat est **refusé par défaut**. Les transitions `denied`, `allowed`,
  `suspended` sont explicites et n'affectent pas l'accès identifié tant que
  le citoyen demeure actif. Aucun client du registre ne reçoit implicitement
  la permission de créer des justificatifs anonymes.
- Le `ServiceBanLedger` est une **autre** base, qui contient uniquement
  `(service_id, nullifier)` ; ni identité civile, ni identifiant citoyen, ni
  clé SSH. Le bannissement d'un service n'est pas une révocation nationale.
- Les fichiers SQLite doivent résider dans un répertoire privé, appartenant
  au processus, sans permission pour les autres (`0700`). La création des
  bases est `0600` ; les bases existantes non privées et les liens symboliques
  sont refusés. Le dossier ne doit pas être accessible à un processus non
  autorisé : les commandes d'administration sont une frontière de sécurité.

## Objectif anti-Sybil : bannir la personne, pas un pseudonyme renouvelable

Deux niveaux distincts :

1. **Révocation nationale ou suspension du droit anonyme** : associée à
   l'identité citoyenne unique ; l'autorité est responsable de la décision.
   Un nouveau compte, une nouvelle clé SSH ou un renouvellement de titre ne
   crée pas une nouvelle identité citoyenne.
2. **Bannissement sur un service** : le service conserve un nullifier *stable
   par citoyen et par service*, mais différent entre services. Une future
   preuve cryptographique devra imposer sa dérivation authentifiée, non
   choisie librement, du secret citoyen et de l'identifiant du service. La
   rotation d'une clé ou la réémission d'un justificatif ne doit PAS le changer.

Le second point n'est **pas encore garanti** par le code : `ServiceBanLedger`
stocke les décisions, mais NE vérifie pas la provenance des nullifiers. Ne
jamais accepter la valeur envoyée librement par un utilisateur comme preuve
d'identité. Un utilisateur peut aujourd'hui choisir une autre valeur si une
application lui expose directement cette fonction.

Les nullifiers stables permettent aussi au service de suivre les usages. Ils
sont donc réservés aux opérations nécessitant unicité ou bannissement (compte,
publication, droits limités), **pas** aux simples lectures anonymes. Le
périmètre `service_id` doit être authentifié, canonique et approuvé par le
service ; le validateur de preuve ne doit pas laisser le client le choisir.
Un nullifier n'empêche pas les requêtes automatisées d'un même citoyen : les
services doivent gérer leurs propres quotas et limites d'usage.

## Suite cryptographique nécessaire avant l'intégration au transport

- Enregistrement juridiquement vérifié, contrôle d'unicité de la personne,
  attestations signées des autorités habilitées et authentification de leurs
  opérations d'administration. Gestion des contestations et des erreurs.
- Preuve de possession de la clé au moment de l'enregistrement ou rotation,
  journal d'audit de l'autorité et sauvegarde du registre. `CitizenRegistry`
  est une bibliothèque de stockage, pas un serveur protégé par ACL.
- Justificatif anonyme réellement **non corrélable** entre services,
  preuve d'appartenance et d'autorisation `allowed`, preuve de révocation
  fraîche, et dérivation de nullifier authentifiée et stable par service.
  Vérification locale possible sans notification nominative de l'autorité à
  chaque connexion. Des justificatifs déjà émis ne doivent pas contourner
  une suspension ou une révocation : définir des époques, une limite d'âge
  des preuves et des données de révocation adaptées.
- Publication anonyme attribuable uniquement sous ouverture autorisée :
  mécanisme cryptographique ouvrable à seuil, séparation des responsabilités,
  contrôles juridictionnels et audit. Le lien doit couvrir l'acte signé et
  non seulement l'ouverture de session. Ce n'est pas requis pour une simple
  lecture privée et ne s'applique pas au secret du vote.
- Réduction des métadonnées de transport comme chantier indépendant, optionnel
  selon l'application. L'enregistrement SSH actuel expose encore une clé
  permanente au correspondant et n'apporte **aucun anonymat**.

## Exécuter les tests

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure
```

`maat-citizen-registry-tests` vérifie notamment : inscription unique, refus
sans autorisation explicite, suspension et reprise, rotation/révocation des
clés, impossibilité de réinscrire un citoyen révoqué, séparation des bans par
service, persistance après réouverture et rejet des bases non privées.
La suite intégrale 0.20-alpha1 n'a pas encore été rejouée en Docker ou QEMU.
