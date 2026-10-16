# Maât 0.20.0-alpha4 — Scope-free issuance (préparation BBS)

## Ce qui est réellement obtenu

`ScopeFreeCredentialIssuer` délivre **un justificatif indépendant du
service**. Sa requête signée contient une clé citoyenne active, un engagement
stable de secret de pseudonyme, un défi à usage unique et l'ID du registre.
Elle ne contient **ni nom de service ni identifiant de destination**.
L'émetteur voit **toujours** le citoyen demandeur et l'engagement stable,
mais ne reçoit pas la destination dans ce protocole. Les métadonnées réseau
ou d'autres canaux externes peuvent toutefois révéler une destination.

Le registre privé mémorise une association `citizen_id → nym_commitment` :
une seule association par citoyen et un engagement ne peut être associé à
deux citoyens. Elle ne peut pas être remplacée via le renouvellement d'une
clé SSH/Ed25519. Les réémissions conservent le même engagement, avec un
numéro de série et une signature propres à chaque émission.

Seuls les citoyens actifs, avec clé enregistrée non révoquée et permission
d'anonymat `allowed`, peuvent recevoir un nouveau justificatif. Le refus,
la suspension et la révocation bloquent l'émission. Chaque défi est aléatoire,
valide 60 secondes et consommé avant toute vérification de signature ; la
signature du citoyen couvre tous les champs et le namespace du registre.
L'émetteur utilise une clé Ed25519 distincte de celle de l'administration
et de celle de l'ancien émetteur `ScopedCredentialIssuer`. Son identité est
épinglée au premier `bootstrap`. Les justificatifs sont limités à 300 s.

## Ce qui n'est PAS réalisé : confidentialité des présentations

**ATTENTION : ne jamais transmettre un `ScopeFreeCredential` à un service.**
Il contient `nymCommitment` en clair. Cet engagement étant stable,
plusieurs sites pourraient corréler toutes ses présentations.
Le justificatif est seulement un objet PRIVÉ destiné à devenir le témoin
d'une future preuve à divulgation nulle de connaissance. Aucun vérificateur
anonyme n'est implémenté et rien dans SSH, le broker, Apache, PHP ou `$_AUTH`
ne l'accepte. `identity_verified=false` reste obligatoire.

L'utilitaire local `unverifiedLocalScopeNullifier()` montre la stabilité
`secret+registre+service` avec HMAC-SHA256. Sa sortie est **non vérifiée** :
un attaquant pourrait choisir d'autres secrets ou sorties si un service
l'acceptait telle quelle. Aucun service ne doit lui faire confiance. La
représentation SHA-256 de l'engagement est **provisoire**, non une
construction BBS approuvée ; une migration de l'engagement pourra être
nécessaire. C'est un jalon de gouvernance et de stockage, pas la preuve
cryptographique finale qui rend les bannissements incontournables.

Une émission existante survit jusqu'à 300 s à une suspension ou révocation.
L'émetteur connaît les engagements stables et peut lier ses propres
émissions ; l'absence de service dans une requête ne donne pas à elle seule
l'intraçabilité. Il manque : émission aveugle sur un secret correctement
engagé, preuve ZK de possession de signature, pseudonyme déterministe lié
au même secret et au contexte de service, preuve de non-révocation,
politique de rotation, vérification d'unicité civile et ouverture judiciaire
sous contrôle multipartite.

## Protocole cryptographique candidat (ne PAS réimplémenter au hasard)

Le candidat recommandé est BBS avec pseudonymes par vérificateur :

- `draft-irtf-cfrg-bbs-signatures-13`, daté du 13 octobre 2026 ;
- `draft-irtf-cfrg-bbs-blind-signatures-03`, juin 2026 ;
- `draft-irtf-cfrg-bbs-per-verifier-linkability-03`, juin 2026.

Ces documents sont des **Internet-Drafts actifs**, pas des RFC finalisés.
Ils décrivent justement la présentation ZK de signatures BBS avec un
pseudonyme stable dans le contexte d'un vérificateur, différent pour les
autres vérificateurs. Le `nym_secret` doit rester inconnu des services et
être attribué de manière unique par citoyen, avec continuité lors des
renouvellements. Le mécanisme de blinded issuance et la relation entre
secret sous engagement et preuve de pseudonyme devront être repris de ces
spécifications, avec une implémentation externe revue et des vecteurs de
tests publics. Un hash SHA-256 d'un secret est insuffisant, à lui seul,
pour établir cette relation à un vérificateur.

Références :
- https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/
- https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-blind-signatures/
- https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-per-verifier-linkability/

## Tests et exploitation

`tests/privacy_bootstrap_test.cpp` couvre : refus par défaut ; opération
signée par l'autorité ; défis uniques et signatures falsifiées ; unicité
de l'engagement par citoyen ; impossibilité de partager l'engagement entre
citoyens ; rotation de clé et redémarrage conservant l'engagement ; suspension
et révocation ; refus du recyclage des clés d'administration ; domaines et
scopes des *candidats* locaux de nullifier ; vérification indépendante de
la signature de l'émetteur. Aucun de ces tests n'est un test ZK/BBS.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
ctest --test-dir build --output-on-failure
sudo ./tests/docker/run-e2e.sh
./tests/qemu/run-e2e.sh ./ubuntu-22.04-server-cloudimg-amd64.img
```

La bibliothèque est accessible uniquement à un processus d'émission PRIVÉ.
Les mécanismes de protection contre la réinitialisation/rollback de SQLite,
la perte/compromission du seed de l'émetteur, le HSM et les procédures
administratives restent à construire. **Prototype de recherche, aucun
usage Internet réel autorisé.**
