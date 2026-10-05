# L7 — Note de risques : l'IA dans la chaîne DFIR (BROUILLON)

*Brouillon du 03/10/2026 (phase P8 avancée en P7), rédigé par l'agent de développement à partir
du journal des constats (CLAUDE.md §11) tenu depuis le 29/09. Chaque risque est illustré par un
cas **réellement observé** dans ce projet. Les résultats de l'évaluation (L6) ne sont pas encore
disponibles : les passages qui en dépendent sont marqués **À COMPLÉTER APRÈS L6**. L'appréciation
de la gravité est laissée à l'équipe.*

## 1. Objet et méthode

L'assistant est intégré à l'investigation pour gagner du temps **sans perdre en fiabilité ni en
traçabilité** (CDC §1). Cette note recense les risques propres à l'usage d'un LLM dans cette
chaîne, et ceux qu'introduit l'outillage construit autour. Pour chacun :

- **Risque** : ce qui peut mal tourner ;
- **Observé** : le cas rencontré pendant le projet (date, contexte) ;
- **Parade** : ce qui est en place dans `forensic-mcp`, la skill ou l'organisation ;
- **Résiduel** : ce qui reste, et qui doit être connu de l'analyste.

Principe directeur retenu : **le serveur calcule les faits, le LLM converse**. Le LLM ne compte
pas, ne décode pas, ne convertit pas d'heure, n'invente pas d'identifiant : il cite des valeurs
que le serveur recontrôle, et un analyste nommé décide.

## 2. Absences prises pour des preuves

**Risque.** « Aucun événement trouvé » est lu comme « il ne s'est rien passé ». En forensique,
une absence peut venir d'un journal non collecté, d'une politique d'audit désactivée, d'un
journal écrasé, ou d'un outil qui a échoué sans le dire.

**Observé.**
- 4.3 (02/10) : `bstrings` sous Linux sortait avec le code 0 sans rien produire ; « 0 ligne »
  aurait été lu comme « chaîne absente ». Cause réelle : l'outil lisait l'entrée standard au lieu
  du fichier.
- 4.3 : une requête EVTX filtrée à la source ne voyait pas quels journaux le fichier contenait :
  un preset vide a d'abord été rapporté « journal Security ABSENT » alors qu'il était présent.
- 4.3b : SQLECmd a planté en laissant un fichier JSON vide : le contrôle « pas de sortie = échec »
  ne l'a pas vu.
- Les outils Eric Zimmerman sortent tous avec le code 0, y compris en cas de plantage.
- 5.2 : une absence ne pouvait pas être enregistrée comme constat (pas de ligne à citer).

**Parade.**
- Sortie vide ou marqueurs de plantage ⇒ `tool_error` journalisé et note « zéro ligne ne veut pas
  dire absent ».
- Preset EVTX vide ⇒ réponse recalculée sur l'analyse complète, avec une note par événement :
  journal présent ou absent de la collecte, politique d'audit requise.
- Constat `observation` (5.3) : absence **vérifiée par le serveur** dans un résultat cité ;
  refusée si l'outil a échoué ; phrase rédigée par le serveur, notes recopiées dans le rapport.
- Lab : `lab/prepare_victim.ps1` active la journalisation nécessaire **avant** le scénario et
  `lab/check_logging.ps1` la vérifie.

**Résiduel.** Le serveur ne peut affirmer que « pas de trace dans cet artefact ». Le texte libre
du LLM peut encore surinterpréter (« pas de persistance ») : le rapport montre la phrase du
serveur à côté et l'analyste valide. D'autres outils peuvent échouer silencieusement d'une
manière non détectée.

## 3. Hallucinations et citations

**Risque.** Le LLM affirme un PID, une adresse, une heure ou une technique ATT&CK qui ne figure
pas dans les preuves, ou cite une mauvaise ligne.

**Observé.**
- Adresses 64 bits arrondies par les clients JSON (18446738026487331344 → …330000) : citation
  d'un mauvais offset possible (4.2).
- 5.2 : la propre documentation de la skill citait des numéros de ligne inventés et le mauvais
  outil dans son exemple : la doc enseignait l'erreur qu'elle devait prévenir.
- Les tables d'ATT&CK évoluent : un identifiant « inventé » d'un test (T1003.001) est devenu
  légitime quand l'arbre de triage l'a ajouté (5.1).

**Parade.**
- Entiers > 2^53 en hexadécimal.
- `record_finding` recontrôle chaque valeur dans la ligne brute (exacte, numérique, même
  instant UTC, extrait d'une cellule longue, texte décodé par le serveur) ; sans citation,
  valeur absente, ligne ou résultat inexistant, ATT&CK non fourni par le serveur ⇒ rejet motivé.
- Identifiants ATT&CK limités aux tables du serveur ; tests qui lient la documentation au code.
- Mesure : les rejets sont comptés comme hallucinations par `eval/score.py`.

**Résiduel.** La contre-vérification prouve que la valeur est dans la ligne, pas que
l'interprétation est juste. Un extrait n'est accepté que dans une cellule d'au moins
64 caractères. Taux réels : **À COMPLÉTER APRÈS L6**.

## 4. Validation humaine et excès de confiance

**Risque.** Les suggestions du LLM deviennent des conclusions sans relecture ; ou le LLM valide
lui-même ; ou l'analyste fait confiance à une anomalie présentée avec assurance.

**Observé.**
- 4.2 : faux positifs de la table de règles sur l'échantillon réel (`iexplore.exe` pris pour
  une imitation d'`explorer.exe`, un chemin `\??\` jugé anormal) : une anomalie est une piste,
  jamais un constat.
- 4.4 : trois constats de test (F-0001 à F-0003) ont été écrits dans le **vrai** journal du
  cas ; le journal étant en ajout seul, ils ne peuvent pas être effacés : un analyste doit les
  rejeter.
- Validation : la première version de l'outil de validation ne permettait pas de motiver le
  rejet des constats déjà rejetés par le serveur.

**Parade.**
- Aucun outil MCP ne peut valider : la validation se fait **hors bande**
  (`python -m forensic_mcp validate`, terminal interactif requis), nominative et motivée,
  chaînée dans le journal ; rien n'est supprimé.
- Rapport final refusé tant qu'un constat est « à valider » ou « à revoir » ; le brouillon les
  marque NON VALIDÉ ; le sitrep n'affirme que des constats validés.
- Plugins sensibles (identifiants, extractions) : confirmation nommée de l'analyste.

**Résiduel.** Le contrôle « terminal interactif » est un ralentisseur, pas une barrière : un
client avec shell peut ouvrir un pseudo-terminal. Le nom de l'analyste est saisi, pas
authentifié. La qualité de la relecture humaine n'est pas mesurable par l'outil : coût et
qualité de la validation **À COMPLÉTER APRÈS L6**.

## 5. Contournement des garde-fous par le client

**Risque.** Les garde-fous sont dans le serveur ; un client qui a un shell peut tout faire sans
lui : analyser une preuve directement, lire les secrets, modifier le journal, lancer la
validation.

**Observé.** 30/09 (séance CTF) : la preuve étant hors de la racine du serveur, l'assistant a
installé Volatility 3 en local et analysé le dump avec des scripts : réponses justes, mais **ni
journal, ni empreinte, ni résultat citable**. Le 29/09, des extractions d'identifiants avaient
été faites par l'outil générique de l'époque, sans confirmation ni journal.

**Parade.**
- Décision 3 : pas de shell pour le client d'analyse ; modèle
  `templates/analysis-workspace/.claude/settings.json` (Bash, PowerShell, écriture, lecture des
  preuves et des secrets refusés ; seuls les outils `forensic` autorisés).
- Message explicite du serveur : placer la preuve sous la racine plutôt que contourner.
- Journal chaîné ; hash de tête à conserver hors du poste.

**Résiduel.** Ces règles sont appliquées par le client : un analyste peut les retirer ou
utiliser un autre client. Un journal chaîné est **inviolable en apparence, pas inaltérable** :
quiconque peut écrire `/output` peut réécrire toute la chaîne ; seule une copie du hash de tête
hors du poste le révèle.

## 6. Injection de consignes (prompt injection)

**Risque.** Un artefact (ligne de commande, nom de fichier, événement) contient des consignes
que le LLM suit ; ou une option libre transmise à un outil devient une exécution de code.

**Observé.**
- Volatility 2 accepte `--plugins=<dossier>` (charge du code Python) et `-w` (écriture) : une
  option libre suffirait à exécuter du code via une injection (4.2).
- La première liste d'interdits bloquait `--dump-dir` mais pas sa forme courte `-D`.
- Un motif de chemin de registre acceptait un `-` initial : la clé « --sync » serait devenue
  une option (4.3b).

**Parade.**
- Contenu d'artefact toujours rendu entre marqueurs `EVIDENCE DATA` (« < » échappé), jamais
  interprété par le serveur ; consigne explicite dans la skill.
- Aucun argument libre : paramètres typés, listes d'options autorisées par outil ; aucune chaîne
  commençant par `-` ne peut atteindre une ligne de commande.
- Aucun outil d'action sur l'infrastructure ; confinement uniquement proposé.

**Résiduel.** Les marqueurs réduisent le risque sans l'annuler : un LLM peut encore être
influencé par le contenu. La surface d'attaque des analyseurs eux-mêmes (Volatility 2, code
Python 2 non maintenu ; sleuthkit) face à une image hostile reste entière.

## 7. Preuves importées de Windows

**Risque.** Une partie des artefacts est analysée hors du conteneur durci, sur le poste Windows
de l'analyste ; le serveur doit faire confiance à ce qu'on lui rapporte.

**Observé.** 02/10 : 5 des 17 outils Eric Zimmerman ne fonctionnent pas sous Linux (PECmd,
SrumECmd, SumECmd refusent la plateforme ; SQLECmd et WxTCmd plantent faute de bibliothèque
native). Prefetch, SRUM, historique de navigation n'étaient donc pas disponibles dans le
conteneur. Pièges PowerShell 5.1 rencontrés en écrivant l'export (code de sortie nul non lu,
propriétés absentes sous mode strict).

**Parade.** Option A (décision du 02/10) : `scripts/run_ez_windows.ps1` exécute l'outil sur
Windows avec des options typées et écrit un manifeste (empreinte de l'exécutable, signature
Authenticode, empreinte des entrées et des sorties) ; `ez_import` vérifie les empreintes de
sortie et l'empreinte de l'entrée encore présente sous `/evidence`, et journalise l'import.

**Résiduel.** Le serveur ne peut pas prouver quel binaire a réellement tourné : quelqu'un qui
peut écrire le dossier d'export peut fabriquer un manifeste cohérent. Écart assumé à
l'architecture « tout dans le conteneur » (ET-08).

## 8. Modèle local

**Risque.** Le modèle local (choisi pour les données classées « client ») est moins fiable dans
un usage outillé lourd.

**Observé.**
- Modèles locaux de 20 à 30 milliards de paramètres dans un environnement d'agent : noms
  d'outils inventés, boucles, perte de contexte.
- Le prompt complet de la skill faisait 24 400 caractères (≈ 6 à 7 k jetons) : risque de
  troncature par un petit contexte.
- `llm_mode` est **déclaré** par la configuration du serveur, pas détecté : un client cloud
  connecté à un serveur réglé « local » recevrait des données « client ».

**Parade.**
- Prompt par défaut réduit à SKILL.md (5 442 caractères), références à la demande (sections et
  ressources MCP) (5.3).
- Les mêmes garde-fous serveur s'appliquent aux deux modes (contre-vérification, validation,
  journal).
- Fiche d'essai comparant les deux modes (`docs/essais_skill.md`).

**Résiduel.** Écart de qualité entre modes : **À COMPLÉTER APRÈS L6**. Choix du transport par
défaut et de `llm_mode` par transport : points ouverts de L2 §12.

## 9. Confidentialité et secrets

**Risque.** Données d'enquête ou secrets envoyés au fournisseur du modèle (cloud).

**Observé.**
- Un secret (`WEBUI_SECRET_KEY`) s'est affiché dans le contexte de l'agent de développement
  quand il a modifié `.env` : l'exposition existe aussi pendant le développement.
- Les échantillons EVTX « de dev » sont les vrais journaux d'un poste d'analyste (SID, comptes,
  un effacement de journal) : données personnelles réelles.
- Python considère la plage de documentation 203.0.113.0/24 comme privée : une adresse de C2 de
  test a d'abord été pseudonymisée comme interne.
- Le base64 d'une commande PowerShell encodée contient l'adresse réelle même en mode cloud (le
  texte décodé est pseudonymisé, l'argument brut ne l'est pas).
- `.env` n'était pas exclu du contexte de construction Docker (corrigé le 03/10).

**Parade.**
- Classification par cas (`case.toml`) : « client » refusé en mode cloud ; « internal » + cloud
  ⇒ pseudonymisation stable (HOST_n, USER_n, IP_EXT_n / IP_INT_n), correspondance gardée côté
  serveur.
- Règle 11 (jamais de secret dans la conversation, contrôle par longueur ou empreinte) ; jeton
  en fichier 0600 ; `.env` et `.secrets/` exclus du contexte Docker ; lecture des secrets
  refusée dans l'espace d'analyse.

**Résiduel.** Pseudonymisation limitée aux colonnes d'hôte et d'utilisateur et aux noms
déclarés ; IPv6, messages d'erreur et blobs encodés non couverts. Rotation du secret exposé :
**À VÉRIFIER** par l'équipe.

## 10. Traçabilité et intégrité de la preuve

**Risque.** Une analyse impossible à rejouer ou à prouver ; une preuve modifiée sans le savoir.

**Observé.**
- 2.1 (30/09) : un journal chaîné existait et était testé, mais **aucun appel n'y écrivait**
  (0 % tracé). « Le journal existe » ≠ « les appels sont journalisés ».
- Les appels rejetés par la validation de schéma du SDK n'atteignent pas le serveur et ne sont
  pas journalisés : « 100 % » veut dire 100 % des appels qui atteignent le serveur.
- Un cache de hachage par fichier n'est pas une vérification avant/après.
- Les fichiers extraits d'une image sont en lecture seule, mais leur dossier reste modifiable.

**Parade.** Journal en ajout seul, chaîné, verrouillé ; chaque appel journalisé (paramètres,
commande, version, empreinte de preuve, empreinte de sortie, nombre de lignes, notes) ;
`replay` ; empreinte complète à l'enregistrement, contrôle rapide avant chaque appel, re-hachage
à l'export final et par `scripts/register_evidence.py --after` ; manifestes en lecture seule.

**Résiduel.** Voir §5 (journal falsifiable par qui écrit `/output`) ; altération des extraits
détectée, pas empêchée.

## 11. Chaîne d'approvisionnement et fiabilité des outils

**Risque.** Un outil change ou est compromis sans que l'équipe le sache ; un outil donne un
résultat faux.

**Observé.**
- Versions Debian : la version affichée par packages.debian.org n'est pas celle du binaire
  amd64 (« +b1 ») ; la première construction épinglée a échoué, et l'agent avait conclu à tort
  qu'elle avait réussi (code de sortie de `tail`).
- Les URL de téléchargement des outils Eric Zimmerman ne sont pas versionnées.
- Un relancement de l'outil de vérification sans le bon chemin a marqué Volatility 3 en échec
  et réécrit la configuration.
- Un cache d'analyse a survécu à un changement de format (CSV → JSON) et mélangé les deux.

**Parade.** Durcissement du 03/10 : image de base par digest, paquets Python par version,
runtime .NET par version, sleuthkit/ewf-tools par version, empreinte SHA-256 de chaque
téléchargement (une nouvelle version fait échouer la construction), Open WebUI par digest ;
clé de cache versionnée ; contrôles de construction sur le statut réel.

**Résiduel.** Empreintes des outils EZ en confiance au premier usage ; paquets Python épinglés
sans empreinte ; paquets système de base non épinglés ; surface d'attaque des analyseurs (§6).

## 12. Synthèse

| Risque | Parade principale | Résiduel principal |
|---|---|---|
| Absences prises pour des preuves | notes serveur, `observation` vérifiée, journalisation du lab | surinterprétation du texte libre |
| Hallucinations | contre-vérification de chaque valeur citée | interprétation non vérifiable |
| Validation / excès de confiance | validation hors bande, rapport final bloqué | TTY contournable, nom non authentifié |
| Message envoyé ou décidé à la place de l'humain (coordination, EF-15) | le serveur n'envoie rien : `stakeholder_suggest` propose « à valider », `comms_log` consigne une communication déjà faite sans changer le statut, aucun outil vers l'extérieur (testé) | le texte libre saisi par le LLM (nom, note) n'est pas vérifié ; un statut « prévenu » reste une déclaration |
| Contournement par le client | pas de shell (décision 3), journal chaîné | règles côté client, journal réécrivable |
| Injection de consignes | marqueurs, paramètres typés, pas d'outil d'action | influence résiduelle, analyseurs exposés |
| Preuves importées de Windows | manifeste, empreintes, import journalisé | binaire réellement exécuté non prouvable |
| Modèle local | prompt réduit, mêmes garde-fous | écart de qualité (**À COMPLÉTER APRÈS L6**) |
| Confidentialité / secrets | classification, pseudonymisation, règle 11 | couverture partielle de la pseudonymisation |
| Traçabilité / preuve | journal chaîné, hachage avant/après | dépend d'une copie du hash hors poste |
| Chaîne d'approvisionnement | épinglage et empreintes | confiance au premier usage |

**À COMPLÉTER APRÈS L6** : risques observés pendant les sessions chronométrées, en particulier
les écarts entre les modes cloud et local.
