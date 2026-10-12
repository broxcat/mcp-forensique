# forensic-mcp — serveur MCP forensique (Majeure Blue Team)

Serveur [MCP](https://modelcontextprotocol.io) qui met les outils DFIR à disposition d'un
assistant IA **sans perte de fiabilité ni de traçabilité** : Volatility 3 et 2 (mémoire), outils
Eric Zimmerman (EVTX, $MFT, registre, artefacts Windows), The Sleuth Kit (images disque), un
assistant de crise et un tableau de coordination des parties prenantes. Le serveur calcule les
faits (nombre de lignes, anomalies et identifiants ATT&CK, commandes décodées, IOC,
chronologie) ; l'IA converse, cite ses sources, et chaque affirmation est revérifiée avant
d'entrer au rapport. Référence : cahier des charges du 26/09/2026 (L. Plancke, W. Triffault) ;
conception : [`docs/L2_architecture.md`](docs/L2_architecture.md) ; conformité exigence par
exigence : [`docs/compliance.md`](docs/compliance.md) ; risques :
[`docs/L7_note_risques.md`](docs/L7_note_risques.md).

## 1. Architecture en bref

- Poste analyste **Windows** + **un conteneur Linux** (Docker Desktop) qui exécute le serveur et
  les outils : Debian, Python 3.12, `mcp==2.2.0`, Volatility 3 (2.28.2) et 2 (2.6), .NET 9 et
  17 outils Eric Zimmerman, sleuthkit + ewf-tools.
- Preuves montées **en lecture seule** (`/evidence`), résultats et journal dans `/output`
  (visibles sous Windows, ouvrables dans Timeline Explorer).
- Utilisateur non privilégié, toutes les capacités Linux supprimées, aucun montage possible.
- Transport de référence **stdio** ; transport **HTTP** sur `127.0.0.1:8000` (jeton), écart au
  cahier des charges documenté (L2 §6), réservé à Open WebUI pour le modèle local.

## 2. Installation

Prérequis : Windows 10/11, Docker Desktop démarré, Git.

```powershell
git clone git@github.com:broxcat/mcp-forensique.git
cd mcp-forensique
Copy-Item .env.example .env      # puis éditer .env (voir ci-dessous)
docker compose up -d --build     # premier build long : .NET 9, outils EZ, Volatility 2
docker compose exec forensic python scripts/check_tools_18.py --vol3 /opt/venv/bin/vol
docker compose exec forensic pytest -q
```

Fichier `.env` (jamais commité, ne contient aucun secret à partager ; modèle :
[`.env.example`](.env.example)) :

| Variable | Rôle |
|---|---|
| `COMPOSE_PROJECT_NAME` | `forensic-mcp` : nom du projet Compose, fixé pour ne pas dépendre du nom du dossier (voir §3) |
| `EVIDENCE_DIR` | Dossier Windows des preuves, monté en lecture seule sur `/evidence` (barres obliques `/`, par exemple `C:/cases/evidence`) |
| `OUTPUT_DIR` | Dossier Windows des résultats et du journal (`/output`) |
| `WEBUI_SECRET_KEY` | Secret de session d'Open WebUI (32 caractères aléatoires ou plus), à générer soi-même |
| `OLLAMA_BASE_URL` | Optionnel : URL d'Ollama vue depuis le conteneur Open WebUI |

Le jeton HTTP n'est pas dans `.env` : il est créé au premier démarrage dans `.secrets/api_token`
(ignoré par Git). Ne copiez jamais `.env`, `.secrets/` ni un jeton dans une conversation avec un
modèle.

Organisation conseillée des preuves : `evidence/<HÔTE>/memory/`, `evidence/<HÔTE>/kape/` et un
`case.toml` par hôte :

```toml
case = "WS-042"
classification = "lab"      # lab | internal | client
hosts = ["WS-042"]          # noms toujours pseudonymisés en mode cloud
users = ["alice"]
```

Configuration du serveur : [`forensic-mcp.docker.toml`](forensic-mcp.docker.toml) (bornes de
réponse, délai maximal, classification par défaut `internal`, `llm_mode = "local"` par défaut).
Après une modification du code ou de la configuration : `docker compose restart forensic` (pas de
rechargement automatique).

## 3. Un seul dossier de déploiement

**Le conteneur doit tourner depuis le dépôt à jour, et depuis lui seul.** Le nom du conteneur
est fixe (`forensic-mcp`) : un `docker compose up` lancé depuis un autre clone le recrée sur
l'ancien code, avec d'autres dossiers de preuves et de résultats, sans message d'erreur si les
deux clones ont le même nom de projet Compose. C'est arrivé pendant le projet (`CLAUDE.md` §11,
« Two clones ») : une session d'analyse a tourné sans les garde-fous ajoutés depuis.

- Mettre `COMPOSE_PROJECT_NAME=forensic-mcp` dans `.env` de ce dépôt et ne lancer
  `docker compose` que d'ici. Fait le 12/10 : l'ancien conteneur (créé depuis l'autre clone,
  24 outils) a été supprimé et recréé d'ici. *Non vérifié* : ce que fait un `docker compose up`
  lancé depuis un second clone avec ce réglage (non essayé) ; le nom de conteneur étant fixe,
  un second clone ne peut de toute façon pas tourner en même temps.
- Les deux volumes (cache des symboles Volatility, données d'Open WebUI) ont un nom fixe dans
  `docker-compose.yml` (`scp-forensique_vol3-cache`, `scp-forensique_open-webui`) : ils
  survivent à un changement de nom de projet. Compose affiche alors un avertissement
  « already exists but was created for project … », sans conséquence.
- Vérifier ce qui tourne, avant chaque session :

```powershell
# dossiers montés : la source de /app doit être CE dépôt
docker inspect forensic-mcp --format "{{range .Mounts}}{{.Source}} -> {{.Destination}}{{println}}{{end}}"
```

  puis demander `tool_status` à l'assistant : le résumé donne le **nombre d'outils MCP** (51
  pour cette version), le **commit du code chargé au démarrage du serveur** et l'heure de
  démarrage. Le commit doit être celui de `git rev-parse --short=12 HEAD` dans ce dépôt ; les
  modifications non commitées ne sont pas détectées.

## 4. Clients et modes LLM

**Claude Code, stdio (référence).** Utiliser le dossier d'analyse modèle
[`templates/analysis-workspace/`](templates/analysis-workspace/LISEZMOI.md), séparé du dépôt :
son `.mcp.json` lance `docker exec -i forensic-mcp python -m forensic_mcp --stdio` et son
`.claude/settings.json` n'autorise que les outils `mcp__forensic__*` et refuse `Bash`,
`PowerShell`, `Edit`, `Write`, `WebFetch`, `WebSearch` et la lecture directe des preuves, des
résultats et des secrets. Sans shell, l'assistant ne peut ni analyser une preuve hors du serveur
ni lancer la validation. Ces règles sont appliquées par le client, pas par le serveur.
Ajout manuel équivalent :

```powershell
claude mcp add forensic -- docker exec -i forensic-mcp python -m forensic_mcp --stdio
```

**Open WebUI, HTTP avec jeton (écart documenté, L2 §6).** `http://localhost:3000` ; serveur MCP
à déclarer avec l'URL interne `http://forensic:8000/mcp` et l'en-tête
`Authorization: Bearer <jeton>` (contenu de `.secrets/api_token`). `GET /health` est public,
tout le reste exige le jeton (`/mcp` sans jeton : 401). *Non vérifié* : l'enregistrement du
serveur dans Open WebUI et les confirmations d'actions sensibles depuis ce client.

**Modes LLM** (`llm_mode` dans `forensic-mcp.docker.toml`) :

| Mode | Usage | Effet |
|---|---|---|
| `local` | modèle Ollama, via Open WebUI | sorties brutes |
| `cloud` | modèle hébergé par un tiers (Claude) | cas `lab` : brut ; `internal` : pseudonymisation stable (`HOST_n`, `USER_n`, `IP_EXT_n`, `IP_INT_n`, `PERSON_n`, `CONTACT_n`), correspondance gardée côté serveur ; `client` : refusé |

Le mode est **déclaré** dans la configuration, pas détecté : un client cloud connecté à un
serveur réglé sur `local` reçoit des données brutes.

## 5. Outils disponibles

Tableaux générés à partir du serveur (`tools/list`, `prompts/list`, `resources/list` demandés
par un client MCP en mémoire) et de [`docs/tool_catalog.yaml`](docs/tool_catalog.yaml) pour la
catégorie, le rôle en français et les événements de journal. Pour les régénérer après un
changement d'outil : `docker compose exec forensic python scripts/tool_inventory.py --write`.
Un test échoue si ce bloc ne correspond plus au serveur.

Classes : **lecture seule** (aucun effet) ; **écrit au journal** (ajoute un événement ou un
fichier de résultat, rien sur les preuves ni l'infrastructure) ; **sensible** (lecture par
défaut ; identifiants, extractions et `dump` ne s'exécutent qu'après confirmation d'un analyste
nommé dans le client MCP, sinon refus journalisé).

<!-- tools:begin (généré par scripts/tool_inventory.py --write, ne pas éditer) -->
**51 outils**, 1 prompt, 6 ressources (liste demandée au serveur). `*` = paramètre obligatoire. Chaque appel qui atteint le serveur, réussi, refusé ou en échec, écrit un `tool_call` au journal ; la colonne « Journal » donne ce qui s'y ajoute.

### Socle

État du serveur, preuves, résultats, rejeu. Une preuve non encore enregistrée est hachée (SHA-256 complet) et journalisée `evidence_registered` au premier appel d'un outil d'analyse.

| Outil | Rôle | Paramètres | Classe | Journal (en plus de `tool_call`) |
|---|---|---|---|---|
| `tool_status` | Moteurs installés et versions ; nombre d'outils MCP, commit du code chargé au démarrage, heure de démarrage, mode LLM | — ; pagination `limit`, `offset` | lecture seule | — |
| `list_evidence` | Fichiers sous la racine des preuves : taille, état d'enregistrement, SHA-256, cas et classification | `subdir` (texte) ; pagination `limit`, `offset` | lecture seule | — |
| `register_evidence` | Hache une preuve (SHA-256 complet) avant analyse | `path*` (texte) | écrit au journal | `evidence_registered` |
| `verify_evidence` | Recalcule l'empreinte d'une preuve enregistrée et la compare (contrôle « après ») | `path*` (texte) | écrit au journal | `evidence_verified` |
| `query_results` | Filtre, trie ou pagine les lignes d'un résultat précédent | `result_id*` (texte), `contains` (texte), `column` (texte), `equals` (texte), `regex` (texte), `columns` (liste de texte), `sort_by` (texte), `sort_desc` (booléen) ; pagination `limit`, `offset` | lecture seule | — |
| `list_results` | Résultats déjà produits : outil, plugin, entrée, code de sortie, nombre de lignes | — ; pagination `limit`, `offset` | lecture seule | — |
| `replay` | Rejoue un appel mémoire ou EZ journalisé et compare l'empreinte de la sortie | `audit_id*` (entier) | sensible : confirmation d'un analyste nommé | `action_request` / `action_confirmed` si l'appel rejoué est sensible |

### Volatility 3 (mémoire)

Image mémoire Windows sous la racine des preuves. Les anomalies (règles, ATT&CK), le décodage PowerShell et les IOC sont calculés par le serveur. Volatility 3 ne lit pas les images Windows XP / 2003 : ces outils le disent et renvoient vers `vol2_run`. `mem_extract_vad` fonctionne avec les deux moteurs.

| Outil | Rôle | Paramètres | Classe | Journal (en plus de `tool_call`) |
|---|---|---|---|---|
| `vol_list_plugins` | Plugins Volatility 3 installés (plugins sensibles signalés) | `contains` (texte) ; pagination `limit`, `offset` | lecture seule | — |
| `vol_pslist` | Processus (windows.pslist) et règles de détection | `path*` (texte), `pid` (entier) | lecture seule | — |
| `vol_pstree` | Arborescence des processus (windows.pstree) | `path*` (texte), `pid` (entier) | lecture seule | — |
| `vol_cmdline` | Lignes de commande ; PowerShell encodé décodé par le serveur | `path*` (texte), `pid` (entier) | lecture seule | — |
| `vol_netscan` | Connexions réseau (windows.netscan), correspondance avec les IOC | `path*` (texte), `pid` (entier) | lecture seule | — |
| `vol_malfind` | Régions de code injecté ; `dump=true` extrait les régions après confirmation | `path*` (texte), `pid` (entier), `dump` (booléen) | sensible : confirmation d'un analyste nommé | `action_request` / `action_confirmed` si `dump=true` |
| `vol_dlllist` | DLL chargées et chemin de l'image par processus | `path*` (texte), `pid` (entier) | lecture seule | — |
| `vol_printkey` | Clé de registre lue en mémoire (par exemple les clés Run) | `path*` (texte), `key` (texte) | lecture seule | — |
| `vol3_run` | Tout autre plugin Volatility 3, options typées vérifiées dans l'aide du plugin | `path*` (texte), `plugin*` (texte), `pid` (entier), `offset` (texte), `key` (texte), `dump` (booléen) | sensible : confirmation d'un analyste nommé | `action_request` / `action_confirmed` pour un plugin sensible (identifiants, extraction) ou `dump=true` |
| `mem_extract_vad` | Extrait UNE région mémoire (VAD) d'UN processus, la hache (SHA-256) et l'enregistre comme preuve dérivée ; jamais un processus entier | `path*` (texte), `pid*` (entier), `address*` (texte), `profile` (texte) | sensible : confirmation d'un analyste nommé | `action_request` / `action_confirmed` à chaque appel ; `evidence_registered` pour la région extraite |

### Volatility 2 (images anciennes)

Volatility 2.6 avec un profil (seul moteur pour Windows XP / 2003). `--plugins` et `-w` ne sont jamais passés ; `-D` n'est jamais accepté d'un appelant (seul `mem_extract_vad` le fixe lui-même, vers le dossier du résultat).

| Outil | Rôle | Paramètres | Classe | Journal (en plus de `tool_call`) |
|---|---|---|---|---|
| `vol2_list_plugins` | Plugins et profils Volatility 2.6 (sensibles et refusés signalés) | `contains` (texte) ; pagination `limit`, `offset` | lecture seule | — |
| `vol2_imageinfo` | Profils Volatility 2 suggérés pour une image (long, mis en cache par empreinte) | `path*` (texte) | lecture seule | — |
| `vol2_run` | Tout plugin Volatility 2.6 avec un profil, options typées `pid`, `offset`, `key` ; plugins exigeant `--dump-dir` refusés | `path*` (texte), `plugin*` (texte), `profile*` (texte), `pid` (entier), `offset` (texte), `key` (texte) | sensible : confirmation d'un analyste nommé | `action_request` / `action_confirmed` pour un plugin d'identifiants |
| `vol2_yarascan` | Cherche UNE chaîne (texte littéral ou octets hexadécimaux, pas d'expression régulière) dans la mémoire d'UN processus | `path*` (texte), `profile*` (texte), `pid*` (entier), `text` (texte), `hex_bytes` (texte), `wide` (booléen), `case_insensitive` (booléen) ; pagination `limit`, `offset` | lecture seule | — |

### Eric Zimmerman (journaux, $MFT, registre, artefacts Windows)

17 outils EZ, options typées du registre `rules/ez_registry.json`. PECmd, SQLECmd, WxTCmd, SrumECmd et SumECmd ne tournent pas sous Linux : export fait sous Windows puis importé (« import Windows »).

| Outil | Rôle | Paramètres | Classe | Journal (en plus de `tool_call`) |
|---|---|---|---|---|
| `ez_list_tools` | Les 17 outils EZ : artefacts acceptés, entrée, sortie, options typées, exécution Linux ou Windows | — ; pagination `limit`, `offset` | lecture seule | — |
| `ez_run` | Lance un outil EZ sur un fichier ou dossier de preuve ; les 5 outils Windows-only sont refusés (voir `ez_import`) | `tool*` (liste fermée de 17 valeurs), `path*` (texte), `options` (objet) ; pagination `limit`, `offset` | lecture seule | — |
| `evtx_query` | Journaux d'événements (EvtxECmd) : presets, identifiants, fenêtre UTC, texte ; un preset vide indique le journal ou la politique d'audit requis | `path*` (texte), `preset` (logons \| rdp \| execution \| persistence \| log_clearing), `event_ids` (liste de entier), `start` (texte), `end` (texte), `contains` (texte) ; pagination `limit`, `offset` | lecture seule | — |
| `mft_search` | Recherche dans une $MFT (MFTECmd) : chemin, extension, fenêtre UTC sur un horodatage | `path*` (texte), `path_contains` (texte), `extension` (texte), `start` (texte), `end` (texte), `time_field` (liste fermée de 8 valeurs) ; pagination `limit`, `offset` | lecture seule | — |
| `shimcache_query` | ShimCache d'une ruche SYSTEM (AppCompatCacheParser) | `path*` (texte), `path_contains` (texte), `executed_only` (booléen), `start` (texte), `end` (texte) ; pagination `limit`, `offset` | lecture seule | — |
| `amcache_query` | Amcache.hve (AmcacheParser) : nom, SHA-1, fenêtre UTC | `path*` (texte), `name_contains` (texte), `sha1` (texte), `start` (texte), `end` (texte) ; pagination `limit`, `offset` | lecture seule | — |
| `lnk_query` | Raccourcis LNK (LECmd) : cible, fenêtre UTC | `path*` (texte), `target_contains` (texte), `start` (texte), `end` (texte) ; pagination `limit`, `offset` | lecture seule | — |
| `jumplist_query` | Jump lists (JLECmd) : cible, fenêtre UTC | `path*` (texte), `target_contains` (texte), `start` (texte), `end` (texte) ; pagination `limit`, `offset` | lecture seule | — |
| `recyclebin_query` | Corbeille, fichiers $I / INFO2 (RBCmd) : nom, date de suppression | `path*` (texte), `name_contains` (texte), `start` (texte), `end` (texte) ; pagination `limit`, `offset` | lecture seule | — |
| `ez_import` | Importe un export fait sous Windows par `scripts/run_ez_windows.ps1` : manifeste, empreintes des sorties et de l'entrée vérifiés | `tool*` (liste fermée de 17 valeurs), `path*` (texte) ; pagination `limit`, `offset` | écrit au journal ; import Windows | `imported_from_windows` |
| `prefetch_query` | Prefetch (PECmd) à partir d'un export Windows : exécutable, fenêtre UTC | `path*` (texte), `executable_contains` (texte), `start` (texte), `end` (texte) ; pagination `limit`, `offset` | lecture seule ; import Windows | `imported_from_windows` au premier import de l'export |
| `browser_history` | Historique de navigation (SQLECmd) à partir d'un export Windows : URL ou titre, fenêtre UTC | `path*` (texte), `url_contains` (texte), `start` (texte), `end` (texte) ; pagination `limit`, `offset` | lecture seule ; import Windows | `imported_from_windows` au premier import de l'export |
| `srum_query` | SRUM (SrumECmd) à partir d'un export Windows : application, table, fenêtre UTC | `path*` (texte), `app_contains` (texte), `table` (liste fermée de 7 valeurs), `start` (texte), `end` (texte) ; pagination `limit`, `offset` | lecture seule ; import Windows | `imported_from_windows` au premier import de l'export |

### Images disque (The Sleuth Kit)

Images raw/dd, E01, VMDK, VHD lues sans montage ; les fichiers extraits s'utilisent ensuite comme `@<result_id>/<chemin>`.

| Outil | Rôle | Paramètres | Classe | Journal (en plus de `tool_call`) |
|---|---|---|---|---|
| `disk_info` | Table de partitions d'une image disque (mmls) ; donne `partition_offset` | `path*` (texte) | lecture seule | — |
| `disk_list` | Liste récursive des fichiers d'un système de fichiers (fls), fichiers effacés compris | `path*` (texte), `partition_offset` (entier), `path_contains` (texte), `deleted` (booléen) ; pagination `limit`, `offset` | lecture seule | — |
| `disk_extract` | Extrait des artefacts par cibles fixes (icat), en lecture seule ; `sam_security` après confirmation | `path*` (texte), `targets*` (liste de liste fermée de 19 valeurs), `partition_offset` (entier), `include_deleted` (booléen) ; pagination `limit`, `offset` | sensible : confirmation d'un analyste nommé | `evidence_registered` par fichier extrait (image source, inode) ; `action_request` / `action_confirmed` pour `sam_security` |
| `disk_extract_file` | Extrait des fichiers choisis par inode dans la liste de `disk_list`, effacés compris | `path*` (texte), `inodes*` (liste de entier), `partition_offset` (entier) ; pagination `limit`, `offset` | sensible : confirmation d'un analyste nommé | `evidence_registered` par fichier extrait ; `action_request` / `action_confirmed` pour une ruche d'identifiants |

### Constats, chronologie et rapport

Aucun de ces outils ne valide un constat : la validation est faite par un analyste, hors MCP.

| Outil | Rôle | Paramètres | Classe | Journal (en plus de `tool_call`) |
|---|---|---|---|---|
| `timeline` | Chronologie UTC d'un cas (processus mémoire, EVTX, $MFT) à partir des résultats déjà produits ; chaque événement cite son résultat et sa ligne | `around*` (texte), `case` (texte), `window_minutes` (entier) ; pagination `limit`, `offset` | lecture seule | — |
| `record_finding` | Enregistre UN constat (fait, hypothèse, recommandation, observation = absence vérifiée) ; chaque valeur citée est recontrôlée, sinon rejet | `kind*` (fact \| hypothesis \| recommendation \| observation), `text*` (texte), `citations*` (liste de Citation), `confidence*` (low \| medium \| high), `attack` (liste de texte) | écrit au journal | `suggestion` (« à valider » ou rejeté par le serveur) |
| `list_findings` | Constats et statut courant lu dans le journal | `status` (à valider \| validé \| rejeté \| à revoir \| rejeté par le serveur), `kind` (fact \| hypothesis \| recommendation \| observation) ; pagination `limit`, `offset` | lecture seule | — |
| `report_export` | Rapport Markdown depuis les constats journalisés ; `final=true` refusé tant qu'un constat est à valider ou à revoir | `final` (booléen), `title` (texte) | écrit au journal | `evidence_verified` (« après ») pour chaque preuve si `final=true` |
| `checklist_status` | Étapes de la checklist faites / à faire pour un hôte, déduites du journal | `case` (texte) ; pagination `limit`, `offset` | lecture seule | — |

### Assistant de crise

Le serveur consigne et propose ; aucune mesure n'est exécutée.

| Outil | Rôle | Paramètres | Classe | Journal (en plus de `tool_call`) |
|---|---|---|---|---|
| `crisis_add_event` | Ajoute une entrée C-NNNN à la chronologie de crise (heure avec décalage, responsable, source vérifiée) | `time_utc*` (texte), `kind*` (event \| decision \| action), `description*` (texte), `owner*` (texte), `source*` (texte), `case` (texte) | écrit au journal | `crisis_event` |
| `crisis_timeline` | Chronologie de crise en UTC, avec les changements de statut et communications des parties prenantes | `case` (texte), `kind` (event \| decision \| action \| communication) ; pagination `limit`, `offset` | lecture seule | — |
| `sitrep_draft` | Brouillon de point de situation (6 sections) depuis les constats validés, la chronologie et le tableau des parties prenantes ; écrit `sitrep.md` | `audience*` (direction \| technique \| juridique \| communication), `case` (texte), `title` (texte) | écrit au journal | — |
| `containment_suggestions` | Mesures de confinement à proposer pour un type d'incident, toutes « à valider », jamais exécutées | `incident_type*` (ransomware \| compte_compromis \| exfiltration) | lecture seule | — |

### Coordination des parties prenantes

Le serveur n'envoie aucun message ; les délais légaux sont « à confirmer par le juridique ».

| Outil | Rôle | Paramètres | Classe | Journal (en plus de `tool_call`) |
|---|---|---|---|---|
| `stakeholder_suggest` | Parties prenantes à proposer pour un type d'incident (ordre, délai indicatif, règle), « à valider » ; n'écrit rien | `case*` (texte), `incident_type*` (ransomware \| compte_compromis \| exfiltration \| autre) | lecture seule | — |
| `stakeholder_upsert` | Crée ou met à jour une entrée S-NNNN du tableau (rôle, nom, canal, responsable, échéance, statut) | `case*` (texte), `role*` (liste fermée de 13 valeurs), `name` (texte), `organisation` (texte), `channel` (telephone \| courriel \| reunion \| ticket \| autre), `owner` (texte), `notify_by_utc` (texte), `status` (a_prevenir \| prevenu \| accuse_reception \| sans_objet \| a_revoir), `note` (texte), `source` (texte), `stakeholder_id` (texte) | écrit au journal | `stakeholder_update` |
| `stakeholder_list` | Tableau courant recalculé depuis le journal, retards calculés par le serveur | `case` (texte), `status` (a_prevenir \| prevenu \| accuse_reception \| sans_objet \| a_revoir), `role` (liste fermée de 13 valeurs) ; pagination `limit`, `offset` | lecture seule | — |
| `comms_log` | Consigne une communication déjà faite par une personne ; ne change pas le statut | `case*` (texte), `stakeholder_id*` (texte), `direction*` (sortante \| entrante), `summary*` (texte), `at_utc*` (texte), `source` (texte) | écrit au journal | `comms_logged` |

Prompt : `playbook_poste_compromis(case, section)`. Ressources : `playbook://references/artefacts`, `playbook://references/citations`, `playbook://references/checklist`, `playbook://references/arbre`, `playbook://references/confinement`, `playbook://references/coordination`.
<!-- tools:end -->

Chaque réponse suit le même contrat ([`docs/output_schema.json`](docs/output_schema.json)) :
`result_id`, `audit_id`, empreinte de la preuve, lignes numérotées `_row`, page suivante
(`page.next_call`), lien vers la sortie brute, anomalies (règles et ATT&CK du serveur), pistes
suivantes. Le texte est encadré par des marqueurs `EVIDENCE DATA` : c'est une donnée, jamais une
consigne.

La skill « playbook poste compromis » est dans `skills/playbook-poste-compromis/` (Claude Code :
copier ou lier ce dossier dans `.claude/skills/` du dossier d'analyse). Pour les clients sans
skills, le même contenu est le prompt MCP `playbook_poste_compromis(case, section)` : SKILL.md
seul par défaut, une référence par section.

Il n'existe **pas d'outil MCP `verify_audit`** : la chaîne du journal est vérifiée par
`report_export`, `sitrep_draft` et `eval/score.py`, ou à la main :

```powershell
docker compose exec forensic python -c "from forensic_mcp import audit; print(audit.verify_report('/output/audit.jsonl'))"
```

## 6. Hors serveur MCP

Ces actions sont faites par une personne, dans un terminal ; aucun outil MCP ne les déclenche.

| Commande | Qui | Rôle |
|---|---|---|
| `docker exec -it forensic-mcp python -m forensic_mcp validate` | analyste | **Validation des constats** (valider, rejeter, à revoir) avec nom et motif ; terminal interactif obligatoire ; chaque décision est chaînée au journal |
| `docker compose exec forensic python scripts/register_evidence.py <HÔTE> --analyst "Nom"` (puis `--after`) | analyste | Empreintes SHA-256 d'un dossier de cas avant l'analyse, puis recontrôle après ; manifeste dans `/output/manifests/` |
| `.\scripts\run_ez_windows.ps1` (PowerShell, poste Windows) | analyste | Lance un outil EZ Windows-only et écrit un export avec manifeste (§7) |
| `docker compose exec forensic python eval/score.py --journal /output/audit.jsonl` | équipe | Note une session contre la vérité terrain (`eval/ground_truth.yaml`) et mesure la complétude de la documentation ; rien n'est estimé (« À MESURER ») |
| `docker compose exec forensic python scripts/tool_inventory.py --check` | développeur | Vérifie que les tableaux du §5 correspondent au serveur |

**Validation.** L'IA enregistre ses constats avec `record_finding` ; ils restent « à valider ».
Le menu de validation recontrôle chaque citation (valeur citée, valeur actuelle dans la donnée
brute) ; un constat rejeté par le serveur ne peut qu'être rejeté ; aucun constat n'est supprimé.
`report_export(final=false)` marque les constats en attente **NON VALIDÉ** ;
`report_export(final=true)` est refusé tant qu'il en reste, recalcule l'empreinte de chaque
preuve utilisée et inscrit le hash de tête du journal, à conserver hors du poste.

## 7. Outils Eric Zimmerman Windows-only

PECmd (prefetch), SrumECmd (SRUM), SumECmd (UAL), SQLECmd (historique de navigation) et WxTCmd
(Timeline Windows) refusent Linux ou dépendent de bibliothèques Windows (causes vérifiées dans
`CLAUDE.md` §11). Le serveur ne les lance jamais. Flux :

1. **Sous Windows**, l'analyste lance l'outil avec le script (mêmes options typées que le
   serveur, `rules/ez_registry.json` ; entrée obligatoirement sous la racine des preuves ;
   `-DryRun` affiche la commande sans rien exécuter) :

```powershell
.\scripts\run_ez_windows.ps1 -Tool PECmd -CaseHost WS-042 `
    -InputPath WS-042\kape\C\Windows\prefetch -EzDir C:\Tools\ZimmermanTools\net9
```

   Il écrit `evidence/<HÔTE>/ez_out/<Outil>_<UTC>/` : sorties et `manifest.json` (version,
   empreinte et signature de l'exécutable, empreinte de l'entrée et des sorties).
2. **Import** : `ez_import(tool, path)` vérifie le manifeste, les empreintes des sorties et
   celle de l'entrée encore présente sous `/evidence`, puis journalise `imported_from_windows`.
3. **Interrogation** : `prefetch_query`, `browser_history`, `srum_query` sur le dossier
   d'export (ils l'importent eux-mêmes au premier appel), ou `query_results` sur le résultat.

**Limite** : le manifeste est écrit par le poste de l'analyste. Le serveur vérifie la cohérence
des empreintes, il **ne prouve pas quel binaire a réellement tourné** ; ces artefacts sont
analysés hors du conteneur durci.

## 8. Limites connues

- **Volatility 3 ne lit pas les images Windows XP / 2003** (pas de table de symboles
  utilisable ; limite de l'outil, pas un défaut du serveur). Les outils `vol_*` et `vol3_run`
  échouent alors avec un message explicite (« Windows XP / 2003 image detected… ») et proposent
  `vol2_imageinfo` puis `vol2_run`, moins typé : `pid`, `offset`, `key` seulement. Les règles
  de détection s'appliquent aussi aux sorties de `vol2_run` (pslist, cmdline, connscan…).
  Vérifié sur une image XP SP2 le 12/10.
- **Recherche dans la mémoire d'un processus** : `vol2_yarascan` (Volatility 2 uniquement, le
  module yara de Volatility 3 n'est pas chargé dans l'image) cherche une chaîne littérale ou
  des octets, jamais une expression régulière ni un fichier de règles. Les pages absentes de
  l'image ne sont pas lues : « 0 résultat » n'est pas « jamais présent ».
- **Extraction depuis la mémoire** : `mem_extract_vad` extrait une région (VAD) d'un
  processus, pas un fichier. Son SHA-256 est celui d'une région mémoire (pages absentes
  remplies de zéros) : il **ne se compare pas** à l'empreinte d'un fichier sur disque ni à une
  base de réputation. L'extraction d'un objet fichier (`dumpfiles`) et celle d'un processus
  entier (`procdump`, `memdump`) ne sont pas proposées. Voie Volatility 3 : testée sur le faux
  outil seulement, *non vérifiée* sur une image réelle.
- **Hors périmètre, volontairement** (cahier des charges) : le serveur s'arrête aux empreintes
  de mots de passe (`hashdump` après confirmation) et ne les casse pas ; il ne fait ni
  rétro-ingénierie de code malveillant (désobfuscation de JavaScript, analyse de shellcode),
  ni requête vers l'extérieur (pas de VirusTotal ni d'autre service de réputation : les
  preuves restent en environnement cloisonné).
- **17 outils EZ, pas 18** : Hasher n'a pas de build .NET 9, il n'est pas installé.
- **MFTECmd non vérifié sur une $MFT réelle** (aucun échantillon) : les noms de colonnes de
  `mft_search` sont supposés ; EvtxECmd, lui, a été vérifié sur de vrais journaux.
- **Colonnes des 5 outils Windows-only non vérifiées** : aucun export réel de PECmd, SrumECmd,
  SumECmd, SQLECmd ou WxTCmd n'a été importé ; les filtres retombent sur la ligne entière si une
  colonne manque.
- **Une absence est une observation** : `record_finding(kind="observation")` enregistre
  « aucune trace dans cet artefact », vérifié par le serveur ; ce n'est jamais la preuve qu'un
  comportement n'a pas eu lieu (journal absent, politique d'audit désactivée).
- **Le serveur n'envoie jamais de message** et n'agit jamais sur l'infrastructure : confinement
  et parties prenantes sont des propositions et des consignations.
- **La validation humaine est hors MCP** ; le nom de l'analyste est saisi, pas authentifié, et
  aucun relecteur senior n'est exigé.
- Un client disposant d'un shell peut contourner les garde-fous du serveur : utiliser le dossier
  d'analyse sans Bash (§4).
- Le journal chaîné rend une modification détectable, pas impossible : conserver le hash de
  tête hors du poste.
- Pseudonymisation partielle : IPv6, messages d'erreur, contenus encodés (base64) et numéros de
  téléphone hors format français ne sont pas couverts.
- Les appels rejetés par la validation de types du SDK n'atteignent pas le serveur et ne sont
  pas journalisés.
- Évaluation (temps de triage, rappel, sitrep) : **non mesurée à ce jour**
  ([`docs/L6_evaluation.md`](docs/L6_evaluation.md)).

Détail et cas observés : `CLAUDE.md` §11 et [`docs/L7_note_risques.md`](docs/L7_note_risques.md).

## 9. Modèle de sécurité (rappel)

| Garde-fou | Mise en œuvre |
|---|---|
| Lecture seule | montage `:ro` ; jail de chemins (`resolve` + `is_relative_to`, liens résolus) ; seconde racine en lecture seule réservée aux extraits de `disk_extract` |
| Pas d'argument libre | noms de plugins et d'outils issus de la liste découverte ou du registre ; chaque option est typée et vérifiée dans l'aide réelle de l'outil (`docs/tool_help/`) |
| Traçabilité | journal `/output/audit.jsonl` chaîné par SHA-256 : chaque appel (y compris refusé ou en échec), chaque enregistrement de preuve, chaque constat, chaque décision ; `replay` rejoue un appel et compare la sortie |
| Chaîne de preuve | SHA-256 complet avant la première analyse, contrôle taille/date avant chaque appel (preuve modifiée ⇒ refus), recontrôle « après » (`verify_evidence`, export final) |
| Validation humaine | actions sensibles après confirmation nominative dans le client MCP ; constats validés hors bande (§6) ; l'IA ne peut pas valider |
| Anti-hallucination | `record_finding` revérifie chaque valeur citée dans la ligne brute ; constat rejeté si la valeur, la ligne ou l'identifiant ATT&CK ne viennent pas du serveur |
| Données confidentielles | `case.toml` : `client` refusé en mode cloud ; `internal` + cloud ⇒ pseudonymisation (§4) |
| Injection de prompt | contenu d'artefact uniquement dans des champs de données, entre marqueurs ; le serveur n'exécute jamais ce contenu |

## 10. Tests

```powershell
docker compose exec forensic pytest -q
```

Faux outils dans `tests/fakebin/` (aucun outil réel n'est lancé par les tests) ; scénario de
référence WS-042 de bout en bout dans [`tests/scenario_ws042/`](tests/scenario_ws042/). Des
tests vérifient que chaque outil exposé est appelé au moins une fois (ET-09), que chaque
réponse respecte le schéma, et que ce README correspond au serveur (nombre d'outils, tableaux,
catégories).

## 11. Versions épinglées

Le build est reproductible ou échoue : image de base par empreinte (`python:3.12-slim-bookworm@sha256:…`),
paquets Python par version exacte (`requirements.lock`), runtime .NET 9.0.20, paquets
forensiques Debian par version, Open WebUI par empreinte, et **SHA-256 de chaque fichier
téléchargé** (script d'installation .NET, zip de Volatility 2, les 17 zips EZ dans
`rules/ez_zips.sha256`).

Les URL des zips EZ ne portent pas de version : leurs empreintes ont été relevées au premier
usage (03/10/2026). **Quand Eric Zimmerman publie une nouvelle version, le build échoue
volontairement** (« EZ <outil>.zip changed upstream ») : relire la publication, puis mettre à
jour `rules/ez_zips.sha256`. Non épinglés : les paquets système de base de Debian, et les
paquets Python ne sont pas vérifiés par empreinte (`--require-hashes` non utilisé).
