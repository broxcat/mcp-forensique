# forensic-mcp — serveur MCP forensique (Majeure Blue Team)

Serveur [MCP](https://modelcontextprotocol.io) qui met les outils DFIR à disposition d'un
assistant IA **sans perte de fiabilité ni de traçabilité** : Volatility 3 et 2 (mémoire), outils
Eric Zimmerman (EVTX, $MFT, registre, artefacts Windows), The Sleuth Kit (images disque). Le
serveur calcule les faits (nombre de lignes, anomalies et identifiants ATT&CK, commandes
décodées, IOC, chronologie) ; l'IA converse, cite ses sources et chaque affirmation est
revérifiée avant d'entrer au rapport. Référence : cahier des charges du 26/09/2026
(L. Plancke, W. Triffault) ; conception détaillée : [`docs/L2_architecture.md`](docs/L2_architecture.md) ;
conformité exigence par exigence : [`docs/compliance.md`](docs/compliance.md).

## 1. Architecture en bref

- Poste analyste **Windows** + **un conteneur Linux** (Docker Desktop) qui exécute le serveur et
  les outils : Debian, Python 3.12, `mcp==2.2.0`, Volatility 3 (2.28.2) et 2 (2.6), .NET 9 et
  les outils Eric Zimmerman, sleuthkit + ewf-tools.
- Preuves montées **en lecture seule** (`/evidence`), résultats et journal dans `/output`
  (visibles sous Windows, ouvrables dans Timeline Explorer).
- Utilisateur non privilégié, toutes les capacités Linux supprimées, aucun montage possible.
- Transport de référence **stdio** ; transport **HTTP** sur `127.0.0.1:8000` (jeton) réservé à
  Open WebUI pour le mode modèle local.

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

Fichier `.env` (jamais commité) :

| Variable | Rôle |
|---|---|
| `EVIDENCE_DIR` | Dossier Windows des preuves, monté en lecture seule sur `/evidence` (barres obliques `/`) |
| `OUTPUT_DIR` | Dossier Windows des résultats et du journal (`/output`) |
| `WEBUI_SECRET_KEY` | Secret de session d'Open WebUI (32 caractères aléatoires ou plus) |
| `OLLAMA_BASE_URL` | Optionnel : URL d'Ollama vue depuis le conteneur Open WebUI |

Organisation conseillée des preuves : `evidence/<HÔTE>/memory/`, `evidence/<HÔTE>/kape/` et un
`case.toml` par hôte :

```toml
case = "WS-042"
classification = "lab"      # lab | internal | client
hosts = ["WS-042"]          # noms toujours pseudonymisés en mode cloud
users = ["alice"]
```

Configuration du serveur : [`forensic-mcp.docker.toml`](forensic-mcp.docker.toml) (bornes de
réponse, délai maximal, `llm_mode = "local"` par défaut). Après une modification du code ou de la
configuration : `docker compose restart forensic` (pas de rechargement automatique).

## 3. Clients

**Claude Code, stdio (référence)** — le serveur est lancé dans le conteneur en cours d'exécution :

```powershell
claude mcp add forensic -- docker exec -i forensic-mcp python -m forensic_mcp --stdio
```

**HTTP** (`http://localhost:8000/mcp`, en-tête `Authorization: Bearer <jeton>`). Le jeton est créé
au premier démarrage dans `.secrets/api_token` (droits 0600, ignoré par Git) ; ne le copiez
jamais dans une conversation avec un modèle :

```powershell
claude mcp add --transport http forensic http://localhost:8000/mcp --header "Authorization: Bearer $(Get-Content .secrets\api_token)"
```

`GET /health` est public ; tout le reste exige le jeton. **Open WebUI** (modèle local Ollama) :
`http://localhost:3000`, serveur MCP à déclarer avec l'URL interne `http://forensic:8000/mcp` et
le même jeton.

## 4. Outils exposés (41) et prompt MCP

| Domaine | Outils |
|---|---|
| Socle | `tool_status`, `list_evidence`, `register_evidence`, `verify_evidence`, `query_results`, `list_results`, `replay` |
| Mémoire (vol3) | `vol_pslist`, `vol_pstree`, `vol_cmdline`, `vol_netscan`, `vol_malfind`, `vol_dlllist`, `vol_printkey`, `vol3_run`, `vol_list_plugins` |
| Mémoire (vol2) | `vol2_list_plugins`, `vol2_imageinfo`, `vol2_run` |
| Disque (EZ) | `evtx_query` (presets logons, rdp, execution, persistence, log_clearing), `mft_search`, `shimcache_query`, `amcache_query`, `lnk_query`, `jumplist_query`, `recyclebin_query`, `ez_run`, `ez_list_tools`, `timeline` |
| Outils EZ Windows-only | `prefetch_query`, `browser_history`, `srum_query`, `ez_import` (voir §5) |
| Images disque | `disk_info`, `disk_list`, `disk_extract` (cibles fixes), `disk_extract_file` (fichiers choisis par inode dans la liste de `disk_list`, fichiers effacés compris) ; extraits utilisables ensuite comme `@<result_id>/<chemin>` |
| Constats et rapport | `record_finding`, `list_findings`, `report_export` |
| Playbook (skill) | `checklist_status(case)` : étapes de la checklist faites / à faire pour un hôte, déduites du journal d'audit |

La skill « playbook poste compromis » est dans `skills/playbook-poste-compromis/` (Claude Code :
copier ou lier ce dossier dans `.claude/skills/`). Pour les clients sans skills (Open WebUI,
modèle local), le même contenu est exposé comme prompt MCP `playbook_poste_compromis(case)`.

Chaque réponse suit le même contrat ([`docs/output_schema.json`](docs/output_schema.json)) :
`result_id`, `audit_id`, empreinte de la preuve, lignes numérotées `_row`, page suivante
(`page.next_call`), lien vers la sortie brute, anomalies (règles et ATT&CK du serveur),
pistes suivantes. Le texte est encadré par des marqueurs `EVIDENCE DATA`.

## 5. Outils Eric Zimmerman qui ne tournent pas sous Linux

PECmd (prefetch), SQLECmd (historique de navigation), WxTCmd (Timeline Windows), SrumECmd
(SRUM) et SumECmd (UAL) refusent Linux ou dépendent de bibliothèques Windows (causes dans
`CLAUDE.md` §11). Le serveur ne les lance jamais ; l'analyste les exécute sur le poste Windows :

```powershell
.\scripts\run_ez_windows.ps1 -Tool PECmd -CaseHost WS-042 `
    -InputPath WS-042\kape\C\Windows\prefetch -EzDir C:\Tools\ZimmermanTools\net9
```

Le script utilise le même registre que le serveur (`rules/ez_registry.json`, options typées
uniquement, entrée obligatoirement sous la racine des preuves) et écrit
`evidence/<HÔTE>/ez_out/<Outil>_<UTC>/` avec un manifeste (version, empreintes de
l'exécutable, de l'entrée et des sorties). Ensuite `ez_import` ou directement
`prefetch_query(path="WS-042/ez_out/PECmd_…")` : le serveur vérifie les empreintes avant
d'utiliser l'export. `-DryRun` affiche la commande sans rien exécuter.

## 6. Validation des constats et rapport

L'IA enregistre ses constats avec `record_finding` (fait, hypothèse, recommandation, ou
observation = absence de trace vérifiée par le serveur dans un résultat cité) ; ils restent
« à valider ». **Seul un analyste valide, hors MCP**, depuis un terminal interactif :

```powershell
docker exec -it forensic-mcp python -m forensic_mcp validate
```

Le menu liste les constats à valider ou à revoir, recontrôle chaque citation (valeur citée,
valeur actuelle dans la donnée brute), puis enregistre la décision (valider, rejeter, à revoir)
avec le nom de l'analyste et un motif. Chaque décision est chaînée au journal ; aucun constat
n'est supprimé. Un identifiant (`F-0002`) donne accès à n'importe quel constat ; un constat
rejeté par le serveur ne peut qu'être rejeté. Aucun outil MCP ne permet de valider.

`report_export(final=false)` produit un brouillon où les constats en attente sont marqués
**NON VALIDÉ** ; `report_export(final=true)` est refusé tant qu'il en reste et indique lesquels,
recalcule l'empreinte de chaque preuve utilisée et inscrit le hash de tête du journal, à
conserver hors du poste.

## 7. Modèle de sécurité

| Garde-fou | Mise en œuvre |
|---|---|
| Lecture seule | montage `:ro` ; jail de chemins (`resolve` + `is_relative_to`, liens refusés) ; seconde racine en lecture seule réservée aux extraits de `disk_extract` |
| Pas d'argument libre | noms de plugins et d'outils issus de la liste découverte ou du registre ; chaque option est typée et vérifiée dans l'aide réelle de l'outil (`docs/tool_help/`) |
| Traçabilité | journal `/output/audit.jsonl` chaîné par SHA-256 : chaque appel (y compris refusé ou en échec), chaque enregistrement de preuve, chaque constat ; `replay` rejoue un appel et compare la sortie |
| Chaîne de preuve | SHA-256 complet avant la première analyse, contrôle taille/date avant chaque appel (preuve modifiée ⇒ refus), `verify_evidence` pour le contrôle « après » |
| Validation humaine | plugins sensibles (identifiants, extractions, `--dump`, ruches SAM/SECURITY) exécutés seulement après confirmation nominative de l'analyste dans le client MCP ; constats validés hors bande (§6) ; l'IA ne peut pas valider |
| Anti-hallucination | `record_finding` revérifie chaque valeur citée dans la ligne brute ; constat rejeté si la valeur, la ligne ou l'identifiant ATT&CK ne sont pas fournis par le serveur |
| Données confidentielles | `case.toml` : `client` refusé en mode cloud ; `internal` + cloud ⇒ pseudonymisation stable (`HOST_1`, `USER_1`, `IP_EXT_1`…), correspondance gardée côté serveur |
| Injection de prompt | contenu d'artefact uniquement dans des champs de données, entre marqueurs ; le serveur n'exécute jamais ce contenu |

Limites connues (détail dans `CLAUDE.md` §11 et, à terme, la note de risques L7) : un client
disposant d'un shell (Claude Code) peut contourner les garde-fous du serveur — refuser Bash dans
l'espace d'analyse ; le journal est infalsifiable sans détection, pas inaltérable ; le mode LLM
est déclaré, pas détecté ; les exports Windows reposent sur un manifeste écrit par le poste de
l'analyste.

## 8. Tests

```powershell
docker compose exec forensic pytest -q
```

Faux outils dans `tests/fakebin/` (aucun outil réel n'est lancé par les tests) ; scénario de
référence WS-042 de bout en bout dans [`tests/scenario_ws042/`](tests/scenario_ws042/) ; un test
vérifie que chaque outil exposé est couvert (ET-09) et que chaque réponse respecte le schéma.
