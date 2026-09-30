# Matrice de conformité CDC ↔ forensic-mcp

Mise à jour : J3 (30/09/2026), tâche 2.1 — audit du code existant (construit avant le plan
aligné sur le CDC). À tenir à jour à la fin de chaque tâche (règle 1 de `CLAUDE.md`).

Statuts : **fait** · **partiel** · **manquant** · **hors périmètre**.
Les intitulés ET-xx sont repris de `CLAUDE.md` (§4, §8, §9) ; le CDC n'est pas versionné
dans le dépôt, les intitulés sont à vérifier contre le CDC du 26/09/2026.

## 1. Exigences fonctionnelles (EF)

| ID | Prio | Exigence | Statut | Existant (fichier) | Test existant | Écart / tâche |
|---|---|---|---|---|---|---|
| EF-01 | M | Plugins Volatility 3 | partiel | `engines/volatility3.py` (`list_plugins`, `resolve_plugin`, `run`), `server.py` (`memory_list_plugins`, `memory_run`) | `test_fasttrack.py::test_plugins_parsed_and_resolved`, `::test_run_flattens_children_with_depth`, `::test_run_pid_and_jail` | `memory_run` accepte **n'importe quel** plugin : pas d'outils typés `vol_*`, pas d'allowlist, pas d'analyseurs. → 4.2 |
| EF-02 | M | Filtrage EVTX | manquant | EvtxECmd installé seulement | — | `evtx_query` + presets. → 4.3 |
| EF-03 | M | Recherche $MFT | manquant | MFTECmd installé seulement | — | `mft_search`. → 4.3 |
| EF-04 | M | Résultats paginés + lien vers la sortie brute | partiel | `results.query` (limit/offset, streaming, tri par tas), `results.summarize` | `test_phase2.py::test_query_streams_big_csv`, `::test_sort_covers_all_rows_with_bounded_memory` | Pas de `page.next_offset`, pas de `raw_output`, pas de pagination sur `memory_run`. → 4.1 + 4.4 |
| EF-05 | M | SHA-256 des preuves journalisé | partiel | `results.sha256_cached` (cache par chemin/taille/mtime), `input_sha256` dans `meta.json` | — | Hash non journalisé ; cache ≠ vérification avant/après ; pas d'enregistrement. → 4.1 |
| EF-06 | M | Lecture seule des preuves | fait | `docker-compose.yml` (`/evidence:ro`), `safety.jail_path` | Phase 1 : `touch /evidence/x` → *Read-only file system* ; `test_phase2.py::test_jail_*` | Revérifier en 4.1 (seconde racine éventuelle). |
| EF-07 | C | Requête SIEM du lab | manquant | — | — | Seulement si temps après M5. |
| EF-08 | M | Checklist de collecte | manquant | — | — | `references/checklist_collecte.md` + `checklist_status`. → 5.1 |
| EF-09 | M | Arbre de triage ATT&CK | manquant | — | — | `references/arbre_triage.md`. → 5.1 |
| EF-10 | M | Citation de l'artefact source | partiel | `result_id` dans chaque réponse | — | Pas de `_row` stable. → 4.4 + 5.2 |
| EF-11 | M | Distinction fait / hypothèse / recommandation | manquant | — | — | `record_finding(kind=…)`. → 4.4 + 5.2 |
| EF-12 | M | Timeline de crise | manquant | — | — | `crisis_add_event`, `crisis_timeline`. → 6.1 |
| EF-13 | S | Sitrep au format fixe | manquant | — | — | `sitrep_draft` + `templates/sitrep.md`. → 6.1 |
| EF-14 | S | Suggestions de confinement | manquant | — | — | `containment_suggestions`, toujours « à valider ». → 6.1 |
| EF-15 | C | Tableau des parties prenantes | manquant | — | — | 6.1 si temps. |

## 2. Exigences techniques (ET)

| ID | Exigence | Statut | Existant (fichier) | Test existant | Écart / tâche |
|---|---|---|---|---|---|
| ET-01 | Serveur MCP, SDK officiel, transport de référence stdio | partiel | `__main__.py --stdio`, `server.py` (`mcp==2.2.0`) | `test_fasttrack.py::test_mcp_lists_six_tools_and_runs` (client en mémoire) | stdio jamais vérifié depuis Windows (`docker exec -i`) ; HTTP seul testé de bout en bout. → 4.4 |
| ET-02 | Outils en sous-processus, timeout, sortie bornée | partiel | `runner.run_process` (exec sans shell, timeout, kill du groupe de processus) | `test_phase2.py::test_runner_kills_on_timeout` | `stdout.txt` non borné en taille ; réponses bornées seulement en lignes/cellules (pas de `max_response_kb`). → 4.1 |
| ET-03 | Sorties JSON structurées | partiel | dicts `summarize`/`query` | — | Contrat §5 absent ; schéma créé : `docs/output_schema.json` (2.1). Validation en test → 4.1 |
| ET-04 | Journal d'audit horodaté et rejouable | partiel | `audit.py` (chaînage SHA-256, `verify_audit`) | `test_phase2.py::test_audit_chain_detects_tampering` | **Non branché sur le serveur** (aucun appel journalisé) ; `ts` en epoch au lieu d'UTC ISO ; pas de types ni d'`audit_id` ; pas de `replay`. Schéma créé : `docs/audit_schema.json` (2.1). → 4.1 |
| ET-05 | Validation des chemins (jail) | fait | `safety.jail_path` (`resolve` + `is_relative_to`) | `test_phase2.py::test_jail_blocks_traversal_and_symlink`, `::test_jail_sibling_prefix_symlink_dir_and_relative` | — |
| ET-06 | Skill au format SKILL.md | manquant | — | — | `skills/playbook-poste-compromis/`. → P5 |
| ET-07 | LLM cloud et LLM local | partiel | Service `webui` (Open WebUI + Ollama), transport HTTP, clé `llm_mode` | `test_config_docker.py` | Serveur MCP pas encore enregistré dans Open WebUI ; `llm_mode` lu mais inutilisé. → 5.2 |
| ET-08 | Machine d'analyse Linux | fait | `Dockerfile` (Debian bookworm, Python 3.12, utilisateur `analyst`, `cap_drop: ALL`, `no-new-privileges`) | Phase 1 : `check_tools.py` 20/20 | Justification à rédiger dans L2 (fait en 2.1, §5). |
| ET-09 | ≥ 1 test unitaire par outil exposé | partiel | 17 tests pytest, faux `vol` dans `tests/fakebin/` | `tests/` | Pas de test par outil ni de validation du schéma de sortie. → 4.4 |

## 3. Garde-fous (CDC §5)

| Garde-fou | Statut | Existant | Écart / tâche |
|---|---|---|---|
| Validation humaine | manquant | Aucun outil d'action n'existe (conforme par défaut) | Annotations lecture/action absentes ; `ctx.elicit` / page `/approvals` à faire. → 4.1 |
| Traçabilité | partiel | `meta.json` par exécution (argv, version, hash, durée, code retour) ; `audit.py` non branché | Enregistrements `tool_call` automatiques, `record_finding`. → 4.1, 4.4 |
| Chaîne de preuve | partiel | Montage `:ro`, SHA-256 mis en cache | Enregistrement + vérification avant/après, hash dans le rapport. → 4.1 |
| Données confidentielles | manquant | `llm_mode = "local"` par défaut (clé seule) | `case.toml` (classification), refus `client`+cloud, pseudonymisation. → 4.1 |
| Limites de confiance | manquant | — | `confidence` sur chaque finding + revérification serveur. → 4.4 |
| Anti-hallucination | partiel | Entiers > 2^53−1 en hexadécimal (`volatility3.safe_value`), filtres numériques exacts | Contre-vérification des citations dans `record_finding`. → 4.4 |
| Excès de confiance | manquant | — | Statut « à valider », nom du relecteur, export final refusé sinon. → 4.4 / 6.1 |
| Injection de prompt | partiel | Phrase dans `INSTRUCTIONS` ; aucun argument libre (seul `pid` typé) | Marqueurs `EVIDENCE DATA`, `untrusted_notice`, fixture d'injection. → 4.1 |

## 4. Objectifs mesurables (CDC §2)

| Objectif | Mesuré par | Tâche |
|---|---|---|
| O1 : −30 % de temps de triage initial | `eval/score.py` (horodatages du journal) | P7 |
| O2 : ≥ 80 % des IOC / étapes retrouvés | `eval/score.py` vs `eval/ground_truth.yaml` | 3.2, P7 |
| O3 : 100 % des appels et suggestions tracés | `tool_call` automatique + `record_finding` + `verify_audit` | 4.1, 4.4 |
| O4 : sitrep conforme en < 10 min | `sitrep_draft` chronométré | 6.1, P7 |
| O5 : risques LLM et garde-fous documentés | L2 (matrice), L7 | 2.2, P8 |

## 5. Écarts de périmètre et éléments hérités à réconcilier

| Élément | Constat | Décision proposée |
|---|---|---|
| Transport HTTP + jeton bearer + Open WebUI | Extension hors CDC, déjà construite | Conservée pour le mode LLM local (ET-07) ; surface d'attaque → L7. |
| Volatility 2, 15 outils Zimmerman | Installés, non exposés | Conforme au périmètre (non exposés). `safety.FORBIDDEN_FLAGS["vol2"/"ez"]` et `validate_args` inutilisés : à retirer en 4.1 au profit des paramètres typés (règle 8). |
| `max_upload_gb` | Clé de config sans usage (pas de téléversement dans le CDC) | À retirer en 4.1 (à confirmer par l'utilisateur). |
| Cache SHA-256 (`output/.cache/sha256.json`) | Accélère, mais n'est pas une preuve avant/après | Remplacé par enregistrement + contrôle rapide en 4.1. |
| `memory_run(path, plugin, pid)` générique | Tout plugin vol3 exécutable, y compris ceux qui extraient des fichiers vers `/output/<id>/files` | Restreint à une allowlist en 4.2 ; extractions = outil d'action. |
| Noms d'outils (`memory_list_plugins`) | Diffèrent de la cible (`vol_list_plugins`) | Renommage en 4.2. |
