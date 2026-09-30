# Matrice de conformité CDC ↔ forensic-mcp

Mise à jour : J3 (30/09/2026), tâche 4.2 (Volatility 2 + 3, Décision J3). Les statuts décrivent le **code** ;
la conception est dans [`L2_architecture.md`](L2_architecture.md) (sa matrice §10 est l'état
au J4, jalon M2). À tenir à jour à la fin de chaque tâche (règle 1 de `CLAUDE.md`).

Statuts : **fait** · **partiel** · **manquant** · **hors périmètre**.
Les intitulés ET-xx sont repris de `CLAUDE.md` (§4, §8, §9) ; le CDC n'est pas versionné
dans le dépôt, les intitulés sont à vérifier contre le CDC du 26/09/2026.
Tests : `tests/test_memory.py` + `tests/test_rules.py` (4.2), `tests/test_socle.py` (4.1), `tests/test_fasttrack.py`, `tests/test_phase2.py` — 58 tests.

## 1. Exigences fonctionnelles (EF)

| ID | Prio | Exigence | Statut | Code | Test | Écart / tâche |
|---|---|---|---|---|---|---|
| EF-01 | M | Plugins Volatility 3 | fait | `memory_ops.py` (`vol_pslist`, `vol_pstree`, `vol_cmdline`, `vol_netscan`, `vol_malfind`, `vol_dlllist`, `vol_printkey`, `vol3_run`, `vol_list_plugins`), `engines/volatility3.py` (`plugin_options` lu dans `vol <plugin> -h`), `analyzers.py`, `decode.py`, `rules/process_rules.yaml` | `test_memory.py` (un test par outil), `test_rules.py` (une fixture par règle) ; contrôle réel sur `Triage-Memory.mem` (STATUS) | Test de référence complet `tests/scenario_ws042/` : 4.4. |
| EF-02 | M | Filtrage EVTX | manquant | EvtxECmd installé seulement | — | `evtx_query` + presets. → 4.3 |
| EF-03 | M | Recherche $MFT | manquant | MFTECmd installé seulement | — | `mft_search`. → 4.3 |
| EF-04 | M | Résultats paginés + lien vers la sortie brute | partiel | `contract.build` (`page.next_offset`, `raw_output`), `results.query` (streaming, `matched`), `query_results(offset, limit)` | `test_socle.py::test_every_tool_response_matches_contract`, `::test_response_size_is_bounded` | `memory_run` + `query_results` paginés ; les outils de liste sont tronqués à `max_rows_returned` sans paramètre `offset`. → 4.4 |
| EF-05 | M | SHA-256 des preuves journalisé | fait | `evidence.py` (enregistrement avant analyse, contrôle rapide, re-hachage), `register_evidence`, `verify_evidence` | `test_socle.py::test_registration_before_analysis_and_change_detected` | Hash « après » dans le rapport exporté : 4.4 / 6.1. |
| EF-06 | M | Lecture seule des preuves | fait | `docker-compose.yml` (`/evidence:ro`), `safety.jail_path` | Phase 1 : `touch /evidence/x` → *Read-only file system* ; `test_phase2.py::test_jail_*` | Aucune seconde racine ajoutée en 4.1. |
| EF-07 | C | Requête SIEM du lab | manquant | — | — | Seulement si temps après M5. |
| EF-08 | M | Checklist de collecte | manquant | — | — | `references/checklist_collecte.md` + `checklist_status`. → 5.1 |
| EF-09 | M | Arbre de triage ATT&CK | partiel | Table de règles `rules/process_rules.yaml` : 7 règles + `ioc_match`, identifiants ATT&CK fournis par le serveur, `next_steps` par règle | `test_rules.py` | Arbre de triage de la skill (`references/arbre_triage.md`). → 5.1 |
| EF-10 | M | Citation de l'artefact source | partiel | `_row` stable (`results.iter_rows`), `result_id` + `audit_id` dans chaque réponse | `test_fasttrack.py::test_mcp_lists_tools_and_runs` (`_row` conservé par filtre) | `record_finding` avec citations. → 4.4 + 5.2 |
| EF-11 | M | Distinction fait / hypothèse / recommandation | manquant | (schéma `suggestion` prêt) | — | `record_finding(kind=…)`. → 4.4 + 5.2 |
| EF-12 | M | Timeline de crise | manquant | (schéma `crisis_event` prêt) | — | `crisis_add_event`, `crisis_timeline`. → 6.1 |
| EF-13 | S | Sitrep au format fixe | manquant | — | — | `sitrep_draft` + `templates/sitrep.md`. → 6.1 |
| EF-14 | S | Suggestions de confinement | manquant | — | — | `containment_suggestions`, toujours « à valider ». → 6.1 |
| EF-15 | C | Tableau des parties prenantes | manquant | — | — | 6.1 si temps. |

## 2. Exigences techniques (ET)

| ID | Exigence | Statut | Code | Test | Écart / tâche |
|---|---|---|---|---|---|
| ET-01 | Serveur MCP, SDK officiel, transport de référence stdio | partiel | `__main__.py --stdio`, `server.py` (`mcp==2.2.0`) | `test_fasttrack.py::test_mcp_lists_tools_and_runs` (client en mémoire) | stdio jamais vérifié depuis Windows (`docker exec -i`). HTTP = écart documenté (L2 §6). → 4.4 |
| ET-02 | Outils en sous-processus, timeout, sortie bornée | fait | `runner.run_process` (sans shell, timeout, `max_output_mb`, arrêt du groupe de processus, fichiers tronqués à la borne) ; `contract.fit` (`max_response_kb`) | `test_phase2.py::test_runner_kills_on_timeout`, `test_socle.py::test_runner_bounds_output`, `::test_tool_output_bound_is_journaled`, `::test_response_size_is_bounded` | — |
| ET-03 | Sorties JSON structurées | fait | `contract.py` (contrat §5 + `iocs`, `decoded`), `schemas.validate_output` appelé sur **chaque** réponse dans `ops.Engine.call` | `test_socle.py::test_every_tool_response_matches_contract` (les 19 outils), `test_memory.py` | — |
| ET-04 | Journal d'audit horodaté et rejouable | fait (socle) | `audit.py` (types, `audit_id`, `ts_utc`, verrou `flock`, `verify_report` : chaîne + séquence + schéma, `head_hash`), `ops.Engine.call` (`tool_call` automatique : ok / tool_error / timeout / refused), `replay` | `test_socle.py::test_every_call_is_journaled_ok_refused_failed`, `::test_concurrent_appends_keep_the_chain`, `::test_verify_detects_schema_and_sequence_errors`, `::test_replay_reruns_and_compares` ; `test_phase2.py::test_audit_chain_detects_tampering` | Événements `suggestion`, `validation` : 4.4 ; `crisis_event` : 6.1 ; ancrage du hash de tête dans le rapport : 4.4. |
| ET-05 | Validation des chemins (jail) | fait | `safety.jail_path` (`resolve` + `is_relative_to`), message explicite « placer la preuve sous EVIDENCE_DIR » | `test_phase2.py::test_jail_*`, `test_socle.py::test_every_call_is_journaled_ok_refused_failed` | — |
| ET-06 | Skill au format SKILL.md | manquant | — | — | `skills/playbook-poste-compromis/`. → P5 |
| ET-07 | LLM cloud et LLM local | partiel | `llm_mode` appliqué par `redact.pseudonymizer_for` ; service `webui` (Open WebUI + Ollama) | `test_socle.py::test_*_cloud_mode` | Serveur MCP pas encore enregistré dans Open WebUI ; mode déclaré, pas détecté (L2 §12 point 2). → 5.2 |
| ET-08 | Machine d'analyse Linux | fait | `Dockerfile`, `docker-compose.yml` | Phase 1 : `check_tools.py` 20/20 | Justification : L2 §5. Épinglage des versions à faire (L2 §12 point 4). |
| ET-09 | ≥ 1 test unitaire par outil exposé | partiel | 58 tests, faux `vol` et faux `vol2` dans `tests/fakebin/` | `test_memory.py` : un test par outil mémoire ; `test_socle.py` : les 19 outils | Outils EZ (4.3a/b) ; test de référence (4.4). |

## 3. Garde-fous (CDC §5)

Conception, risque couvert et test d'acceptation de chaque garde-fou : L2 §10.

| Garde-fou | Statut | Code | Test | Écart / tâche |
|---|---|---|---|---|
| Validation humaine | partiel | Classes MCP : `read`, `journal`, `action_on_demand` (`vol_malfind`, `vol3_run`, `vol2_run`, `replay`) ; plugins sensibles (`hashdump`, `lsadump`, `cachedump`, `dumpfiles`, `pedump`, `layerwriter`, `truecrypt`, `--dump`) exécutés **seulement** après confirmation nominative par formulaire MCP (*elicitation* via un *resolver* du SDK, protocole 2025-11-25 ou 2026-07-28) ; `action_request` + `action_confirmed` journalisés (approuvé / refusé / client incapable) ; le schéma refuse une validation par le LLM | `test_memory.py::test_vol_malfind_dump_needs_named_confirmation`, `::test_vol3_sensitive_plugin_refused_then_approved`, `test_socle.py::test_tools_are_annotated_and_actions_only_on_demand` | Open WebUI : support du formulaire à vérifier (sinon refus) ; validation des findings (4.4) ; décision 3 côté analyste. |
| Traçabilité | partiel | `tool_call` automatique pour **chaque** appel, y compris refusé ou en erreur ; `audit_id` dans chaque réponse et chaque message d'erreur | `test_socle.py::test_every_call_is_journaled_ok_refused_failed` | `record_finding` pour les suggestions ; rapport citant les `audit_id`. → 4.4 |
| Chaîne de preuve | partiel | Montage `:ro` ; SHA-256 complet à l'enregistrement, avant analyse ; contrôle taille/mtime avant chaque appel (preuve modifiée ⇒ refus + `evidence_verified`) ; `verify_evidence` (re-hachage) ; cache de hash supprimé | `test_socle.py::test_registration_before_analysis_and_change_detected` | Hashes avant/après dans le rapport exporté. → 4.4 ; manifeste de collecte `scripts/register_evidence.py` → 3.2 |
| Données confidentielles | fait | `redact.py` : `case.toml` (`lab` / `internal` / `client`) ; `client` + cloud ⇒ refus (et masqué des listes) ; `internal` + cloud ⇒ `HOST_n`, `USER_n`, `IP_EXT_n`, `IP_INT_n` stables, table côté serveur (`/output/.pseudo/`), jetons acceptés en entrée ; journal et disque gardent les valeurs réelles | `test_socle.py::test_client_case_refused_in_cloud_mode`, `::test_internal_case_pseudonymised_in_cloud_mode`, `::test_lab_case_and_local_mode_stay_raw` | Limites : IPv6 non pseudonymisées ; noms reconnus seulement par colonne (hôte / utilisateur) ou déclarés dans `case.toml` ; messages d'erreur non pseudonymisés ; mode déclaré, pas détecté. → L7 |
| Limites de confiance | manquant | — | — | `confidence` sur chaque finding + revérification serveur. → 4.4 |
| Anti-hallucination | partiel | Faits calculés par le serveur : `row_count`, anomalies et identifiants ATT&CK (table de règles), décodage PowerShell (≤ 2 couches), IOC, `_row` ; entiers > 2^53−1 en hexadécimal | `test_rules.py`, `test_fasttrack.py::test_big_int_addresses_are_exact_hex` | Contre-vérification des citations dans `record_finding`. → 4.4 |
| Excès de confiance | manquant | — | — | Statut « à valider », nom du relecteur, export final refusé sinon. → 4.4 / 6.1 |
| Injection de prompt | fait | Texte rendu entre `<<<EVIDENCE DATA …>>>` et `<<<END EVIDENCE DATA>>>`, `<` échappé (`<`) : une donnée ne peut pas fermer le marqueur ; `untrusted_notice` ; paramètres typés ; aucun outil d'action | `test_socle.py::test_text_is_wrapped_and_injection_stays_data` | Les marqueurs réduisent le risque sans l'annuler (modèle qui obéit quand même) → L7. |

## 4. Objectifs mesurables (CDC §2)

| Objectif | Mesuré par | Tâche |
|---|---|---|
| O1 : −30 % de temps de triage initial | `eval/score.py` (horodatages du journal) | P7 |
| O2 : ≥ 80 % des IOC / étapes retrouvés | `eval/score.py` vs `eval/ground_truth.yaml` | 3.2, P7 |
| O3 : 100 % des appels et suggestions tracés | `tool_call` automatique (**fait**, 4.1) + `record_finding` + `verify_audit` | 4.4 |
| O4 : sitrep conforme en < 10 min | `sitrep_draft` chronométré | 6.1, P7 |
| O5 : risques LLM et garde-fous documentés | L2 (matrice), L7 | P8 |

## 5. Décision J3 — extension de périmètre (30/09/2026, L. Plancke)

Volatility 2 et Volatility 3 avec **tous** leurs plugins, et les **17** outils Eric Zimmerman,
sont exposés (investigation d'une image disque, tous artefacts). Règle 8 maintenue (noms issus
de la liste découverte ou du registre, options typées) ; vol2 `--plugins`, `-w/--write`,
`-D/--dump-dir` interdits ; plugins sensibles soumis à confirmation humaine. Détail et impact
sur le Gantt (4.3 découpée en 4.3a/4.3b/4.3c, M4 → J12, M5 → J14) : L2 §12.

| ID | Prio | Exigence | Statut | Tâche |
|---|---|---|---|---|
| EXT-01 | M (décision) | vol2 + tous les plugins vol3, options typées, plugins sensibles confirmés | fait | 4.2 : `vol3_run`, `vol2_list_plugins`, `vol2_imageinfo` (cache par hash), `vol2_run` ; vol2 `--plugins`, `-w`, `-D` jamais passés, plugins vol2 à `-D` refusés |
| EXT-02 | M (décision) | 17 outils EZ + extraction depuis image disque | manquant | 4.3a / 4.3b / 4.3c |

## 6. Écarts de périmètre et éléments hérités

| Élément | Constat | Décision / état |
|---|---|---|
| Transport HTTP + jeton bearer + Open WebUI | Écart à ET-01, déjà construit | Conservé pour le mode LLM local (ET-07) ; L2 §6 ; transport par défaut à trancher (L2 §12 point 1). |
| Volatility 2, 15 outils Zimmerman | Installés, non exposés | Conforme au périmètre. `validate_args` / `FORBIDDEN_FLAGS` **retirés** (décision 5, 4.1). |
| `max_upload_gb` | Clé sans usage | **Retirée** (décision 5, 4.1) ; la config la refuse désormais. |
| Cache SHA-256 (`output/.cache/sha256.json`) | Pas une preuve avant/après | **Remplacé** par `evidence_registry.json` + journal (4.1). L'ancien dossier `output/.cache/` n'est plus lu (à supprimer à la main). |
| `memory_run(path, plugin, pid)` générique | Tout plugin exécutable (ex. résultats `windows.registry.hashdump` et `windows.dumpfiles` du 29/09 dans `output/`) | **Remplacé** en 4.2 par `vol3_run` (options typées) avec confirmation humaine des plugins sensibles. |
| Noms d'outils (`memory_list_plugins`) | Différaient de la cible | **Renommés** en 4.2 (`vol_list_plugins`). |
| Versions non épinglées | Outils Zimmerman, `uvicorn`, `pyyaml`, `open-webui:main` | Épingler avant M3 (L2 §12 point 4), après accord. |
| Écriture concurrente du journal | Serveurs HTTP et stdio simultanés | **Fait** : verrou `flock` (4.1). |
| Contrôle rapide journalisé | L2 §9.3 prévoyait un `evidence_verified` à chaque appel | Implémenté : journalisé seulement en cas d'écart ; chaque `tool_call` porte le `evidence_sha256` vérifié (journal plus compact). |
