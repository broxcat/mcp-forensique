# Checklist de collecte et d'analyse — poste Windows compromis (EF-08)

Ordre de volatilité : **mémoire d'abord**, puis disque, puis journaux. Les étapes marquées
« humaine » sont faites par l'analyste (le serveur ne voit que leur résultat : la preuve
enregistrée). L'état de chaque étape est calculé par l'outil `checklist_status(case)` à partir du
journal d'audit ; les identifiants ci-dessous sont ceux de `rules/checklist.yaml`.

## Cadrage

| Étape | Identifiant | Qui | Vérifiée par le serveur |
|---|---|---|---|
| Dossier `<HÔTE>/` sous la racine des preuves, avec `case.toml` (classification lab / internal / client) | `case_folder` | humaine | présence de `case.toml` |

Avant toute collecte : noter l'heure UTC, le fuseau du poste, qui intervient ; ne pas éteindre le
poste avant le dump mémoire ; ne rien installer sur le poste au-delà de l'outil de collecte.

## Collecte volatile

| Étape | Identifiant | Qui | Vérifiée par le serveur |
|---|---|---|---|
| Dump mémoire (WinPmem) copié dans `<HÔTE>/memory/` et enregistré (SHA-256) | `memory_acquired` | humaine | `evidence_registered` sous `memory/` |

## Collecte disque et journaux

| Étape | Identifiant | Qui | Vérifiée par le serveur |
|---|---|---|---|
| Collecte KAPE ($MFT, $J, ruches, EVTX, prefetch, profils) copiée dans `<HÔTE>/kape/` et enregistrée | `triage_acquired` | humaine | `evidence_registered` sous `kape/` |

Chaque fichier est haché à son enregistrement ; renseigner la fiche de chaîne de possession
(qui, quand, quel support, empreinte).

## Analyse mémoire

| Étape | Identifiant | Outils |
|---|---|---|
| Processus et arborescence (parents anormaux, doublons, noms imités) | `mem_processes` | `vol_pslist`, `vol_pstree` |
| Lignes de commande (PowerShell encodé décodé par le serveur, IOC) | `mem_cmdline` | `vol_cmdline` |
| Connexions réseau (adresses publiques, correspondance avec les IOC) | `mem_network` | `vol_netscan` |
| Code injecté | `mem_injection` | `vol_malfind` |
| Clés Run lues en mémoire | `mem_run_keys` | `vol_printkey` |

## Analyse disque

| Étape | Identifiant | Outils |
|---|---|---|
| $MFT : fichiers créés autour de l'incident (Temp, AppData, Public, archives) | `disk_mft` | `mft_search` |
| Registre : ShimCache, Amcache, persistance | `disk_registry` | `shimcache_query`, `amcache_query`, `ez_run` (RECmd, lot Kroll) |
| Traces d'exécution : prefetch, SRUM | `disk_execution` | `prefetch_query`, `srum_query` (export Windows puis import) |
| Activité utilisateur : LNK, jump lists, corbeille, navigateur | `disk_user_activity` | `lnk_query`, `jumplist_query`, `recyclebin_query`, `browser_history` |

## Journaux d'événements

| Étape | Identifiant | Outil |
|---|---|---|
| Ouvertures de session (4624, 4625, 4648, 4672) | `logs_logons` | `evtx_query(preset="logons")` |
| Sessions RDP (4778, 4779, 1149, 21, 25) | `logs_rdp` | `evtx_query(preset="rdp")` |
| Exécution (4688 avec ligne de commande, 4104) | `logs_execution` | `evtx_query(preset="execution")` |
| Persistance (4698, 106, 7045, 4697) | `logs_persistence` | `evtx_query(preset="persistence")` |
| Effacement de journaux (1102, 104) | `logs_clearing` | `evtx_query(preset="log_clearing")` |

Un preset vide n'est pas une absence d'activité : lire la note du serveur (journal absent de la
collecte, politique d'audit désactivée).

## Synthèse, validation, rapport

| Étape | Identifiant | Qui / outil |
|---|---|---|
| Chronologie UTC autour du premier indice | `timeline` | `timeline` |
| Constats enregistrés avec citations | `findings` | `record_finding` |
| Constats validés ou rejetés par un analyste nommé | `validation` | humaine, hors MCP : `python -m forensic_mcp validate` |
| Rapport final exporté, hash de tête du journal conservé hors du poste | `report` | `report_export(final=true)` |
