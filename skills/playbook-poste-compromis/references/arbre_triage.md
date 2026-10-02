# Arbre de triage — poste Windows compromis (EF-09)

Chaque branche pose des questions ; chaque question indique les outils du serveur qui y
répondent et les techniques MITRE ATT&CK associées. Ces identifiants (avec ceux des anomalies
du serveur, `rules/process_rules.yaml`) sont les **seuls** que `record_finding` accepte. Données
source : `rules/triage_tree.yaml`. Commencer par la branche qu'indiquent les anomalies du
serveur ; une réponse positive ouvre souvent une autre branche (une exécution suspecte mène à la
persistance, une connexion sortante à l'exfiltration).

## Exécution

| Question | Outils | ATT&CK |
|---|---|---|
| Un programme Office a-t-il lancé un interpréteur (PowerShell, cmd, wscript, mshta…) ? | `vol_pslist`, `vol_pstree` | T1566.001, T1204.002, T1059 |
| Des commandes PowerShell encodées ou des blocs de script suspects ? | `vol_cmdline`, `evtx_query` (execution) | T1059.001, T1027 |
| Un interpréteur de commandes Windows a-t-il été utilisé ? | `vol_cmdline`, `evtx_query` (execution) | T1059.003 |
| Quels exécutables ont tourné, et quand ? | `prefetch_query`, `amcache_query`, `shimcache_query` | T1204.002 |

## Persistance

| Question | Outils | ATT&CK |
|---|---|---|
| Une tâche planifiée a-t-elle été créée (4698, 106) ? | `evtx_query` (persistence), `disk_extract` (scheduled_tasks) | T1053.005 |
| Une clé Run ou le dossier Démarrage pointe-t-il vers un exécutable inconnu ? | `vol_printkey`, `ez_run` (RECmd) | T1547.001 |
| Un service a-t-il été installé (7045, 4697) ? | `evtx_query` (persistence), `vol3_run` (windows.svcscan) | T1543.003 |

## Mouvement latéral et identifiants

| Question | Outils | ATT&CK |
|---|---|---|
| Des sessions RDP entrantes ou sortantes ? | `evtx_query` (rdp, logons) | T1021.001 |
| Des identifiants explicites ou des comptes valides utilisés à distance ? | `evtx_query` (logons) | T1078, T1021.002 |
| Le processus LSASS a-t-il été lu ou vidé ? | `vol_pslist`, `vol_malfind`, `vol_cmdline` | T1003.001 |

## Collecte et exfiltration

| Question | Outils | ATT&CK |
|---|---|---|
| Des archives ont-elles été créées dans un dossier temporaire ou public ? | `mft_search` | T1560.001, T1074.001 |
| Des connexions sortantes vers des adresses publiques depuis un processus suspect ? | `vol_netscan`, `timeline` | T1071.001, T1041 |
| Des outils ou fichiers téléchargés, ou des envois vers un service web ? | `browser_history`, `srum_query`, `vol_cmdline` | T1105, T1567 |

## Dissimulation

| Question | Outils | ATT&CK |
|---|---|---|
| Des journaux ont-ils été effacés (1102, 104) ? | `evtx_query` (log_clearing) | T1070.001 |
| Du code a-t-il été injecté dans un autre processus ? | `vol_malfind` | T1055 |
| Un processus imite-t-il un binaire système (nom, chemin, parent) ? | `vol_pslist`, `vol_cmdline` | T1036, T1036.005 |

## Règle de sortie

Une question est close quand le serveur a répondu (même par « rien trouvé », en lisant ses
notes) et que la réponse est consignée avec `record_finding` (fait si observé, hypothèse sinon).
