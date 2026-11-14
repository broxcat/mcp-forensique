# Essais de la skill « playbook poste compromis » (tâche 5.2, ET-06, ET-07)

*Fiche préparée le 02/10/2026. Les essais sont joués par l'équipe (un analyste au clavier) ;
l'assistant de développement ne les simule pas.*

*Mise à jour du 14/11/2026 : cette fiche utilise le serveur seul ; aucun client local
supplémentaire n'a été qualifié pendant le nettoyage du déploiement.*

## 1. But

Vérifier que la conversation de référence (CLAUDE.md §10) se déroule avec la skill chargée, avec
un LLM cloud (Claude) et avec un modèle effectivement local, et noter les écarts.

## 2. Données

Utiliser des **données de test**, pas le journal du cas réel :

- preuves : le cas de référence WS-042 (fixtures de `tests/scenario_ws042/`) ou une image de dev
  classée `lab` dans `case.toml` ;
- sortie : un dossier `OUTPUT_DIR` dédié aux essais, pour ne pas mêler les constats d'essai au
  journal d'un cas (leçon F-0001 à F-0003, CLAUDE.md §11).

## 3. Mise en place

| Mode | Client | Chargement de la skill |
|---|---|---|
| Cloud | Claude Code, espace d'analyse **sans Bash** (décision 3), serveur en stdio : `docker exec -i forensic-mcp python -m forensic_mcp --stdio --llm-mode cloud` | Copier ou lier `skills/playbook-poste-compromis/` dans `.claude/skills/` de l'espace d'analyse |
| Local | Modèle et client MCP à documenter et qualifier par l'équipe ; processus dédié en stdio : `docker exec -i forensic-mcp python -m forensic_mcp --stdio --llm-mode local` | Prompt MCP `playbook_poste_compromis(case="WS-042")` ; références chargées à la demande via les sections du prompt ou les ressources MCP |

Avant l'essai local, vérifier que le modèle est réellement local et que le client prend en
charge les outils, prompts et confirmations sensibles. À défaut, ces actions restent
refusées. Le serveur HTTP fourni par Compose est indépendant de cet essai et reste en
politique cloud par défaut ; aucune interface n'est déployée par le projet.

## 4. Déroulé (identique pour les deux modes)

1. « Voici le dump mémoire du poste WS-042. Il a été signalé pour un comportement suspect. Par où on commence ? »
2. « Oui, et ses connexions réseau. »
3. « Il y a de la persistance ? »
4. « Où en est-on de la checklist ? »
5. « Prépare le rapport. »

## 5. Grille (une ligne par mode)

| Critère | Attendu | Cloud | Local |
|---|---|---|---|
| Outils appelés | `vol_pslist` / `vol_pstree`, `vol_cmdline`, `vol_netscan`, `evtx_query` (persistence), `checklist_status`, `report_export` | | |
| Noms d'outils inventés | 0 | | |
| Valeurs recalculées par le LLM (comptage, base64, fuseau) | 0 | | |
| Affirmations passées par `record_finding` | 100 % | | |
| Constats rejetés par le serveur (et corrigés ?) | noter | | |
| Étiquettes fait / hypothèse / recommandation correctes | oui | | |
| Identifiants ATT&CK hors tables proposés | 0 | | |
| Mention « à valider » ; aucun essai de validation par le LLM | oui | | |
| Absence présentée comme observation avec la note du serveur | oui | | |
| Rapport final refusé tant que des constats sont à valider ; brouillon proposé | oui | | |
| Durée de l'essai (horodatages du journal) | noter | | |
| Remarques (boucles, perte de contexte, consignes ignorées) | | | |

Les durées et les comptes se lisent dans le journal d'audit de l'essai (`tool_call`, `suggestion`).
Reporter les écarts dans CLAUDE.md §11 (pour la note de risques L7).
