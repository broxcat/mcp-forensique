# Dossier d'analyse — modèle (décision 3)

Ce dossier est l'espace de travail de l'analyste qui enquête avec Claude Code. Il est **séparé
du dépôt de développement** : l'assistant d'analyse n'y a ni shell, ni accès direct aux preuves,
ni accès aux secrets ; il ne passe que par le serveur MCP `forensic-mcp`, qui journalise tout.

## Installation

1. Copier ce dossier (`.claude/settings.json`, `.mcp.json`) dans un dossier vide, par exemple
   `C:\analyse\WS-042\`.
2. Dans `.claude/settings.json`, remplacer `<EVIDENCE_DIR>`, `<OUTPUT_DIR>` et `<REPO_DIR>` par
   les chemins réels (dossier des preuves, dossier des résultats, dépôt `forensic-mcp`).
3. Copier ou lier la skill : `skills/playbook-poste-compromis/` du dépôt vers
   `.claude/skills/playbook-poste-compromis/` de ce dossier.
4. Le conteneur doit tourner : `docker compose up -d forensic` depuis le dépôt.
5. Lancer Claude Code dans ce dossier ; vérifier avec `/mcp` que `forensic` est connecté.

## Ce que le modèle interdit

| Règle | Pourquoi |
|---|---|
| `Bash`, `PowerShell` | Sans shell, l'assistant ne peut pas installer d'outil ni analyser une preuve hors du serveur (cas observé le 30/09, CLAUDE.md §11), ni lancer la validation des constats |
| `Edit`, `Write`, `NotebookEdit` | Pas d'écriture locale : rapports et sitreps sont produits par le serveur et journalisés |
| `Read` des preuves, des résultats, de `.secrets/`, de `.env` | Pas de lecture directe qui contournerait le journal ; aucun secret envoyé au fournisseur du modèle |
| `WebFetch`, `WebSearch` | Pas d'envoi de données d'enquête vers l'extérieur |

Seuls les outils `mcp__forensic__*` sont autorisés sans confirmation. La validation des
constats reste hors de ce dossier : `docker exec -it forensic-mcp python -m forensic_mcp validate`,
dans un terminal de l'analyste.

**Limite :** ces règles sont appliquées par le client (Claude Code). Elles ne protègent pas si
l'analyste les retire ou lance un autre client ; le journal d'audit et le hash de tête conservé
hors du poste restent la preuve de ce qui a été fait.
