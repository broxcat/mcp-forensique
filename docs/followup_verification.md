# Contre-vérification des correctifs — 31 octobre 2026

Base : `2c519f4275fbaed99269e4f5267eff2c1093a5e1`.
Travail dans une worktree dédiée, conteneur temporaire sans réseau, sans montage
de preuves ni journal réels. Les attestations de tests sont synthétiques.

## F01 — Vues de crise (CDC §5, EF-12, EF-13, EF-15)

Les vues globales sont conservées : avant tout filtrage ou compteur, chaque
dossier contributeur est contrôlé. Un contributeur client interdit la vue en
cloud ; chaque cas interne possède son pseudonymiseur et son apprentissage des
contacts. Les vues ciblées restent limitées au dossier demandé.
Les alias de chemins sont résolus par la jail puis ramenés à un périmètre canonique.
La racine (`""`, `.`, `./`, `LAB/..`) désigne la même vue globale ; un sitrep
exige toujours un paramètre de dossier explicite. Ses dossiers contributeurs
sont conservés dans les métadonnées pour les consultations ultérieures.

Validation : avant correction, 12 échecs / 1 réussite pour les premiers tests F01.
