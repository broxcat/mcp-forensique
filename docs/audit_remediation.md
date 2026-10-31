# Corrections de l’audit du 31 octobre 2026

Référence : bfea22c53615464b9ed9a03ae6d8deea790146b9. Les tests de
régression utilisent le SDK, jsonschema, YAML et les verrous Linux réels dans
l’image du projet. Les preuves des tests sont synthétiques, jamais des résultats de lab.

## R03 — Provenance des extractions (EF-05, EF-10, CDC §5)

La résolution de classification remonte tous les parents par `meta.json`, pour
disque, mémoire et réseau. Les chaînes absentes, cycliques, hors racine ou de plus
de 32 niveaux sont refusées, sans retour silencieux à internal.

## R04 — Réutilisation par inode (EF-04, EF-05)

Les références `disk_extract_file` passent par la même racine `extracted/`
que les autres extractions. Les traversées restent interdites. Le test chaîne
l’extraction à verify_evidence et au parseur MFT (binaire de test synthétique).
