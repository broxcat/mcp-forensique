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

## R01 — Lectures de synthèse (CDC §5, EF-10, ET-04)

Les constats, rapports et consultations ultérieures résolvent toutes les sources
citées. En cloud, client est refusé et les politiques internes sont composées.
Une ancienne synthèse sans provenance est refusée : la régénérer localement.
Les fichiers bruts restent sensibles et doivent être protégés côté serveur.

## R02 — Isolation des sitreps (EF-12, EF-13, CDC §5)

Un dossier explicite est obligatoire. Tous les parents des citations d’un constat
doivent appartenir à ce dossier ; les constats multi-dossiers sont exclus.
Recommandations et compteurs sont calculés après filtrage. La politique du dossier
est conservée même si le sitrep ne contient aucun constat.

## R05 — Dossiers parents (CDC §5, EF-05)

La politique d’un répertoire examine chaque fichier descendant avant son
enregistrement ou son analyse. Une source client bloque l’ensemble en cloud ;
les politiques internes des sous-dossiers sont composées. Ce contrôle couvre
aussi le périmètre de timeline.
