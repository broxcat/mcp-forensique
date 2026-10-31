# Mesurer la traçabilité — 31 octobre 2026

Exigences : CDC §2 O3, ET-04. Le journal couvre les appels atteignant
`Engine.call` et les événements métier enregistrés. Il ne couvre pas à lui seul
les suggestions du chat, les analyses externes ou les refus antérieurs du SDK.

Pour chaque session d’évaluation, conserver une transcription horodatée complète,
sa version et son empreinte, puis établir une table de rapprochement :

| Suggestion ou appel dans la transcription | Identifiant du journal | Rejouable | Motif d’exclusion |
|---|---|---|---|
| À renseigner par l’équipe | | | |

Calculer séparément : appels journalisés / appels observés dans la transcription ;
suggestions enregistrées / suggestions observées dans la transcription ; appels
rejoués et comparés / appels éligibles. Publier numérateurs, dénominateurs et
exclusions. Une session sans transcription n’a pas de taux global mesurable.

La vérification du chaînage prouve sa cohérence interne. Une réécriture complète
reste possible pour un acteur contrôlant le stockage : conserver la tête du
journal et l’empreinte de la transcription hors du poste, dans un emplacement
contrôlé par l’équipe. Aucun ancrage ni rapprochement réel n’a été effectué ici.
