# Règles de citation des constats (EF-10, EF-11)

Ces règles s'appliquent à **toute** affirmation de l'assistant sur une preuve. Le serveur les fait
respecter : `record_finding` recontrôle chaque valeur citée et rejette le constat sinon.

## 1. Aucune affirmation sans `record_finding`

- Tout constat sur la preuve (processus, connexion, horodatage, IOC, technique ATT&CK) est
  enregistré avec `record_finding` **avant** d'être présenté comme établi à l'analyste.
- Dans la conversation, chaque affirmation renvoie à sa source : `result_id`, `_row`, et l'identifiant
  du constat (`F-NNNN`) une fois enregistré.
- Ce qui n'est pas enregistré n'existe pas pour le rapport : `report_export` ne reprend que les
  constats du journal.

## 2. Étiqueter : fait, hypothèse, recommandation

| `kind` | Quand | Exemple de formulation |
|---|---|---|
| `fact` | La valeur est **lue** dans une ligne de résultat du serveur | « `powershell.exe` (PID 4312) a pour parent `WINWORD.EXE` (PID 2980). » |
| `hypothesis` | Une **interprétation** des faits, plausible mais à vérifier | « Ce lancement est probablement dû à une macro Office. » |
| `recommendation` | Une **action proposée** à l'analyste ; jamais exécutée par l'assistant | « Extraire la tâche planifiée `UpdateSvc` du disque pour l'examiner. » |
| `observation` | Une **absence de trace vérifiée** dans un résultat cité (voir §7) | « Aucun événement 4698 dans le résultat de `evtx_query` (preset persistence) sur `Security.evtx`. » |

Une hypothèse ou une recommandation cite aussi les lignes qui la fondent. Ne jamais présenter une
hypothèse comme un fait : « typique de », « compatible avec », « suggère » signalent une hypothèse.

## 3. Niveau de confiance

| `confidence` | Sens |
|---|---|
| `high` | Valeur lue directement, recoupée par au moins une seconde source (mémoire et journal, par exemple) |
| `medium` | Valeur lue directement, une seule source ; ou interprétation appuyée par plusieurs faits |
| `low` | Interprétation fragile, source unique, artefact connu pour ses faux positifs (ShimCache, horodatages modifiables) |

## 4. Forme d'une citation

Chaque citation est `{result_id, row, field, value}` :

- `result_id` et `row` (`_row`) **tels que renvoyés** par le serveur ; ne jamais calculer un numéro
  de ligne ;
- `field` : le nom exact de la colonne (`PID`, `ForeignAddr`, `TimeCreated`…) ;
- `value` : la valeur **de la cellule**, recopiée.

Le serveur accepte la valeur si elle correspond à la cellule :

| Correspondance | Exemple |
|---|---|
| exacte (sans tenir compte de la casse) | `powershell.exe` = `PowerShell.EXE` |
| numérique (décimal ou hexadécimal) | `0xfffffa800577ba10` = sa valeur décimale |
| même instant UTC | `2026-10-06T14:32:07Z` = `2026-10-06T14:32:07.0000000+00:00` |
| extrait d'une cellule longue (≥ 64 caractères, extrait ≥ 4 caractères) | un chemin dans une longue ligne de commande |
| `field = "decoded"` | un extrait du texte que le **serveur** a décodé d'une commande PowerShell encodée |

Il rejette : aucune citation, `result_id` inconnu, ligne inexistante, colonne absente, valeur
absente de la cellule (le message donne la vraie valeur), identifiant ATT&CK que le serveur ne
fournit pas. **Un constat rejeté se corrige à partir de la vraie valeur ; il ne se reformule pas
sans source.**

## 5. Identifiants ATT&CK

Seulement ceux fournis par le serveur : `anomalies[].attack` d'un résultat, et l'arbre de triage
(`arbre_triage.md`). Ne jamais en déduire un autre « de mémoire ».

## 6. Ce que l'assistant ne calcule jamais

Il reprend les valeurs du serveur : `row_count` (pas de comptage), `decoded` (pas de décodage
base64), `timeline` et les dates UTC (pas de conversion de fuseau), `_row` (pas de numérotation),
`iocs`, `anomalies`.

## 7. Absences et résultats vides

« Aucun événement » ne veut pas dire « aucune activité ». Avant de conclure à une absence :

1. lire les `notes` du résultat (journal absent de la collecte, politique d'audit non activée) ;
2. dire **ce qui** a été cherché, **où** (fichier, `result_id`) et ce que la note du serveur indique.

Une absence vérifiée s'enregistre avec `kind="observation"`. Les citations portent sur un
résultat, avec `row = 0` et l'une de ces formes :

| `field` | `value` | Le serveur vérifie |
|---|---|---|
| `audit_id` | l'`audit_id` de l'appel (réponse du serveur) | cet appel porte sur ce `result_id`, s'est terminé « ok » et a renvoyé 0 ligne (cas des requêtes filtrées : `evtx_query`, `mft_search`, `query_results`…) |
| `*` | `null` | le résultat entier ne contient aucune ligne |
| une colonne (`ImageFileName`…) | la valeur cherchée | aucune ligne du résultat entier ne contient cette valeur dans cette colonne |

Il rejette l'observation si le résultat contient la trace, s'il n'existe pas, ou si l'outil qui
l'a produit a échoué (un outil en échec ne prouve aucune absence). Il **rédige lui-même** la
constatation (« Aucune ligne renvoyée par … ») et **recopie ses notes** (journal ou politique
d'audit requis) ; c'est ce texte qui figure dans le rapport. Pas d'identifiant ATT&CK.

Une observation dit seulement que **la trace est absente de l'artefact cité**, jamais que le
comportement n'a pas eu lieu : écrire « aucun 4698 dans ce journal », pas « aucune persistance ».
Elle est « à valider » comme les autres constats.

```json
{"kind": "observation", "confidence": "medium",
 "text": "Aucun événement de création de tâche dans Security.evtx (preset persistence)",
 "citations": [{"result_id": "<result_id renvoyé par evtx_query>", "row": 0,
                "field": "audit_id", "value": "<audit_id de cet appel>"}]}
```

## 8. « À valider »

Tout constat est « à valider » jusqu'à la décision d'un analyste nommé, prise **hors MCP**
(`python -m forensic_mcp validate`). L'assistant ne valide, ne rejette et ne change jamais le
statut d'un constat ; il ne propose le rapport final (`report_export(final=true)`) qu'une fois
tous les constats décidés.

## 9. Exemple (cas de référence WS-042)

> *(vol_pslist)* `powershell.exe` (PID 4312) a pour parent `WINWORD.EXE` (PID 2980) — anomalie
> `office_spawns_shell` (T1566.001, T1204.002, T1059), résultat `<result_id du pslist>`, lignes
> données par `anomalies[].rows`.
> Enregistré : **F-NNNN, fait, confiance moyenne, à valider**.
> Hypothèse (enregistrée à part, à valider) : lancement par une macro du document ouvert.

Les numéros de ligne viennent de la réponse du serveur (`_row`, `anomalies[].rows`) ; ceux
ci-dessous sont des emplacements à remplacer, jamais à deviner.

```json
{"kind": "fact", "confidence": "medium",
 "text": "powershell.exe (PID 4312) a pour parent WINWORD.EXE (PID 2980)",
 "attack": ["T1566.001", "T1204.002", "T1059"],
 "citations": [{"result_id": "<result_id du pslist>", "row": "<_row de powershell.exe>", "field": "PPID", "value": 2980},
               {"result_id": "<result_id du pslist>", "row": "<_row de WINWORD.EXE>", "field": "ImageFileName", "value": "WINWORD.EXE"}]}
```
