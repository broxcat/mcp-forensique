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

Une absence ne peut pas être enregistrée comme constat (il n'y a pas de ligne à citer) : la
présenter comme une **observation à valider**, avec le `result_id` et la note, jamais comme un fait.

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
