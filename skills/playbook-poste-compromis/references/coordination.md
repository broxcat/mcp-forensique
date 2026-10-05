# Coordination des parties prenantes (EF-15)

Le serveur **propose** qui prévenir, la cellule de crise **décide**, une personne **prévient**.
Aucun outil n'envoie de message, de courriel ni n'appelle qui que ce soit : le tableau consigne
seulement ce qui a été décidé et fait. Données source : `rules/stakeholders.yaml`.

## Outils

| Outil | Rôle |
|---|---|
| `stakeholder_suggest(case, incident_type)` | Parties prenantes à proposer pour `ransomware`, `compte_compromis`, `exfiltration` ou `autre` : ordre, délai indicatif, motif, règle d'origine. Tout est « à valider » ; rien n'est écrit au tableau |
| `stakeholder_upsert(case, role, …)` | Ajoute ou met à jour une entrée `S-NNNN` (rôle, nom, organisation, canal, responsable, échéance, statut, note, source) ; chaque appel ajoute un événement au journal |
| `stakeholder_list(case, status, role)` | Tableau courant recalculé depuis le journal ; `en_retard` calculé par le serveur |
| `comms_log(case, stakeholder_id, direction, summary, at_utc)` | Consigne une communication **déjà faite** (sortante / entrante) ; ne change pas le statut |

## Statuts

`a_prevenir` → `prevenu` → `accuse_reception` ; `sans_objet` si la partie prenante n'est pas
concernée ; `a_revoir` si la décision doit être reprise. Seuls `prevenu` et `accuse_reception`
apparaissent comme faits dans le sitrep (section 6) ; les autres sont listés « à prévenir / en
attente ». Une communication sortante consignée ne passe pas l'entrée à `prevenu` : une personne
le décide avec `stakeholder_upsert`.

## Règles

- Heures en ISO-8601 **avec décalage** (`Z` ou `+02:00`), converties en UTC. Avec le statut
  `prevenu` ou `accuse_reception`, `notify_by_utc` est l'heure à laquelle la personne a été
  prévenue : jamais dans le futur.
- `source` peut citer un constat `F-NNNN`, un `audit_id` ou un `result_id` : le serveur vérifie
  qu'ils existent.
- Noms et notes sont des données personnelles : en mode cloud, le serveur les remplace par
  `PERSON_n` / `CONTACT_n` (correspondance gardée côté serveur, jetons acceptés en entrée).
  Ne jamais saisir de vrais numéros ni adresses dans les fichiers du dépôt.
- Délais légaux, réglementaires ou contractuels : **à confirmer par le juridique**. Pour une
  violation de données personnelles, l'obligation de notifier l'autorité de protection des
  données est **à évaluer par le DPO / le juridique** ; l'assistant ne donne aucun avis juridique.

## Suggestions par type d'incident

Communes à tous les types :

| Règle | Rôle | Ordre |
|---|---|---|
| `sh_rssi` | RSSI | 1 |
| `sh_dsi` | DSI | 1 |
| `sh_direction` | Direction générale | 2 |
| `sh_juridique` | Service juridique | 2 |
| `sh_dpo` | DPO | 2 |

| Type | Règle | Rôle | Ordre |
|---|---|---|---|
| Rançongiciel | `rw_prestataire` | Prestataire IT / infogérant | 1 |
| Rançongiciel | `rw_assurance` | Assureur cyber (délai à confirmer par le juridique) | 3 |
| Rançongiciel | `rw_autorite` | Autorité de protection des données (à évaluer par le DPO / le juridique) | 3 |
| Rançongiciel | `rw_communication` | Communication | 3 |
| Compte compromis | `cc_prestataire` | Prestataire IT / infogérant | 1 |
| Compte compromis | `cc_rh` | Ressources humaines | 3 |
| Compte compromis | `cc_fournisseur` | Fournisseur concerné | 3 |
| Compte compromis | `cc_autorite` | Autorité de protection des données (à évaluer par le DPO / le juridique) | 4 |
| Exfiltration | `ex_autorite` | Autorité de protection des données (à évaluer par le DPO / le juridique) | 3 |
| Exfiltration | `ex_client` | Client(s) concerné(s) (à confirmer par le juridique) | 3 |
| Exfiltration | `ex_assurance` | Assureur cyber (délai à confirmer par le juridique) | 3 |
| Exfiltration | `ex_communication` | Communication | 4 |
| Autre | `au_autre` | Autre partie prenante | 3 |

## Déroulé type

1. `stakeholder_suggest` dès la qualification de l'incident ; la cellule retient ou écarte.
2. `stakeholder_upsert` pour chaque partie prenante retenue (statut `a_prevenir`, responsable,
   échéance).
3. Une personne prévient ; `comms_log` consigne l'échange, puis `stakeholder_upsert` passe le
   statut à `prevenu` (ou `accuse_reception`).
4. `stakeholder_list` pour suivre les entrées en retard ; `sitrep_draft` reprend le tableau
   (section 6) ; `crisis_timeline` montre changements de statut et communications en UTC.
