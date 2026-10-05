# Confinement et gestion de crise (EF-12, EF-13, EF-14)

L'assistant **propose**, la cellule de crise **décide**, les équipes **exécutent**. Aucune
action sur l'infrastructure n'est faite par l'assistant ni par le serveur (hors périmètre du
CDC). Données source : `rules/containment.yaml` ; outil `containment_suggestions(incident_type)`.

## Outils de crise

| Outil | Rôle |
|---|---|
| `crisis_add_event` | Ajoute à la chronologie de crise un événement, une décision ou une action (heure UTC, responsable, source) ; journalisé |
| `crisis_timeline` | Chronologie de crise triée en UTC |
| `sitrep_draft` | Brouillon de point de situation (situation, impact, actions, prochaines étapes, décisions attendues) à partir des constats **validés** et de la chronologie ; à relire avant diffusion |
| `containment_suggestions` | Mesures de confinement proposées pour un type d'incident, toutes « à valider » |

Règles : une entrée de chronologie cite sa source (constat `F-NNNN`, `audit_id` ou personne) ;
le sitrep ne reprend que les constats validés par un analyste ; une suggestion de confinement
n'est jamais présentée comme faite.

Qui prévenir (direction, DPO, juridique, assureur, autorité…) : voir
[coordination des parties prenantes](coordination.md) et l'outil `stakeholder_suggest(case,
incident_type)` ; le tableau (`stakeholder_upsert`, `comms_log`) alimente la section 6 du sitrep.
Le serveur n'envoie aucun message.

## Mesures communes

| Identifiant | Mesure | Responsable |
|---|---|---|
| `preserver_preuves` | Dump mémoire puis collecte avant toute action ; ne pas éteindre ni redémarrer | Analyste forensique |
| `journal_crise` | Consigner chaque décision et action dans la chronologie de crise | Responsable de crise |

## Rançongiciel (`ransomware`)

| Identifiant | Mesure | Responsable |
|---|---|---|
| `rw_isoler` | Isoler du réseau les postes et serveurs touchés, sans les éteindre | Équipe réseau / SOC |
| `rw_sauvegardes` | Déconnecter et protéger les sauvegardes, vérifier qu'elles sont saines | Équipe infrastructure |
| `rw_comptes` | Réinitialiser les comptes à privilèges utilisés, désactiver les comptes inconnus | Équipe annuaire / IAM |
| `rw_flux` | Bloquer les IOC réseau validés au pare-feu et au proxy | Équipe réseau |
| `rw_notifier` | Évaluer les notifications (CNIL 72 h, ANSSI / CERT-FR, assureur) et la plainte | Juridique / DPO |

## Compte compromis (`compte_compromis`)

| Identifiant | Mesure | Responsable |
|---|---|---|
| `cc_reinitialiser` | Réinitialiser le mot de passe, révoquer sessions et jetons | Équipe annuaire / IAM |
| `cc_mfa` | Vérifier ou imposer le MFA, retirer les facteurs ajoutés | Équipe annuaire / IAM |
| `cc_perimetre` | Lister les connexions du compte pour définir le périmètre | Analyste forensique |
| `cc_privileges` | Retirer temporairement les droits non indispensables | Équipe annuaire / IAM |

## Exfiltration (`exfiltration`)

| Identifiant | Mesure | Responsable |
|---|---|---|
| `ex_flux` | Bloquer les destinations d'exfiltration validées | Équipe réseau |
| `ex_isoler` | Isoler les postes sources, sans les éteindre | Équipe réseau / SOC |
| `ex_perimetre` | Identifier les données concernées | Analyste forensique |
| `ex_notifier` | Évaluer les notifications (CNIL 72 h, clients, partenaires) et la plainte | Juridique / DPO |
