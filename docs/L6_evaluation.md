# L6 — Rapport d'évaluation comparative (BROUILLON)

*Brouillon du 03/10/2026 (phase P7), préparé par l'agent de développement. Aucun résultat
d'évaluation n'a encore été mesuré : chaque valeur à obtenir est marquée **À MESURER**. Les
seuls chiffres présents sont des mesures techniques faites pendant le développement, signalées
comme telles. Les investigations chronométrées sont jouées par l'équipe (L. Plancke,
W. Triffault) ; le protocole ci-dessous est à confirmer avec le §6 du CDC.*

## 1. Objet

Mesurer ce que l'assistant (serveur `forensic-mcp` + skill « playbook poste compromis » +
assistant de crise) apporte à l'investigation d'un poste Windows compromis, par rapport à une
investigation classique, au regard des objectifs du CDC :

| Objectif | Cible | Mesure |
|---|---|---|
| O1 — temps de triage initial | ≥ 30 % de moins qu'en classique | durées des deux investigations (§5) |
| O2 — IOC et étapes retrouvés | ≥ 80 % de la vérité terrain | `eval/score.py` : rappel des faits, des IOC, des étapes |
| O3 — traçabilité | 100 % des appels et suggestions dans un journal horodaté et rejouable | journal d'audit (chaîne vérifiée), `replay` |
| O4 — sitrep | conforme en < 10 min à partir de la chronologie | délai jusqu'au sitrep relu et conforme |
| O5 — risques LLM | documentés avec leurs garde-fous | note de risques L7 |

## 2. Dispositif évalué

- Serveur `forensic-mcp` (49 outils, journal d'audit chaîné, contre-vérification des constats,
  validation hors bande), image Docker épinglée (commit à indiquer : **À COMPLÉTER**).
- Skill `playbook-poste-compromis` (SKILL.md + 5 références), chargée dans Claude Code ou
  fournie par le prompt MCP au modèle local.
- Deux modes de LLM (ET-07) : **cloud** (Claude, via Claude Code, sans shell : modèle
  `templates/analysis-workspace/`) et **local** (modèle Ollama : **À COMPLÉTER** nom, taille,
  quantification ; via Open WebUI 0.11.4).

## 3. Jeu de données

Scénario du livrable L3 (poste WS-042 et second hôte, 5 étapes du CDC), preuves collectées en
J6 et enregistrées avec `scripts/register_evidence.py` (manifeste « before » : **À COMPLÉTER**),
vérité terrain `eval/ground_truth.yaml` remplie par l'équipe (`status: filled`).

| Élément | Valeur |
|---|---|
| Hôtes | **À COMPLÉTER** |
| Taille du dump mémoire / de la collecte KAPE | **À MESURER** |
| Étapes, faits attendus, IOC de la vérité terrain | **À COMPLÉTER** (nombres) |
| Empreinte du manifeste « before » | **À COMPLÉTER** |

## 4. Protocole

### 4.1 Investigations

| Session | Analyste | Outils | Mode LLM |
|---|---|---|---|
| A — classique | **À COMPLÉTER** | Volatility, EvtxECmd, MFTECmd, Timeline Explorer… en ligne de commande, sans assistant | — |
| B — assistée (cloud) | **À COMPLÉTER** | Claude Code + `forensic-mcp` + skill | cloud |
| C — assistée (local) | **À COMPLÉTER** | Open WebUI + `forensic-mcp` + prompt MCP | local |

Règles communes :

1. Même scénario, mêmes preuves (empreintes vérifiées avant et après chaque session).
2. Même consigne de départ : « Le poste WS-042 a été signalé pour un comportement suspect.
   Établir ce qui s'est passé, les IOC et les mesures à proposer ; produire un sitrep. »
3. Chronométrage : début = première commande (A) ou premier appel d'outil (B, C) ; fin du
   triage initial = **À DÉFINIR avec le CDC §6** (par exemple, premier constat validé de chaque
   étape trouvée, ou fin déclarée par l'analyste).
4. Les constats des sessions assistées sont validés ou rejetés par l'analyste, hors MCP ; le
   sitrep est relu avant d'être déclaré conforme.
5. Chaque session assistée a son propre dossier de sortie (`OUTPUT_DIR`), pour que le journal
   ne mélange pas les sessions.
6. Le résultat de la session A est reporté dans la même grille, par l'analyste, avec ses
   sources (outil et ligne).

### 4.2 Biais connus et parades

| Biais | Parade |
|---|---|
| Apprentissage : le même analyste connaît le scénario après la première session | Analystes différents par session, ou ordre inversé sur un second scénario (**À DÉCIDER**) |
| L'équipe a construit le scénario et l'outil | Analyste extérieur pour au moins une session (**À DÉCIDER**) ; vérité terrain figée avant les sessions |
| Variabilité du LLM (réponses non déterministes) | Noter la version du modèle ; au moins **À DÉCIDER** répétitions par mode |
| Échantillon très petit (un scénario) | Résultats présentés comme une étude de cas, sans généralisation |

## 5. Mesures

Calculées par `eval/score.py` sur le journal de chaque session assistée (session A : grille
remplie à la main). Définitions :

| Mesure | Définition |
|---|---|
| Outils attendus appelés | outils du serveur cités par les faits attendus et appelés avec succès |
| Faits retrouvés | fait attendu cité par un constat **de type fait ou observation** accepté par le serveur (même outil producteur, même preuve, même champ, même valeur) |
| Faits retrouvés puis validés | le constat qui retrouve le fait a été validé par l'analyste |
| Précision | part des constats de type fait acceptés qui correspondent à un fait attendu |
| Rappel des IOC / des étapes | IOC présents dans un constat accepté ; étape dont au moins un fait est retrouvé |
| Citations valides | citations recontrôlées sans écart par `record_finding` |
| Hallucinations | constats rejetés par la contre-vérification du serveur (valeur, ligne, résultat ou ATT&CK inexistants), avec leurs motifs |
| Délais | début de session → premier constat, première validation, premier sitrep |

## 6. Résultats

### 6.1 Synthèse

| Mesure | A — classique | B — cloud | C — local |
|---|---|---|---|
| Durée du triage initial | **À MESURER** | **À MESURER** | **À MESURER** |
| Gain de temps vs A (O1 ≥ 30 %) | — | **À MESURER** | **À MESURER** |
| Rappel des faits (O2 ≥ 80 %) | **À MESURER** | **À MESURER** | **À MESURER** |
| Rappel des IOC | **À MESURER** | **À MESURER** | **À MESURER** |
| Étapes retrouvées (sur 5) | **À MESURER** | **À MESURER** | **À MESURER** |
| Précision des constats | **À MESURER** | **À MESURER** | **À MESURER** |
| Citations valides | — | **À MESURER** | **À MESURER** |
| Hallucinations (constats rejetés) | — | **À MESURER** | **À MESURER** |
| Constats validés / rejetés par l'analyste | — | **À MESURER** | **À MESURER** |
| Délai jusqu'au sitrep conforme (O4 < 10 min) | **À MESURER** | **À MESURER** | **À MESURER** |
| Appels journalisés / chaîne vérifiée (O3) | — | **À MESURER** | **À MESURER** |

### 6.2 Détail par étape du scénario

| Étape (CDC) | A | B | C |
|---|---|---|---|
| 1. Macro Office → PowerShell encodé | **À MESURER** | **À MESURER** | **À MESURER** |
| 2. Persistance : tâche planifiée + clé Run | **À MESURER** | **À MESURER** | **À MESURER** |
| 3. Vol d'identifiants + RDP vers un second hôte | **À MESURER** | **À MESURER** | **À MESURER** |
| 4. Archive dans un dossier temporaire | **À MESURER** | **À MESURER** | **À MESURER** |
| 5. Collecte | **À MESURER** | **À MESURER** | **À MESURER** |

### 6.3 Observations qualitatives

**À COMPLÉTER** après les sessions, avec la grille de `docs/essais_skill.md` : outils inventés,
valeurs recalculées par le LLM, boucles, perte de contexte, consignes ignorées, absences
présentées comme des faits, qualité du sitrep.

## 7. Mesures techniques déjà disponibles (développement, hors évaluation)

Ces valeurs viennent du développement (CLAUDE.md, STATUS) ; elles ne sont **pas** des résultats
de l'évaluation.

| Mesure | Valeur | Contexte |
|---|---|---|
| Premier appel sur une image de 5 Gio (hachage d'enregistrement) | ≈ 45 s | échantillon de dev Triage-Memory.mem |
| `windows.info` : premier appel / suivants | 54,0 s / 3,3 s | téléchargement puis cache des symboles |
| `vol_pslist` / `vol_netscan` / `vol_malfind` | 6,4 s / 87,4 s / 94,3 s | même échantillon, 30/09 |
| `evtx_query` (preset logons, Security.evtx réel) | 8,0 s, 2 007 lignes | 02/10 |
| Génération d'un sitrep par le serveur | 0,14 s | copie du journal réel, 03/10 ; **ne mesure pas O4**, qui est le délai humain jusqu'au sitrep relu |
| Contrôle de `eval/score.py` sur le cas synthétique WS-042 | faits 4/6, IOC 3/4, 7 constats faux rejetés sur 12 | cas de test conçu pour l'outil de notation, **pas une évaluation** |

## 8. Discussion

**À RÉDIGER** après les mesures : objectifs atteints ou non, apport selon le mode de LLM,
coût de la validation humaine, limites (§4.2), risques observés (renvoi au L7).

## 9. Conclusion

**À RÉDIGER.**

## Annexes

- A. Commande de notation, le conteneur étant lancé avec l'`OUTPUT_DIR` de la session :
  `docker compose exec forensic python eval/score.py --journal /output/audit.jsonl --json /output/score.json`
  (options `--from-audit-id` / `--since` pour isoler une session dans un journal partagé).
- B. Grille de l'essai de la skill : `docs/essais_skill.md`.
- C. Vérité terrain : `eval/ground_truth.yaml` et son schéma.
- D. Empreintes des preuves (manifestes « before » et « after ») : **À COMPLÉTER**.
