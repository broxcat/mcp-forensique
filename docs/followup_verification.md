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

## F02 — Intégrité avant politique et lecture (CDC §5, EF-05, EF-10, ET-04)

`verified_meta` contrôle le producteur et tous les manifestes parents avant de
parser les octets des métadonnées scellées. Le vérificateur d’intégrité ne dépend
d’aucune politique de classification. Lectures, listes, synthèses et caches passent
par ce contrôle ; les résultats non scellés sont refusés, les producteurs en échec
ne sont pas proposés dans le catalogue. Les diagnostics cloud restent génériques.
Les candidats de rapport sont scellés avant toute revue hors MCP, sans devenir
pour autant des exports finaux. Les anciennes fixtures R01/R02 créent désormais
de vrais producteurs de test, au lieu de métadonnées non scellées.

Validation avant correction : 17 échecs / 1 réussite aux premières régressions F02.
Après correction : 24 tests F02/R01/R02/C03 réussis ; 72 tests ciblés incluant
imports, réseau, rapports et playbook réussis lors du contrôle élargi.

## F03 — Preuves originales derrière les synthèses (CDC §5, EF-05, EF-10)

Le rapport parcourt récursivement le graphe scellé des citations : `policy_sources`,
entrées directes, extractions successives, imports Windows, sources auxiliaires et
manifestes d’export. Les preuves sont dédupliquées et leurs empreintes complètes
sont recalculées avant candidature puis après revue, même si taille/mtime restent
identiques. Les empreintes scellées et les manifestes de dossiers sont comparés,
en plus du registre. Les sources absentes, non enregistrées ou incohérentes bloquent
l’export. Les audit_id « après » figurent dans le candidat ; la finalisation lie
ses nouveaux événements de vérification sans réécrire les octets relus.
Les listings internes produits par une extraction sont également scellés, afin que
leur provenance soit vérifiable dans les parcours successifs.

Avant correction : les tests de timeline détectent le défaut de revérification ;
le parcours de deux extractions détecte aussi un listing interne sans producteur.
Après correction : 51 tests ciblés F03, rapports, extractions et imports réussis.
Le contrôle complet précédent, après F02, donnait 300 réussites en 131,88 s.

## F04 — Flux séparés et sorties natives (ET-02, CDC §9)

Le runner compte explicitement stdout et stderr, même hors du périmètre natif.
`output_dir` désigne le répertoire de tâche surveillé pour les nouveaux fichiers
natifs ; les moteurs le passent explicitement, notamment icat avec son stderr
dans le parent de `extracted/`. Les chemins résolus sont dédupliqués. Aucun ancêtre
commun arbitraire n’est parcouru. Les fichiers natifs préexistants et les autres
résultats sont exclus de la troncature ; les deux flux désignés restent les fichiers
de sortie appartenant à l’appelant, ouverts en écriture par le runner.
Les contrôles ont lieu pendant le processus et après sa terminaison. Un dépassement
arrête le groupe, borne les fichiers de cette exécution et signale un échec.

Avant correction : les quatre régressions F04 échouaient. Après correction :
38 tests ciblés F04, runner, tshark réel, extraction et socle réussis.

## Contre-vérifications fournies

Le script fourni a été recopié dans `.scratch/`, sans modification du fichier
original. Seuls les deux appels qui divulguaient auparavant des données ont été
adaptés pour accepter les refus ToolError attendus et poursuivre les quatre sondes.
Des assertions exigent les quatre protections :

- Vue globale de crise : aucune donnée client exposée en cloud.
- Métadonnées altérées : requête refusée, aucune donnée client retournée.
- Preuve derrière timeline modifiée : export refusé avant création du candidat.
- stderr séparé : dépassement détecté, 1 024 octets conservés pour une borne de 1 024.

Les quatre assertions passent dans le conteneur temporaire sans réseau. Aucun
nom de test ni aucune attestation synthétique n’est une revue humaine réelle.
Les limites organisationnelles et de lab du bilan initial restent applicables.
Le polling autorise toujours des pics transitoires : il ne remplace pas un quota
dur de système de fichiers.

## Validation finale

`docker exec forensic-followup-tests python -m pytest -q -p no:cacheprovider` :
**327 passed in 152.25s**, sans échec ni test ignoré. Compilation Python
(`compileall -q src eval`) réussie ; inventaire du README conforme.
Les quatre contre-vérifications adaptées aux refus attendus passent aussi.
Les tests utilisent les bibliothèques réelles du projet dans `forensic-mcp:dev`.
La majorité des moteurs forensiques des fixtures restent synthétiques ; le test
tshark réel existant est inclus. Aucune validation sur un lab réel n’est revendiquée.
Le serveur d’enquête, ses preuves et son journal n’ont pas été utilisés.
