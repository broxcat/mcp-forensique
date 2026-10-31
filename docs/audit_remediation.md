# Corrections de l’audit du 31 octobre 2026

Référence : bfea22c53615464b9ed9a03ae6d8deea790146b9. Les tests de
régression utilisent le SDK, jsonschema, YAML et les verrous Linux réels dans
l’image du projet. Les preuves des tests sont synthétiques, jamais des résultats de lab.

## R03 — Provenance des extractions (EF-05, EF-10, CDC §5)

La résolution de classification remonte tous les parents par `meta.json`, pour
disque, mémoire et réseau. Les chaînes absentes, cycliques, hors racine ou de plus
de 32 niveaux sont refusées, sans retour silencieux à internal.
Les nouveaux résultats enregistrent aussi les identités de preuves parentes,
empreintes, identités de cas et classifications dans les métadonnées scellées.
Une classification historique plus restrictive est conservée si case.toml change.

## R04 — Réutilisation par inode (EF-04, EF-05)

Les références `disk_extract_file` passent par la même racine `extracted/`
que les autres extractions. Les traversées restent interdites. Le test chaîne
l’extraction à verify_evidence et au parseur MFT (binaire de test synthétique).

## R01 — Lectures de synthèse (CDC §5, EF-10, ET-04)

Les constats, rapports et consultations ultérieures résolvent toutes les sources
citées. En cloud, client est refusé et les politiques internes sont composées.
Une ancienne synthèse sans provenance est refusée : la régénérer localement.
Les fichiers bruts restent sensibles et doivent être protégés côté serveur.
Les citations de synthèses résolvent aussi leur provenance composite. Les réponses
de création de constats et les timelines conservent les politiques de leurs sources.

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

## R06 — Sorties des processus (ET-02, CDC §9)

Le runner compte les nouveaux fichiers du répertoire de sortie, y compris les
sorties natives et stdout/stderr, pendant et après le processus. Un dépassement
arrête le groupe et tronque les sorties au budget ; le statut est un échec explicite.
La borne est contrôlée par polling, pas par quota disque : un pic transitoire
reste possible. Le budget partagé `max_session_output_mb` (10 Gio par défaut)
porte sur tout `output_root`, y compris les sessions précédentes. Les processus
partagent un verrou de budget pour leurs sous-processus. La normalisation fait
également l’objet d’un contrôle final : les nouveaux résultats excessifs sont
tronqués et journalisés en échec. Le journal lui-même reste conservé même quand
le budget est épuisé ; un quota de système de fichiers reste nécessaire pour
une borne absolue sans pic transitoire. Utiliser un output_root dédié par session.
Les commandes de découverte et d’aide Volatility passent également par le runner,
avec fichiers temporaires nettoyés et arrêt du groupe au timeout.

## R07 — Réponses bornées (EF-04, ET-02)

La mesure inclut l’enveloppe CallToolResult, ses deux représentations (texte et
contenu structuré), les marqueurs et l’échappement des caractères `<`. Une réserve
de 512 octets couvre l’identifiant final d’audit et les métadonnées du SDK.
Une réponse dont les champs hors lignes dépassent le budget est refusée avec une
erreur explicite. Une ligne qui ne tient pas ne produit jamais un curseur immobile.
Les données complètes restent dans les fichiers du résultat.

## R09 — Allocation concurrente (ET-04, EF-12, CDC §5)

L’allocation F/C/S et l’écriture partagent le même verrou Linux du journal.
Les vues utilisent l’identifiant effectivement alloué. Le test lance quatre
processus indépendants partageant le fichier, sans substitut de flock.

## R08 — Intégrité des résultats (EF-10, CDC §5)

Le premier appel producteur scelle dans le journal les empreintes de tous les
fichiers du résultat. Citation, validation positive et export final comparent ce
manifeste et exigent un producteur réussi et une chaîne valide. Les résultats
historiques non scellés doivent être recalculés. Toute anomalie est journalisée.
L’ancrage externe du journal reste une mesure organisationnelle indispensable.

## R11 — Sources des imports Windows (EF-05, EF-10)

Les empreintes de l’export et de sa source sont contrôlées avant tout retour du
cache. La source originale est enregistrée par le mécanisme commun, y compris
les fichiers d’un dossier. L’export final refuse une source citée absente du registre.
Les options de chemin sont inventoriées dans `source_inputs` du manifeste Windows,
enregistrées et revérifiées avant réutilisation. Les anciens exports comportant
de telles options sans inventaire doivent être régénérés.

## R12 — Rejeu EVTX/MFT (ET-04, CDC §2 O3)

EVTX et MFT sont rejouables avec les paramètres journalisés. Un contexte propre
à l’appel désactive les deux chemins de cache EZ, sans affecter les autres appels.
Les événements métier restent reconstruits par réduction déterministe du journal,
sans réinsérer suggestions ou décisions humaines.

## R10 — Correspondances IOC (CDC §6 O2)

Les adresses sont comparées comme adresses IP ; les domaines, URL, empreintes,
processus et chemins utilisent des limites de token adaptées au type.
Le score distingue IOC exploratoires, validés et rejetés par l’analyste.
Un rejet ne contribue plus au rappel exploratoire. Aucune vérité terrain réelle
n’est ajoutée : le fichier de lab reste à remplir par l’équipe.

## C01 — Appariement du modèle (ET-07, CDC §5)

Chaque processus CLI utilise cloud par défaut, même si le fichier TOML indique
local. Le modèle local exige `--llm-mode local` sur un processus distinct. Le
modèle d’espace cloud fixe explicitement cloud. Le transport ne prouve pas
l’hébergement du modèle ; l’équipe doit contrôler la configuration du client.

## C02 — Représentations et erreurs (CDC §5)

Les IPv6 et arguments PowerShell encodés sont masqués. En cloud, une erreur
n’expose que son identifiant d’audit ; le détail reste dans le journal local.
La pseudonymisation n’est pas une garantie d’anonymat des textes libres ou de
tous les encodages. Les données client restent obligatoirement locales ; l’accord
fournisseur de non-rétention reste à obtenir et documenter par l’équipe.

## C03 — Relecture senior (CDC §5)

`report_export(final=true)` prépare un candidat et refuse sa diffusion finale
tant qu’il n’a pas une revue senior hors MCP. Depuis un terminal local :
`python -m forensic_mcp review-report`, puis relancer l’export. L’événement lie
le nom déclaré, le motif, l’empreinte exacte du rapport et la version des constats.
Le rapport approuvé est réutilisé sans réécriture. Une modification l’invalide.
L’identité et la qualification senior doivent être authentifiées par les contrôles
du poste et la procédure d’équipe ; la saisie du nom est une attestation déclarative.

## C05 — Exports Windows (EF-06)

Le script exige `-StagingRoot`, distinct et non imbriqué avec `-EvidenceRoot`.
Les sorties et manifestes sont produits uniquement dans cet espace de préparation.
L’équipe vérifie les empreintes, copie l’export comme nouvelle preuve dans le dossier
du cas puis le monte en lecture seule avant `ez_import`. Le script ne modifie pas
les originaux. Cette intégration contrôlée et l’exécution sur de vrais outils Windows
restent à réaliser par l’équipe ; le montage `:ro` ne protège pas des écritures hôte.
