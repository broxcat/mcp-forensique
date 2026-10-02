# Interprétation des artefacts — normal ou suspect ?

Pour chaque artefact : ce qui est normal, ce qui doit attirer l'attention, les pièges connus. Une
ligne « suspecte » est une **piste** à recouper, jamais un constat en soi : elle passe par
`record_finding` (fait si observé, hypothèse si interprété). Les anomalies du serveur
(`anomalies[]`) sont aussi des pistes : la table de règles produit des faux positifs.
Les identifiants ATT&CK cités ici sont ceux de l'arbre de triage, les seuls admis.

## Mémoire

### Processus et arborescence
**Outils :** `vol_pslist`, `vol_pstree`

| Normal | Suspect |
|---|---|
| `System` (PID 4) → `smss.exe` → `wininit.exe` / `csrss.exe` / `winlogon.exe` ; `services.exe` et `lsass.exe` enfants de `wininit.exe` ; `svchost.exe` enfant de `services.exe` | Un interpréteur (`powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`…) enfant d'Office ou d'un navigateur (T1566.001, T1204.002, T1059) |
| Un seul `lsass.exe`, `services.exe`, `wininit.exe` | Doublon d'un processus système, mauvais parent, nom proche d'un binaire système (`scvhost.exe`) (T1036, T1036.005) |
| Binaires système sous `C:\Windows\System32` | Exécutable sous `Temp`, `AppData`, `Users\Public` ; nom aléatoire |

**Pièges :** un processus terminé peut rester listé avec une heure de fin ; `iexplore.exe` n'est
pas une imitation d'`explorer.exe` ; les heures de création sont en UTC dans les sorties du serveur.

### Lignes de commande
**Outils :** `vol_cmdline`

| Normal | Suspect |
|---|---|
| Chemins complets de binaires signés, arguments de service connus | `-enc` / `-EncodedCommand` (le serveur fournit `decoded`), `-nop`, `-w hidden`, `IEX`, téléchargement (`DownloadString`, `Invoke-WebRequest`, `certutil -urlcache`, `bitsadmin`) (T1059.001, T1027, T1105) |
| | `cmd.exe /c` lancé par un processus inattendu (T1059.003) |

**Pièges :** la ligne de commande vient de la mémoire du processus et peut être modifiée par lui ;
pour un processus terminé, elle peut manquer.

### Connexions réseau
**Outils :** `vol_netscan`

| Normal | Suspect |
|---|---|
| `svchost.exe`, navigateur, client de messagerie vers des services connus ; adresses privées | Connexion `ESTABLISHED` d'un processus suspect vers une adresse publique (T1071.001, T1041) ; port inhabituel ; adresse déjà vue comme IOC (`ioc_match`) |

**Pièges :** les structures réseau persistent après fermeture (états `CLOSED`) ; le PID peut avoir
été réutilisé ; une adresse de documentation (203.0.113.0/24) est publique pour le serveur.

### Code injecté
**Outils :** `vol_malfind`

| Normal | Suspect |
|---|---|
| Régions RWX de compilateurs JIT (.NET, navigateurs) | Région exécutable non adossée à un fichier commençant par un en-tête PE (`MZ`) ou du code dans un processus qui n'en génère pas (T1055) |

**Pièges :** beaucoup de faux positifs (JIT, protections logicielles) ; confirmer par une autre
source (processus parent, réseau, chronologie).

### Clés Run en mémoire
**Outils :** `vol_printkey`

| Normal | Suspect |
|---|---|
| Logiciels installés (pilotes audio, synchronisation) avec un chemin `Program Files` | Valeur pointant vers `Temp`, `AppData`, `Public`, un script ou `powershell.exe` (T1547.001) |

## Journaux d'événements

**Outils :** `evtx_query`

| Événement | Normal | Suspect |
|---|---|---|
| 4624 (ouverture de session) | Type 2 (interactif), 5 (service), 7 (déverrouillage) attendus | Type 10 (RDP) ou 3 (réseau) depuis un hôte inattendu ; compte de service en interactif (T1021.001, T1078) |
| 4625 (échec) | Quelques erreurs de saisie | Rafale d'échecs, puis un succès (T1078) |
| 4648 (identifiants explicites) | `runas`, tâches d'administration | Depuis un processus suspect, vers un autre hôte (T1078, T1021.002) |
| 4672 (privilèges spéciaux) | Comptes d'administration, `SYSTEM` | Compte utilisateur standard |
| 4688 (création de processus) | Processus courants | Mêmes signes que la mémoire (parents, arguments, chemins) ; utile pour les processus terminés (T1059) |
| 4104 (bloc de script PowerShell) | Scripts d'administration signés | Contenu décodé, téléchargement, `IEX`, obfuscation (T1059.001, T1027) |
| 4698 / 106 (tâche créée) | Tâches de mises à jour de logiciels connus | Tâche au nom générique (`UpdateSvc`) qui lance un script ou un binaire hors `Program Files` (T1053.005) |
| 7045 / 4697 (service installé) | Pilotes et logiciels installés | Service pointant vers `Temp`, un nom aléatoire, `cmd /c` (T1543.003) |
| 1149, 21, 25, 4778, 4779 (RDP) | Administration à distance prévue | Session RDP vers ou depuis un poste de travail, hors horaires (T1021.001) |
| 1102 / 104 (journal effacé) | Rare en production | Presque toujours à expliquer (T1070.001) |

**Pièges :** pas de 4688 avec ligne de commande, pas de 4698, pas de 4104 si l'audit n'était pas
activé (lire les `notes`) ; un journal trop petit a pu écraser le début de l'incident ; l'heure
`TimeCreated` est en UTC.

## Disque

### $MFT
**Outils :** `mft_search`

| Normal | Suspect |
|---|---|
| Fichiers d'installations et de mises à jour | Exécutables, scripts ou archives (`.zip`, `.7z`, `.rar`) créés dans `Temp`, `AppData`, `Public` autour de l'incident (T1560.001, T1074.001) |

**Pièges :** les dates `$STANDARD_INFORMATION` sont modifiables par un outil (horodatage falsifié) ;
les comparer aux dates `$FILE_NAME`. Un fichier supprimé peut encore figurer dans la $MFT.

### Prefetch
**Outils :** `prefetch_query` (outil Windows-only : export puis `ez_import`)

| Normal | Suspect |
|---|---|
| Applications courantes | Exécutable lancé depuis un dossier temporaire, outil d'administration à distance, outil d'archivage juste avant une connexion sortante (T1204.002) |

**Pièges :** le prefetch peut être désactivé (serveurs, SSD selon la configuration) ; 8 dernières
exécutions seulement (Windows 8+).

### Amcache et ShimCache
**Outils :** `amcache_query`, `shimcache_query`

| Normal | Suspect |
|---|---|
| Logiciels installés | Binaire inconnu, chemin temporaire, SHA-1 (Amcache) correspondant à un IOC |

**Pièges :** sous Windows 10/11, une entrée ShimCache **ne prouve pas l'exécution** (seulement la
présence ou l'examen du fichier) : confiance `low` sans autre source. Les dates ShimCache sont des
dates de modification du fichier, pas d'exécution.

### LNK, jump lists, corbeille
**Outils :** `lnk_query`, `jumplist_query`, `recyclebin_query`

| Normal | Suspect |
|---|---|
| Documents de travail ouverts | Document ouvert juste avant le premier processus suspect ; fichier ouvert depuis un support amovible ou un partage ; archive ou outil supprimé après usage |

### Historique de navigation et SRUM
**Outils :** `browser_history`, `srum_query` (outils Windows-only : export puis `ez_import`)

| Normal | Suspect |
|---|---|
| Sites professionnels | Téléchargement d'un exécutable ou d'un document à macro juste avant l'exécution ; envoi vers un service de stockage en ligne (T1105, T1567) |
| Volumes réseau habituels par application | Volume sortant inhabituel d'un processus (SRUM, par heure) (T1041) |

## Recouper

Un fait solide est vu par **deux sources indépendantes** : par exemple un processus en mémoire
(`vol_pstree`) et son 4688, une connexion (`vol_netscan`) et l'adresse décodée de la commande, une
tâche 4698 et le fichier de la tâche sur le disque. `timeline` aligne ces sources en UTC autour du
premier indice.
