# Pathdog

Analyse un export BloodHound ZIP et trouve les chemins d'attaque vers Domain Admin — sans Neo4j, sans GUI, sans limite de profondeur.

Pour chaque hop, Pathdog affiche les commandes exactes à exécuter avec l'identité courante propagée tout au long de la chaîne.

---

## Installation

```bash
pip install -r requirements.txt
```

Python 3.10+

---

## Usage

```
python pathdog.py -z <dump.zip> -u <user> [options]

  -z  ZIP(s) BloodHound           -z dump.zip  ou  -z a.zip b.zip
  -u  User(s) owned               -u alice@corp.local  ou  -u owned.txt
  -t  Cible (défaut: DOMAIN ADMINS auto-détecté)
  -k  Nombre de chemins par user  (défaut: 3)
  -o  Nom de base du rapport      (défaut: pathdog_report)
  -f  Format: md | html | both    (défaut: both)
  -l  Lister les nœuds et quitter: users | computers | groups | domains | all
  -v  Stats du graphe
```

---

## Exemples

```bash
# Basique
python pathdog.py -z corp.zip -u john.doe@corp.local

# Plusieurs ZIPs et users sur une ligne
python pathdog.py -z dump1.zip dump2.zip -u alice@corp.local bob@corp.local

# Users depuis un fichier texte (# = commentaire)
python pathdog.py -z dump1.zip dump2.zip -u owned.txt -k 5 -f html -v

# Explorer les nœuds du dump avant de lancer l'analyse
python pathdog.py -z corp.zip --list users
python pathdog.py -z corp.zip --list all
```

---

## Ce que ça fait

**Graphe sans limite de profondeur** — BloodHound GUI tronque silencieusement les chemins longs (limite Cypher). Pathdog utilise NetworkX sans plafond de hops.

**Pruning par ancêtres** — avant le pathfinding, le graphe est réduit aux seuls nœuds qui peuvent atteindre DA. Sur un gros dump, ça élimine ~80% des nœuds inutiles.

**Fusion de ZIPs** — plusieurs dumps sont mergés en un seul graphe avant analyse. Les nœuds/arêtes dupliqués sont dédupliqués automatiquement. Un chemin cross-user (`alice → svc → [ForceChangePassword] → bob → DA`) est trouvé en un seul passage.

**Propagation d'identité** — les commandes utilisent l'identité *courante* à chaque hop, pas le nœud intermédiaire du graphe :

```
john.doe@corp.local
  └─[MemberOf]──────────────────────────► HELPDESK@corp.local
     ↳ Structural relationship — no action required.
  └─[GenericWrite]──────────────────────► svc_backup@corp.local
     ↳ pywhisker -d corp.local -u 'john.doe' ...   ← john, pas HELPDESK
     → now operating as: svc_backup@corp.local
  └─[ForceChangePassword]───────────────► bob@corp.local
     ↳ net rpc password 'bob' ... -U 'corp.local/svc_backup%...'
     → now operating as: bob@corp.local
  └─[DCSync]────────────────────────────► DOMAIN ADMINS@corp.local
     ↳ impacket-secretsdump ... 'corp.local/bob:...'
```

**Formats BloodHound** — supporte le format legacy (v4) et BloodHound CE (v5+) avec les arrays `Members`, `LocalAdmins`, `Sessions`, `AllowedToDelegate`, etc.

---

## Exit codes

| Code | Signification |
|------|--------------|
| 0 | Chemins trouvés |
| 1 | Erreur (ZIP invalide, user introuvable, etc.) |
| 2 | Aucun chemin vers DA |

---

## Edge types supportés

| Weight | Edges |
|--------|-------|
| 1 | MemberOf, Contains |
| 2 | GenericAll, DCSync, GetChangesAll, AllExtendedRights, AddMember, AddSelf, ReadLAPSPassword, SyncLAPSPassword, AdminTo, GPLink |
| 3 | WriteDacl, WriteOwner, GenericWrite, Owns, ForceChangePassword, CanRDP, CanPSRemote, ExecuteDCOM, SQLAdmin, WriteSPN, TrustedBy |
| 4 | AllowedToDelegate, HasSession, WriteAccountRestrictions, AddKeyCredentialLink |
| 5 | AllowedToAct, *(inconnu)* |

Le weight représente la résistance d'exploitation — Dijkstra cherche le chemin de **weight total minimum** (le plus facile à exploiter de bout en bout).
