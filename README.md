# Pathdog

BloodHound attack path analyzer — finds paths from an owned user to Domain Admin **without Neo4j or any GUI dependency**.

---

## Install

```bash
pip install -r requirements.txt
```

Python 3.10+ required.

---

## Usage

```
usage: pathdog [-h] -z FILE -u USER [-t TARGET] [-k K] [-o BASENAME] [-f {md,html,both}] [-v]

arguments:
  -z / --zip       Path to BloodHound ZIP export (required)
  -u / --user      Owned user identity, e.g. john.doe@corp.local (required)
  -t / --target    Target node (default: auto-detect DOMAIN ADMINS node)
  -k / --paths     Number of paths to find (default: 3)
  -o / --output    Output file base name (default: pathdog_report)
  -f / --format    Output format: md, html, or both (default: both)
  -v / --verbose   Show graph stats (total nodes, pruned nodes, edges)
```

---

## Examples

**Basic scan — owned user to Domain Admin, top 3 paths, both report formats:**
```bash
python main.py -z corp_bloodhound.zip -u john.doe@corp.local
```

**Find 5 paths, HTML only, with verbose graph stats:**
```bash
python main.py -z megacorp_dump.zip -u svc_backup@megacorp.local -k 5 -f html -v -o megacorp_report
```

**Explicit target, Markdown report only:**
```bash
python main.py -z acme_export.zip -u alice@acme.local -t "DOMAIN ADMINS@acme.local" -f md -o acme_paths
```

---

## Why this finds paths that BloodHound GUI misses

BloodHound's built-in Cypher queries (`shortestPath`, `allShortestPaths`) operate on Neo4j with a **default depth limit** (typically 20 hops in the UI, and often lower in custom queries). This limit silently truncates paths that traverse more nodes.

Pathdog uses **NetworkX's `shortest_simple_paths`** (Yen's K-shortest algorithm) on a locally-built graph. There is no hop limit. Additionally, the ancestor-pruning step reduces the graph to only nodes that can actually reach DA, so even very large dumps are processed quickly.

The result: Pathdog reliably surfaces multi-hop chains that the BloodHound GUI would simply not display.

---

## Supported BloodHound edge types

| Edge | Weight | Description |
|------|--------|-------------|
| MemberOf | 1 | Group membership |
| Contains | 1 | OU/GPO containment |
| GenericAll | 2 | Full control |
| DCSync | 2 | Replicate directory changes |
| GetChangesAll | 2 | DCSync prerequisite |
| AllExtendedRights | 2 | All extended AD rights |
| AddMember | 2 | Add users to group |
| ReadLAPSPassword | 2 | Read LAPS local admin password |
| SyncLAPSPassword | 2 | Sync LAPS password |
| AddSelf | 2 | Add self to group |
| AdminTo | 2 | Local admin on target |
| GPLink | 2 | GPO linked to OU/domain |
| WriteDacl | 3 | Modify DACL |
| WriteOwner | 3 | Change object owner |
| GenericWrite | 3 | Generic write on object |
| Owns | 3 | Object ownership |
| ForceChangePassword | 3 | Reset user password |
| CanRDP | 3 | RDP access |
| CanPSRemote | 3 | WinRM / PSRemote access |
| ExecuteDCOM | 3 | DCOM execution |
| SQLAdmin | 3 | SQL Server admin |
| WriteSPN | 3 | Write servicePrincipalName |
| TrustedBy | 3 | Domain trust direction |
| AllowedToDelegate | 4 | Kerberos constrained delegation |
| HasSession | 4 | Active session on host |
| WriteAccountRestrictions | 4 | Write msDS-AllowedToActOnBehalfOfOtherIdentity |
| AddKeyCredentialLink | 4 | Shadow credential attack |
| AllowedToAct | 5 | Resource-based constrained delegation |
| *(unknown)* | 5 | Default for unmapped edge types |

---

## Report output

### Console
```
[PATH 1] Total weight: 8 | Hops: 4
──────────────────────────────────────────────────
john.doe@corp.local
  └─[MemberOf]──────────────────────────────────► HELPDESK@corp.local
  └─[GenericWrite]──────────────────────────────► svc_backup@corp.local
  └─[AllowedToDelegate]─────────────────────────► DC01.corp.local
  └─[DCSync]────────────────────────────────────► DOMAIN ADMINS@corp.local
```

### HTML
Standalone single-file HTML with dark theme, no external dependencies.

### Markdown
GitBook-compatible with tables and code blocks.

---

## Project structure

```
pathdog/
├── pathdog/
│   ├── __init__.py
│   ├── loader.py       # ZIP parsing → nodes/edges
│   ├── graph.py        # NetworkX DiGraph builder + pruning
│   ├── weights.py      # Edge weight table
│   ├── pathfinder.py   # Path computation logic
│   └── report.py       # Markdown + HTML report renderer
├── main.py             # CLI entrypoint
├── requirements.txt
└── README.md
```
