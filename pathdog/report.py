"""Markdown + HTML report renderer for pathdog results."""

from __future__ import annotations
from typing import TYPE_CHECKING

from .commands import get_commands, CommandSet

if TYPE_CHECKING:
    import networkx as nx
    from .pathfinder import PathResult
    from .quickwins import QuickWin


# ── helpers ───────────────────────────────────────────────────────────────────

def _display_name(G: "nx.DiGraph", nid: str) -> str:
    name = G.nodes[nid].get("name", nid) if nid in G else nid
    return name if name else nid


def _node_flags(G: "nx.DiGraph", nid: str) -> list[str]:
    """Return short tags about a node (asreproast, kerberoast, unconstrained...)."""
    if nid not in G:
        return []
    p = G.nodes[nid].get("props", {})
    tags: list[str] = []
    if p.get("dontreqpreauth"):
        tags.append("AS-REP roastable")
    if p.get("hasspn") and G.nodes[nid].get("kind") == "users":
        if _display_name(G, nid).split("@", 1)[0].lower() != "krbtgt":
            tags.append("Kerberoastable")
    if p.get("unconstraineddelegation"):
        tags.append("Unconstrained deleg.")
    if p.get("passwordnotreqd"):
        tags.append("PasswordNotReqd")
    if p.get("admincount"):
        tags.append("AdminCount=1")
    if p.get("highvalue") or p.get("HighValue"):
        tags.append("HighValue")
    if p.get("haslaps") and G.nodes[nid].get("kind") == "computers":
        tags.append("LAPS")
    return tags


def _edge_commands(
    G: "nx.DiGraph", edge: dict, actor: str
) -> tuple[CommandSet, str]:
    """Return (CommandSet, next_actor) for one edge, given the current actor."""
    src, dst = edge["src"], edge["dst"]
    return get_commands(
        rel_type=edge["relation"],
        src_id=src,
        dst_id=dst,
        src_name=_display_name(G, src),
        dst_name=_display_name(G, dst),
        src_kind=G.nodes[src].get("kind", "") if src in G else "",
        dst_kind=G.nodes[dst].get("kind", "") if dst in G else "",
        actor=actor,
    )


def _stats_md_lines(stats: dict) -> list[str]:
    lines = [
        "## Graph Statistics\n",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total nodes | {stats['total_nodes']} |",
        f"| Total edges | {stats['total_edges']} |",
        f"| Pruned nodes (reachable) | {stats['pruned_nodes']} |",
        f"| Pruned edges | {stats['pruned_edges']} |",
        f"| Node reduction | {stats['reduction_pct']}% |",
        "",
    ]
    return lines


# ── Console ───────────────────────────────────────────────────────────────────

_DCSYNC_GRANTING_EDGES = {
    "DCSync", "GetChangesAll", "GetChanges", "GetChangesInFilteredSet",
    "WriteDacl", "WriteOwner", "Owns", "GenericAll", "AllExtendedRights",
}


def _path_yields_dcsync(G: "nx.DiGraph", path: "PathResult") -> bool:
    """True if the last non-structural edge ends on a domain with a DCSync-granting rel."""
    for edge in reversed(path.edges):
        rel = edge["relation"]
        if rel in ("MemberOf", "Contains"):
            continue
        if rel in _DCSYNC_GRANTING_EDGES and G.nodes.get(edge["dst"], {}).get("kind") == "domains":
            return True
        return False
    return False


def print_paths_console(
    paths: list["PathResult"],
    G: "nx.DiGraph",
    source: str,
    target: str,
) -> None:
    if not paths:
        src = _display_name(G, source)
        tgt = _display_name(G, target)
        print(
            f"\n[!] No path found from {src} to {tgt}.\n"
            "    The owned user may not have any edges leading to DA in this dump."
        )
        return

    for i, path in enumerate(paths, 1):
        print(f"\n[PATH {i}] Total weight: {path.total_weight} | Hops: {path.hops}")
        print("─" * 50)
        actor = _display_name(G, path.nodes[0])
        flags = _node_flags(G, path.nodes[0])
        flag_str = f"  ⚑ {', '.join(flags)}" if flags else ""
        print(f"{actor}{flag_str}")
        for edge in path.edges:
            rel = edge["relation"]
            dst_name = _display_name(G, edge["dst"])
            dst_flags = _node_flags(G, edge["dst"])
            flag_str = f"  ⚑ {', '.join(dst_flags)}" if dst_flags else ""
            arrow = f"  └─[{rel}]"
            pad = max(1, 42 - len(arrow))
            print(f"{arrow}{'─' * pad}► {dst_name}{flag_str}")

            cmd, next_actor = _edge_commands(G, edge, actor)
            print(f"     ↳ {cmd.description}")
            for c in cmd.commands:
                print(f"       $ {c}")
            if next_actor != actor:
                print(f"     → now operating as: {next_actor}")
            actor = next_actor

        if _path_yields_dcsync(G, path):
            print("\n  ✦ This path grants DCSync — domain compromise. Use the secretsdump")
            print("    command above to harvest all hashes (krbtgt → Golden Ticket forever).")


def print_intermediate_targets(
    G: "nx.DiGraph",
    source: str,
    suggestions: list[dict],
) -> None:
    """Console output for fallback intermediate-target suggestions."""
    if not suggestions:
        return
    src_name = _display_name(G, source)
    print(f"\n[+] No DA path — best intermediate targets reachable from {src_name}:")
    for i, s in enumerate(suggestions, 1):
        nid = s["node"]
        path = s["path"]
        score = s["score"]
        d_name = _display_name(G, nid)
        kind = G.nodes[nid].get("kind", "?")
        flags = _node_flags(G, nid)
        flag_str = f"  ⚑ {', '.join(flags)}" if flags else ""
        hops = path.hops if path else "?"
        print(f"  {i:>2}. [score={score:>3}] {d_name} ({kind}) — {hops} hop(s){flag_str}")
        if path:
            chain = " → ".join(_display_name(G, n) for n in path.nodes)
            print(f"        path: {chain}")


def print_pivot_candidates(
    G: "nx.DiGraph",
    pivots: list[dict],
    limit: int = 10,
) -> None:
    """Console output: principals with a path to DA that you can compromise out-of-band."""
    if not pivots:
        return
    print(f"\n[+] Pivot candidates — compromise any of these and you inherit a path to DA:")
    for i, pv in enumerate(pivots[:limit], 1):
        nid = pv["node"]
        ptd = pv["path_to_da"]
        name = _display_name(G, nid)
        kind = G.nodes[nid].get("kind", "?")
        flags = _node_flags(G, nid)
        flag_str = f"  ⚑ {', '.join(flags)}" if flags else ""
        hops = ptd.hops if ptd else "?"
        print(f"\n  {i:>2}. [score={pv['score']:>3}] {name} ({kind}) — {hops} hops to DA{flag_str}")
        print(f"        Attack vectors: {', '.join(pv['vectors'])}")
        for c in pv["vector_commands"][:3]:
            print(f"          $ {c}")
        if ptd:
            chain = " → ".join(_display_name(G, n) for n in ptd.nodes)
            print(f"        Onward path: {chain}")


def print_quickwins(
    G: "nx.DiGraph",
    quickwins: dict[str, list["QuickWin"]],
    limit_per_cat: int = 5,
) -> None:
    if not quickwins:
        return
    print(f"\n[+] Domain-wide quick wins (independent of any owned user):")
    for cat in sorted(quickwins):
        items = quickwins[cat]
        print(f"\n  ◆ {cat}: {len(items)} candidate(s)")
        for qw in items[:limit_per_cat]:
            print(f"     • {qw.node_name} ({qw.node_kind}) — {qw.detail}")
            for c in qw.commands[:2]:
                print(f"        $ {c}")
        if len(items) > limit_per_cat:
            print(f"     … and {len(items) - limit_per_cat} more")


# ── Markdown ──────────────────────────────────────────────────────────────────

def render_markdown(
    paths: list["PathResult"],
    G: "nx.DiGraph",
    source: str,
    target: str,
    stats: dict | None = None,
    intermediate: list[dict] | None = None,
    quickwins: dict[str, list["QuickWin"]] | None = None,
    pivots: list[dict] | None = None,
) -> str:
    lines: list[str] = []
    lines.append("# Pathdog — Attack Path Report\n")
    lines.append(f"**Source:** `{_display_name(G, source)}`  ")
    lines.append(f"**Target:** `{_display_name(G, target)}`\n")

    if stats:
        lines.extend(_stats_md_lines(stats))

    if not paths:
        lines.append(
            f"> **No path found** from `{_display_name(G, source)}` to "
            f"`{_display_name(G, target)}`.  \n"
            "> The owned user may not have any edges leading to DA in this dump."
        )
        if intermediate:
            lines.extend(_intermediate_md(G, source, intermediate))
        if pivots:
            lines.extend(_pivots_md(G, pivots))
        if quickwins:
            lines.extend(_quickwins_md(quickwins))
        lines.append("\n---")
        lines.append("*Generated by [pathdog](https://github.com/dikabraxis/pathdog)*")
        return "\n".join(lines)

    lines.append(f"## Paths Found: {len(paths)}\n")

    for i, path in enumerate(paths, 1):
        lines.append(f"### Path {i} — Weight: {path.total_weight} | Hops: {path.hops}\n")

        # ASCII chain (with property flags)
        lines.append("```")
        first_flags = _node_flags(G, path.nodes[0])
        first_str = _display_name(G, path.nodes[0])
        if first_flags:
            first_str += f"  ⚑ {', '.join(first_flags)}"
        lines.append(first_str)
        for edge in path.edges:
            rel = edge["relation"]
            dst_name = _display_name(G, edge["dst"])
            dst_flags = _node_flags(G, edge["dst"])
            tail = f"  ⚑ {', '.join(dst_flags)}" if dst_flags else ""
            arrow = f"  └─[{rel}]"
            pad = max(1, 42 - len(arrow))
            lines.append(f"{arrow}{'─' * pad}► {dst_name}{tail}")
        lines.append("```\n")

        if _path_yields_dcsync(G, path):
            lines.append(
                "> ✦ **DCSync acquired** — once `dacledit` lands, "
                "`secretsdump` returns every domain hash (incl. krbtgt → Golden Ticket).\n"
            )

        # Edge table
        lines.append("| # | From | Relation | To | Weight |")
        lines.append("|---|------|----------|----|--------|")
        for j, edge in enumerate(path.edges, 1):
            lines.append(
                f"| {j} "
                f"| `{_display_name(G, edge['src'])}` "
                f"| **{edge['relation']}** "
                f"| `{_display_name(G, edge['dst'])}` "
                f"| {edge['weight']} |"
            )
        lines.append("")

        # Per-hop exploit steps with actor tracking
        lines.append("#### Exploit steps\n")
        actor = _display_name(G, path.nodes[0])
        for j, edge in enumerate(path.edges, 1):
            cmd, next_actor = _edge_commands(G, edge, actor)
            src_label = _display_name(G, edge["src"])
            dst_label = _display_name(G, edge["dst"])
            lines.append(f"**Hop {j} — [{edge['relation']}]** `{src_label}` → `{dst_label}`\n")
            lines.append(f"> *Operating as: `{actor}`*  ")
            lines.append(f"> {cmd.description}\n")
            if cmd.has_commands:
                lines.append("```bash")
                lines.extend(cmd.commands)
                lines.append("```\n")
            if next_actor != actor:
                lines.append(f"> ✦ **Identity obtained: `{next_actor}`**\n")
            actor = next_actor

    if pivots:
        lines.extend(_pivots_md(G, pivots))

    if quickwins:
        lines.extend(_quickwins_md(quickwins))

    lines.append("---")
    lines.append("*Generated by [pathdog](https://github.com/dikabraxis/pathdog)*")
    return "\n".join(lines)


def _intermediate_md(
    G: "nx.DiGraph", source: str, suggestions: list[dict]
) -> list[str]:
    lines: list[str] = ["\n## Intermediate targets reachable\n",
                        "When DA isn't directly reachable, pivot through these:\n",
                        "| # | Score | Target | Kind | Hops | Flags |",
                        "|---|-------|--------|------|------|-------|"]
    for i, s in enumerate(suggestions, 1):
        nid = s["node"]
        path = s["path"]
        score = s["score"]
        flags = ", ".join(_node_flags(G, nid)) or "—"
        hops = path.hops if path else "?"
        lines.append(
            f"| {i} | {score} | `{_display_name(G, nid)}` "
            f"| {G.nodes[nid].get('kind', '?')} | {hops} | {flags} |"
        )
    lines.append("")
    for i, s in enumerate(suggestions, 1):
        path = s["path"]
        if not path:
            continue
        chain = " → ".join(f"`{_display_name(G, n)}`" for n in path.nodes)
        lines.append(f"**{i}.** {chain}\n")
    return lines


def _quickwins_md(quickwins: dict[str, list["QuickWin"]]) -> list[str]:
    lines: list[str] = ["\n## Domain-wide quick wins\n",
                        "Surfaced from BloodHound node properties — independent of any owned user.\n"]
    for cat in sorted(quickwins):
        items = quickwins[cat]
        lines.append(f"### {cat} — {len(items)} candidate(s)\n")
        for qw in items:
            lines.append(f"- **`{qw.node_name}`** ({qw.node_kind}) — {qw.detail}")
            if qw.commands:
                lines.append("  ```bash")
                for c in qw.commands:
                    lines.append(f"  {c}")
                lines.append("  ```")
        lines.append("")
    return lines


def _pivots_md(G: "nx.DiGraph", pivots: list[dict]) -> list[str]:
    if not pivots:
        return []
    lines = [
        "\n## Pivot candidates (have a path to DA, attackable out-of-band)\n",
        "Compromise any of these via the listed vector and the existing graph path takes you to DA.\n",
        "| # | Score | Pivot | Hops to DA | Vectors | Flags |",
        "|---|-------|-------|------------|---------|-------|",
    ]
    for i, pv in enumerate(pivots, 1):
        nid = pv["node"]
        ptd = pv["path_to_da"]
        flags = ", ".join(_node_flags(G, nid)) or "—"
        hops = ptd.hops if ptd else "?"
        vectors = ", ".join(pv["vectors"])
        lines.append(
            f"| {i} | {pv['score']} | `{_display_name(G, nid)}` | {hops} | {vectors} | {flags} |"
        )
    lines.append("")
    for i, pv in enumerate(pivots, 1):
        nid = pv["node"]
        ptd = pv["path_to_da"]
        lines.append(f"### {i}. `{_display_name(G, nid)}`\n")
        if pv["vector_commands"]:
            lines.append("```bash")
            lines.extend(pv["vector_commands"])
            lines.append("```\n")
        if ptd:
            chain = " → ".join(f"`{_display_name(G, n)}`" for n in ptd.nodes)
            lines.append(f"**Onward path to DA:** {chain}\n")
    return lines


def _pivots_html(G: "nx.DiGraph", pivots: list[dict]) -> str:
    if not pivots:
        return ""
    parts = [
        '<h2>Pivot Candidates</h2>',
        '<p class="meta">Principals with an existing graph path to DA. '
        'Compromise any of them out-of-band (Kerberoast, AS-REP, weak password, LAPS) '
        'and the chain to DA becomes exploitable.</p>',
    ]
    for i, pv in enumerate(pivots, 1):
        nid = pv["node"]
        ptd = pv["path_to_da"]
        name = _escape(_display_name(G, nid))
        kind = _escape(G.nodes[nid].get("kind", "?"))
        flags = ", ".join(_node_flags(G, nid)) or "—"
        hops = ptd.hops if ptd else "?"
        vectors = _escape(", ".join(pv["vectors"]))
        chain = (
            " &#8594; ".join(_escape(_display_name(G, n)) for n in ptd.nodes)
            if ptd else "—"
        )
        parts.append('<div class="path-card">')
        parts.append(
            f'<div class="path-header">'
            f'<span class="path-badge">PIVOT {i}</span>'
            f'<span class="path-meta">'
            f'<strong>{name}</strong> ({kind}) — score {pv["score"]} '
            f'&nbsp;|&nbsp; {hops} hops to DA</span></div>'
        )
        parts.append('<div class="chain">')
        parts.append(f'<div class="exploit-desc"><b>Vectors:</b> {vectors}</div>')
        parts.append(f'<div class="exploit-desc"><b>Flags:</b> {_escape(flags)}</div>')
        if pv["vector_commands"]:
            lines = []
            for c in pv["vector_commands"]:
                if c.startswith("#"):
                    lines.append(f'<span class="comment">{_escape(c)}</span>')
                else:
                    lines.append(_escape(c))
            parts.append(f'<div class="exploit-commands">{"<br>".join(lines)}</div>')
        parts.append(f'<div class="exploit-desc" style="margin-top:.5rem"><b>Onward to DA:</b> {chain}</div>')
        parts.append('</div></div>')
    return "\n".join(parts)


# ── HTML ──────────────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pathdog — Attack Path Report</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --accent: #58a6ff; --accent2: #3fb950; --warn: #d29922;
    --danger: #f85149; --text: #c9d1d9; --muted: #8b949e;
    --code-bg: #1f2428; --new-actor: #bc8cff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; font-size: 14px; line-height: 1.6; padding: 2rem; }
  h1 { color: var(--accent); font-size: 1.6rem; margin-bottom: 0.5rem; }
  h2 { color: var(--accent); font-size: 1.2rem; margin: 1.5rem 0 0.75rem; border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }
  .meta { color: var(--muted); margin-bottom: 1.5rem; }
  .meta span { color: var(--accent); font-family: monospace; }
  .stats-table { border-collapse: collapse; margin-bottom: 1.5rem; }
  .stats-table th, .stats-table td { border: 1px solid var(--border); padding: 0.4rem 0.8rem; }
  .stats-table th { background: var(--surface); color: var(--accent); }
  .stats-table td { font-family: monospace; }
  .no-path { background: var(--surface); border: 1px solid var(--danger); border-radius: 6px; padding: 1rem 1.25rem; color: var(--danger); margin-top: 1rem; }
  .path-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }
  .path-header { background: #1c2128; padding: 0.6rem 1rem; display: flex; align-items: center; gap: 1rem; border-bottom: 1px solid var(--border); }
  .path-badge { background: var(--accent); color: #0d1117; font-weight: 700; font-size: 0.8rem; padding: 0.2rem 0.6rem; border-radius: 20px; }
  .path-meta { color: var(--muted); font-size: 0.85rem; }
  .path-meta strong { color: var(--text); }
  .chain { padding: 1.25rem 1.5rem; }
  .chain-node { display: flex; align-items: center; gap: 0.5rem; margin: 0.1rem 0; }
  .node-pill { background: var(--code-bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.25rem 0.6rem; font-family: monospace; font-size: 0.85rem; color: var(--text); white-space: nowrap; }
  .node-pill.source { border-color: var(--accent2); color: var(--accent2); }
  .node-pill.target { border-color: var(--danger); color: var(--danger); }
  .actor-badge { font-size: 0.72rem; color: var(--muted); margin-left: 0.4rem; font-style: italic; }
  .chain-edge { padding: 0.15rem 0 0.15rem 1rem; }
  .edge-connector { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; color: var(--muted); }
  .edge-line { width: 2px; height: 14px; background: var(--border); flex-shrink: 0; }
  .rel-badge { background: #21262d; border: 1px solid var(--border); border-radius: 20px; padding: 0.1rem 0.55rem; font-family: monospace; font-size: 0.78rem; color: var(--warn); }
  .weight-badge { font-size: 0.72rem; color: var(--muted); }
  .exploit-block { margin: 0.4rem 0 0.4rem 1.6rem; border-left: 2px solid var(--border); padding-left: 0.75rem; }
  .exploit-desc { font-size: 0.82rem; color: var(--muted); margin-bottom: 0.3rem; font-style: italic; }
  .exploit-commands { background: var(--code-bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.6rem 0.9rem; font-family: monospace; font-size: 0.8rem; white-space: pre; overflow-x: auto; color: var(--accent2); line-height: 1.7; }
  .exploit-commands .comment { color: var(--muted); }
  .actor-change { font-size: 0.78rem; color: var(--new-actor); margin-top: 0.3rem; padding: 0.2rem 0.5rem; background: #1a1040; border-radius: 4px; display: inline-block; }
  .user-section { margin-bottom: 2.5rem; }
  .user-banner { background: #1c2128; border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem 1rem; margin-bottom: 1rem; font-family: monospace; color: var(--accent2); font-size: 0.95rem; }
  footer { margin-top: 2rem; color: var(--muted); font-size: 0.8rem; border-top: 1px solid var(--border); padding-top: 1rem; }
  footer a { color: var(--accent); text-decoration: none; }
</style>
</head>
<body>
<h1>&#128021; Pathdog — Attack Path Report</h1>
<div class="meta">Source: <span>{{SOURCE_NAME}}</span> &nbsp;&#8594;&nbsp; Target: <span>{{TARGET_NAME}}</span></div>
{{STATS_BLOCK}}
<h2>Paths Found: {{PATH_COUNT}}</h2>
{{PATHS_BLOCK}}
<footer>Generated by <a href="https://github.com/dikabraxis/pathdog">pathdog</a></footer>
</body>
</html>
"""

_HTML_MULTI_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pathdog — Multi-User Attack Path Report</title>
<style>
  :root { --bg:#0d1117;--surface:#161b22;--border:#30363d;--accent:#58a6ff;--accent2:#3fb950;--warn:#d29922;--danger:#f85149;--text:#c9d1d9;--muted:#8b949e;--code-bg:#1f2428;--new-actor:#bc8cff; }
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,monospace;font-size:14px;line-height:1.6;padding:2rem;}
  h1{color:var(--accent);font-size:1.6rem;margin-bottom:.5rem;}
  h2{color:var(--accent);font-size:1.2rem;margin:1.5rem 0 .75rem;border-bottom:1px solid var(--border);padding-bottom:.4rem;}
  .meta{color:var(--muted);margin-bottom:1.5rem;} .meta span{color:var(--accent);font-family:monospace;}
  .stats-table{border-collapse:collapse;margin-bottom:1.5rem;} .stats-table th,.stats-table td{border:1px solid var(--border);padding:.4rem .8rem;} .stats-table th{background:var(--surface);color:var(--accent);} .stats-table td{font-family:monospace;}
  .no-path{background:var(--surface);border:1px solid var(--danger);border-radius:6px;padding:1rem 1.25rem;color:var(--danger);margin-top:1rem;}
  .path-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:1.5rem;overflow:hidden;}
  .path-header{background:#1c2128;padding:.6rem 1rem;display:flex;align-items:center;gap:1rem;border-bottom:1px solid var(--border);}
  .path-badge{background:var(--accent);color:#0d1117;font-weight:700;font-size:.8rem;padding:.2rem .6rem;border-radius:20px;}
  .path-meta{color:var(--muted);font-size:.85rem;} .path-meta strong{color:var(--text);}
  .chain{padding:1.25rem 1.5rem;}
  .chain-node{display:flex;align-items:center;gap:.5rem;margin:.1rem 0;}
  .node-pill{background:var(--code-bg);border:1px solid var(--border);border-radius:4px;padding:.25rem .6rem;font-family:monospace;font-size:.85rem;color:var(--text);white-space:nowrap;}
  .node-pill.source{border-color:var(--accent2);color:var(--accent2);} .node-pill.target{border-color:var(--danger);color:var(--danger);}
  .actor-badge{font-size:.72rem;color:var(--muted);margin-left:.4rem;font-style:italic;}
  .chain-edge{padding:.15rem 0 .15rem 1rem;}
  .edge-connector{display:flex;align-items:center;gap:.5rem;font-size:.8rem;color:var(--muted);}
  .edge-line{width:2px;height:14px;background:var(--border);flex-shrink:0;}
  .rel-badge{background:#21262d;border:1px solid var(--border);border-radius:20px;padding:.1rem .55rem;font-family:monospace;font-size:.78rem;color:var(--warn);}
  .weight-badge{font-size:.72rem;color:var(--muted);}
  .exploit-block{margin:.4rem 0 .4rem 1.6rem;border-left:2px solid var(--border);padding-left:.75rem;}
  .exploit-desc{font-size:.82rem;color:var(--muted);margin-bottom:.3rem;font-style:italic;}
  .exploit-commands{background:var(--code-bg);border:1px solid var(--border);border-radius:4px;padding:.6rem .9rem;font-family:monospace;font-size:.8rem;white-space:pre;overflow-x:auto;color:var(--accent2);line-height:1.7;}
  .exploit-commands .comment{color:var(--muted);}
  .actor-change{font-size:.78rem;color:var(--new-actor);margin-top:.3rem;padding:.2rem .5rem;background:#1a1040;border-radius:4px;display:inline-block;}
  .user-section{margin-bottom:2.5rem;}
  .user-banner{background:#1c2128;border:1px solid var(--border);border-radius:6px;padding:.6rem 1rem;margin-bottom:1rem;font-family:monospace;color:var(--accent2);font-size:.95rem;}
  footer{margin-top:2rem;color:var(--muted);font-size:.8rem;border-top:1px solid var(--border);padding-top:1rem;}
  footer a{color:var(--accent);text-decoration:none;}
</style>
</head>
<body>
<h1>&#128021; Pathdog — Multi-User Attack Path Report</h1>
<div class="meta">Target: <span>{{TARGET_NAME}}</span></div>
{{STATS_BLOCK}}
{{SECTIONS}}
<footer>Generated by <a href="https://github.com/dikabraxis/pathdog">pathdog</a></footer>
</body>
</html>
"""

_STATS_HTML = """\
<h2>Graph Statistics</h2>
<table class="stats-table">
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Total nodes</td><td>{total_nodes}</td></tr>
<tr><td>Total edges</td><td>{total_edges}</td></tr>
<tr><td>Pruned nodes (reachable)</td><td>{pruned_nodes}</td></tr>
<tr><td>Pruned edges</td><td>{pruned_edges}</td></tr>
<tr><td>Node reduction</td><td>{reduction_pct}%</td></tr>
</table>
"""

_NO_PATH_HTML = """\
<div class="no-path">&#10060; No path found from <code>{source}</code> to <code>{target}</code>.<br>
The owned user may not have any edges leading to DA in this dump.</div>
"""


def _escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _render_exploit_html(cmd: CommandSet, actor: str, next_actor: str) -> str:
    parts = ['<div class="exploit-block">']
    parts.append(f'<div class="actor-badge">acting as: {_escape(actor)}</div>')
    parts.append(f'<div class="exploit-desc">{_escape(cmd.description)}</div>')
    if cmd.has_commands:
        lines = []
        for c in cmd.commands:
            if c.startswith("#"):
                lines.append(f'<span class="comment">{_escape(c)}</span>')
            else:
                lines.append(_escape(c))
        parts.append(f'<div class="exploit-commands">{"<br>".join(lines)}</div>')
    if next_actor != actor:
        parts.append(f'<div class="actor-change">&#10024; Identity obtained: {_escape(next_actor)}</div>')
    parts.append("</div>")
    return "\n".join(parts)


def _render_path_html(path: "PathResult", G: "nx.DiGraph", index: int) -> str:
    parts = ['<div class="path-card">']
    parts.append(
        f'<div class="path-header">'
        f'<span class="path-badge">PATH {index}</span>'
        f'<span class="path-meta">Weight: <strong>{path.total_weight}</strong>'
        f' &nbsp;|&nbsp; Hops: <strong>{path.hops}</strong></span>'
        f"</div>"
    )
    parts.append('<div class="chain">')

    actor = _display_name(G, path.nodes[0])

    for i, nid in enumerate(path.nodes):
        name = _escape(_display_name(G, nid))
        if i == 0:
            cls = "node-pill source"
        elif i == len(path.nodes) - 1:
            cls = "node-pill target"
        else:
            cls = "node-pill"
        parts.append(f'<div class="chain-node"><span class="{cls}">{name}</span></div>')

        if i < len(path.edges):
            edge = path.edges[i]
            rel = _escape(edge["relation"])
            w = edge["weight"]
            parts.append(
                f'<div class="chain-edge">'
                f'<div class="edge-connector">'
                f'<div class="edge-line"></div>'
                f'<span class="rel-badge">{rel}</span>'
                f'<span class="weight-badge">(w={w})</span>'
                f"</div></div>"
            )
            cmd, next_actor = _edge_commands(G, edge, actor)
            parts.append(_render_exploit_html(cmd, actor, next_actor))
            actor = next_actor

    parts.append("</div></div>")
    return "\n".join(parts)


def render_html(
    paths: list["PathResult"],
    G: "nx.DiGraph",
    source: str,
    target: str,
    stats: dict | None = None,
    intermediate: list[dict] | None = None,
    quickwins: dict[str, list["QuickWin"]] | None = None,
    pivots: list[dict] | None = None,
) -> str:
    source_name = _escape(_display_name(G, source))
    target_name = _escape(_display_name(G, target))
    stats_block = _STATS_HTML.format(**stats) if stats else ""

    if not paths:
        body = _NO_PATH_HTML.format(source=source_name, target=target_name)
        if intermediate:
            body += _intermediate_html(G, source, intermediate)
        if pivots:
            body += _pivots_html(G, pivots)
        if quickwins:
            body += _quickwins_html(quickwins)
        paths_block = body
        path_count = "0"
    else:
        paths_block = "\n".join(_render_path_html(p, G, i) for i, p in enumerate(paths, 1))
        if pivots:
            paths_block += _pivots_html(G, pivots)
        if quickwins:
            paths_block += _quickwins_html(quickwins)
        path_count = str(len(paths))

    return (
        _HTML_TEMPLATE
        .replace("{{SOURCE_NAME}}", source_name)
        .replace("{{TARGET_NAME}}", target_name)
        .replace("{{STATS_BLOCK}}", stats_block)
        .replace("{{PATH_COUNT}}", path_count)
        .replace("{{PATHS_BLOCK}}", paths_block)
    )


def _intermediate_html(
    G: "nx.DiGraph", source: str, suggestions: list[dict]
) -> str:
    if not suggestions:
        return ""
    rows = []
    for i, s in enumerate(suggestions, 1):
        nid = s["node"]
        path = s["path"]
        flags = ", ".join(_node_flags(G, nid)) or "—"
        hops = path.hops if path else "?"
        chain = (
            " &#8594; ".join(_escape(_display_name(G, n)) for n in path.nodes)
            if path else "(no path)"
        )
        rows.append(
            f'<tr><td>{i}</td><td>{s["score"]}</td>'
            f'<td><code>{_escape(_display_name(G, nid))}</code></td>'
            f'<td>{_escape(G.nodes[nid].get("kind", "?"))}</td>'
            f'<td>{hops}</td><td>{_escape(flags)}</td><td>{chain}</td></tr>'
        )
    return (
        '<h2>Intermediate Targets Reachable</h2>'
        '<p class="meta">When DA is not directly reachable, pivot through these.</p>'
        '<table class="stats-table">'
        '<tr><th>#</th><th>Score</th><th>Target</th><th>Kind</th><th>Hops</th>'
        '<th>Flags</th><th>Path</th></tr>'
        + "".join(rows)
        + "</table>"
    )


def _quickwins_html(quickwins: dict[str, list["QuickWin"]]) -> str:
    if not quickwins:
        return ""
    parts = ['<h2>Domain-Wide Quick Wins</h2>',
             '<p class="meta">Surfaced from node properties — independent of any owned user.</p>']
    for cat in sorted(quickwins):
        items = quickwins[cat]
        parts.append(f'<h3 style="color:var(--warn);margin-top:1rem">{_escape(cat)} '
                     f'<span class="weight-badge">({len(items)})</span></h3>')
        for qw in items:
            parts.append('<div class="exploit-block">')
            parts.append(
                f'<div class="actor-badge">{_escape(qw.node_name)} '
                f'({_escape(qw.node_kind)})</div>'
            )
            parts.append(f'<div class="exploit-desc">{_escape(qw.detail)}</div>')
            if qw.commands:
                lines = []
                for c in qw.commands:
                    if c.startswith("#"):
                        lines.append(f'<span class="comment">{_escape(c)}</span>')
                    else:
                        lines.append(_escape(c))
                parts.append(f'<div class="exploit-commands">{"<br>".join(lines)}</div>')
            parts.append("</div>")
    return "\n".join(parts)


# ── Multi-user renderers ──────────────────────────────────────────────────────

def render_markdown_multi(
    results: list[tuple[str, list]],
    G: "nx.DiGraph",
    target: str,
    stats: dict | None = None,
    intermediates: dict[str, list[dict]] | None = None,
    quickwins: dict[str, list["QuickWin"]] | None = None,
    pivots: list[dict] | None = None,
) -> str:
    intermediates = intermediates or {}
    if len(results) == 1:
        source, paths = results[0]
        return render_markdown(
            paths, G, source, target, stats,
            intermediate=intermediates.get(source),
            quickwins=quickwins,
            pivots=pivots,
        )

    lines: list[str] = []
    lines.append("# Pathdog — Multi-User Attack Path Report\n")
    lines.append(f"**Target:** `{_display_name(G, target)}`\n")
    if stats:
        lines.extend(_stats_md_lines(stats))

    for source, paths in results:
        src_label = _display_name(G, source)
        lines.append(f"\n---\n\n## Owned: `{src_label}`\n")
        single = render_markdown(
            paths, G, source, target, stats=None,
            intermediate=intermediates.get(source),
            quickwins=None,
            pivots=None,  # rendered once globally below
        )
        lines.append("\n".join(single.split("\n")[3:]))

    if pivots:
        lines.append("\n---\n")
        lines.extend(_pivots_md(G, pivots))

    if quickwins:
        lines.append("\n---\n")
        lines.extend(_quickwins_md(quickwins))

    return "\n".join(lines)


def render_html_multi(
    results: list[tuple[str, list]],
    G: "nx.DiGraph",
    target: str,
    stats: dict | None = None,
    intermediates: dict[str, list[dict]] | None = None,
    quickwins: dict[str, list["QuickWin"]] | None = None,
    pivots: list[dict] | None = None,
) -> str:
    intermediates = intermediates or {}
    if len(results) == 1:
        source, paths = results[0]
        return render_html(
            paths, G, source, target, stats,
            intermediate=intermediates.get(source),
            quickwins=quickwins,
            pivots=pivots,
        )

    target_name = _escape(_display_name(G, target))
    stats_block = _STATS_HTML.format(**stats) if stats else ""

    sections: list[str] = []
    for source, paths in results:
        src_label = _escape(_display_name(G, source))
        parts = [
            '<div class="user-section">',
            f'<div class="user-banner">&#128100; Owned: {src_label} &nbsp;&#8594;&nbsp; {target_name}</div>',
        ]
        if not paths:
            parts.append(_NO_PATH_HTML.format(source=src_label, target=target_name))
            inter = intermediates.get(source)
            if inter:
                parts.append(_intermediate_html(G, source, inter))
        else:
            parts.append(f'<h2>Paths Found: {len(paths)}</h2>')
            for i, p in enumerate(paths, 1):
                parts.append(_render_path_html(p, G, i))
        parts.append("</div>")
        sections.append("\n".join(parts))

    if pivots:
        sections.append(_pivots_html(G, pivots))

    if quickwins:
        sections.append(_quickwins_html(quickwins))

    return (
        _HTML_MULTI_TEMPLATE
        .replace("{{TARGET_NAME}}", target_name)
        .replace("{{STATS_BLOCK}}", stats_block)
        .replace(
            "{{SECTIONS}}",
            "\n<hr style='border-color:var(--border);margin:2rem 0'>\n".join(sections),
        )
    )
