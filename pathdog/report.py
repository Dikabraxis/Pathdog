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


# ── ANSI colors ───────────────────────────────────────────────────────────────

import os
import sys

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, code: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if _USE_COLOR else text


def _bold(s):    return _c(s, "1")
def _dim(s):     return _c(s, "2")
def _red(s):     return _c(s, "31")
def _green(s):   return _c(s, "32")
def _yellow(s):  return _c(s, "33")
def _blue(s):    return _c(s, "34")
def _magenta(s): return _c(s, "35")
def _cyan(s):    return _c(s, "36")


def print_paths_console(
    paths: list["PathResult"],
    G: "nx.DiGraph",
    source: str,
    target: str,
) -> None:
    """Print only the BEST path: ASCII chain + commands grouped by step."""
    src = _display_name(G, source)
    tgt = _display_name(G, target)

    if not paths:
        print(f"\n  {_red('✗')} No path from {_cyan(src)} to {_magenta(tgt)}.")
        return

    best = paths[0]
    dcsync_tag = _magenta(" [DCSync]") if _path_yields_dcsync(G, best) else ""
    print(f"\n  {_green('✓')} {_cyan(src)} {_dim('→')} {_magenta(tgt)}"
          f"   {_dim(f'{best.hops} hops, weight {best.total_weight}')}{dcsync_tag}")

    # ASCII chain
    print()
    print(f"    {_cyan(src)}")
    for edge in best.edges:
        rel = _yellow(f"[{edge['relation']}]")
        dst = _display_name(G, edge["dst"])
        dst_styled = _magenta(dst) if edge["dst"] == target else dst
        print(f"      {_dim('└─')}{rel}{_dim('──►')} {dst_styled}")

    # Commands grouped by actionable step
    print()
    actor = src
    step = 0
    for edge in best.edges:
        if edge["relation"] in ("MemberOf", "Contains"):
            continue
        step += 1
        cmd, next_actor = _edge_commands(G, edge, actor)
        rel = edge["relation"]
        dst = _display_name(G, edge["dst"])
        print(f"    {_bold(_blue(f'# Step {step}: {rel} on {dst}'))}  "
              f"{_dim(f'(as {actor})')}")
        for c in cmd.commands or []:
            if c.startswith("#"):
                print(f"      {_dim(c)}")
            else:
                print(f"      {_green('$')} {c}")
        if next_actor != actor:
            print(f"      {_magenta('→')} now operating as: {_cyan(next_actor)}")
        print()
        actor = next_actor

    # Footer pointer to extras
    extras = []
    if len(paths) > 1:
        extras.append(f"+{len(paths) - 1} more paths")
    if extras:
        print(f"  {_dim('  ' + ' · '.join(extras) + '  →  see HTML report')}")


def print_intermediate_targets(
    G: "nx.DiGraph",
    source: str,
    suggestions: list[dict],
) -> None:
    """One-line summary; details in the HTML report."""
    if not suggestions:
        return
    print(f"  {_dim('  ' + str(len(suggestions)) + ' intermediate target(s) reachable  →  see HTML report')}")


def print_pivot_candidates(
    G: "nx.DiGraph",
    pivots: list[dict],
    limit: int = 10,
) -> None:
    """Compact summary: top pivot + count; details in the HTML report."""
    if not pivots:
        return
    top = pivots[0]
    name = _display_name(G, top["node"])
    ptd = top["path_to_da"]
    hops = ptd.hops if ptd else "?"
    vector = top["vectors"][0] if top["vectors"] else "out-of-band"
    print()
    print(f"  {_yellow('◆')} {_bold('Best pivot:')} {_cyan(name)} "
          f"{_dim(f'({vector}, {hops} hops onward)')}")
    if len(pivots) > 1:
        print(f"  {_dim(f'  +{len(pivots) - 1} more pivot candidate(s)  →  see HTML report')}")


def print_quickwins(
    G: "nx.DiGraph",
    quickwins: dict[str, list["QuickWin"]],
    limit_per_cat: int = 5,
) -> None:
    """One-line summary per category."""
    if not quickwins:
        return
    print()
    print(f"  {_yellow('◆')} {_bold('Domain quick-wins:')}")
    for cat in sorted(quickwins, key=lambda c: -len(quickwins[c])):
        items = quickwins[cat]
        print(f"      {_yellow('•')} {cat} {_dim(f'({len(items)})')}")
    print(f"  {_dim('  full details + commands  →  see HTML report')}")


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



# ── Multi-user Markdown ───────────────────────────────────────────────────────

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
            pivots=None,
        )
        lines.append("\n".join(single.split("\n")[3:]))

    if pivots:
        lines.append("\n---\n")
        lines.extend(_pivots_md(G, pivots))

    if quickwins:
        lines.append("\n---\n")
        lines.extend(_quickwins_md(quickwins))

    return "\n".join(lines)


# ── HTML ──────────────────────────────────────────────────────────────────────

from .explanations import for_edge as _explain_edge
from .explanations import for_vector as _explain_vector
from .explanations import for_quickwin as _explain_quickwin


def _escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _bullet_list(items: list[str]) -> str:
    return "<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>"


def _flag_pills_html(G: "nx.DiGraph", nid: str) -> str:
    flags = _node_flags(G, nid)
    if not flags:
        return ""
    palette = {
        "AS-REP roastable":     "#dc2626",
        "Kerberoastable":       "#dc2626",
        "Unconstrained deleg.": "#dc2626",
        "PasswordNotReqd":      "#dc2626",
        "LAPS":                 "#0891b2",
        "AdminCount=1":         "#a16207",
        "HighValue":            "#7c3aed",
    }
    pills = []
    for f in flags:
        c = palette.get(f, "#475569")
        pills.append(f'<span class="flag-pill" style="background:{c}1a;color:{c};border-color:{c}55">{_escape(f)}</span>')
    return "".join(pills)


def _kind_icon(kind: str) -> str:
    return {
        "users": "👤",
        "computers": "💻",
        "groups": "👥",
        "domains": "🌐",
        "gpos": "📜",
        "ous": "📁",
    }.get(kind, "•")


def _verdict_html(
    G: "nx.DiGraph",
    source: str,
    target: str,
    paths: list,
    pivots: list[dict] | None,
) -> str:
    """One-line verdict at the very top — green/orange/red dot + status."""
    if paths:
        best = paths[0]
        kind = "win"
        msg = f"Path found — {best.hops} hops, weight {best.total_weight}"
    elif pivots:
        top = pivots[0]
        ptd = top["path_to_da"]
        node_name = _escape(_display_name(G, top["node"]))
        vector = top["vectors"][0] if top["vectors"] else "out-of-band"
        hops = ptd.hops if ptd else "?"
        kind = "warn"
        msg = (f"No direct path — pivot via <b>{node_name}</b> "
               f"({_escape(vector)}, {hops} hops onward)")
    else:
        kind = "fail"
        msg = "No actionable path or pivot found"

    return (
        f'<div class="verdict verdict-{kind}">'
        f'<span class="verdict-dot"></span>'
        f'<span class="verdict-msg">{msg}</span>'
        f'</div>'
    )


def _step_html(
    G: "nx.DiGraph",
    edge: dict,
    actor: str,
    step_num: int,
) -> tuple[str, str]:
    """Render one hop as a step card. Returns (html, next_actor)."""
    rel = edge["relation"]
    src_name = _display_name(G, edge["src"])
    dst_name = _display_name(G, edge["dst"])
    src_kind = G.nodes[edge["src"]].get("kind", "") if edge["src"] in G else ""
    dst_kind = G.nodes[edge["dst"]].get("kind", "") if edge["dst"] in G else ""
    explain = _explain_edge(rel)

    if rel in ("MemberOf", "Contains"):
        body = (
            f'<div class="step step-structural">'
            f'<div class="step-num">·</div>'
            f'<div class="step-body">'
            f'<div class="step-headline">{_kind_icon(src_kind)} '
            f'<code>{_escape(src_name)}</code> '
            f'<span class="step-arrow">→</span> '
            f'{_kind_icon(dst_kind)} <code>{_escape(dst_name)}</code></div>'
            f'<div class="step-meta">via <span class="rel-tag">{_escape(rel)}</span> '
            f'— {_escape(explain["plain"])}</div>'
            f'</div></div>'
        )
        return body, actor

    cmd, next_actor = _edge_commands(G, edge, actor)
    ident_change = ""
    if next_actor != actor:
        ident_change = (
            f'<div class="ident-change">'
            f'<span class="ident-arrow">↳</span> '
            f'You now operate as <code>{_escape(next_actor)}</code>'
            f'</div>'
        )

    cmd_block = ""
    if cmd.has_commands:
        lines = []
        for c in cmd.commands:
            if c.startswith("#"):
                lines.append(f'<span class="cmt">{_escape(c)}</span>')
            else:
                lines.append(_escape(c))
        cmd_block = (
            f'<details class="cmd-details" open>'
            f'<summary>Commands ({len(cmd.commands)})</summary>'
            f'<pre class="cmd-pre">{"<br>".join(lines)}</pre>'
            f'</details>'
        )

    body = (
        f'<div class="step step-action">'
        f'<div class="step-num">{step_num}</div>'
        f'<div class="step-body">'
        f'<div class="step-headline">'
        f'{_kind_icon(src_kind)} <code>{_escape(src_name)}</code> '
        f'<span class="rel-tag">{_escape(rel)}</span> '
        f'{_kind_icon(dst_kind)} <code>{_escape(dst_name)}</code>'
        f'{_flag_pills_html(G, edge["dst"])}'
        f'</div>'
        f'<div class="step-title">{_escape(explain["title"])}</div>'
        f'<div class="step-explain">{_escape(explain["plain"])}</div>'
        f'<div class="step-impact"><b>After this:</b> {_escape(explain["impact"])}</div>'
        f'{cmd_block}'
        f'{ident_change}'
        f'</div></div>'
    )
    return body, next_actor


def _path_card_html(
    path: "PathResult",
    G: "nx.DiGraph",
    index: int,
    is_best: bool = False,
) -> str:
    """Path card: ASCII chain + per-hop step (title, what it means, commands)."""
    src_name = _display_name(G, path.nodes[0])
    badge_text = "BEST" if is_best else f"PATH {index}"
    badge_cls = "best" if is_best else ""

    # ASCII chain at the top (overview)
    chain_lines = [_escape(src_name)]
    for edge in path.edges:
        rel = _escape(edge["relation"])
        dst = _escape(_display_name(G, edge["dst"]))
        chain_lines.append(f"  └─[{rel}]──► {dst}")
    chain_ascii = "\n".join(chain_lines)

    # Per-hop steps (the riches)
    steps_html: list[str] = []
    actor = src_name
    step_num = 0
    for edge in path.edges:
        if edge["relation"] in ("MemberOf", "Contains"):
            html, _ = _step_html(G, edge, actor, step_num)  # structural — no number
            steps_html.append(html)
        else:
            step_num += 1
            html, actor = _step_html(G, edge, actor, step_num)
            steps_html.append(html)

    dcsync_pill = ""
    if _path_yields_dcsync(G, path):
        dcsync_pill = '<span class="badge-dcsync">DCSync</span>'

    return (
        f'<div class="path-card{(" best" if is_best else "")}" id="path-{index}">'
        f'<div class="path-head">'
        f'<span class="path-badge {badge_cls}">{badge_text}</span>'
        f'<span class="path-stat">{path.hops} hops</span>'
        f'<span class="path-stat">weight {path.total_weight}</span>'
        f'{dcsync_pill}'
        f'</div>'
        f'<pre class="chain-ascii">{chain_ascii}</pre>'
        f'<div class="path-steps">{"".join(steps_html)}</div>'
        f'</div>'
    )


def _pivots_html(G: "nx.DiGraph", pivots: list[dict]) -> str:
    if not pivots:
        return ""
    cards = []
    for i, pv in enumerate(pivots, 1):
        nid = pv["node"]
        ptd = pv["path_to_da"]
        name = _escape(_display_name(G, nid))
        kind = G.nodes[nid].get("kind", "?")
        hops = ptd.hops if ptd else "?"

        # Vector blocks (each vector + its plain-English explanation)
        vec_blocks = []
        for v in pv["vectors"]:
            vexp = _explain_vector(v)
            vec_blocks.append(
                f'<div class="vector-block">'
                f'<div class="vector-name">{_escape(v)}</div>'
                f'<div class="vector-explain">{_escape(vexp)}</div>'
                f'</div>'
            )
        vectors_html = "".join(vec_blocks)

        # Commands always visible (the whole point: copy-paste them)
        cmd_block = ""
        if pv["vector_commands"]:
            lines = []
            for c in pv["vector_commands"]:
                if c.startswith("#"):
                    lines.append(f'<span class="cmt">{_escape(c)}</span>')
                else:
                    lines.append(_escape(c))
            cmd_block = f'<pre class="cmd-pre">{"<br>".join(lines)}</pre>'

        # Onward path
        chain = ""
        if ptd:
            lines = [_escape(_display_name(G, ptd.nodes[0]))]
            for edge in ptd.edges:
                rel = _escape(edge["relation"])
                dst = _escape(_display_name(G, edge["dst"]))
                lines.append(f"  └─[{rel}]──► {dst}")
            chain = (
                f'<div class="pivot-chain-label">Onward path to target:</div>'
                f'<pre class="chain-ascii">{chr(10).join(lines)}</pre>'
            )

        cards.append(
            f'<div class="pivot-card">'
            f'<div class="pivot-head">'
            f'<span class="pivot-rank">#{i}</span>'
            f'<span class="pivot-name">{_kind_icon(kind)} {name}</span>'
            f'<span class="pivot-stat">{hops} hops onward</span>'
            f'<span class="pivot-stat">score {pv["score"]}</span>'
            f'{_flag_pills_html(G, nid)}'
            f'</div>'
            f'<div class="pivot-body">'
            f'{vectors_html}'
            f'{cmd_block}'
            f'{chain}'
            f'</div>'
            f'</div>'
        )
    return "".join(cards)


def _intermediate_html(
    G: "nx.DiGraph", source: str, suggestions: list[dict]
) -> str:
    if not suggestions:
        return ""
    cards = []
    for i, s in enumerate(suggestions, 1):
        nid = s["node"]
        path = s["path"]
        name = _escape(_display_name(G, nid))
        kind = G.nodes[nid].get("kind", "?")
        hops = path.hops if path else "?"
        chain = ""
        if path:
            lines = [_escape(_display_name(G, path.nodes[0]))]
            for edge in path.edges:
                rel = _escape(edge["relation"])
                dst = _escape(_display_name(G, edge["dst"]))
                lines.append(f"  └─[{rel}]──► {dst}")
            chain = f'<pre class="chain-ascii">{chr(10).join(lines)}</pre>'
        cards.append(
            f'<div class="pivot-card">'
            f'<div class="pivot-head">'
            f'<span class="pivot-rank">#{i}</span>'
            f'<span class="pivot-name">{_kind_icon(kind)} {name}</span>'
            f'<span class="pivot-stat">{hops} hops</span>'
            f'<span class="pivot-stat">score {s["score"]}</span>'
            f'{_flag_pills_html(G, nid)}'
            f'</div>'
            f'<div class="pivot-body">{chain}</div>'
            f'</div>'
        )
    return "".join(cards)


def _quickwins_html(quickwins: dict[str, list["QuickWin"]]) -> str:
    if not quickwins:
        return ""
    blocks = []
    for cat in sorted(quickwins, key=lambda c: -len(quickwins[c])):
        items = quickwins[cat]
        explain = _explain_quickwin(cat) or ""

        item_cards = []
        for qw in items:
            cmd_block = ""
            if qw.commands:
                lines = []
                for c in qw.commands:
                    if c.startswith("#"):
                        lines.append(f'<span class="cmt">{_escape(c)}</span>')
                    else:
                        lines.append(_escape(c))
                cmd_block = f'<pre class="cmd-pre">{"<br>".join(lines)}</pre>'
            item_cards.append(
                f'<div class="qw-item">'
                f'<div class="qw-item-name">{_kind_icon(qw.node_kind)} '
                f'<code>{_escape(qw.node_name)}</code></div>'
                f'<div class="qw-item-detail">{_escape(qw.detail)}</div>'
                f'{cmd_block}'
                f'</div>'
            )

        blocks.append(
            f'<div class="qw-cat">'
            f'<div class="qw-cat-head">'
            f'<span class="qw-cat-title">{_escape(cat)}</span> '
            f'<span class="qw-count-small">{len(items)}</span>'
            f'</div>'
            f'<div class="qw-cat-explain">{_escape(explain)}</div>'
            f'<div class="qw-items">{"".join(item_cards)}</div>'
            f'</div>'
        )
    return "".join(blocks)


def _slug(s: str) -> str:
    return "".join(c.lower() if c.isalnum() else "-" for c in s).strip("-")


def _stats_html_block(stats: dict) -> str:
    return (
        '<details class="stats-details">'
        '<summary>Graph statistics</summary>'
        '<table class="data-table">'
        '<tr><th>Metric</th><th>Value</th></tr>'
        f'<tr><td>Total nodes</td><td>{stats["total_nodes"]}</td></tr>'
        f'<tr><td>Total edges</td><td>{stats["total_edges"]}</td></tr>'
        f'<tr><td>Pruned nodes (reachable to target)</td><td>{stats["pruned_nodes"]}</td></tr>'
        f'<tr><td>Pruned edges</td><td>{stats["pruned_edges"]}</td></tr>'
        f'<tr><td>Node reduction</td><td>{stats["reduction_pct"]}%</td></tr>'
        '</table></details>'
    )


_HTML_HEAD = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pathdog — {{TITLE_SUFFIX}}</title>
<style>
  :root {
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --soft: #1c2128;
    --code-bg: #010409; --code-text: #e6edf3; --code-cmt: #6e7681;
    --primary: #58a6ff; --primary-soft: #1f3759;
    --success: #3fb950; --success-soft: #0f2e1a;
    --warn: #d29922; --warn-soft: #3d2e0a;
    --danger: #f85149; --danger-soft: #3d1417;
    --purple: #bc8cff; --purple-soft: #2d1a55;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body {
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px; line-height: 1.55; padding: 2rem 1.5rem; max-width: 1100px;
    margin: 0 auto;
  }
  code, pre, .mono { font-family: "SF Mono", Menlo, Consolas, monospace; }
  .title { color: var(--text); font-size: 1.05rem; margin-bottom: 1rem;
           padding-bottom: .55rem; border-bottom: 1px solid var(--border); }
  .title code { background: var(--soft); padding: .1rem .35rem;
                border-radius: 3px; color: var(--primary); font-size: .85rem; }
  h2 { font-size: 1rem; color: var(--text); margin: 0 0 .5rem; }
  .more-section { background: var(--card); border: 1px solid var(--border);
                  border-radius: 6px; padding: .55rem .85rem; margin-bottom: .65rem; }
  .more-section > summary { cursor: pointer; list-style: none; color: var(--muted);
                            font-size: .85rem; font-weight: 600; user-select: none; }
  .more-section > summary::before { content: "▶ "; font-size: .65rem; }
  .more-section[open] > summary::before { content: "▼ "; }
  .more-section[open] > summary { color: var(--text); margin-bottom: .65rem;
                                  padding-bottom: .4rem; border-bottom: 1px solid var(--border); }

  /* VERDICT — one line, top of page */
  .verdict { display: flex; align-items: center; gap: .65rem;
             padding: .65rem 1rem; border-radius: 6px; margin-bottom: 1rem;
             background: var(--card); border: 1px solid var(--border); }
  .verdict-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .verdict-win  .verdict-dot { background: var(--success); }
  .verdict-warn .verdict-dot { background: var(--warn); }
  .verdict-fail .verdict-dot { background: var(--danger); }
  .verdict-msg { font-size: .92rem; }
  .verdict-msg b { color: var(--primary); }
  .verdict-msg code { background: var(--soft); padding: .1rem .35rem; border-radius: 3px; }
  .badge-dcsync { background: var(--purple-soft); color: var(--purple);
                  border: 1px solid var(--purple); padding: .1rem .45rem;
                  border-radius: 10px; font-size: .68rem; font-weight: 700;
                  letter-spacing: .05em; margin-left: auto; }

  /* SECTION */
  .report-section { background: var(--card); border: 1px solid var(--border);
                    border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }
  .section-lead { color: var(--muted); margin-bottom: 1rem; font-size: .9rem; }

  /* PATH CARD */
  .path-card { background: var(--card); border: 1px solid var(--border);
               border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
  .path-card.best { border-color: var(--success); }
  .path-head { display: flex; align-items: center; gap: .75rem;
               padding: .55rem .85rem; background: var(--soft);
               border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .path-badge { background: var(--primary); color: var(--bg); font-weight: 700;
                font-size: .7rem; padding: .15rem .5rem; border-radius: 10px;
                letter-spacing: .05em; }
  .path-badge.best { background: var(--success); }
  .path-stat { color: var(--muted); font-size: .78rem; }
  .chain-ascii { padding: .85rem 1rem; margin: 0; color: var(--text);
                 font-family: "SF Mono", Menlo, Consolas, monospace; font-size: .82rem;
                 line-height: 1.6; white-space: pre; overflow-x: auto;
                 border-bottom: 1px solid var(--border); }

  /* CHAIN PILLS */
  .path-chain { padding: .75rem 1.25rem; display: flex; flex-wrap: wrap;
                gap: .35rem; align-items: center; }
  .chain-pill { background: var(--soft); border: 1px solid var(--border);
                padding: .25rem .55rem; border-radius: 5px; font-family: monospace;
                font-size: .78rem; color: var(--text); }
  .chain-pill.src { background: var(--success-soft); border-color: var(--success);
                    color: var(--success); font-weight: 600; }
  .chain-pill.dst { background: var(--danger-soft); border-color: var(--danger);
                    color: var(--danger); font-weight: 600; }
  .chain-pill.mini { font-size: .72rem; padding: .15rem .4rem; }
  .chain-rel { color: var(--muted); font-size: .72rem; font-family: monospace;
               padding: 0 .15rem; }
  .chain-rel.mini { font-size: .68rem; }

  /* DCSYNC BANNER */
  .dcsync-banner { background: var(--purple-soft); color: var(--purple);
                   padding: .75rem 1.25rem; border-top: 1px solid var(--border);
                   border-bottom: 1px solid var(--border); font-size: .88rem; }
  .dcsync-banner code { background: var(--card); padding: .1rem .3rem;
                        border-radius: 3px; font-size: .82rem; }

  /* STEPS */
  .path-steps { padding: 0; }
  .step { display: flex; gap: .85rem; padding: .85rem 1rem;
          border-top: 1px solid var(--border); }
  .step:first-child { border-top: none; }
  .step-num { flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%;
              background: var(--primary); color: var(--bg); display: flex;
              align-items: center; justify-content: center; font-weight: 700;
              font-size: .75rem; }
  .step-structural { padding: .35rem 1rem; opacity: .65; }
  .step-structural .step-num { background: var(--soft); color: var(--muted);
                               border: 1px solid var(--border); width: 18px;
                               height: 18px; font-size: .7rem; }
  .step-body { flex: 1; min-width: 0; }
  .step-headline { font-size: .88rem; margin-bottom: .3rem; display: flex;
                   align-items: center; gap: .35rem; flex-wrap: wrap;
                   color: var(--muted); }
  .step-headline code { background: var(--soft); padding: .1rem .35rem;
                        border-radius: 3px; font-size: .8rem; color: var(--text); }
  .step-arrow { color: var(--muted); }
  .step-meta { color: var(--muted); font-size: .78rem; }
  .step-title { font-weight: 700; color: var(--primary); margin-bottom: .15rem;
                font-size: .95rem; }
  .step-explain { color: var(--text); font-size: .85rem; margin-bottom: .45rem;
                  opacity: .9; }
  .step-impact { background: var(--soft); padding: .4rem .7rem;
                 border-radius: 4px; font-size: .82rem; margin-bottom: .55rem;
                 border-left: 3px solid var(--primary); color: var(--text); }
  .step-impact b { color: var(--primary); }

  /* REL TAG */
  .rel-tag { background: var(--warn-soft); color: var(--warn); border: 1px solid var(--warn);
             padding: .1rem .4rem; border-radius: 4px; font-family: monospace;
             font-size: .72rem; font-weight: 600; }

  /* IDENTITY CHANGE */
  .ident-change { color: var(--purple); font-size: .85rem; margin-top: .5rem; }
  .ident-change code { background: var(--purple-soft); padding: .1rem .35rem;
                       border-radius: 3px; color: var(--purple); }
  .ident-arrow { font-weight: 700; }

  /* COMMANDS */
  .cmd-details { margin: .35rem 0 0; }
  .cmd-details > summary { cursor: pointer; color: var(--primary);
                           font-size: .76rem; font-weight: 600; padding: .15rem 0;
                           list-style: none; user-select: none; }
  .cmd-details > summary::before { content: "▶ "; font-size: .6rem; }
  .cmd-details[open] > summary::before { content: "▼ "; }
  .cmd-details > summary:hover { color: var(--text); }
  .cmd-pre { background: var(--code-bg); color: var(--code-text);
             padding: .85rem 1rem; margin: 0; font-size: .8rem;
             line-height: 1.7; overflow-x: auto;
             white-space: pre-wrap; word-break: break-word; }
  .cmd-pre.small { font-size: .76rem; padding: .55rem .75rem;
                   border-radius: 5px; margin-top: .35rem; }
  .cmd-pre .cmt { color: var(--code-cmt); }

  /* FLAG PILLS */
  .flag-pill { display: inline-block; font-size: .68rem; font-weight: 600;
               padding: .1rem .45rem; border-radius: 10px; border: 1px solid;
               margin-left: .25rem; }

  /* PIVOTS / INTERMEDIATES */
  .pivot-card { background: var(--card); border: 1px solid var(--border);
                border-radius: 6px; margin-bottom: .85rem; overflow: hidden; }
  .pivot-head { display: flex; align-items: center; gap: .55rem;
                padding: .55rem .85rem; background: var(--soft);
                border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .pivot-rank { background: var(--primary); color: var(--bg); font-weight: 700;
                font-size: .7rem; padding: .15rem .45rem; border-radius: 8px; }
  .pivot-name { font-weight: 600; color: var(--text); }
  .pivot-name code { background: var(--soft); padding: .1rem .35rem;
                     border-radius: 3px; }
  .pivot-stat { color: var(--muted); font-size: .78rem; }
  .pivot-body { padding: .65rem .85rem; }
  .pivot-chain-label { color: var(--muted); font-size: .78rem;
                       margin: .55rem 0 .25rem; font-weight: 600; }

  /* VECTOR (out-of-band attack) */
  .vector-block { background: var(--soft); border-left: 3px solid var(--warn);
                  padding: .55rem .75rem; border-radius: 4px;
                  margin-bottom: .5rem; }
  .vector-name { font-weight: 600; font-size: .85rem; color: var(--warn); }
  .vector-explain { color: var(--text); font-size: .82rem; margin-top: .2rem;
                    opacity: .9; }

  /* QUICK-WINS */
  .qw-cat { margin-bottom: 1.25rem; padding-bottom: 1rem;
            border-bottom: 1px dashed var(--border); }
  .qw-cat:last-child { border-bottom: none; }
  .qw-cat-head { display: flex; align-items: baseline; gap: .55rem;
                 margin-bottom: .35rem; }
  .qw-cat-title { color: var(--warn); font-weight: 700; font-size: .98rem; }
  .qw-cat-explain { color: var(--muted); font-size: .82rem;
                    margin-bottom: .65rem; }
  .qw-count-small { background: var(--soft); color: var(--muted);
                    padding: .1rem .4rem; border-radius: 8px;
                    font-size: .7rem; font-weight: 700; }
  .qw-items { display: flex; flex-direction: column; gap: .55rem; }
  .qw-item { background: var(--soft); border: 1px solid var(--border);
             border-radius: 5px; padding: .55rem .75rem; }
  .qw-item-name { font-size: .88rem; margin-bottom: .2rem; }
  .qw-item-name code { background: var(--card); padding: .1rem .35rem;
                       border-radius: 3px; color: var(--text); }
  .qw-item-detail { color: var(--muted); font-size: .8rem;
                    margin-bottom: .35rem; }
  .qw-item .cmd-pre { margin-top: .35rem; font-size: .76rem;
                      padding: .55rem .7rem; border-radius: 4px; }

  /* QUICK-WINS */
  .qw-tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
              gap: .65rem; margin-bottom: 1.25rem; }
  .qw-tile { background: var(--soft); border: 1px solid var(--border);
             border-radius: 8px; padding: .75rem .85rem; text-decoration: none;
             color: var(--text); transition: all .15s; }
  .qw-tile:hover { background: var(--primary-soft); border-color: var(--primary); }
  .qw-tile-num { font-size: 1.4rem; font-weight: 700; color: var(--primary); }
  .qw-tile-cat { font-size: .75rem; color: var(--muted); margin-top: .15rem; }
  .qw-section { margin-bottom: .85rem; border: 1px solid var(--border);
                border-radius: 8px; padding: .75rem 1rem; background: var(--card); }
  .qw-section > summary { cursor: pointer; list-style: none; display: flex;
                          align-items: center; gap: .5rem; font-weight: 600; }
  .qw-section > summary::before { content: "▶"; font-size: .7rem; color: var(--muted); }
  .qw-section[open] > summary::before { content: "▼"; }
  .qw-cat { font-size: .95rem; }
  .qw-count { background: var(--soft); color: var(--muted); font-size: .72rem;
              padding: .15rem .45rem; border-radius: 10px; font-weight: 700; }
  .qw-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
             gap: .6rem; margin-top: .75rem; }
  .qw-card { background: var(--soft); border: 1px solid var(--border);
             border-radius: 6px; padding: .6rem .75rem; }
  .qw-card-name { font-weight: 600; font-size: .85rem; margin-bottom: .2rem; }
  .qw-card-detail { color: var(--muted); font-size: .8rem; margin-bottom: .35rem; }

  /* DATA TABLE */
  .data-table { width: 100%; border-collapse: collapse; margin-top: .5rem; }
  .data-table th, .data-table td { padding: .45rem .75rem; text-align: left;
                                   border-bottom: 1px solid var(--border);
                                   font-size: .85rem; }
  .data-table th { background: var(--soft); font-weight: 600; color: var(--muted);
                   font-size: .75rem; letter-spacing: .03em; text-transform: uppercase; }
  .data-table .num { font-family: monospace; color: var(--muted); }
  .data-table code { background: var(--soft); padding: .1rem .35rem;
                     border-radius: 3px; }
  .chain-cell { white-space: nowrap; overflow-x: auto; max-width: 480px; }

  /* STATS */
  .stats-details { margin-bottom: 1.25rem; background: var(--card);
                   border: 1px solid var(--border); border-radius: 8px;
                   padding: .65rem 1rem; }
  .stats-details > summary { cursor: pointer; color: var(--muted);
                             font-size: .82rem; font-weight: 600; }

  /* USER BLOCK (multi-user) */
  .user-block { margin-bottom: 1.5rem; padding-bottom: 1rem;
                border-bottom: 1px dashed var(--border); }
  .user-block:last-of-type { border-bottom: none; }
  .user-tag { color: var(--success); font-size: .9rem; margin-bottom: .5rem; }
  .user-tag code { background: var(--soft); padding: .15rem .4rem;
                   border-radius: 4px; color: var(--success); }

  /* USER SECTION (multi-user) */
  .user-section { margin-bottom: 2rem; }
  .user-section-head { background: var(--card); border: 1px solid var(--border);
                       border-left: 4px solid var(--primary); border-radius: 8px;
                       padding: .65rem 1rem; margin-bottom: 1rem; }
  .user-section-head .label { font-size: .68rem; color: var(--muted);
                              letter-spacing: .12em; text-transform: uppercase;
                              font-weight: 700; margin-bottom: .15rem; }
  .user-section-head .who { font-family: monospace; font-weight: 600; }
  .user-section .verdict { margin-bottom: .85rem; }
  .empty-block { background: var(--soft); border: 1px solid var(--border);
                 border-radius: 8px; padding: 1rem; color: var(--muted);
                 text-align: center; font-size: .9rem; }

  footer { color: var(--muted); font-size: .75rem; padding-top: 1rem;
           border-top: 1px solid var(--border); margin-top: 2rem; text-align: center; }
  footer a { color: var(--primary); text-decoration: none; }
</style>
</head>
<body>
"""


def render_html(
    paths: list,
    G: "nx.DiGraph",
    source: str,
    target: str,
    stats: dict | None = None,
    intermediate: list[dict] | None = None,
    quickwins: dict[str, list["QuickWin"]] | None = None,
    pivots: list[dict] | None = None,
) -> str:
    src_name = _escape(_display_name(G, source))
    tgt_name = _escape(_display_name(G, target))

    head = _HTML_HEAD.replace("{{TITLE_SUFFIX}}", "Attack Path Report")
    body_parts = [
        head,
        f'<div class="title">🐶 Pathdog &nbsp;·&nbsp; '
        f'<code>{src_name}</code> → <code>{tgt_name}</code></div>',
        _verdict_html(G, source, target, paths, pivots),
    ]

    # ── Best path visible by default ──────────────────────────────────────────
    if paths:
        body_parts.append(_path_card_html(paths[0], G, 1, is_best=True))
        # Extra paths collapsed
        if len(paths) > 1:
            extra = "".join(
                _path_card_html(p, G, i, is_best=False)
                for i, p in enumerate(paths[1:], 2)
            )
            body_parts.append(
                f'<details class="more-section">'
                f'<summary>More paths ({len(paths) - 1})</summary>'
                f'{extra}</details>'
            )

    # ── Pivots, intermediates, quickwins — visible by default ────────────────
    if pivots:
        body_parts.append(
            f'<details class="more-section" open>'
            f'<summary>Pivot candidates ({len(pivots)})</summary>'
            f'{_pivots_html(G, pivots)}</details>'
        )
    if intermediate:
        body_parts.append(
            f'<details class="more-section" open>'
            f'<summary>Intermediate targets ({len(intermediate)})</summary>'
            f'{_intermediate_html(G, source, intermediate)}</details>'
        )
    if quickwins:
        n = sum(len(v) for v in quickwins.values())
        body_parts.append(
            f'<details class="more-section" open>'
            f'<summary>Domain quick-wins ({n})</summary>'
            f'{_quickwins_html(quickwins)}</details>'
        )
    if stats:
        body_parts.append(
            f'<details class="more-section">'
            f'<summary>Graph stats</summary>'
            f'{_stats_html_block(stats)}</details>'
        )

    body_parts.append('<footer>Generated by '
                      '<a href="https://github.com/dikabraxis/pathdog">pathdog</a></footer>')
    body_parts.append('</body></html>')
    return "\n".join(body_parts)


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

    tgt_name = _escape(_display_name(G, target))
    head = _HTML_HEAD.replace("{{TITLE_SUFFIX}}", "Multi-User Attack Path Report")

    body_parts = [
        head,
        f'<div class="title">🐶 Pathdog &nbsp;·&nbsp; '
        f'target <code>{tgt_name}</code> &nbsp;·&nbsp; {len(results)} owned</div>',
    ]

    # One block per user — best path visible, rest collapsed
    for source, paths in results:
        src_label = _escape(_display_name(G, source))
        body_parts.append(f'<div class="user-block">')
        body_parts.append(f'<div class="user-tag">👤 <code>{src_label}</code></div>')
        body_parts.append(_verdict_html(G, source, target, paths, pivots))
        if paths:
            body_parts.append(_path_card_html(paths[0], G, 1, is_best=True))
            if len(paths) > 1:
                extra = "".join(
                    _path_card_html(p, G, i, is_best=False)
                    for i, p in enumerate(paths[1:], 2)
                )
                body_parts.append(
                    f'<details class="more-section">'
                    f'<summary>More paths ({len(paths) - 1})</summary>'
                    f'{extra}</details>'
                )
        else:
            inter = intermediates.get(source)
            if inter:
                body_parts.append(
                    f'<details class="more-section" open>'
                    f'<summary>Intermediate targets ({len(inter)})</summary>'
                    f'{_intermediate_html(G, source, inter)}</details>'
                )
        body_parts.append('</div>')

    # Global sections (pivots / quickwins) — open; stats — collapsed
    if pivots:
        body_parts.append(
            f'<details class="more-section" open>'
            f'<summary>Pivot candidates ({len(pivots)})</summary>'
            f'{_pivots_html(G, pivots)}</details>'
        )
    if quickwins:
        n = sum(len(v) for v in quickwins.values())
        body_parts.append(
            f'<details class="more-section" open>'
            f'<summary>Domain quick-wins ({n})</summary>'
            f'{_quickwins_html(quickwins)}</details>'
        )
    if stats:
        body_parts.append(
            f'<details class="more-section">'
            f'<summary>Graph stats</summary>'
            f'{_stats_html_block(stats)}</details>'
        )

    body_parts.append('<footer>Generated by '
                      '<a href="https://github.com/dikabraxis/pathdog">pathdog</a></footer>')
    body_parts.append('</body></html>')
    return "\n".join(body_parts)
