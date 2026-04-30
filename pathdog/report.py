"""Markdown + HTML report renderer for pathdog results."""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

from .commands import CommandSet, get_commands
from .explanations import for_edge as _explain_edge
from .explanations import for_quickwin as _explain_quickwin
from .explanations import for_vector as _explain_vector

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
    # DCSync is synthesized in graph.py when both replication rights are
    # present — the half-edges (GetChanges/GetChangesAll alone) are NOT
    # exploitable on their own and are deliberately deprioritized there.
    "DCSync",
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


def _kind_label(kind: str) -> str:
    return {
        "users": "USER",
        "computers": "COMPUTER",
        "groups": "GROUP",
        "domains": "DOMAIN",
        "gpos": "GPO",
        "ous": "OU",
    }.get(kind, "NODE")


def _kind_badge(kind: str) -> str:
    return f'<span class="kind-badge kind-{_escape(kind or "unknown")}">{_kind_label(kind)}</span>'


def _status_badge(label: str, kind: str) -> str:
    return f'<span class="status-badge status-{_escape(kind)}">{_escape(label)}</span>'


def _sticky_nav_html(items: list[tuple[str, str]]) -> str:
    if not items:
        return ""
    links = "".join(
        f'<a href="#{_escape(anchor)}">{_escape(label)}</a>'
        for label, anchor in items
    )
    return f'<nav class="sticky-nav">{links}</nav>'


def _format_command_line(command: str) -> str:
    escaped = _escape(command)
    out = []
    i = 0
    while i < len(escaped):
        start = escaped.find("&lt;", i)
        if start == -1:
            out.append(escaped[i:])
            break
        end = escaped.find("&gt;", start)
        if end == -1:
            out.append(escaped[i:])
            break
        token = escaped[start + 4:end]
        if not token or not all(c.isalnum() or c in "_-.$" for c in token):
            out.append(escaped[i:start + 4])
            i = start + 4
            continue
        out.append(escaped[i:start])
        out.append(f'<span class="placeholder">{escaped[start:end + 4]}</span>')
        i = end + 4
    return "".join(out)


def _command_block(commands: list[str], *, small: bool = False, title: str | None = None) -> str:
    if not commands:
        return ""
    lines = []
    for c in commands:
        if c.startswith("#"):
            lines.append(f'<span class="cmt">{_format_command_line(c)}</span>')
        else:
            lines.append(_format_command_line(c))
    cls = "cmd-pre small" if small else "cmd-pre"
    label = _escape(title or f"Commands ({len(commands)})")
    return (
        '<div class="cmd-box">'
        f'<div class="cmd-toolbar"><span>{label}</span>'
        '<button type="button" class="copy-btn">Copy</button></div>'
        f'<pre class="{cls}">{"<br>".join(lines)}</pre>'
        '</div>'
    )


def _action_plan_html(path: "PathResult", G: "nx.DiGraph") -> str:
    actions = []
    actor = _display_name(G, path.nodes[0])
    step_num = 0
    for edge in path.edges:
        if edge["relation"] in ("MemberOf", "Contains"):
            continue
        step_num += 1
        cmd, next_actor = _edge_commands(G, edge, actor)
        dst_name = _display_name(G, edge["dst"])
        runnable = [c for c in cmd.commands if not c.startswith("#")]
        identity = ""
        if next_actor != actor:
            identity = f'<span class="plan-change">then operate as <code>{_escape(next_actor)}</code></span>'
        command_html = ""
        if runnable:
            plan_commands = runnable
            title = "Primary commands" if len(plan_commands) > 1 else "Primary command"
            command_html = _command_block(plan_commands, small=True, title=title)
        actions.append(
            '<div class="plan-row">'
            f'<div class="plan-num">{step_num}</div>'
            '<div class="plan-main">'
            f'<div class="plan-title"><span class="rel-tag">{_escape(edge["relation"])}</span> '
            f'on <code>{_escape(dst_name)}</code></div>'
            f'<div class="plan-meta">as <code>{_escape(actor)}</code> {identity}</div>'
            f'{command_html}'
            '</div></div>'
        )
        actor = next_actor
    if not actions:
        return ""
    dcsync = _status_badge("DCSYNC", "dcsync") if _path_yields_dcsync(G, path) else ""
    return (
        '<section class="action-plan" id="action-plan">'
        '<div class="plan-head">'
        '<div><div class="eyebrow">Action plan</div>'
        '<h2>Primary exploit sequence</h2></div>'
        f'<div class="plan-stats"><span>{path.hops} hops</span>'
        f'<span>weight {path.total_weight}</span>{dcsync}</div>'
        '</div>'
        f'<div class="plan-list">{"".join(actions)}</div>'
        '</section>'
    )


def _verdict_html(
    G: "nx.DiGraph",
    source: str,
    target: str,
    paths: list,
    pivots: list[dict] | None,
    info_only: bool = False,
) -> str:
    """One-line verdict at the very top — green/orange/red dot + status."""
    if paths:
        best = paths[0]
        kind = "win"
        badge = _status_badge("EXPLOITABLE", "exploitable")
        msg = f"Path found — {best.hops} hops, weight {best.total_weight}"
    elif pivots:
        top = pivots[0]
        ptd = top["path_to_da"]
        node_name = _escape(_display_name(G, top["node"]))
        vector = top["vectors"][0] if top["vectors"] else "out-of-band"
        hops = ptd.hops if ptd else "?"
        kind = "warn"
        badge = _status_badge("PIVOT REQUIRED", "pivot")
        msg = (f"No direct path — pivot via <b>{node_name}</b> "
               f"({_escape(vector)}, {hops} hops onward)")
    else:
        kind = "fail"
        if info_only:
            badge = _status_badge("INFO ONLY", "info")
            msg = "No actionable path or pivot found — informational findings are available below"
        else:
            badge = _status_badge("NO PATH", "fail")
            msg = "No actionable path or pivot found"

    return (
        f'<div class="verdict verdict-{kind}" id="verdict">'
        f'<span class="verdict-dot"></span>'
        f'{badge}'
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
            f'<div class="step-headline">{_kind_badge(src_kind)} '
            f'<code>{_escape(src_name)}</code> '
            f'<span class="step-arrow">→</span> '
            f'{_kind_badge(dst_kind)} <code>{_escape(dst_name)}</code></div>'
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
        cmd_block = (
            f'<details class="cmd-details" open>'
            f'<summary>Commands ({len(cmd.commands)})</summary>'
            f'{_command_block(cmd.commands)}'
            f'</details>'
        )

    alt_html = ""
    alt_rels = [
        r for r in (edge.get("relations") or {})
        if r != rel and r not in ("MemberOf", "Contains")
    ]
    if alt_rels:
        alt_html = (
            '<div class="step-meta">also has on this target: '
            + " ".join(f'<span class="rel-tag rel-tag-alt">{_escape(r)}</span>' for r in sorted(alt_rels))
            + '</div>'
        )

    body = (
        f'<div class="step step-action">'
        f'<div class="step-num">{step_num}</div>'
        f'<div class="step-body">'
        f'<div class="step-headline">'
        f'{_kind_badge(src_kind)} <code>{_escape(src_name)}</code> '
        f'<span class="rel-tag">{_escape(rel)}</span> '
        f'{_kind_badge(dst_kind)} <code>{_escape(dst_name)}</code>'
        f'{_flag_pills_html(G, edge["dst"])}'
        f'</div>'
        f'<div class="step-title">{_escape(explain["title"])}</div>'
        f'<div class="step-explain">{_escape(explain["plain"])}</div>'
        f'<div class="step-impact"><b>After this:</b> {_escape(explain["impact"])}</div>'
        f'{alt_html}'
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

    exploit_edges = [edge for edge in path.edges if edge["relation"] not in ("MemberOf", "Contains")]
    exploit_rows = []
    actor = src_name
    for n, edge in enumerate(exploit_edges, 1):
        cmd, next_actor = _edge_commands(G, edge, actor)
        actor_note = ""
        if next_actor != actor:
            actor_note = f'<span class="exploit-actor">operate as <code>{_escape(next_actor)}</code></span>'
        exploit_rows.append(
            '<div class="exploit-hop">'
            f'<span class="exploit-num">{n}</span>'
            f'<span class="rel-tag">{_escape(edge["relation"])}</span>'
            f'<code>{_escape(_display_name(G, edge["dst"]))}</code>'
            f'<span class="exploit-desc">{_escape(cmd.description)}</span>'
            f'{actor_note}'
            '</div>'
        )
        actor = next_actor

    exploit_html = ""
    if exploit_rows:
        exploit_html = (
            '<div class="exploit-only">'
            '<div class="eyebrow">Exploit chain</div>'
            f'{"".join(exploit_rows)}'
            '</div>'
        )

    card_id = "best-path" if is_best else f"path-{index}"
    return (
        f'<div class="path-card{(" best" if is_best else "")}" id="{card_id}">'
        f'<div class="path-head">'
        f'<span class="path-badge {badge_cls}">{badge_text}</span>'
        f'<span class="path-stat">{path.hops} hops</span>'
        f'<span class="path-stat">weight {path.total_weight}</span>'
        f'{dcsync_pill}'
        f'</div>'
        f'{exploit_html}'
        f'<details class="graph-chain">'
        f'<summary>Full graph chain ({path.hops} hops)</summary>'
        f'<pre class="chain-ascii">{chain_ascii}</pre>'
        f'</details>'
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
            cmd_block = _command_block(pv["vector_commands"], title="Pivot commands")

        # Onward path — chain always visible, per-hop commands collapsible
        chain = ""
        if ptd:
            lines = [_escape(_display_name(G, ptd.nodes[0]))]
            for edge in ptd.edges:
                rel = _escape(edge["relation"])
                dst = _escape(_display_name(G, edge["dst"]))
                lines.append(f"  └─[{rel}]──► {dst}")
            onward_steps_html: list[str] = []
            actor = _display_name(G, ptd.nodes[0])
            step_num = 0
            for edge in ptd.edges:
                if edge["relation"] in ("MemberOf", "Contains"):
                    html, _ = _step_html(G, edge, actor, step_num)
                    onward_steps_html.append(html)
                else:
                    step_num += 1
                    html, actor = _step_html(G, edge, actor, step_num)
                    onward_steps_html.append(html)
            chain = (
                f'<div class="pivot-chain-label">Onward path to target:</div>'
                f'<pre class="chain-ascii">{chr(10).join(lines)}</pre>'
                f'<details class="more-section">'
                f'<summary>Per-hop commands ({step_num})</summary>'
                f'<div class="path-steps">{"".join(onward_steps_html)}</div>'
                f'</details>'
            )

        cards.append(
            f'<div class="pivot-card">'
            f'<div class="pivot-head">'
            f'<span class="pivot-rank">#{i}</span>'
            f'<span class="pivot-name">{_kind_badge(kind)} {name}</span>'
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


def _collapsible_pivot_card_html(
    G: "nx.DiGraph",
    nid: str,
    path,
    score: int,
    index: int,
    extra_label: str = "",
) -> str:
    """Render a node entry as a collapsible card with full path + commands.

    Head (always visible): rank, name, hops, score, flags, [DCSync].
    Body (toggle): ASCII chain + per-hop steps with commands.
    """
    name = _escape(_display_name(G, nid))
    kind = G.nodes[nid].get("kind", "?")
    flags_html = _flag_pills_html(G, nid)
    extra_html = f'<span class="pivot-stat">{_escape(extra_label)}</span>' if extra_label else ""

    if not path:
        return (
            f'<div class="pivot-card">'
            f'<div class="pivot-head">'
            f'<span class="pivot-rank">#{index}</span>'
            f'<span class="pivot-name">{_kind_badge(kind)} {name}</span>'
            f'<span class="pivot-stat">no path</span>'
            f'<span class="pivot-stat">score {score}</span>'
            f'{extra_html}{flags_html}'
            f'</div>'
            f'</div>'
        )

    hops = path.hops
    src_name = _display_name(G, path.nodes[0])
    chain_lines = [_escape(src_name)]
    for edge in path.edges:
        rel = _escape(edge["relation"])
        dst = _escape(_display_name(G, edge["dst"]))
        chain_lines.append(f"  └─[{rel}]──► {dst}")
    chain_ascii = "\n".join(chain_lines)

    steps_html: list[str] = []
    actor = src_name
    step_num = 0
    for edge in path.edges:
        if edge["relation"] in ("MemberOf", "Contains"):
            html, _ = _step_html(G, edge, actor, step_num)
            steps_html.append(html)
        else:
            step_num += 1
            html, actor = _step_html(G, edge, actor, step_num)
            steps_html.append(html)

    dcsync_pill = ""
    if _path_yields_dcsync(G, path):
        dcsync_pill = '<span class="badge-dcsync">DCSync</span>'

    return (
        f'<details class="pivot-card">'
        f'<summary class="pivot-head">'
        f'<span class="pivot-rank">#{index}</span>'
        f'<span class="pivot-name">{_kind_badge(kind)} {name}</span>'
        f'<span class="pivot-stat">{hops} hops</span>'
        f'<span class="pivot-stat">score {score}</span>'
        f'{extra_html}{dcsync_pill}{flags_html}'
        f'</summary>'
        f'<pre class="chain-ascii">{chain_ascii}</pre>'
        f'<div class="path-steps">{"".join(steps_html)}</div>'
        f'</details>'
    )


def _intermediate_html(
    G: "nx.DiGraph", source: str, suggestions: list[dict]
) -> str:
    if not suggestions:
        return ""
    cards = [
        _collapsible_pivot_card_html(G, s["node"], s["path"], s["score"], i)
        for i, s in enumerate(suggestions, 1)
    ]
    return "".join(cards)


def _quickwins_html(quickwins: dict[str, list["QuickWin"]]) -> str:
    if not quickwins:
        return ""
    blocks = []
    categories = sorted(quickwins, key=lambda c: -len(quickwins[c]))
    tiles = []
    for cat in categories:
        items = quickwins[cat]
        slug = _slug(cat)
        tiles.append(
            f'<a class="qw-tile" href="#qw-{slug}">'
            f'<span class="qw-tile-num">{len(items)}</span>'
            f'<span class="qw-tile-cat">{_escape(cat)}</span>'
            f'</a>'
        )

    for i, cat in enumerate(categories, 1):
        items = quickwins[cat]
        explain = _explain_quickwin(cat) or ""
        slug = _slug(cat)

        item_cards = []
        for qw in items[:3]:
            cmd_block = ""
            if qw.commands:
                cmd_block = (
                    '<details class="cmd-details">'
                    f'<summary>Commands ({len(qw.commands)})</summary>'
                    f'{_command_block(qw.commands, small=True, title="Commands")}'
                    '</details>'
                )
            item_cards.append(
                f'<div class="qw-item">'
                f'<div class="qw-item-name">{_kind_badge(qw.node_kind)} '
                f'<code>{_escape(qw.node_name)}</code></div>'
                f'<div class="qw-item-detail">{_escape(qw.detail)}</div>'
                f'{cmd_block}'
                f'</div>'
            )

        more_items = []
        for qw in items[3:]:
            cmd_block = ""
            if qw.commands:
                cmd_block = (
                    '<details class="cmd-details">'
                    f'<summary>Commands ({len(qw.commands)})</summary>'
                    f'{_command_block(qw.commands, small=True, title="Commands")}'
                    '</details>'
                )
            more_items.append(
                f'<div class="qw-item">'
                f'<div class="qw-item-name">{_kind_badge(qw.node_kind)} '
                f'<code>{_escape(qw.node_name)}</code></div>'
                f'<div class="qw-item-detail">{_escape(qw.detail)}</div>'
                f'{cmd_block}'
                f'</div>'
            )
        more_html = ""
        if more_items:
            more_html = (
                f'<details class="qw-more">'
                f'<summary>Show all remaining ({len(more_items)})</summary>'
                f'<div class="qw-items">{"".join(more_items)}</div>'
                f'</details>'
            )
        open_attr = " open" if i <= 3 else ""
        blocks.append(
            f'<details class="qw-cat" id="qw-{slug}"{open_attr}>'
            f'<summary class="qw-cat-head">'
            f'<span class="qw-cat-title">{_escape(cat)}</span> '
            f'<span class="qw-count-small">{len(items)}</span>'
            f'</summary>'
            f'<div class="qw-cat-explain">{_escape(explain)}</div>'
            f'<div class="qw-items">{"".join(item_cards)}</div>'
            f'{more_html}'
            f'</details>'
        )
    return (
        '<div class="quickwin-summary">'
        f'{"".join(tiles)}'
        '</div>'
        + "".join(blocks)
    )


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
	<script>
	document.addEventListener("click", (event) => {
	  const button = event.target.closest(".copy-btn");
	  if (!button) return;
	  const box = button.closest(".cmd-box");
	  const pre = box ? box.querySelector("pre") : null;
	  if (!pre) return;
	  const done = () => {
	    const original = button.textContent;
	    button.textContent = "Copied";
	    window.setTimeout(() => { button.textContent = original; }, 1200);
	  };
	  if (navigator.clipboard) {
	    navigator.clipboard.writeText(pre.innerText).then(done);
	    return;
	  }
	  const range = document.createRange();
	  range.selectNodeContents(pre);
	  const selection = window.getSelection();
	  selection.removeAllRanges();
	  selection.addRange(range);
	  document.execCommand("copy");
	  selection.removeAllRanges();
	  done();
	});
	document.addEventListener("input", (event) => {
	  const input = event.target.closest(".object-filter");
	  if (!input) return;
	  const block = input.closest(".object-control-block");
	  if (!block) return;
	  const needle = input.value.trim().toLowerCase();
	  block.querySelectorAll("tr[data-filter]").forEach((row) => {
	    row.hidden = needle.length > 0 && !row.dataset.filter.includes(needle);
	  });
	});
	</script>
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
	  .brand { font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
	  h2 { font-size: 1rem; color: var(--text); margin: 0 0 .5rem; }
  .sticky-nav { position: sticky; top: 0; z-index: 20; display: flex; gap: .35rem;
                overflow-x: auto; padding: .45rem 0 .75rem; margin-bottom: .5rem;
                background: var(--bg); border-bottom: 1px solid var(--border); }
  .sticky-nav a { flex: 0 0 auto; color: var(--muted); text-decoration: none;
                  border: 1px solid var(--border); background: var(--card);
                  border-radius: 999px; padding: .25rem .6rem; font-size: .75rem;
                  font-weight: 700; }
  .sticky-nav a:hover { color: var(--primary); border-color: var(--primary); }
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

	  /* ACTION PLAN */
	  .action-plan { background: var(--card); border: 1px solid var(--success);
	                 border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
	  .plan-head { display: flex; justify-content: space-between; align-items: flex-start;
	               gap: 1rem; padding: .85rem 1rem; background: var(--success-soft);
	               border-bottom: 1px solid var(--border); }
	  .eyebrow { color: var(--muted); font-size: .68rem; letter-spacing: .12em;
	             text-transform: uppercase; font-weight: 800; margin-bottom: .1rem; }
	  .plan-stats { display: flex; align-items: center; gap: .45rem; flex-wrap: wrap;
	                color: var(--muted); font-size: .78rem; justify-content: flex-end; }
	  .status-badge { border: 1px solid var(--border); border-radius: 10px;
	                  padding: .1rem .45rem; font-size: .68rem; font-weight: 800;
	                  letter-spacing: .06em; }
	  .status-exploitable { color: var(--success); border-color: var(--success);
	                        background: var(--success-soft); }
	  .status-pivot { color: var(--warn); border-color: var(--warn);
	                  background: var(--warn-soft); }
	  .status-fail { color: var(--danger); border-color: var(--danger);
	                 background: var(--danger-soft); }
	  .status-info { color: var(--primary); border-color: var(--primary);
	                 background: var(--primary-soft); }
	  .status-dcsync { color: var(--purple); border-color: var(--purple);
	                   background: var(--purple-soft); }
	  .plan-list { display: flex; flex-direction: column; }
	  .plan-row { display: flex; gap: .75rem; padding: .85rem 1rem;
	              border-top: 1px solid var(--border); }
	  .plan-row:first-child { border-top: none; }
	  .plan-num { width: 24px; height: 24px; border-radius: 50%; flex: 0 0 auto;
	              display: flex; align-items: center; justify-content: center;
	              background: var(--success); color: var(--bg); font-weight: 800;
	              font-size: .72rem; }
	  .plan-main { min-width: 0; flex: 1; }
	  .plan-title { font-weight: 700; margin-bottom: .2rem; }
	  .plan-meta, .plan-change { color: var(--muted); font-size: .78rem; }
	  .plan-meta code { background: var(--soft); color: var(--text);
	                    padding: .1rem .35rem; border-radius: 3px; }

	  /* KIND BADGES */
	  .kind-badge { display: inline-block; border: 1px solid var(--border);
	                color: var(--muted); background: var(--soft); border-radius: 4px;
	                padding: .05rem .3rem; font-size: .62rem; font-weight: 800;
	                letter-spacing: .05em; vertical-align: middle; }
	  .kind-users { color: var(--primary); border-color: var(--primary); background: var(--primary-soft); }
	  .kind-computers { color: var(--success); border-color: var(--success); background: var(--success-soft); }
	  .kind-groups { color: var(--warn); border-color: var(--warn); background: var(--warn-soft); }
	  .kind-domains { color: var(--purple); border-color: var(--purple); background: var(--purple-soft); }

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
  .exploit-only { padding: .8rem 1rem; border-bottom: 1px solid var(--border);
                  background: color-mix(in srgb, var(--success-soft) 55%, transparent); }
  .exploit-hop { display: flex; align-items: center; gap: .45rem; flex-wrap: wrap;
                 padding: .3rem 0; font-size: .82rem; }
  .exploit-num { width: 20px; height: 20px; border-radius: 50%; background: var(--success);
                 color: var(--bg); display: inline-flex; align-items: center;
                 justify-content: center; font-weight: 800; font-size: .68rem; }
  .exploit-desc, .exploit-actor { color: var(--muted); }
  .exploit-actor code { background: var(--purple-soft); color: var(--purple);
                        padding: .1rem .35rem; border-radius: 3px; }
  .graph-chain { border-bottom: 1px solid var(--border); }
  .graph-chain > summary { cursor: pointer; list-style: none; color: var(--muted);
                           font-size: .78rem; font-weight: 700; padding: .55rem 1rem;
                           background: var(--soft); user-select: none; }
  .graph-chain > summary::before { content: "▶ "; font-size: .6rem; }
  .graph-chain[open] > summary::before { content: "▼ "; }
  .graph-chain .chain-ascii { border-bottom: none; }

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
  .rel-tag-alt { background: transparent; color: var(--muted); border-color: var(--border);
                 font-weight: 500; }

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
	  .cmd-box { margin-top: .35rem; border: 1px solid var(--border);
	             border-radius: 6px; overflow: hidden; background: var(--code-bg); }
	  .cmd-toolbar { display: flex; align-items: center; justify-content: space-between;
	                 gap: .75rem; padding: .35rem .55rem; background: var(--soft);
	                 border-bottom: 1px solid var(--border); color: var(--muted);
	                 font-size: .72rem; font-weight: 700; }
	  .copy-btn { border: 1px solid var(--border); background: var(--card);
	              color: var(--text); border-radius: 4px; padding: .15rem .45rem;
	              font: inherit; cursor: pointer; }
	  .copy-btn:hover { border-color: var(--primary); color: var(--primary); }
	  .cmd-pre { background: var(--code-bg); color: var(--code-text);
	             padding: .85rem 1rem; margin: 0; font-size: .8rem;
             line-height: 1.7; overflow-x: auto;
             white-space: pre-wrap; word-break: break-word; }
  .cmd-pre.small { font-size: .76rem; padding: .55rem .75rem;
                   border-radius: 5px; margin-top: .35rem; }
  .cmd-pre .cmt { color: var(--code-cmt); }
  .placeholder { color: var(--warn); background: var(--warn-soft);
                 border: 1px solid color-mix(in srgb, var(--warn) 55%, transparent);
                 border-radius: 3px; padding: 0 .18rem; font-weight: 700; }

  /* FLAG PILLS */
  .flag-pill { display: inline-block; font-size: .68rem; font-weight: 600;
               padding: .1rem .45rem; border-radius: 10px; border: 1px solid;
               margin-left: .25rem; }

  /* PIVOTS / INTERMEDIATES */
  .pivot-card { background: var(--card); border: 1px solid var(--border);
                border-radius: 6px; margin-bottom: .85rem; overflow: hidden; }
  details.pivot-card > summary { cursor: pointer; list-style: none; user-select: none; }
  details.pivot-card > summary::-webkit-details-marker { display: none; }
  details.pivot-card > summary.pivot-head { border-bottom: 1px solid transparent; }
  details.pivot-card[open] > summary.pivot-head { border-bottom-color: var(--border); }
  details.pivot-card > summary.pivot-head::before {
    content: "▶"; color: var(--muted); font-size: .65rem; margin-right: .15rem;
  }
  details.pivot-card[open] > summary.pivot-head::before { content: "▼"; }
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
  .quickwin-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
                      gap: .5rem; margin-bottom: .85rem; }
  .quickwin-summary .qw-tile { display: flex; align-items: center; gap: .55rem;
                               border-radius: 6px; padding: .45rem .6rem; }
  .quickwin-summary .qw-tile-num { font-size: 1rem; line-height: 1; }
  .quickwin-summary .qw-tile-cat { margin-top: 0; }
  .qw-cat { margin-bottom: 1.25rem; padding-bottom: 1rem;
            border-bottom: 1px dashed var(--border); }
  details.qw-cat > summary { cursor: pointer; list-style: none; user-select: none; }
  details.qw-cat > summary::before { content: "▶"; color: var(--muted); font-size: .65rem; }
  details.qw-cat[open] > summary::before { content: "▼"; }
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
  .qw-more { margin-top: .6rem; }
  .qw-more > summary { cursor: pointer; color: var(--primary); font-size: .78rem;
                       font-weight: 700; list-style: none; }

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
  .object-control-block { display: flex; flex-direction: column; gap: .55rem; }
  .object-tools { display: flex; justify-content: flex-end; }
  .object-filter { width: min(260px, 100%); background: var(--soft); color: var(--text);
                   border: 1px solid var(--border); border-radius: 5px;
                   padding: .35rem .55rem; font: inherit; font-size: .8rem; }
  .object-filter:focus { outline: none; border-color: var(--primary); }
  .relation-chips { display: flex; flex-wrap: wrap; gap: .35rem; }
  .relation-chip { display: inline-flex; align-items: center; gap: .35rem;
                   border: 1px solid var(--border); background: var(--soft);
                   border-radius: 999px; padding: .15rem .45rem; color: var(--muted);
                   font-size: .72rem; }
  .relation-chip b { color: var(--text); }
  .object-table { margin-top: 0; }
  .show-all { border: 1px dashed var(--border); border-radius: 6px;
              padding: .5rem .65rem; }
  .show-all > summary { cursor: pointer; color: var(--primary); font-size: .8rem;
                        font-weight: 700; list-style: none; }

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

  .section-banner { border-left: 4px solid var(--primary); background: var(--soft);
                    padding: .75rem 1.25rem; border-radius: 8px; margin-bottom: 1.5rem;
                    display: flex; align-items: center; gap: .75rem; }
  .section-banner .banner-title { font-size: .8rem; letter-spacing: .1em;
                                  text-transform: uppercase; font-weight: 800; }
  .section-banner .banner-meta { font-size: .75rem; color: var(--muted); }
  .section-banner.attack { border-left-color: var(--success); background: var(--success-soft); }
  .section-banner.attack .banner-title { color: var(--success); }
  .section-banner.node { border-left-color: var(--purple); background: var(--purple-soft); }
  .section-banner.node .banner-title { color: var(--purple); }

  @media (max-width: 720px) {
    body { padding: .75rem; font-size: 13px; }
    .title { line-height: 1.8; }
    .sticky-nav { top: 0; margin-left: -.75rem; margin-right: -.75rem;
                  padding-left: .75rem; padding-right: .75rem; }
    .report-section { padding: .8rem; border-radius: 8px; }
    .plan-head, .path-head, .pivot-head { align-items: flex-start; }
    .plan-head { flex-direction: column; }
    .plan-stats { justify-content: flex-start; }
    .step { gap: .55rem; padding: .65rem .75rem; }
    .step-num, .plan-num { width: 22px; height: 22px; }
    .exploit-hop { align-items: flex-start; }
    .data-table { display: block; overflow-x: auto; white-space: nowrap; }
    .quickwin-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .object-tools { justify-content: stretch; }
    .object-filter { width: 100%; }
  }

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
    nav_items = [("Verdict", "verdict")]
    if paths:
        nav_items.extend([("Action plan", "action-plan"), ("Best path", "best-path")])
        if len(paths) > 1:
            nav_items.append(("More paths", "more-paths"))
    if pivots:
        nav_items.append(("Pivots", "pivots"))
    if intermediate:
        nav_items.append(("Intermediate", "intermediate"))
    if quickwins:
        nav_items.append(("Quick-wins", "quickwins"))
    if stats:
        nav_items.append(("Stats", "stats"))
    body_parts = [
        head,
        f'<div class="title"><span class="brand">Pathdog</span> &nbsp;·&nbsp; '
        f'<code>{src_name}</code> → <code>{tgt_name}</code></div>',
        _sticky_nav_html(nav_items),
        _verdict_html(
            G, source, target, paths, pivots,
            info_only=bool(intermediate or quickwins),
        ),
    ]

    # ── Best path visible by default ──────────────────────────────────────────
    if paths:
        body_parts.append(_action_plan_html(paths[0], G))
        body_parts.append(_path_card_html(paths[0], G, 1, is_best=True))
        # Extra paths collapsed
        if len(paths) > 1:
            extra = "".join(
                _path_card_html(p, G, i, is_best=False)
                for i, p in enumerate(paths[1:], 2)
            )
            body_parts.append(
                f'<details class="more-section" id="more-paths">'
                f'<summary>More paths ({len(paths) - 1})</summary>'
                f'{extra}</details>'
            )

    # ── Pivots, intermediates, quickwins — visible by default ────────────────
    if pivots:
        body_parts.append(
            f'<details class="more-section" id="pivots" open>'
            f'<summary>Pivot candidates ({len(pivots)})</summary>'
            f'{_pivots_html(G, pivots)}</details>'
        )
    if intermediate:
        body_parts.append(
            f'<details class="more-section" id="intermediate" open>'
            f'<summary>Intermediate targets ({len(intermediate)})</summary>'
            f'{_intermediate_html(G, source, intermediate)}</details>'
        )
    if quickwins:
        n = sum(len(v) for v in quickwins.values())
        body_parts.append(
            f'<details class="more-section" id="quickwins" open>'
            f'<summary>Domain quick-wins ({n})</summary>'
            f'{_quickwins_html(quickwins)}</details>'
        )
    if stats:
        body_parts.append(
            f'<details class="more-section" id="stats">'
            f'<summary>Graph stats</summary>'
            f'{_stats_html_block(stats)}</details>'
        )

    body_parts.append('<footer>Generated by '
                      '<a href="https://github.com/dikabraxis/pathdog">pathdog</a></footer>')
    body_parts.append('</body></html>')
    return "\n".join(body_parts)


def print_node_visibility_console(
    G: "nx.DiGraph",
    node: str,
    target: str | None,
    outbound_paths: list,
    outbound_intermediate: list[dict],
    inbound_sources: list[dict],
    outbound_control: list[dict] | None = None,
    inbound_control: list[dict] | None = None,
) -> None:
    """Print a compact node visibility summary — full details are in the HTML report."""
    name = _display_name(G, node)
    kind = G.nodes[node].get("kind", "?") if node in G else "?"
    flags = _node_flags(G, node)
    flags_str = f"  [{', '.join(flags)}]" if flags else ""

    print(f"\n  {_bold('Node:')} {_cyan(name)} {_dim(f'({kind}){flags_str}')}")
    print(f"  {'─' * 55}")

    # ── Object control (compact: count + one example) ─────────────────────────
    outbound_control = outbound_control or []
    inbound_control = inbound_control or []

    direct = [e for e in outbound_control if e["via_group"] is None]
    indirect = [e for e in outbound_control if e["via_group"] is not None]
    if outbound_control:
        example = outbound_control[0]
        ex_dst = _display_name(G, example["dst"])
        ex_via = f" via {example['via_group']}" if example["via_group"] else ""
        print(f"\n  {_bold(_yellow('→ OUTBOUND CONTROL'))}  "
              f"{_dim(f'{len(direct)} direct, {len(indirect)} via group(s)')}")
        print(f"    {_yellow('•')} {_yellow(example['relation'])} on {ex_dst}{_dim(ex_via)}")
        if len(outbound_control) > 1:
            print(f"    {_dim(f'  +{len(outbound_control) - 1} more privilege(s)  →  see HTML report')}")
    else:
        print(f"\n  {_bold(_yellow('→ OUTBOUND CONTROL'))}  {_dim('no direct privileges found')}")

    if inbound_control:
        example_in = inbound_control[0]
        ex_src = _display_name(G, example_in["src"])
        ex_rel = example_in["relation"]
        print(f"\n  {_bold(_yellow('← INBOUND CONTROL'))}  "
              f"{_dim(f'{len(inbound_control)} principal(s) have privileges over this node')}")
        print(f"    {_yellow('•')} {_cyan(ex_src)} {_dim(f'[{ex_rel}]')}")
        if len(inbound_control) > 1:
            print(f"    {_dim(f'  +{len(inbound_control) - 1} more  →  see HTML report')}")
    else:
        print(f"\n  {_bold(_yellow('← INBOUND CONTROL'))}  {_dim('no direct incoming privileges found')}")

    # ── Attack paths (outbound) ───────────────────────────────────────────────
    tgt_label = _display_name(G, target) if target else "high-value targets"
    print(f"\n  {_bold(_yellow('→ ATTACK PATHS'))}  outbound to {_magenta(tgt_label)}")

    if outbound_paths:
        best = outbound_paths[0]
        dcsync_tag = _magenta(" [DCSync]") if _path_yields_dcsync(G, best) else ""
        print(f"    {_green('✓')} {best.hops} hops, weight {best.total_weight}{dcsync_tag}")
        extras = []
        if len(outbound_paths) > 1:
            extras.append(f"+{len(outbound_paths) - 1} more paths")
        if extras:
            print(f"    {_dim('  ' + ' · '.join(extras) + '  →  see HTML report')}")
    elif outbound_intermediate:
        print(f"    {_yellow('~')} No path to DA — "
              f"{len(outbound_intermediate)} reachable high-value target(s)  "
              f"{_dim('→  see HTML report')}")
    else:
        print(f"    {_red('✗')} No paths to high-value targets found.")

    # ── Inbound attackers ─────────────────────────────────────────────────────
    print(f"\n  {_bold(_yellow('← INBOUND ATTACKERS'))}  who can reach {_cyan(name)}")

    if inbound_sources:
        # inbound_sources is sorted by score; for "closest" we want fewest hops.
        top = min(
            inbound_sources,
            key=lambda x: (x["path"].hops if x["path"] else 10**9, -x["score"]),
        )
        top_name = _display_name(G, top["node"])
        top_hops = top["path"].hops if top["path"] else "?"
        print(f"    {_red('!')} {len(inbound_sources)} principal(s) — "
              f"closest: {_cyan(top_name)} {_dim(f'({top_hops} hops)')}")
        print(f"    {_dim('  full list  →  see HTML report')}")
    else:
        print(f"    {_green('✓')} No paths found from other principals.")
    print()


def _relation_chips(entries: list[dict]) -> str:
    counts: dict[str, int] = {}
    for e in entries:
        rel = e.get("relation", "?")
        counts[rel] = counts.get(rel, 0) + 1
    chips = "".join(
        f'<span class="relation-chip"><span>{_escape(rel)}</span><b>{count}</b></span>'
        for rel, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    )
    return f'<div class="relation-chips">{chips}</div>' if chips else ""


def _object_control_out_html(G: "nx.DiGraph", entries: list[dict]) -> str:
    """Render outbound object control table (direct + via group)."""
    if not entries:
        return '<div class="empty-block">No outbound privileges found.</div>'
    rows = []
    for e in entries:
        dst_name = _escape(_display_name(G, e["dst"]))
        dst_kind = G.nodes[e["dst"]].get("kind", "?") if e["dst"] in G else "?"
        via = f'<span class="step-meta">via {_escape(e["via_group"])}</span>' if e["via_group"] else '<span class="step-meta">direct</span>'
        filter_text = _escape(f'{e["relation"]} {dst_name} {e["via_group"] or "direct"}'.lower())
        rows.append(
            f'<tr data-filter="{filter_text}">'
            f'<td><span class="rel-tag">{_escape(e["relation"])}</span></td>'
            f'<td>{_kind_badge(dst_kind)} <code>{dst_name}</code>'
            f'{_flag_pills_html(G, e["dst"])}</td>'
            f'<td>{via}</td>'
            f'</tr>'
        )
    shown = rows[:50]
    remaining = rows[50:]
    table_head = '<tr><th>Relation</th><th>Target object</th><th>How</th></tr>'
    remaining_html = ""
    if remaining:
        remaining_html = (
            f'<details class="show-all">'
            f'<summary>Show all remaining rows ({len(remaining)})</summary>'
            f'<table class="data-table object-table">{table_head}{"".join(remaining)}</table>'
            f'</details>'
        )
    return (
        '<div class="object-control-block">'
        '<div class="object-tools">'
        '<input class="object-filter" type="search" placeholder="Filter rows">'
        '</div>'
        f'{_relation_chips(entries)}'
        f'<table class="data-table object-table">{table_head}{"".join(shown)}</table>'
        f'{remaining_html}'
        '</div>'
    )


def _object_control_in_html(G: "nx.DiGraph", entries: list[dict]) -> str:
    """Render inbound object control table (who has privileges over this node)."""
    if not entries:
        return '<div class="empty-block">No inbound privileges found.</div>'
    rows = []
    for e in entries:
        src_name = _escape(_display_name(G, e["src"]))
        src_kind = G.nodes[e["src"]].get("kind", "?") if e["src"] in G else "?"
        filter_text = _escape(f'{e["relation"]} {src_name}'.lower())
        rows.append(
            f'<tr data-filter="{filter_text}">'
            f'<td><span class="rel-tag">{_escape(e["relation"])}</span></td>'
            f'<td>{_kind_badge(src_kind)} <code>{src_name}</code>'
            f'{_flag_pills_html(G, e["src"])}</td>'
            f'</tr>'
        )
    shown = rows[:50]
    remaining = rows[50:]
    table_head = '<tr><th>Relation</th><th>Principal</th></tr>'
    remaining_html = ""
    if remaining:
        remaining_html = (
            f'<details class="show-all">'
            f'<summary>Show all remaining rows ({len(remaining)})</summary>'
            f'<table class="data-table object-table">{table_head}{"".join(remaining)}</table>'
            f'</details>'
        )
    return (
        '<div class="object-control-block">'
        '<div class="object-tools">'
        '<input class="object-filter" type="search" placeholder="Filter rows">'
        '</div>'
        f'{_relation_chips(entries)}'
        f'<table class="data-table object-table">{table_head}{"".join(shown)}</table>'
        f'{remaining_html}'
        '</div>'
    )


def _inbound_sources_html(G: "nx.DiGraph", sources: list[dict]) -> str:
    """Render inbound source cards (who can reach the target node)."""
    if not sources:
        return '<div class="empty-block">No paths found from other principals.</div>'
    cards = [
        _collapsible_pivot_card_html(G, s["node"], s["path"], s["score"], i)
        for i, s in enumerate(sources, 1)
    ]
    return "".join(cards)


def render_html_node_visibility(
    G: "nx.DiGraph",
    node: str,
    target: str | None,
    outbound_paths: list,
    outbound_intermediate: list[dict],
    inbound_sources: list[dict],
    stats: dict | None = None,
    outbound_control: list[dict] | None = None,
    inbound_control: list[dict] | None = None,
) -> str:
    """Render a standalone HTML report for outbound/inbound node visibility."""
    node_name = _escape(_display_name(G, node))
    flags_html = _flag_pills_html(G, node)
    tgt_display = _escape(_display_name(G, target)) if target else "—"
    outbound_control = outbound_control or []
    inbound_control = inbound_control or []

    head = _HTML_HEAD.replace("{{TITLE_SUFFIX}}", _escape(f"Node Visibility: {_display_name(G, node)}"))
    nav_items = []
    if outbound_paths:
        nav_items.extend([("Action plan", "action-plan"), ("Best path", "best-path")])
        if len(outbound_paths) > 1:
            nav_items.append(("More paths", "more-paths"))
    if outbound_intermediate:
        nav_items.append(("Reachable HVTs", "intermediate"))
    nav_items.extend([
        ("Inbound attackers", "inbound-attackers"),
        ("Outbound control", "outbound-control"),
        ("Inbound control", "inbound-control"),
    ])
    if stats:
        nav_items.append(("Stats", "stats"))
    body_parts = [
        head,
        f'<div class="title"><span class="brand">Pathdog</span> &nbsp;·&nbsp; '
        f'<span style="color:var(--muted);font-size:.85rem">node visibility</span>'
        f' &nbsp;·&nbsp; <code>{node_name}</code> {flags_html}</div>',
        _sticky_nav_html(nav_items),
    ]

    # ── Attack paths (outbound) + collapsible secondary sections ─────────────
    direct_count = sum(1 for e in outbound_control if e["via_group"] is None)
    indirect_count = len(outbound_control) - direct_count
    inbound_count = len(inbound_sources)

    outbound_path_label = (
        f"→ Attack Paths — outbound to {tgt_display}"
        if target else "→ Attack Paths — reachable targets"
    )
    if outbound_paths:
        outbound_path_content = (
            _action_plan_html(outbound_paths[0], G)
            + _path_card_html(outbound_paths[0], G, 1, is_best=True)
        )
        if len(outbound_paths) > 1:
            extra = "".join(
                _path_card_html(p, G, i, is_best=False)
                for i, p in enumerate(outbound_paths[1:], 2)
            )
            outbound_path_content += (
                f'<details class="more-section" id="more-paths">'
                f'<summary>More paths ({len(outbound_paths) - 1})</summary>'
                f'{extra}</details>'
            )
        if outbound_intermediate:
            outbound_path_content += (
                f'<details class="more-section" id="intermediate" open>'
                f'<summary>Other reachable high-value targets ({len(outbound_intermediate)})'
                f' — nodes reachable from here, useful as pivot steps even without a direct DA path'
                f'</summary>'
                f'{_intermediate_html(G, node, outbound_intermediate)}</details>'
            )
    elif outbound_intermediate:
        outbound_path_content = (
            f'<details class="more-section" id="intermediate" open>'
            f'<summary>Other reachable high-value targets ({len(outbound_intermediate)})'
            f' — nodes reachable from here, useful as pivot steps even without a direct DA path'
            f'</summary>'
            f'{_intermediate_html(G, node, outbound_intermediate)}</details>'
        )
    else:
        outbound_path_content = (
            '<div class="empty-block">No outbound paths to high-value targets.</div>'
        )

    outbound_path_content += (
        f'<details class="more-section" id="inbound-attackers">'
        f'<summary>← Inbound Attackers ({inbound_count} principal(s))'
        f' — who has an attack path leading TO this node</summary>'
        f'{_inbound_sources_html(G, inbound_sources)}'
        f'</details>'
    )
    outbound_path_content += (
        f'<details class="more-section" id="outbound-control">'
        f'<summary>→ Outbound Object Control ({direct_count} direct · {indirect_count} via group)'
        f' — objects this node has privileges over</summary>'
        f'{_object_control_out_html(G, outbound_control)}'
        f'</details>'
    )
    outbound_path_content += (
        f'<details class="more-section" id="inbound-control">'
        f'<summary>← Inbound Object Control ({len(inbound_control)} principal(s))'
        f' — principals with direct privileges over this node</summary>'
        f'{_object_control_in_html(G, inbound_control)}'
        f'</details>'
    )

    body_parts.append(
        f'<div class="report-section">'
        f'<h2>{outbound_path_label}</h2>'
        f'<p class="section-lead">Full attack chains from this node.</p>'
        f'{outbound_path_content}'
        f'</div>'
    )

    if stats:
        body_parts.append(
            f'<details class="more-section" id="stats">'
            f'<summary>Graph stats</summary>'
            f'{_stats_html_block(stats)}</details>'
        )

    body_parts.append('<footer>Generated by '
                      '<a href="https://github.com/dikabraxis/pathdog">pathdog</a></footer>')
    body_parts.append('</body></html>')
    return "\n".join(body_parts)


def render_markdown_node_visibility(
    G: "nx.DiGraph",
    node: str,
    target: str | None,
    outbound_paths: list,
    outbound_intermediate: list[dict],
    inbound_sources: list[dict],
    stats: dict | None = None,
    outbound_control: list[dict] | None = None,
    inbound_control: list[dict] | None = None,
) -> str:
    """Render a Markdown report for outbound/inbound node visibility."""
    node_label = _display_name(G, node)
    tgt_label = _display_name(G, target) if target else "high-value targets"
    flags = _node_flags(G, node)
    outbound_control = outbound_control or []
    inbound_control = inbound_control or []

    lines: list[str] = []
    lines.append(f"# Pathdog — Node Visibility: `{node_label}`\n")
    if flags:
        lines.append(f"**Flags:** {', '.join(flags)}\n")
    if stats:
        lines.extend(_stats_md_lines(stats))

    # ── Outbound object control ───────────────────────────────────────────────
    direct_count = sum(1 for e in outbound_control if e["via_group"] is None)
    lines.append(f"## → Outbound Object Control ({direct_count} direct, "
                 f"{len(outbound_control) - direct_count} via group)\n")
    if outbound_control:
        lines.append("| Relation | Target | How |")
        lines.append("|----------|--------|-----|")
        for e in outbound_control:
            via = f"via {e['via_group']}" if e["via_group"] else "direct"
            lines.append(
                f"| **{e['relation']}** "
                f"| `{_display_name(G, e['dst'])}` "
                f"| {via} |"
            )
        lines.append("")
    else:
        lines.append("> No outbound privileges found.\n")

    # ── Inbound object control ────────────────────────────────────────────────
    lines.append(f"## ← Inbound Object Control ({len(inbound_control)} principal(s))\n")
    if inbound_control:
        lines.append("| Relation | Principal |")
        lines.append("|----------|-----------|")
        for e in inbound_control:
            lines.append(
                f"| **{e['relation']}** "
                f"| `{_display_name(G, e['src'])}` |"
            )
        lines.append("")
    else:
        lines.append("> No inbound privileges found.\n")

    # ── Attack paths (outbound) ───────────────────────────────────────────────
    lines.append(f"## → Attack Paths — outbound to `{tgt_label}`\n")
    if outbound_paths:
        for i, path in enumerate(outbound_paths, 1):
            lines.append(f"### Path {i} — Weight: {path.total_weight} | Hops: {path.hops}\n")
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
                lines.append("> ✦ **DCSync acquired**\n")
            actor = _display_name(G, path.nodes[0])
            for j, edge in enumerate(path.edges, 1):
                if edge["relation"] in ("MemberOf", "Contains"):
                    continue
                cmd, next_actor = _edge_commands(G, edge, actor)
                src_l = _display_name(G, edge["src"])
                dst_l = _display_name(G, edge["dst"])
                lines.append(f"**Hop {j} — [{edge['relation']}]** `{src_l}` → `{dst_l}`\n")
                lines.append(f"> *Operating as: `{actor}`*  ")
                lines.append(f"> {cmd.description}\n")
                if cmd.has_commands:
                    lines.append("```bash")
                    lines.extend(cmd.commands)
                    lines.append("```\n")
                if next_actor != actor:
                    lines.append(f"> ✦ **Identity obtained: `{next_actor}`**\n")
                actor = next_actor
        if outbound_intermediate:
            lines.extend(_intermediate_md(G, node, outbound_intermediate))
    elif outbound_intermediate:
        lines.extend(_intermediate_md(G, node, outbound_intermediate))
    else:
        lines.append("> No outbound paths to high-value targets found.\n")

    # ── Inbound attackers (full paths) ────────────────────────────────────────
    lines.append(f"## ← Inbound Attackers — who can reach `{node_label}`\n")
    if inbound_sources:
        lines.append(f"{len(inbound_sources)} principal(s) have an attack path to this node.\n")
        lines.append("| # | Score | Principal | Kind | Hops | Flags |")
        lines.append("|---|-------|-----------|------|------|-------|")
        for i, s in enumerate(inbound_sources, 1):
            nid = s["node"]
            path = s["path"]
            flags_s = ", ".join(_node_flags(G, nid)) or "—"
            hops = path.hops if path else "?"
            lines.append(
                f"| {i} | {s['score']} | `{_display_name(G, nid)}` "
                f"| {G.nodes[nid].get('kind', '?')} | {hops} | {flags_s} |"
            )
        lines.append("")
        for i, s in enumerate(inbound_sources, 1):
            path = s["path"]
            if not path:
                continue
            chain = " → ".join(f"`{_display_name(G, n)}`" for n in path.nodes)
            lines.append(f"**{i}.** {chain}\n")
    else:
        lines.append("> No paths found from other principals.\n")

    lines.append("---")
    lines.append("*Generated by [pathdog](https://github.com/dikabraxis/pathdog)*")
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

    tgt_name = _escape(_display_name(G, target))
    head = _HTML_HEAD.replace("{{TITLE_SUFFIX}}", "Multi-User Attack Path Report")
    nav_items = [("Owned users", "owned-users")]
    if pivots:
        nav_items.append(("Pivots", "pivots"))
    if quickwins:
        nav_items.append(("Quick-wins", "quickwins"))
    if stats:
        nav_items.append(("Stats", "stats"))

    body_parts = [
        head,
        f'<div class="title"><span class="brand">Pathdog</span> &nbsp;·&nbsp; '
        f'target <code>{tgt_name}</code> &nbsp;·&nbsp; {len(results)} owned</div>',
        _sticky_nav_html(nav_items),
        '<div id="owned-users"></div>',
    ]

    # One block per user — best path visible, rest collapsed
    for source, paths in results:
        src_label = _escape(_display_name(G, source))
        body_parts.append('<div class="user-block">')
        body_parts.append(f'<div class="user-tag">{_kind_badge("users")} <code>{src_label}</code></div>')
        body_parts.append(
            _verdict_html(
                G, source, target, paths, pivots,
                info_only=bool(intermediates.get(source) or quickwins),
            )
        )
        if paths:
            body_parts.append(_action_plan_html(paths[0], G))
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
            f'<details class="more-section" id="pivots" open>'
            f'<summary>Pivot candidates ({len(pivots)})</summary>'
            f'{_pivots_html(G, pivots)}</details>'
        )
    if quickwins:
        n = sum(len(v) for v in quickwins.values())
        body_parts.append(
            f'<details class="more-section" id="quickwins" open>'
            f'<summary>Domain quick-wins ({n})</summary>'
            f'{_quickwins_html(quickwins)}</details>'
        )
    if stats:
        body_parts.append(
            f'<details class="more-section" id="stats">'
            f'<summary>Graph stats</summary>'
            f'{_stats_html_block(stats)}</details>'
        )

    body_parts.append('<footer>Generated by '
                      '<a href="https://github.com/dikabraxis/pathdog">pathdog</a></footer>')
    body_parts.append('</body></html>')
    return "\n".join(body_parts)


def _html_body_only(html: str) -> str:
    """Strip HTML head and footer, return just the body content."""
    start = html.index("<body>") + len("<body>\n")
    end = html.rindex("<footer>")
    return html[start:end].rstrip()


def render_html_combined(
    results: list[tuple[str, list]],
    G: "nx.DiGraph",
    target: str,
    node_data: dict,
    stats: dict | None = None,
    intermediates: dict | None = None,
    quickwins=None,
    pivots: list[dict] | None = None,
) -> str:
    """Single HTML combining -u (attack paths) and --node (visibility) sections.

    When the --node target is also one of the -u sources, the --node section
    drops the duplicate Attack Paths / HVTs blocks and only keeps the unique
    parts: inbound attackers and inbound/outbound object control.
    """
    node_id = node_data["node_id"]
    node_name = _escape(_display_name(G, node_id))
    node_overlaps_u = any(source == node_id for source, _ in results)

    attack_html = render_html_multi(
        results, G, target, stats, intermediates, quickwins, pivots,
    )
    attack_body = _html_body_only(attack_html)

    if node_overlaps_u:
        outbound_control = node_data["outbound_control"] or []
        inbound_control = node_data["inbound_control"] or []
        inbound_sources = node_data["inbound_sources"]
        direct = sum(1 for e in outbound_control if e["via_group"] is None)
        indirect = len(outbound_control) - direct
        node_body = (
            f'<div class="report-section">'
            f'<p class="section-lead">Outbound paths and reachable HVTs are already '
            f'covered in the Attack Paths section above. Below are the inbound '
            f'attackers and the object-control surface of <code>{node_name}</code>.</p>'
            f'<details class="more-section" open>'
            f'<summary>← Inbound Attackers ({len(inbound_sources)} principal(s))'
            f' — who has an attack path leading TO this node</summary>'
            f'{_inbound_sources_html(G, inbound_sources)}'
            f'</details>'
            f'<details class="more-section">'
            f'<summary>→ Outbound Object Control ({direct} direct · {indirect} via group)'
            f' — objects this node has privileges over</summary>'
            f'{_object_control_out_html(G, outbound_control)}'
            f'</details>'
            f'<details class="more-section">'
            f'<summary>← Inbound Object Control ({len(inbound_control)} principal(s))'
            f' — principals with direct privileges over this node</summary>'
            f'{_object_control_in_html(G, inbound_control)}'
            f'</details>'
            f'</div>'
        )
    else:
        node_html = render_html_node_visibility(
            G, node_id, node_data["target"],
            node_data["outbound_paths"], node_data["outbound_intermediate"],
            node_data["inbound_sources"], node_data.get("stats"),
            node_data["outbound_control"], node_data["inbound_control"],
        )
        node_body = _html_body_only(node_html)

    head = _HTML_HEAD.replace("{{TITLE_SUFFIX}}", _escape(f"Combined — {_display_name(G, node_id)}"))

    attack_banner = (
        '<div class="section-banner attack">'
        '<span class="banner-title">Attack Paths</span>'
        '<span class="banner-meta">-u</span>'
        '</div>'
    )

    divider = (
        '<div style="margin:2.5rem 0 2rem;border-top:2px dashed var(--border);'
        'position:relative;text-align:center;">'
        '<span style="display:inline-block;position:relative;top:-.75rem;'
        'background:var(--bg);padding:0 1rem;font-size:.7rem;color:var(--muted);'
        'letter-spacing:.1em;text-transform:uppercase;">─── node visibility ───</span>'
        '</div>'
    )

    node_banner = (
        f'<div class="section-banner node">'
        f'<span class="banner-title">Node Visibility</span>'
        f'<span class="banner-meta">--node <code '
        f'style="background:var(--purple-soft);color:var(--purple);padding:.1rem .3rem;'
        f'border-radius:3px;">{node_name}</code></span>'
        f'</div>'
    )

    footer = ('<footer>Generated by '
              '<a href="https://github.com/dikabraxis/pathdog">pathdog</a></footer>')

    return "\n".join([
        head,
        attack_banner,
        attack_body,
        divider,
        node_banner,
        node_body,
        footer,
        '</body></html>',
    ])
