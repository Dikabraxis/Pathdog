"""HTML report renderers for pathdog results."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._helpers import (
    _display_name, _edge_commands, _node_flags, _path_yields_dcsync,
)
from ._helpers import _DCSYNC_GRANTING_EDGES  # noqa: F401  (re-exported for callers)
from .assets import _HTML_HEAD
from ..explanations import for_edge as _explain_edge
from ..explanations import for_quickwin as _explain_quickwin
from ..explanations import for_vector as _explain_vector

if TYPE_CHECKING:
    import networkx as nx

    from ..findings import Finding
    from ..pathfinder import PathResult
    from ..quickwins import QuickWin


# ── helpers ───────────────────────────────────────────────────────────────────


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
        "containers": "CONTAINER",
        "certtemplates": "CERTTPL",
        "enterprisecas": "CA",
        "rootcas": "ROOTCA",
        "aiacas": "AIACA",
        "ntauthstores": "NTAUTH",
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


def _findings_html(findings: list["Finding"]) -> str:
    if not findings:
        return ""
    rows = []
    for finding in findings:
        commands = ""
        if finding.commands:
            commands = (
                '<details class="cmd-details">'
                f'<summary>Commands ({len(finding.commands)})</summary>'
                f'{_command_block(finding.commands, small=True, title="Commands")}'
                '</details>'
            )
        rows.append(
            '<div class="finding-row">'
            f'<div class="finding-score sev-{finding.severity}">{finding.severity}</div>'
            '<div class="finding-main">'
            f'<div class="finding-title"><span class="rel-tag">{_escape(finding.category)}</span> '
            f'{_escape(finding.title)}</div>'
            f'<div class="finding-meta">{_kind_badge(finding.node_kind)} '
            f'<code>{_escape(finding.node_name or finding.node_id)}</code> '
            f'<span>confidence: {_escape(finding.confidence)}</span> '
            f'<span>source: {_escape(finding.source)}</span></div>'
            f'<div class="finding-evidence">{_escape(finding.evidence)}</div>'
            f'{commands}'
            '</div></div>'
        )
    return '<div class="findings-list">' + "".join(rows) + '</div>'


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


def render_html(
    paths: list,
    G: "nx.DiGraph",
    source: str,
    target: str,
    stats: dict | None = None,
    intermediate: list[dict] | None = None,
    quickwins: dict[str, list["QuickWin"]] | None = None,
    pivots: list[dict] | None = None,
    findings: list["Finding"] | None = None,
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
    if findings:
        nav_items.append(("Findings", "findings"))
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
            info_only=bool(intermediate or quickwins or findings),
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
    if findings:
        body_parts.append(
            f'<details class="more-section" id="findings" open>'
            f'<summary>Prioritized findings ({len(findings)})</summary>'
            f'{_findings_html(findings)}</details>'
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



def render_html_multi(
    results: list[tuple[str, list]],
    G: "nx.DiGraph",
    target: str,
    stats: dict | None = None,
    intermediates: dict[str, list[dict]] | None = None,
    quickwins: dict[str, list["QuickWin"]] | None = None,
    pivots: list[dict] | None = None,
    findings: list["Finding"] | None = None,
) -> str:
    intermediates = intermediates or {}
    if len(results) == 1:
        source, paths = results[0]
        return render_html(
            paths, G, source, target, stats,
            intermediate=intermediates.get(source),
            quickwins=quickwins,
            pivots=pivots,
            findings=findings,
        )

    triage_only = not results
    tgt_name = _escape(_display_name(G, target)) if target else "global"
    title_suffix = "Triage Report" if triage_only else "Multi-User Attack Path Report"
    head = _HTML_HEAD.replace("{{TITLE_SUFFIX}}", title_suffix)
    nav_items = [] if triage_only else [("Owned users", "owned-users")]
    if pivots:
        nav_items.append(("Pivots", "pivots"))
    if findings:
        nav_items.append(("Findings", "findings"))
    if quickwins:
        nav_items.append(("Quick-wins", "quickwins"))
    if stats:
        nav_items.append(("Stats", "stats"))

    body_parts = [
        head,
        '<div class="title"><span class="brand">Pathdog</span> &nbsp;·&nbsp; '
        + (
            f'triage report &nbsp;·&nbsp; context <code>{tgt_name}</code></div>'
            if triage_only
            else f'target <code>{tgt_name}</code> &nbsp;·&nbsp; {len(results)} owned</div>'
        ),
        _sticky_nav_html(nav_items),
    ]
    if not triage_only:
        body_parts.append('<div id="owned-users"></div>')

    # One block per user — best path visible, rest collapsed
    for source, paths in results:
        src_label = _escape(_display_name(G, source))
        body_parts.append('<div class="user-block">')
        body_parts.append(f'<div class="user-tag">{_kind_badge("users")} <code>{src_label}</code></div>')
        body_parts.append(
            _verdict_html(
                G, source, target, paths, pivots,
                info_only=bool(intermediates.get(source) or quickwins or findings),
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
    if findings:
        body_parts.append(
            f'<details class="more-section" id="findings" open>'
            f'<summary>Prioritized findings ({len(findings)})</summary>'
            f'{_findings_html(findings)}</details>'
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
    findings: list["Finding"] | None = None,
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
        results, G, target, stats, intermediates, quickwins, pivots, findings,
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

    first_section_title = "Attack Paths" if results else "Triage"
    first_section_meta = "-u" if results else "--triage"
    attack_banner = (
        '<div class="section-banner attack">'
        f'<span class="banner-title">{first_section_title}</span>'
        f'<span class="banner-meta">{first_section_meta}</span>'
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
