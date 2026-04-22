"""Markdown + HTML report renderer for pathdog results."""

from __future__ import annotations
from typing import TYPE_CHECKING

from .commands import get_commands, CommandSet

if TYPE_CHECKING:
    import networkx as nx
    from .pathfinder import PathResult


# ── helpers ──────────────────────────────────────────────────────────────────

def _display_name(G: "nx.DiGraph", nid: str) -> str:
    name = G.nodes[nid].get("name", nid) if nid in G else nid
    return name if name else nid


def _edge_commands(G: "nx.DiGraph", edge: dict) -> CommandSet:
    src, dst = edge["src"], edge["dst"]
    return get_commands(
        rel_type=edge["relation"],
        src_id=src,
        dst_id=dst,
        src_name=_display_name(G, src),
        dst_name=_display_name(G, dst),
        src_kind=G.nodes[src].get("kind", "") if src in G else "",
        dst_kind=G.nodes[dst].get("kind", "") if dst in G else "",
    )


# ── Console ───────────────────────────────────────────────────────────────────

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
        src_name = _display_name(G, path.nodes[0])
        print(src_name)
        for edge in path.edges:
            rel = edge["relation"]
            dst_name = _display_name(G, edge["dst"])
            arrow = f"  └─[{rel}]"
            pad = max(1, 42 - len(arrow))
            print(f"{arrow}{'─' * pad}► {dst_name}")

            cmd = _edge_commands(G, edge)
            print(f"     ↳ {cmd.description}")
            for c in cmd.commands:
                print(f"       $ {c}")


# ── Markdown ──────────────────────────────────────────────────────────────────

def render_markdown(
    paths: list["PathResult"],
    G: "nx.DiGraph",
    source: str,
    target: str,
    stats: dict | None = None,
) -> str:
    lines: list[str] = []
    lines.append("# Pathdog — Attack Path Report\n")
    lines.append(f"**Source:** `{_display_name(G, source)}`  ")
    lines.append(f"**Target:** `{_display_name(G, target)}`\n")

    if stats:
        lines.append("## Graph Statistics\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total nodes | {stats['total_nodes']} |")
        lines.append(f"| Total edges | {stats['total_edges']} |")
        lines.append(f"| Pruned nodes (reachable) | {stats['pruned_nodes']} |")
        lines.append(f"| Pruned edges | {stats['pruned_edges']} |")
        lines.append(f"| Node reduction | {stats['reduction_pct']}% |")
        lines.append("")

    if not paths:
        lines.append(
            f"> **No path found** from `{_display_name(G, source)}` to "
            f"`{_display_name(G, target)}`.  \n"
            "> The owned user may not have any edges leading to DA in this dump."
        )
        return "\n".join(lines)

    lines.append(f"## Paths Found: {len(paths)}\n")

    for i, path in enumerate(paths, 1):
        lines.append(f"### Path {i} — Weight: {path.total_weight} | Hops: {path.hops}\n")

        # ASCII chain
        lines.append("```")
        src_name = _display_name(G, path.nodes[0])
        lines.append(src_name)
        for edge in path.edges:
            rel = edge["relation"]
            dst_name = _display_name(G, edge["dst"])
            arrow = f"  └─[{rel}]"
            pad = max(1, 42 - len(arrow))
            lines.append(f"{arrow}{'─' * pad}► {dst_name}")
        lines.append("```\n")

        # Per-hop exploit table + commands
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

        # Exploit commands per hop
        lines.append("#### Exploit steps\n")
        for j, edge in enumerate(path.edges, 1):
            cmd = _edge_commands(G, edge)
            src_label = _display_name(G, edge["src"])
            dst_label = _display_name(G, edge["dst"])
            lines.append(f"**Hop {j} — [{edge['relation']}]** `{src_label}` → `{dst_label}`\n")
            lines.append(f"> {cmd.description}\n")
            if cmd.has_commands:
                lines.append("```bash")
                lines.extend(cmd.commands)
                lines.append("```\n")

    lines.append("---")
    lines.append("*Generated by [pathdog](https://github.com/dikabraxis/pathdog)*")
    return "\n".join(lines)


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
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --accent: #58a6ff;
    --accent2: #3fb950;
    --warn: #d29922;
    --danger: #f85149;
    --text: #c9d1d9;
    --muted: #8b949e;
    --code-bg: #1f2428;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
    font-size: 14px;
    line-height: 1.6;
    padding: 2rem;
  }
  h1 { color: var(--accent); font-size: 1.6rem; margin-bottom: 0.5rem; }
  h2 { color: var(--accent); font-size: 1.2rem; margin: 1.5rem 0 0.75rem; border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }
  .meta { color: var(--muted); margin-bottom: 1.5rem; }
  .meta span { color: var(--accent); font-family: monospace; }
  .stats-table { border-collapse: collapse; margin-bottom: 1.5rem; }
  .stats-table th, .stats-table td { border: 1px solid var(--border); padding: 0.4rem 0.8rem; }
  .stats-table th { background: var(--surface); color: var(--accent); }
  .stats-table td { font-family: monospace; }
  .no-path {
    background: var(--surface);
    border: 1px solid var(--danger);
    border-radius: 6px;
    padding: 1rem 1.25rem;
    color: var(--danger);
    margin-top: 1rem;
  }
  .path-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 1.5rem;
    overflow: hidden;
  }
  .path-header {
    background: #1c2128;
    padding: 0.6rem 1rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    border-bottom: 1px solid var(--border);
  }
  .path-badge {
    background: var(--accent);
    color: #0d1117;
    font-weight: 700;
    font-size: 0.8rem;
    padding: 0.2rem 0.6rem;
    border-radius: 20px;
  }
  .path-meta { color: var(--muted); font-size: 0.85rem; }
  .path-meta strong { color: var(--text); }
  .chain { padding: 1.25rem 1.5rem; }
  .chain-node { display: flex; align-items: center; gap: 0.5rem; margin: 0.1rem 0; }
  .node-pill {
    background: var(--code-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.25rem 0.6rem;
    font-family: monospace;
    font-size: 0.85rem;
    color: var(--text);
    white-space: nowrap;
  }
  .node-pill.source { border-color: var(--accent2); color: var(--accent2); }
  .node-pill.target { border-color: var(--danger); color: var(--danger); }
  .chain-edge { padding: 0.15rem 0 0.15rem 1rem; }
  .edge-connector {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8rem;
    color: var(--muted);
  }
  .edge-line { width: 2px; height: 14px; background: var(--border); flex-shrink: 0; }
  .rel-badge {
    background: #21262d;
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 0.1rem 0.55rem;
    font-family: monospace;
    font-size: 0.78rem;
    color: var(--warn);
  }
  .weight-badge { font-size: 0.72rem; color: var(--muted); }
  .exploit-block {
    margin: 0.4rem 0 0.6rem 1.6rem;
    border-left: 2px solid var(--border);
    padding-left: 0.75rem;
  }
  .exploit-desc {
    font-size: 0.82rem;
    color: var(--muted);
    margin-bottom: 0.3rem;
    font-style: italic;
  }
  .exploit-commands {
    background: var(--code-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.6rem 0.9rem;
    font-family: monospace;
    font-size: 0.8rem;
    white-space: pre;
    overflow-x: auto;
    color: var(--accent2);
    line-height: 1.7;
  }
  .exploit-commands .comment { color: var(--muted); }
  footer { margin-top: 2rem; color: var(--muted); font-size: 0.8rem; border-top: 1px solid var(--border); padding-top: 1rem; }
  footer a { color: var(--accent); text-decoration: none; }
</style>
</head>
<body>
<h1>&#128021; Pathdog — Attack Path Report</h1>
<div class="meta">
  Source: <span>{{SOURCE_NAME}}</span> &nbsp;&#8594;&nbsp; Target: <span>{{TARGET_NAME}}</span>
</div>
{{STATS_BLOCK}}
<h2>Paths Found: {{PATH_COUNT}}</h2>
{{PATHS_BLOCK}}
<footer>Generated by <a href="https://github.com/dikabraxis/pathdog">pathdog</a></footer>
</body>
</html>
"""

_STATS_TEMPLATE = """\
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

_NO_PATH_TEMPLATE = """\
<div class="no-path">
  &#10060; No path found from <code>{source}</code> to <code>{target}</code>.<br>
  The owned user may not have any edges leading to DA in this dump.
</div>
"""


def _escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


def _render_exploit_html(cmd: CommandSet) -> str:
    parts = [f'<div class="exploit-block">']
    parts.append(f'<div class="exploit-desc">{_escape(cmd.description)}</div>')
    if cmd.has_commands:
        lines = []
        for c in cmd.commands:
            if c.startswith("#"):
                lines.append(f'<span class="comment">{_escape(c)}</span>')
            else:
                lines.append(_escape(c))
        parts.append(f'<div class="exploit-commands">{"<br>".join(lines)}</div>')
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
                f"</div>"
                f"</div>"
            )
            cmd = _edge_commands(G, edge)
            parts.append(_render_exploit_html(cmd))

    parts.append("</div></div>")
    return "\n".join(parts)


def render_html(
    paths: list["PathResult"],
    G: "nx.DiGraph",
    source: str,
    target: str,
    stats: dict | None = None,
) -> str:
    source_name = _escape(_display_name(G, source))
    target_name = _escape(_display_name(G, target))

    stats_block = _STATS_TEMPLATE.format(**stats) if stats else ""

    if not paths:
        paths_block = _NO_PATH_TEMPLATE.format(source=source_name, target=target_name)
        path_count = "0"
    else:
        paths_block = "\n".join(
            _render_path_html(p, G, i) for i, p in enumerate(paths, 1)
        )
        path_count = str(len(paths))

    return (
        _HTML_TEMPLATE
        .replace("{{SOURCE_NAME}}", source_name)
        .replace("{{TARGET_NAME}}", target_name)
        .replace("{{STATS_BLOCK}}", stats_block)
        .replace("{{PATH_COUNT}}", path_count)
        .replace("{{PATHS_BLOCK}}", paths_block)
    )


# ── Multi-user renderers ──────────────────────────────────────────────────────

def render_markdown_multi(
    results: list[tuple[str, list]],
    G: "nx.DiGraph",
    target: str,
    stats: dict | None = None,
) -> str:
    """Render a combined Markdown report for multiple owned users."""
    if len(results) == 1:
        source, paths = results[0]
        return render_markdown(paths, G, source, target, stats)

    lines: list[str] = []
    lines.append("# Pathdog — Multi-User Attack Path Report\n")
    tgt_label = _display_name(G, target)
    lines.append(f"**Target:** `{tgt_label}`\n")

    if stats:
        lines.append("## Graph Statistics\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total nodes | {stats['total_nodes']} |")
        lines.append(f"| Total edges | {stats['total_edges']} |")
        lines.append(f"| Pruned nodes (reachable) | {stats['pruned_nodes']} |")
        lines.append(f"| Pruned edges | {stats['pruned_edges']} |")
        lines.append(f"| Node reduction | {stats['reduction_pct']}% |")
        lines.append("")

    for source, paths in results:
        src_label = _display_name(G, source)
        lines.append(f"\n---\n\n## Owned: `{src_label}`\n")
        # Inline the single-user content (skip the repeated header)
        single = render_markdown(paths, G, source, target, stats=None)
        # Drop the first 3 lines (title + source/target meta)
        lines.append("\n".join(single.split("\n")[3:]))

    return "\n".join(lines)


_HTML_MULTI_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pathdog — Multi-User Attack Path Report</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --accent: #58a6ff; --accent2: #3fb950; --warn: #d29922;
    --danger: #f85149; --text: #c9d1d9; --muted: #8b949e;
    --code-bg: #1f2428;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; font-size: 14px; line-height: 1.6; padding: 2rem; }
  h1 { color: var(--accent); font-size: 1.6rem; margin-bottom: 0.5rem; }
  h2 { color: var(--accent); font-size: 1.2rem; margin: 1.5rem 0 0.75rem; border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }
  .meta { color: var(--muted); margin-bottom: 1.5rem; }
  .meta span { color: var(--accent); font-family: monospace; }
  .user-section { margin-bottom: 2.5rem; }
  .user-banner { background: #1c2128; border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem 1rem; margin-bottom: 1rem; font-family: monospace; color: var(--accent2); font-size: 0.95rem; }
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
  .chain-edge { padding: 0.15rem 0 0.15rem 1rem; }
  .edge-connector { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; color: var(--muted); }
  .edge-line { width: 2px; height: 14px; background: var(--border); flex-shrink: 0; }
  .rel-badge { background: #21262d; border: 1px solid var(--border); border-radius: 20px; padding: 0.1rem 0.55rem; font-family: monospace; font-size: 0.78rem; color: var(--warn); }
  .weight-badge { font-size: 0.72rem; color: var(--muted); }
  .exploit-block { margin: 0.4rem 0 0.6rem 1.6rem; border-left: 2px solid var(--border); padding-left: 0.75rem; }
  .exploit-desc { font-size: 0.82rem; color: var(--muted); margin-bottom: 0.3rem; font-style: italic; }
  .exploit-commands { background: var(--code-bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.6rem 0.9rem; font-family: monospace; font-size: 0.8rem; white-space: pre; overflow-x: auto; color: var(--accent2); line-height: 1.7; }
  .exploit-commands .comment { color: var(--muted); }
  footer { margin-top: 2rem; color: var(--muted); font-size: 0.8rem; border-top: 1px solid var(--border); padding-top: 1rem; }
  footer a { color: var(--accent); text-decoration: none; }
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


def render_html_multi(
    results: list[tuple[str, list]],
    G: "nx.DiGraph",
    target: str,
    stats: dict | None = None,
) -> str:
    """Render a combined HTML report for multiple owned users."""
    if len(results) == 1:
        source, paths = results[0]
        return render_html(paths, G, source, target, stats)

    target_name = _escape(_display_name(G, target))
    stats_block = _STATS_TEMPLATE.format(**stats) if stats else ""

    sections: list[str] = []
    for source, paths in results:
        src_label = _escape(_display_name(G, source))
        parts = [
            f'<div class="user-section">',
            f'<div class="user-banner">&#128100; Owned: {src_label} &nbsp;&#8594;&nbsp; {target_name}</div>',
        ]
        if not paths:
            parts.append(_NO_PATH_TEMPLATE.format(source=src_label, target=target_name))
        else:
            parts.append(f'<h2>Paths Found: {len(paths)}</h2>')
            for i, p in enumerate(paths, 1):
                parts.append(_render_path_html(p, G, i))
        parts.append("</div>")
        sections.append("\n".join(parts))

    return (
        _HTML_MULTI_TEMPLATE
        .replace("{{TARGET_NAME}}", target_name)
        .replace("{{STATS_BLOCK}}", stats_block)
        .replace("{{SECTIONS}}", "\n<hr style='border-color:var(--border);margin:2rem 0'>\n".join(sections))
    )
