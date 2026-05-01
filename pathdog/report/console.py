"""ANSI-colored console output for pathdog."""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

from ._helpers import _display_name, _edge_commands, _node_flags, _path_yields_dcsync

if TYPE_CHECKING:
    import networkx as nx

    from ..findings import Finding
    from ..pathfinder import PathResult
    from ..quickwins import QuickWin


# ── ANSI colors ───────────────────────────────────────────────────────────────

_USE_COLOR = (
    os.environ.get("NO_COLOR") is None
    and (sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1")
)


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
def _gray(s):    return _c(s, "90")
def _bright_red(s): return _c(s, "91")
def _orange(s):  return _c(s, "38;5;208")


def _severity(s: int | str) -> str:
    label = f"[{s}]"
    try:
        value = int(s)
    except (TypeError, ValueError):
        return _yellow(label)
    if value >= 10:
        return _bold(_bright_red(label))
    if value >= 9:
        return _bright_red(label)
    if value >= 8:
        return _orange(label)
    if value >= 6:
        return _yellow(label)
    return _blue(label)


def _category(s: str) -> str:
    base = s.lower()
    if "adcs" in base or "dcsync" in base:
        return _bold(_bright_red(s))
    if "dangerous" in base or "unconstrained" in base or "password" in base:
        return _orange(s)
    if "roast" in base:
        return _yellow(s)
    if "high-value" in base:
        return _magenta(s)
    return _cyan(s)


def _relation(s: str) -> str:
    if s in ("DCSync", "ADCSESC1", "ADCSESC3", "ADCSESC4", "GoldenCert"):
        return _bold(_bright_red(s))
    if s in ("GenericAll", "WriteDacl", "WriteOwner", "Owns", "AllExtendedRights"):
        return _orange(s)
    if s in ("MemberOf", "Contains"):
        return _gray(s)
    return _yellow(s)


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
        rel = f"[{_relation(edge['relation'])}]"
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
        print(f"    {_bold(_blue(f'# Step {step}:'))} {_relation(rel)} on {_magenta(dst)}  "
              f"{_dim(f'(as {actor})')}")
        for c in cmd.commands or []:
            if c.startswith("#"):
                print(f"      {_dim(c)}")
            else:
                print(f"      {_green('$')} {_cyan(c)}")
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


def print_owned_object_control(
    G: "nx.DiGraph",
    controls: list[dict],
) -> None:
    """Compact owned-user object-control summary for attack-path mode."""
    if not controls:
        return
    direct = [e for e in controls if e["via_group"] is None]
    indirect = [e for e in controls if e["via_group"] is not None]
    print(f"  {_yellow('→')} {_bold('Object control:')} "
          f"{_dim(f'{len(direct)} direct, {len(indirect)} via group(s)')}")
    for entry in controls[:3]:
        dst = _display_name(G, entry["dst"])
        via = f" via {entry['via_group']}" if entry["via_group"] else ""
        print(f"      {_yellow('•')} {_relation(entry['relation'])} on {_cyan(dst)}{_dim(via)}")
    if len(controls) > 3:
        print(f"      {_dim(f'+{len(controls) - 3} more privilege(s)  →  see HTML report')}")


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
    print(f"  {_magenta('◆')} {_bold('Best pivot:')} {_cyan(name)} "
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
    print(f"  {_blue('◆')} {_bold('Domain quick-wins:')}")
    for cat in sorted(quickwins, key=lambda c: -len(quickwins[c])):
        items = quickwins[cat]
        print(f"      {_blue('•')} {_category(cat)} {_dim(f'({len(items)})')}")
    print(f"  {_dim('  full details + commands  →  see HTML report')}")


def print_findings_console(findings: list["Finding"], limit: int = 10) -> None:
    """Compact prioritized triage summary."""
    if not findings:
        return
    print()
    print(f"  {_bright_red('◆')} {_bold('Prioritized findings:')}")
    for finding in findings[:limit]:
        name = f" — {finding.node_name}" if finding.node_name else ""
        print(
            f"      {_gray('•')} {_severity(finding.severity)} "
            f"{_category(finding.category)}: {_bold(finding.title)}{_dim(name)}"
        )
    if len(findings) > limit:
        print(f"  {_dim(f'  +{len(findings) - limit} more finding(s)  →  see HTML/JSON report')}")


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
