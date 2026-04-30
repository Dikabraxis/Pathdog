"""Shared helpers used by console / markdown / html renderers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..commands import CommandSet, get_commands

if TYPE_CHECKING:
    import networkx as nx

    from ..pathfinder import PathResult


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
