"""NetworkX DiGraph builder with ancestor-based pruning."""

import networkx as nx
from collections import defaultdict
from .weights import EDGE_WEIGHTS, DEFAULT_WEIGHT


def build_graph(nodes: list[dict], edges: list[dict]) -> nx.DiGraph:
    """Build a directed graph from loader output."""
    G = nx.DiGraph()

    for node in nodes:
        nid = node["id"]
        name = node["props"].get("name") or node["props"].get("Name") or nid
        G.add_node(nid, kind=node["kind"], name=name, props=node["props"])

    # Track all relations between each (src,dst) so we can detect
    # implicit DCSync = GetChanges + GetChangesAll on the same target.
    multi_rels: dict[tuple[str, str], set[str]] = defaultdict(set)

    for edge in edges:
        src, dst, rtype = edge["src"], edge["dst"], edge["type"]
        if src not in G:
            G.add_node(src, kind="unknown", name=src, props={})
        if dst not in G:
            G.add_node(dst, kind="unknown", name=dst, props={})
        multi_rels[(src, dst)].add(rtype)
        w = EDGE_WEIGHTS.get(rtype, DEFAULT_WEIGHT)
        if G.has_edge(src, dst):
            G[src][dst]["relations"][rtype] = w
            if G[src][dst]["weight"] > w:
                G[src][dst]["weight"] = w
                G[src][dst]["relation"] = rtype
        else:
            G.add_edge(src, dst, relation=rtype, weight=w, relations={rtype: w})

    # Synthesize DCSync edges: principal having both GetChanges and
    # GetChangesAll on a domain (or the equivalent extended right pair).
    # If only one of the pair is present, the edge alone is NOT exploitable —
    # bump its weight to deprioritize it during pathfinding.
    dcsync_w = EDGE_WEIGHTS.get("DCSync", 2)
    inert_changes_w = 8  # replication rights alone — not actionable
    repl_set = {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet"}
    for (src, dst), rels in multi_rels.items():
        if "DCSync" in rels:
            continue
        # DCSync requires GetChanges + GetChangesAll. GetChangesInFilteredSet
        # is the filtered-attribute-set right (RODC scenario) and does NOT
        # substitute for GetChanges — treating it as such yields false positives.
        has_changes = "GetChanges" in rels
        has_changes_all = "GetChangesAll" in rels
        is_domain = G.nodes[dst].get("kind") == "domains"
        if has_changes and has_changes_all and is_domain:
            if G.has_edge(src, dst):
                G[src][dst]["relations"]["DCSync"] = dcsync_w
                if G[src][dst]["weight"] >= dcsync_w:
                    G[src][dst]["weight"] = dcsync_w
                    G[src][dst]["relation"] = "DCSync"
            else:
                G.add_edge(src, dst, relation="DCSync", weight=dcsync_w,
                           relations={"DCSync": dcsync_w})
        elif (rels & repl_set) and is_domain:
            # Any replication right alone (or any partial subset that doesn't
            # cover both GetChanges + GetChangesAll) is NOT actionable for
            # secrets dumping. Bump weight so pathfinder doesn't treat it as
            # a cheap shortcut to the domain.
            if G.has_edge(src, dst) and G[src][dst]["relation"] in repl_set:
                G[src][dst]["weight"] = inert_changes_w
                # Reflect the penalty in the relations map too so HTML alts
                # don't suggest these are cheap.
                for r in G[src][dst]["relations"]:
                    if r in repl_set:
                        G[src][dst]["relations"][r] = inert_changes_w

    return G


def resolve_target(G: nx.DiGraph, target_hint: str | None) -> str | None:
    """Find the Domain Admins node. Accepts explicit SID/name or auto-detects."""
    if target_hint:
        if target_hint in G:
            return target_hint
        hint_lower = target_hint.lower()
        for nid in G.nodes:
            if hint_lower in nid.lower():
                return nid
            name = G.nodes[nid].get("name", "")
            if hint_lower in name.lower():
                return nid
        return None

    for nid in G.nodes:
        if "domain admins" in nid.lower():
            return nid
        name = G.nodes[nid].get("name", "")
        if "domain admins" in name.lower():
            return nid
    return None


def prune_to_target(G: nx.DiGraph, target: str) -> nx.DiGraph:
    """Return a subgraph containing only nodes that can reach *target*.

    1. Reverse the DiGraph
    2. Compute nx.descendants(reversed, target) — equivalent to all nodes that
       can reach target in the original graph (no depth limit)
    3. Rebuild subgraph with those nodes + target
    """
    R = G.reverse(copy=False)
    # descendants of target in R == all nodes that can reach target in G
    reachable = nx.descendants(R, target)
    reachable.add(target)
    return G.subgraph(reachable).copy()


def graph_stats(G: nx.DiGraph, pruned: nx.DiGraph) -> dict:
    return {
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "pruned_nodes": pruned.number_of_nodes(),
        "pruned_edges": pruned.number_of_edges(),
        "reduction_pct": round(
            (1 - pruned.number_of_nodes() / max(G.number_of_nodes(), 1)) * 100, 1
        ),
    }
