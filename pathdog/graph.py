"""Raw graph construction and attack-graph pruning."""

import sys

import networkx as nx

from .postprocess import postprocess_graph
from .schema import (
    KNOWN_BLOODHOUND_EDGES,
    LEGACY_CONTEXT_EDGES,
    SUPPORTED_TRAVERSABLE_EDGES,
    TRAVERSABLE_EDGES,
)
from .weights import DEFAULT_WEIGHT, EDGE_WEIGHTS


def build_raw_graph(nodes: list[dict], edges: list[dict]) -> nx.DiGraph:
    """Build a raw graph containing every collected relationship."""
    G = nx.DiGraph()

    for node in nodes:
        nid = node["id"]
        incoming_props = node.get("props", {})
        if nid in G:
            existing = G.nodes[nid]
            merged_props = {**existing.get("props", {}), **incoming_props}
            incoming_kind = node.get("kind", "unknown")
            kind = (
                incoming_kind
                if incoming_kind != "unknown"
                else existing.get("kind", "unknown")
            )
        else:
            merged_props = dict(incoming_props)
            kind = node.get("kind", "unknown")
        name = merged_props.get("name") or merged_props.get("Name") or nid
        G.add_node(nid, kind=kind, name=name, props=merged_props)

    relationship_types: set[str] = set()

    for edge in edges:
        src, dst, rtype = edge["src"], edge["dst"], edge["type"]
        if src not in G:
            G.add_node(src, kind="unknown", name=src, props={})
        if dst not in G:
            G.add_node(dst, kind="unknown", name=dst, props={})
        relationship_types.add(rtype)
        w = EDGE_WEIGHTS.get(rtype, DEFAULT_WEIGHT)
        if G.has_edge(src, dst):
            G[src][dst]["relations"][rtype] = w
            if G[src][dst]["weight"] > w:
                G[src][dst]["weight"] = w
                G[src][dst]["relation"] = rtype
        else:
            G.add_edge(src, dst, relation=rtype, weight=w, relations={rtype: w})

    unknown = relationship_types - KNOWN_BLOODHOUND_EDGES - LEGACY_CONTEXT_EDGES
    legacy = relationship_types & LEGACY_CONTEXT_EDGES
    unsupported_traversable = (
        relationship_types & TRAVERSABLE_EDGES
    ) - SUPPORTED_TRAVERSABLE_EDGES
    G.graph["relationship_types"] = sorted(relationship_types)
    G.graph["unknown_edge_types"] = sorted(unknown)
    G.graph["legacy_context_edge_types"] = sorted(legacy)
    G.graph["unsupported_traversable_edge_types"] = sorted(unsupported_traversable)

    if unknown:
        print(
            "[warn] Unknown relationship type(s) kept as context but blocked "
            f"from pathfinding: {', '.join(sorted(unknown))}",
            file=sys.stderr,
        )
    if unsupported_traversable:
        print(
            "[warn] BloodHound-traversable relationship type(s) not yet "
            "implemented by Pathdog and blocked from pathfinding: "
            f"{', '.join(sorted(unsupported_traversable))}",
            file=sys.stderr,
        )
    if legacy:
        print(
            "[warn] Legacy/context-only relationship type(s) blocked from "
            f"pathfinding: {', '.join(sorted(legacy))}",
            file=sys.stderr,
        )

    return G


def build_graph(nodes: list[dict], edges: list[dict]) -> nx.DiGraph:
    """Build the raw graph, then add supported post-processed attack edges."""
    return postprocess_graph(build_raw_graph(nodes, edges))


def _domain_hint(G: nx.DiGraph, node_id: str) -> str:
    if node_id not in G:
        return ""
    props = G.nodes[node_id].get("props", {})
    lowered = {str(key).lower(): value for key, value in props.items()}
    for key in ("domain", "domainname", "domainsid"):
        if lowered.get(key):
            return str(lowered[key]).strip().lower()
    name = str(G.nodes[node_id].get("name", ""))
    if "@" in name:
        return name.rsplit("@", 1)[1].strip().lower()
    sid = str(node_id).upper()
    if sid.startswith("S-1-5-21-") and sid.count("-") >= 7:
        return sid.rsplit("-", 1)[0].lower()
    return ""


def target_candidates(
    G: nx.DiGraph,
    target_hint: str | None,
) -> list[str]:
    """Return all matching targets without silently choosing an ambiguity."""
    if target_hint:
        hint = target_hint.strip().lower()
        exact = [
            node_id
            for node_id in G.nodes
            if hint == str(node_id).lower()
            or hint == str(G.nodes[node_id].get("name", "")).lower()
        ]
        if exact:
            return sorted(set(exact))
        partial = [
            node_id
            for node_id in G.nodes
            if hint in str(node_id).lower()
            or hint in str(G.nodes[node_id].get("name", "")).lower()
        ]
        return sorted(set(partial))

    candidates = []
    for node_id, data in G.nodes(data=True):
        if data.get("kind") != "groups":
            continue
        name = str(data.get("name", node_id)).lower()
        base_name = name.split("@", 1)[0].strip()
        sid = str(node_id).upper()
        if base_name == "domain admins" or sid.endswith("-512"):
            candidates.append(node_id)
    return sorted(set(candidates))


def resolve_target(
    G: nx.DiGraph,
    target_hint: str | None,
    *,
    source: str | None = None,
) -> str | None:
    """Resolve a unique target, optionally constrained to the source domain."""
    candidates = target_candidates(G, target_hint)
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1 and source:
        source_domain = _domain_hint(G, source)
        same_domain = [
            candidate
            for candidate in candidates
            if _domain_hint(G, candidate) == source_domain
        ]
        if len(same_domain) == 1:
            return same_domain[0]
    return None


def prune_to_target(G: nx.DiGraph, target: str) -> nx.DiGraph:
    """Return the attack subgraph containing nodes that can reach *target*.

    1. Reverse the DiGraph
    2. Compute nx.descendants(reversed, target) — equivalent to all nodes that
       can reach target in the original graph (no depth limit)
    3. Rebuild subgraph with those nodes + target
    """
    # Import locally to avoid graph <-> pathfinder import cycles.
    from .pathfinder import actionable_view

    attack_graph = actionable_view(G)
    if target not in attack_graph:
        return attack_graph.subgraph([]).copy()
    R = attack_graph.reverse(copy=False)
    # descendants of target in R == all nodes that can reach target in G
    reachable = nx.descendants(R, target)
    reachable.add(target)
    return attack_graph.subgraph(reachable).copy()


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
