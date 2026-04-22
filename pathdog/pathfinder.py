"""Path computation: dijkstra primary, shortest_simple_paths fallback."""

from itertools import islice
import networkx as nx


class PathResult:
    def __init__(self, nodes: list[str], edges: list[dict], weight: int):
        self.nodes = nodes
        self.edges = edges          # [{"src", "dst", "relation", "weight"}, ...]
        self.total_weight = weight
        self.hops = len(nodes) - 1

    def __repr__(self) -> str:
        return f"PathResult(hops={self.hops}, weight={self.total_weight})"


def _path_to_result(G: nx.DiGraph, path: list[str]) -> PathResult:
    edges = []
    total = 0
    for i in range(len(path) - 1):
        src, dst = path[i], path[i + 1]
        data = G[src][dst]
        w = data.get("weight", 5)
        total += w
        edges.append({
            "src": src,
            "dst": dst,
            "relation": data.get("relation", "Unknown"),
            "weight": w,
        })
    return PathResult(nodes=path, edges=edges, weight=total)


def find_paths(
    G: nx.DiGraph,
    source: str,
    target: str,
    k: int = 3,
) -> list[PathResult]:
    """Find up to *k* lowest-resistance paths from *source* to *target*.

    Uses dijkstra for k=1, shortest_simple_paths for k>1.
    Returns empty list if no path exists.
    """
    if source not in G:
        raise ValueError(f"Source node not in graph: {source}")
    if target not in G:
        raise ValueError(f"Target node not in graph: {target}")

    results: list[PathResult] = []

    if k == 1:
        try:
            path = nx.dijkstra_path(G, source, target, weight="weight")
            results.append(_path_to_result(G, path))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass
        return results

    try:
        gen = nx.shortest_simple_paths(G, source, target, weight="weight")
        for path in islice(gen, k):
            results.append(_path_to_result(G, path))
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        pass

    return results


def suggest_similar_nodes(G: nx.DiGraph, query: str, top_n: int = 3) -> list[str]:
    """Return top_n node names/IDs most similar to *query* using fuzzy matching."""
    try:
        from thefuzz import process as fuzz_process
        candidates: dict[str, str] = {}
        for nid in G.nodes:
            name = G.nodes[nid].get("name", nid)
            candidates[name] = nid
            if nid != name:
                candidates[nid] = nid
        hits = fuzz_process.extract(query, list(candidates.keys()), limit=top_n * 2)
        seen: list[str] = []
        for label, _score, *_ in hits:
            nid = candidates[label]
            if nid not in seen:
                seen.append(nid)
            if len(seen) >= top_n:
                break
        return seen
    except ImportError:
        q = query.lower()
        matches = [nid for nid in G.nodes if q in nid.lower()]
        return matches[:top_n]
