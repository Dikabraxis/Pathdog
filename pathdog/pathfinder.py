"""Path computation: dijkstra primary, shortest_simple_paths fallback."""

from itertools import islice
import networkx as nx

_STRUCTURAL = {"MemberOf", "Contains"}


def _exploit_fingerprint(result: "PathResult") -> tuple:
    """Tuple of (src, rel, dst) for non-structural edges only."""
    return tuple(
        (e["src"], e["relation"], e["dst"])
        for e in result.edges
        if e["relation"] not in _STRUCTURAL
    )


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
    """Find up to *k* lowest-resistance paths. Returns [] if none exist."""
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
        seen_fps: set[tuple] = set()
        for path in islice(gen, k * 10):
            r = _path_to_result(G, path)
            fp = _exploit_fingerprint(r)
            if fp not in seen_fps:
                seen_fps.add(fp)
                results.append(r)
            if len(results) >= k:
                break
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        pass

    return results


def suggest_similar_nodes(G: nx.DiGraph, query: str, top_n: int = 3) -> list[str]:
    """Return top_n node IDs most similar to *query*.

    Prefers nodes of kind 'users' since -u expects user identities.
    Falls back to all node types if not enough user matches.
    """
    try:
        from thefuzz import process as fuzz_process

        def _candidates(kind_filter: str | None) -> dict[str, str]:
            result: dict[str, str] = {}
            for nid in G.nodes:
                if kind_filter and G.nodes[nid].get("kind") != kind_filter:
                    continue
                name = G.nodes[nid].get("name", nid)
                result[name] = nid
                if nid != name:
                    result[nid] = nid
            return result

        seen: list[str] = []
        for kind in ("users", None):
            cands = _candidates(kind)
            hits = fuzz_process.extract(query, list(cands.keys()), limit=top_n * 2)
            for label, _score, *_ in hits:
                nid = cands[label]
                if nid not in seen:
                    seen.append(nid)
                if len(seen) >= top_n:
                    return seen
        return seen

    except ImportError:
        q = query.lower()
        # Prefer user nodes
        user_matches = [
            nid for nid in G.nodes
            if G.nodes[nid].get("kind") == "users" and q in nid.lower()
        ]
        if len(user_matches) >= top_n:
            return user_matches[:top_n]
        all_matches = [nid for nid in G.nodes if q in nid.lower()]
        return all_matches[:top_n]
