"""Synthesize BloodHound attack edges from raw SharpHound relationships."""

from __future__ import annotations

import networkx as nx

from .weights import DEFAULT_WEIGHT, EDGE_WEIGHTS

_PRINCIPAL_KINDS = {"users", "groups", "computers"}


def _relations(data: dict) -> dict[str, int]:
    primary = data.get("relation", "Unknown")
    return data.get("relations") or {primary: data.get("weight", DEFAULT_WEIGHT)}


def _add_relation(G: nx.DiGraph, src: str, dst: str, relation: str) -> None:
    """Add a synthesized relation without discarding parallel raw relations."""
    weight = EDGE_WEIGHTS.get(relation, DEFAULT_WEIGHT)
    if G.has_edge(src, dst):
        data = G[src][dst]
        data.setdefault("relations", {})[relation] = weight
        if data.get("weight", DEFAULT_WEIGHT) >= weight:
            data["relation"] = relation
            data["weight"] = weight
    else:
        G.add_edge(
            src,
            dst,
            relation=relation,
            weight=weight,
            relations={relation: weight},
        )


def _membership_graph(G: nx.DiGraph) -> nx.DiGraph:
    """Return only MemberOf edges, preserving member -> group direction."""
    memberships = nx.DiGraph()
    memberships.add_nodes_from(G.nodes)
    for src, dst, data in G.edges(data=True):
        if "MemberOf" in _relations(data):
            memberships.add_edge(src, dst)
    return memberships


def _effective_principals(
    G: nx.DiGraph,
    memberships: nx.DiGraph,
    direct_sources: set[str],
) -> set[str]:
    """Expand a right granted to a group to all of its transitive members."""
    effective: set[str] = set()
    for source in direct_sources:
        if source not in G:
            continue
        if G.nodes[source].get("kind") not in _PRINCIPAL_KINDS:
            continue
        effective.add(source)
        effective.update(
            node
            for node in nx.ancestors(memberships, source)
            if G.nodes[node].get("kind") in _PRINCIPAL_KINDS
        )
    return effective


def _compact_principals(
    memberships: nx.DiGraph,
    principals: set[str],
) -> set[str]:
    """Prefer a qualifying group over every member represented by that group.

    If rights are split across unrelated groups, their common member remains a
    principal in the result because no single qualifying group represents it.
    This mirrors BloodHound's cross-product behaviour while avoiding an edge
    explosion for ordinary group inheritance.
    """
    compact: set[str] = set()
    for principal in principals:
        qualifying_parents = nx.descendants(memberships, principal) & principals
        if not qualifying_parents:
            compact.add(principal)
            continue

        strict_parents = {
            parent
            for parent in qualifying_parents
            if principal not in nx.descendants(memberships, parent)
        }
        if strict_parents:
            continue

        # Malformed directories can contain membership cycles. Keep one stable
        # representative for the strongly connected component instead of
        # suppressing every principal in it.
        cycle = qualifying_parents | {principal}
        if principal == min(cycle):
            compact.add(principal)
    return compact


def _direct_sources_with_relation(
    G: nx.DiGraph,
    target: str,
    relation: str,
) -> set[str]:
    return {
        src
        for src, _ in G.in_edges(target)
        if relation in _relations(G[src][target])
    }


def _principals_with_both_rights(
    G: nx.DiGraph,
    memberships: nx.DiGraph,
    domain: str,
    first: str,
    second: str,
) -> set[str]:
    first_sources = _direct_sources_with_relation(G, domain, first)
    second_sources = _direct_sources_with_relation(G, domain, second)
    first_effective = _effective_principals(G, memberships, first_sources)
    second_effective = _effective_principals(G, memberships, second_sources)
    return _compact_principals(memberships, first_effective & second_effective)


def _property(props: dict, *names: str):
    lowered = {str(key).lower(): value for key, value in props.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _is_true(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)


def _object_domain_hint(G: nx.DiGraph, node_id: str) -> str:
    props = G.nodes[node_id].get("props", {})
    value = _property(props, "domainsid", "domain", "domainname")
    return str(value).strip().lower() if value else ""


def _belongs_to_domain(G: nx.DiGraph, node_id: str, domain_id: str) -> bool:
    """Best-effort, fail-closed mapping of an AD object to its domain."""
    domain_props = G.nodes[domain_id].get("props", {})
    domain_name = str(
        _property(domain_props, "name", "domain")
        or G.nodes[domain_id].get("name", "")
    ).strip().lower()
    domain_sid = str(
        _property(domain_props, "objectid", "domainsid") or domain_id
    ).strip().upper()

    hint = _object_domain_hint(G, node_id)
    if hint and hint in {domain_name, domain_sid.lower()}:
        return True

    node_name = str(G.nodes[node_id].get("name", "")).strip().lower()
    if domain_name and node_name.endswith((f".{domain_name}", f"@{domain_name}")):
        return True

    node_sid = str(node_id).strip().upper()
    return (
        domain_sid.startswith("S-1-5-21-")
        and node_sid.startswith(f"{domain_sid}-")
    )


def _laps_computers_for_domain(
    G: nx.DiGraph,
    domain_id: str,
) -> set[str]:
    computers: set[str] = set()
    for node_id, data in G.nodes(data=True):
        if data.get("kind") != "computers":
            continue
        if not _is_true(_property(data.get("props", {}), "haslaps")):
            continue
        if _belongs_to_domain(G, node_id, domain_id):
            computers.add(node_id)
    return computers


def synthesize_dcsync(G: nx.DiGraph, memberships: nx.DiGraph | None = None) -> int:
    """Create DCSync from effective GetChanges + GetChangesAll rights."""
    memberships = memberships or _membership_graph(G)
    created = 0
    for domain, data in G.nodes(data=True):
        if data.get("kind") != "domains":
            continue
        principals = _principals_with_both_rights(
            G, memberships, domain, "GetChanges", "GetChangesAll"
        )
        for principal in principals:
            existed = G.has_edge(principal, domain) and "DCSync" in _relations(
                G[principal][domain]
            )
            _add_relation(G, principal, domain, "DCSync")
            created += int(not existed)
    return created


def synthesize_sync_laps_password(
    G: nx.DiGraph,
    memberships: nx.DiGraph | None = None,
) -> int:
    """Create SyncLAPSPassword edges to LAPS computers in each domain."""
    memberships = memberships or _membership_graph(G)
    created = 0
    for domain, data in G.nodes(data=True):
        if data.get("kind") != "domains":
            continue
        principals = _principals_with_both_rights(
            G,
            memberships,
            domain,
            "GetChanges",
            "GetChangesInFilteredSet",
        )
        computers = _laps_computers_for_domain(G, domain)
        for principal in principals:
            for computer in computers:
                existed = G.has_edge(principal, computer) and (
                    "SyncLAPSPassword" in _relations(G[principal][computer])
                )
                _add_relation(G, principal, computer, "SyncLAPSPassword")
                created += int(not existed)
    return created


def _domain_for_node(G: nx.DiGraph, node_id: str) -> str | None:
    hint = _object_domain_hint(G, node_id)
    for domain, data in G.nodes(data=True):
        if data.get("kind") != "domains":
            continue
        props = data.get("props", {})
        candidates = {
            str(domain).lower(),
            str(_property(props, "domainsid") or "").lower(),
            str(_property(props, "name", "domain") or data.get("name", "")).lower(),
        }
        if hint and hint in candidates:
            return domain
        if _belongs_to_domain(G, node_id, domain):
            return domain
    return None


def _blocks_owner_implicit_rights(G: nx.DiGraph, target: str) -> bool:
    domain = _domain_for_node(G, target)
    if not domain:
        return False
    value = str(_property(G.nodes[domain].get("props", {}), "dsheuristics") or "")
    return len(value) > 28 and value[28] == "1"


def _is_tier_zero_admin(
    G: nx.DiGraph,
    memberships: nx.DiGraph,
    principal: str,
) -> bool:
    candidates = {principal}
    if principal in memberships:
        candidates.update(nx.descendants(memberships, principal))
    for candidate in candidates:
        name = str(G.nodes[candidate].get("name", "")).split("@", 1)[0].lower()
        sid = str(candidate).upper()
        if name in {"domain admins", "enterprise admins"} or sid.endswith(("-512", "-519")):
            return True
    return False


def synthesize_ownership(
    G: nx.DiGraph,
    memberships: nx.DiGraph | None = None,
) -> dict[str, int]:
    """Convert current OwnsRaw/WriteOwnerRaw relations into usable edges.

    BloodHound suppresses implicit owner rights on computer-derived objects
    when dSHeuristics[28] enables BlockOwnerImplicitRights. The conservative
    checks below reproduce that decision for the object kinds represented by
    SharpHound JSON while retaining the raw edges as context.
    """
    memberships = memberships or _membership_graph(G)
    created = {"Owns": 0, "WriteOwner": 0}
    raw_edges = [
        (src, dst, set(_relations(data)))
        for src, dst, data in list(G.edges(data=True))
        if {"OwnsRaw", "WriteOwnerRaw"} & set(_relations(data))
    ]
    computer_derived = {"computers", "localgroups", "localusers"}
    for source, target, relations in raw_edges:
        blocked = (
            _blocks_owner_implicit_rights(G, target)
            and G.nodes[target].get("kind") in computer_derived
        )
        if "OwnsRaw" in relations and (
            not blocked or _is_tier_zero_admin(G, memberships, source)
        ):
            existed = G.has_edge(source, target) and "Owns" in _relations(
                G[source][target]
            )
            _add_relation(G, source, target, "Owns")
            created["Owns"] += int(not existed)
        if "WriteOwnerRaw" in relations and not blocked:
            existed = G.has_edge(source, target) and "WriteOwner" in _relations(
                G[source][target]
            )
            _add_relation(G, source, target, "WriteOwner")
            created["WriteOwner"] += int(not existed)
    return created


def synthesize_has_trust_keys(G: nx.DiGraph) -> int:
    """Create HasTrustKeys using BloodHound's domain/trust-account rule."""
    created = 0
    users: dict[tuple[str, str], str] = {}
    for node, data in G.nodes(data=True):
        if data.get("kind") != "users":
            continue
        props = data.get("props", {})
        domain_sid = str(_property(props, "domainsid") or "").upper()
        sam = str(_property(props, "samaccountname") or "").upper()
        if domain_sid and sam:
            users[(domain_sid, sam)] = node

    for domain, data in list(G.nodes(data=True)):
        if data.get("kind") != "domains":
            continue
        netbios = str(_property(data.get("props", {}), "netbios") or "").upper()
        if not netbios:
            continue
        for _, trusting_domain in list(G.out_edges(domain)):
            if not (
                {"SameForestTrust", "CrossForestTrust"}
                & set(_relations(G[domain][trusting_domain]))
            ):
                continue
            trusting_sid = str(
                _property(G.nodes[trusting_domain].get("props", {}), "domainsid") or ""
            ).upper()
            trust_account = users.get((trusting_sid, f"{netbios}$"))
            if not trust_account:
                continue
            existed = G.has_edge(domain, trust_account) and "HasTrustKeys" in _relations(
                G[domain][trust_account]
            )
            _add_relation(G, domain, trust_account, "HasTrustKeys")
            created += int(not existed)
    return created


def postprocess_graph(G: nx.DiGraph) -> nx.DiGraph:
    """Apply Pathdog's supported BloodHound post-processing stages in place."""
    memberships = _membership_graph(G)
    ownership = synthesize_ownership(G, memberships)
    # Imported lazily to keep the generic graph helpers independent of the
    # ADCS implementation and avoid an import cycle.
    from .adcs_postprocess import synthesize_adcs

    adcs = synthesize_adcs(G, memberships, _add_relation)
    G.graph["postprocessed_edges"] = {
        **ownership,
        **adcs,
        "HasTrustKeys": synthesize_has_trust_keys(G),
        "DCSync": synthesize_dcsync(G, memberships),
        "SyncLAPSPassword": synthesize_sync_laps_password(G, memberships),
    }
    return G
