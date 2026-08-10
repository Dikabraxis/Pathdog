"""Conservative BloodHound-compatible AD CS post-processing.

The collector emits facts such as PublishedTo, Enroll and certificate
properties. BloodHound turns those facts into attack edges after ingestion.
This module performs the same calculation only when every required property
is present; incomplete collections therefore fail closed.
"""

from __future__ import annotations

from collections.abc import Callable

import networkx as nx

CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
ANY_PURPOSE = "2.5.29.37.0"
ENROLL_RIGHTS = {"Enroll", "GenericAll", "AllExtendedRights"}


def _as_bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)


def _props(graph: nx.DiGraph, node: str) -> dict:
    return graph.nodes[node].get("props", {})


def _get(graph: nx.DiGraph, node: str, name: str, default=None):
    props = _props(graph, node)
    return next(
        (value for key, value in props.items() if str(key).lower() == name.lower()),
        default,
    )


def _rels(graph: nx.DiGraph, source: str, target: str) -> set[str]:
    data = graph[source][target]
    return set(data.get("relations") or {data.get("relation", "Unknown")})


def _direct_sources(graph: nx.DiGraph, target: str, rights: set[str]) -> set[str]:
    return {
        source
        for source, _ in graph.in_edges(target)
        if _rels(graph, source, target) & rights
    }


def _effective(
    graph: nx.DiGraph,
    memberships: nx.DiGraph,
    sources: set[str],
) -> set[str]:
    result: set[str] = set()
    for source in sources:
        if graph.nodes[source].get("kind") not in {"users", "groups", "computers"}:
            continue
        result.add(source)
        result.update(
            member
            for member in nx.ancestors(memberships, source)
            if graph.nodes[member].get("kind") in {"users", "groups", "computers"}
        )
    return result


def _same_domain(graph: nx.DiGraph, first: str, second: str) -> bool:
    a = str(_get(graph, first, "domainsid", "")).upper()
    b = str(_get(graph, second, "domainsid", "")).upper()
    return bool(a and a == b)


def _template_valid(graph: nx.DiGraph, template: str, *, supplies: bool | None) -> bool:
    required = ("requiresmanagerapproval", "authenticationenabled", "schemaversion", "authorizedsignatures")
    if any(_get(graph, template, key) is None for key in required):
        return False
    if _as_bool(_get(graph, template, "requiresmanagerapproval")):
        return False
    if not _as_bool(_get(graph, template, "authenticationenabled")):
        return False
    if float(_get(graph, template, "schemaversion")) > 1 and float(
        _get(graph, template, "authorizedsignatures")
    ) > 0:
        return False
    if supplies is not None:
        value = _get(graph, template, "enrolleesuppliessubject")
        if value is None or _as_bool(value) is not supplies:
            return False
    return True


def _intersection(
    graph: nx.DiGraph,
    memberships: nx.DiGraph,
    target: str,
    right_sets: tuple[set[str], ...],
) -> set[str]:
    effective_sets = [
        _effective(graph, memberships, _direct_sources(graph, target, rights))
        for rights in right_sets
    ]
    return set.intersection(*effective_sets) if effective_sets else set()


def _filter_dns_users(graph: nx.DiGraph, template: str, principals: set[str]) -> set[str]:
    requires_dns = _as_bool(_get(graph, template, "subjectaltrequiredns", False))
    if not requires_dns:
        return principals
    return {p for p in principals if graph.nodes[p].get("kind") != "users"}


def _chained_domains(graph: nx.DiGraph, enterprise_ca: str) -> set[str]:
    """Resolve CA chains through calculated/raw signing relationships."""
    queue = [enterprise_ca]
    seen = {enterprise_ca}
    domains: set[str] = set()
    while queue:
        current = queue.pop()
        for _, target in graph.out_edges(current):
            relations = _rels(graph, current, target)
            if "RootCAFor" in relations and graph.nodes[target].get("kind") == "domains":
                domains.add(target)
            if relations & {"EnterpriseCAFor", "IssuedSignedBy"} and target not in seen:
                seen.add(target)
                queue.append(target)
    return domains


def _forest_domains(graph: nx.DiGraph, domain: str) -> set[str]:
    forest = nx.Graph()
    forest.add_node(domain)
    for source, target in graph.edges:
        if "SameForestTrust" in _rels(graph, source, target):
            forest.add_edge(source, target)
    return nx.node_connected_component(forest, domain)


def _forest_dc_property(graph: nx.DiGraph, domain: str, prop: str) -> list[int]:
    values: list[int] = []
    for forest_domain in _forest_domains(graph, domain):
        for dc, _ in graph.in_edges(forest_domain):
            if "DCFor" not in _rels(graph, dc, forest_domain):
                continue
            value = _get(graph, dc, prop)
            if value is not None:
                try:
                    values.append(int(value))
                except (TypeError, ValueError):
                    continue
    return values


def _schannel_enabled(graph: nx.DiGraph, template: str) -> bool:
    explicit = _get(graph, template, "schannelauthenticationenabled")
    if explicit is not None:
        return _as_bool(explicit)
    ekus = _get(graph, template, "effectiveekus")
    if ekus is None:
        return False
    return not ekus or bool({"1.3.6.1.5.5.7.3.2", ANY_PURPOSE} & set(ekus))


def _valid_schema_and_approval(graph: nx.DiGraph, template: str) -> bool:
    required = ("requiresmanagerapproval", "schemaversion", "authorizedsignatures")
    if any(_get(graph, template, key) is None for key in required):
        return False
    return not _as_bool(_get(graph, template, "requiresmanagerapproval")) and not (
        float(_get(graph, template, "schemaversion")) > 1
        and float(_get(graph, template, "authorizedsignatures")) > 0
    )


def synthesize_adcs(
    graph: nx.DiGraph,
    memberships: nx.DiGraph,
    add_relation: Callable[[nx.DiGraph, str, str, str], None],
) -> dict[str, int]:
    created: dict[str, int] = {}

    def add(
        source: str,
        target: str,
        relation: str,
        evidence: dict[str, str] | None = None,
    ) -> None:
        existed = graph.has_edge(source, target) and relation in _rels(graph, source, target)
        add_relation(graph, source, target, relation)
        if not existed:
            created[relation] = created.get(relation, 0) + 1
        if evidence:
            graph.graph.setdefault("edge_evidence", {}).setdefault(
                (source, target, relation), []
            ).append(evidence)

    nodes_by_kind: dict[str, list[str]] = {}
    for node, data in graph.nodes(data=True):
        nodes_by_kind.setdefault(data.get("kind", "unknown"), []).append(node)

    # Certificate topology edges produced by BloodHound's shared ADCS pass.
    thumbprints: dict[str, list[str]] = {}
    for kind in ("rootcas", "aiacas"):
        for node in nodes_by_kind.get(kind, []):
            thumbprint = str(_get(graph, node, "certthumbprint", "")).upper()
            if thumbprint:
                thumbprints.setdefault(thumbprint, []).append(node)

    for ca in nodes_by_kind.get("enterprisecas", []):
        own_thumbprint = str(_get(graph, ca, "certthumbprint", "")).upper()
        for target in thumbprints.get(own_thumbprint, []):
            add(ca, target, "EnterpriseCAFor")

        chain = [str(value).upper() for value in (_get(graph, ca, "certchain", []) or [])]
        for parent_thumbprint in chain[1:2]:
            for target in thumbprints.get(parent_thumbprint, []):
                add(ca, target, "IssuedSignedBy")

    for store in nodes_by_kind.get("ntauthstores", []):
        trusted = {
            str(value).upper()
            for value in (_get(graph, store, "certthumbprints", []) or [])
        }
        for ca in nodes_by_kind.get("enterprisecas", []):
            if str(_get(graph, ca, "certthumbprint", "")).upper() in trusted:
                add(ca, store, "TrustedForNTAuth")

    policies: dict[tuple[str, str], str] = {}
    for policy in nodes_by_kind.get("issuancepolicies", []):
        key = (
            str(_get(graph, policy, "domainsid", "")).upper(),
            str(_get(graph, policy, "oid", "")),
        )
        if all(key):
            policies[key] = policy
    for template in nodes_by_kind.get("certtemplates", []):
        domain_sid = str(_get(graph, template, "domainsid", "")).upper()
        for oid in _get(graph, template, "issuancepolicies", []) or []:
            if policy := policies.get((domain_sid, str(oid))):
                add(template, policy, "ExtendedByPolicy")

    # Enrollment-agent links are independent of principal ACLs.
    templates = nodes_by_kind.get("certtemplates", [])
    published = {
        template
        for template in templates
        if any("PublishedTo" in _rels(graph, template, ca) for _, ca in graph.out_edges(template))
    }
    for agent in published:
        ekus = set(_get(graph, agent, "effectiveekus", []) or [])
        version = float(_get(graph, agent, "schemaversion", 0) or 0)
        if not (CERT_REQUEST_AGENT in ekus or (version == 1 and not ekus) or ANY_PURPOSE in ekus):
            continue
        for target in published:
            if not _same_domain(graph, agent, target):
                continue
            target_version = float(_get(graph, target, "schemaversion", 0) or 0)
            if version == 1 and target_version == 1:
                add(agent, target, "EnrollOnBehalfOf")
            elif agent != target and version >= 2 and target_version >= 2 and (
                ANY_PURPOSE not in ekus
                and float(_get(graph, target, "authorizedsignatures", 0) or 0) >= 1
                and CERT_REQUEST_AGENT in set(_get(graph, target, "applicationpolicies", []) or [])
            ):
                add(agent, target, "EnrollOnBehalfOf")

    # ESC1: principal can enroll in a valid template and its publishing CA,
    # and that CA chains to the target domain and is trusted for NT auth.
    for template in published:
        if not _template_valid(graph, template, supplies=True):
            continue
        template_enrollers = _effective(
            graph, memberships, _direct_sources(graph, template, ENROLL_RIGHTS)
        )
        for _, ca in graph.out_edges(template):
            if "PublishedTo" not in _rels(graph, template, ca):
                continue
            ca_enrollers = _effective(
                graph, memberships, _direct_sources(graph, ca, {"Enroll"})
            )
            principals = template_enrollers & ca_enrollers
            trusted_domains = {
                domain
                for _, store in graph.out_edges(ca)
                if "TrustedForNTAuth" in _rels(graph, ca, store)
                for _, domain in graph.out_edges(store)
                if "NTAuthStoreFor" in _rels(graph, store, domain)
            }
            for principal in principals:
                for domain in _chained_domains(graph, ca) & trusted_domains:
                    add(
                        principal,
                        domain,
                        "ADCSESC1",
                        {"ca": ca, "template": template},
                    )

    # ESC3: enrollment agent template + target authentication template. Every
    # intersected right is expanded through group membership before use.
    for target in published:
        if _get(graph, target, "authenticationenabled") is None or _get(
            graph, target, "requiresmanagerapproval"
        ) is None:
            continue
        if not _as_bool(_get(graph, target, "authenticationenabled")) or _as_bool(
            _get(graph, target, "requiresmanagerapproval")
        ):
            continue
        for agent, _ in graph.in_edges(target):
            if "EnrollOnBehalfOf" not in _rels(graph, agent, target):
                continue
            version = float(_get(graph, agent, "schemaversion", 0) or 0)
            if _as_bool(_get(graph, agent, "requiresmanagerapproval", True)):
                continue
            if version <= 0 or (
                version > 1 and float(_get(graph, agent, "authorizedsignatures", 1) or 0) > 0
            ):
                continue
            for _, ca in graph.out_edges(target):
                if "PublishedTo" not in _rels(graph, target, ca):
                    continue
                ca2 = _effective(graph, memberships, _direct_sources(graph, ca, {"Enroll"}))
                target_enrollers = _effective(
                    graph, memberships, _direct_sources(graph, target, ENROLL_RIGHTS)
                )
                for _, agent_ca in graph.out_edges(agent):
                    if "PublishedTo" not in _rels(graph, agent, agent_ca):
                        continue
                    ca1 = _effective(
                        graph, memberships, _direct_sources(graph, agent_ca, {"Enroll"})
                    )
                    agent_enrollers = _effective(
                        graph, memberships, _direct_sources(graph, agent, ENROLL_RIGHTS)
                    )
                    principals = agent_enrollers & target_enrollers & ca1 & ca2
                    if _as_bool(_get(graph, ca, "enrollmentagentrestrictionscollected", False)) and _as_bool(
                        _get(graph, ca, "hasenrollmentagentrestrictions", False)
                    ):
                        principals &= _effective(
                            graph,
                            memberships,
                            _direct_sources(graph, target, {"DelegatedEnrollmentAgent"}),
                        )
                    for principal in _filter_dns_users(graph, agent, principals):
                        for domain in _chained_domains(graph, ca):
                            add(
                                principal,
                                domain,
                                "ADCSESC3",
                                {
                                    "ca": ca,
                                    "template": target,
                                    "agent_template": agent,
                                    "agent_ca": agent_ca,
                                },
                            )

    # ESC4: sufficient template control to turn a published authentication
    # template into ESC1. This follows BloodHound's union of the controller,
    # GenericWrite+Enroll and split PKI-flag cases.
    controller_rights = {"Owns", "GenericAll", "WriteDacl", "WriteOwner"}
    for template in published:
        if _get(graph, template, "enrolleesuppliessubject") is None or _get(
            graph, template, "requiresmanagerapproval"
        ) is None:
            continue
        for _, ca in graph.out_edges(template):
            if "PublishedTo" not in _rels(graph, template, ca):
                continue
            ca_enrollers = _effective(
                graph, memberships, _direct_sources(graph, ca, {"Enroll"})
            )
            candidates = _effective(
                graph, memberships, _direct_sources(graph, template, controller_rights)
            )
            candidates |= _intersection(
                graph, memberships, template, ({"GenericWrite"}, {"Enroll", "AllExtendedRights"})
            )
            if _template_valid(graph, template, supplies=None):
                candidates |= _intersection(
                    graph,
                    memberships,
                    template,
                    (
                        {"Enroll", "AllExtendedRights"},
                        {"WritePKINameFlag"},
                        {"WritePKIEnrollmentFlag"},
                    ),
                )
                if _as_bool(_get(graph, template, "enrolleesuppliessubject", False)):
                    candidates |= _intersection(
                        graph,
                        memberships,
                        template,
                        ({"Enroll", "AllExtendedRights"}, {"WritePKIEnrollmentFlag"}),
                    )
                if not _as_bool(_get(graph, template, "requiresmanagerapproval", True)):
                    candidates |= _intersection(
                        graph,
                        memberships,
                        template,
                        ({"Enroll", "AllExtendedRights"}, {"WritePKINameFlag"}),
                    )
            for principal in candidates & ca_enrollers:
                for domain in _chained_domains(graph, ca):
                    add(
                        principal,
                        domain,
                        "ADCSESC4",
                        {"ca": ca, "template": template},
                    )

    # ESC13: issuance policy grants implicit membership in its linked group.
    for template in published:
        if not _template_valid(graph, template, supplies=None):
            continue
        linked_groups = {
            group
            for _, policy in graph.out_edges(template)
            if "ExtendedByPolicy" in _rels(graph, template, policy)
            for _, group in graph.out_edges(policy)
            if "OIDGroupLink" in _rels(graph, policy, group)
        }
        if not linked_groups:
            continue
        template_enrollers = _effective(
            graph, memberships, _direct_sources(graph, template, ENROLL_RIGHTS)
        )
        for _, ca in graph.out_edges(template):
            if "PublishedTo" not in _rels(graph, template, ca):
                continue
            ca_enrollers = _effective(
                graph, memberships, _direct_sources(graph, ca, {"Enroll"})
            )
            for principal in _filter_dns_users(
                graph, template, template_enrollers & ca_enrollers
            ):
                for group in linked_groups:
                    add(
                        principal,
                        group,
                        "ADCSESC13",
                        {"ca": ca, "template": template},
                    )

    # ESC6 uses a CA-wide SAN flag. Scenario A requires a template without the
    # SID security extension; scenario B uses Schannel and therefore also
    # requires UPN certificate mapping on a collected DC in the forest.
    for ca in nodes_by_kind.get("enterprisecas", []):
        if not _as_bool(_get(graph, ca, "isuserspecifiessanenabledcollected", False)):
            continue
        if not _as_bool(_get(graph, ca, "isuserspecifiessanenabled", False)):
            continue
        ca_enrollers = _effective(
            graph, memberships, _direct_sources(graph, ca, {"Enroll"})
        )
        for template, _ in graph.in_edges(ca):
            if "PublishedTo" not in _rels(graph, template, ca):
                continue
            if not _valid_schema_and_approval(graph, template):
                continue
            template_enrollers = _effective(
                graph, memberships, _direct_sources(graph, template, ENROLL_RIGHTS)
            )
            principals = _filter_dns_users(
                graph, template, template_enrollers & ca_enrollers
            )
            for domain in _chained_domains(graph, ca):
                evidence = {"ca": ca, "template": template}
                if (
                    _get(graph, template, "nosecurityextension") is not None
                    and _as_bool(_get(graph, template, "nosecurityextension"))
                    and _as_bool(_get(graph, template, "authenticationenabled", False))
                ):
                    for principal in principals:
                        add(principal, domain, "ADCSESC6a", evidence)
                upn_mapping = any(
                    value != -1 and value & 4
                    for value in _forest_dc_property(
                        graph, domain, "certificatemappingmethodsraw"
                    )
                )
                if _schannel_enabled(graph, template) and upn_mapping:
                    for principal in principals:
                        add(principal, domain, "ADCSESC6b", evidence)

    # ESC9/10 require control of a victim that can enroll. The weak-binding
    # registry inputs are privileged collection data, so absent values block
    # synthesis instead of assuming a vulnerable Windows default.
    control_a = {
        "GenericAll",
        "GenericWrite",
        "Owns",
        "WriteOwner",
        "WriteDacl",
        "WritePublicInformation",
    }
    control_b = control_a - {"WritePublicInformation"}
    for template in published:
        if not _valid_schema_and_approval(graph, template):
            continue
        if _get(graph, template, "enrolleesuppliessubject") is None or _as_bool(
            _get(graph, template, "enrolleesuppliessubject")
        ):
            continue
        for _, ca in graph.out_edges(template):
            if "PublishedTo" not in _rels(graph, template, ca):
                continue
            victims = _effective(
                graph, memberships, _direct_sources(graph, template, ENROLL_RIGHTS)
            ) & _effective(graph, memberships, _direct_sources(graph, ca, {"Enroll"}))
            for domain in _chained_domains(graph, ca):
                weak_binding = any(
                    value in {-1, 0, 1}
                    for value in _forest_dc_property(
                        graph, domain, "strongcertificatebindingenforcementraw"
                    )
                )
                upn_mapping = any(
                    value != -1 and value & 4
                    for value in _forest_dc_property(
                        graph, domain, "certificatemappingmethodsraw"
                    )
                )
                evidence = {"ca": ca, "template": template}
                variants = (
                    (
                        "a",
                        _as_bool(_get(graph, template, "subjectaltrequireupn", False))
                        or _as_bool(_get(graph, template, "subjectaltrequirespn", False)),
                        control_a,
                    ),
                    (
                        "b",
                        _as_bool(_get(graph, template, "subjectaltrequiredns", False)),
                        control_b,
                    ),
                )
                for suffix, required_name, control_rights in variants:
                    if not required_name:
                        continue
                    eligible_victims = victims
                    if suffix == "a":
                        eligible_victims = _filter_dns_users(graph, template, victims)
                    attackers = {
                        attacker
                        for victim in eligible_victims
                        for attacker, _ in graph.in_edges(victim)
                        if _rels(graph, attacker, victim) & control_rights
                        and graph.nodes[attacker].get("kind")
                        in {"users", "groups", "computers"}
                        and (suffix == "a" or graph.nodes[victim].get("kind") == "computers")
                    }
                    if (
                        _as_bool(_get(graph, template, "authenticationenabled", False))
                        and _as_bool(_get(graph, template, "nosecurityextension", False))
                        and weak_binding
                    ):
                        for attacker in attackers:
                            add(attacker, domain, f"ADCSESC9{suffix}", evidence)
                    if _schannel_enabled(graph, template) and upn_mapping:
                        for attacker in attackers:
                            add(attacker, domain, f"ADCSESC10{suffix}", evidence)

    # CA private-key compromise (GoldenCert) starts from its hosting computer.
    for computer in nodes_by_kind.get("computers", []):
        for _, ca in list(graph.out_edges(computer)):
            if "HostsCAService" in _rels(graph, computer, ca):
                for domain in _chained_domains(graph, ca):
                    add(computer, domain, "GoldenCert", {"ca": ca})

    return created
