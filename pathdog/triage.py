"""Global triage engine built on top of Pathdog's graph model."""

from __future__ import annotations

from .commands import get_commands
from .findings import Finding
from .quickwins import collect_all


SEVERITY_BY_CATEGORY = {
    "ADCS": 10,
    "DCSync": 10,
    "Dangerous ACL": 9,
    "Unconstrained delegation": 8,
    "Password not required": 8,
    "Privileged user not protected": 7,
    "AS-REP roast": 6,
    "Kerberoast": 6,
    "LAPS in use": 5,
    "Domain Controller": 5,
    "High-value target": 4,
}

ADCS_EDGES = {
    "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC6a", "ADCSESC6b",
    "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
    "GoldenCert",
}

DANGEROUS_RELATIONS = {
    "GenericAll", "WriteDacl", "WriteOwner", "Owns", "AllExtendedRights",
    "ForceChangePassword", "AddMember", "AddSelf", "GenericWrite",
    "AddKeyCredentialLink", "AllowedToAct", "WriteAccountRestrictions",
    "ReadLAPSPassword", "SyncLAPSPassword", "ManageCA",
    "ManageCertificates", "DelegatedEnrollmentAgent", "WriteGPLink",
}

EXPECTED_TIER0_ADMIN_GROUPS = {
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
}

DANGEROUS_RELATION_PRIORITY = {
    "GenericAll": 0,
    "WriteDacl": 1,
    "WriteOwner": 2,
    "Owns": 3,
    "AllExtendedRights": 4,
    "GenericWrite": 5,
    "AddKeyCredentialLink": 6,
    "ForceChangePassword": 7,
    "AddMember": 8,
    "AddSelf": 9,
    "AllowedToAct": 10,
    "WriteAccountRestrictions": 11,
    "ManageCA": 12,
    "ManageCertificates": 13,
    "DelegatedEnrollmentAgent": 14,
    "WriteGPLink": 15,
    "ReadLAPSPassword": 16,
    "SyncLAPSPassword": 17,
}


def _display_name(G, nid: str) -> str:
    if nid in G:
        return G.nodes[nid].get("name", nid) or nid
    return nid


def _kind(G, nid: str) -> str:
    return G.nodes[nid].get("kind", "") if nid in G else ""


def _is_high_value(G, nid: str) -> bool:
    if nid not in G:
        return False
    props = G.nodes[nid].get("props", {})
    name = _display_name(G, nid).lower()
    if props.get("highvalue") or props.get("HighValue"):
        return True
    return any(
        hint in name for hint in (
            "domain admins", "enterprise admins", "schema admins",
            "administrators", "domain controllers", "key admins",
            "enterprise key admins", "dnsadmins",
        )
    )


def _principal_base_name(G, nid: str) -> str:
    name = _display_name(G, nid).lower()
    if "\\" in name:
        name = name.rsplit("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return " ".join(name.split())


def _is_expected_tier0_admin_control(G, src: str, dst: str) -> bool:
    """True for default admin groups controlling default tier-0 objects.

    These edges are real and must stay in the graph, but as triage findings
    they are usually baseline privileges rather than actionable weaknesses.
    """
    if _kind(G, src) != "groups":
        return False
    if _principal_base_name(G, src) not in EXPECTED_TIER0_ADMIN_GROUPS:
        return False
    return _is_high_value(G, dst)


def _dangerous_relation_sort_key(rel: str) -> tuple[int, str]:
    return DANGEROUS_RELATION_PRIORITY.get(rel, 100), rel


def _commands_for_edge(G, src: str, dst: str, rel: str) -> list[str]:
    cmd, _ = get_commands(
        rel_type=rel,
        src_id=src,
        dst_id=dst,
        src_name=_display_name(G, src),
        dst_name=_display_name(G, dst),
        src_kind=_kind(G, src),
        dst_kind=_kind(G, dst),
        actor=_display_name(G, src),
    )
    return cmd.commands


def collect_findings(G, *, quickwins: dict | None = None, limit: int | None = None) -> list[Finding]:
    """Return normalized findings sorted by severity.

    This intentionally prefers graph relationships that BloodHound already
    considers attack edges. Property-only findings are sourced from quickwins.
    """
    quickwins = quickwins if quickwins is not None else collect_all(G)
    findings: list[Finding] = []
    seen: set[tuple] = set()
    dangerous_by_pair: dict[tuple[str, str], set[str]] = {}

    for category, items in quickwins.items():
        # ADCS quickwins come from graph edges too; keep the graph-sourced
        # finding because it carries better evidence and runnable commands.
        if category.startswith("ADCS "):
            continue
        severity = SEVERITY_BY_CATEGORY.get(category, 5)
        for qw in items:
            key = ("quickwin", category, qw.node_id, qw.detail)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                severity=severity,
                category=category,
                title=f"{category}: {qw.node_name}",
                node_id=qw.node_id,
                node_name=qw.node_name,
                node_kind=qw.node_kind,
                evidence=qw.detail,
                commands=list(qw.commands),
                source="quickwins",
            ))

    for src, dst, data in G.edges(data=True):
        rels = data.get("relations") or {data.get("relation", "Unknown"): data.get("weight", 5)}
        for rel in rels:
            if rel in ("MemberOf", "Contains"):
                continue
            src_name = _display_name(G, src)
            dst_name = _display_name(G, dst)

            if rel == "DCSync":
                if _is_expected_tier0_admin_control(G, src, dst):
                    continue
                key = ("dcsync", src, dst)
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        severity=10,
                        category="DCSync",
                        title=f"{src_name} can DCSync {dst_name}",
                        node_id=dst,
                        node_name=dst_name,
                        node_kind=_kind(G, dst),
                        evidence=f"{src_name} has synthesized DCSync rights on {dst_name}.",
                        commands=_commands_for_edge(G, src, dst, rel),
                        source="graph",
                    ))

            if rel in ADCS_EDGES:
                key = ("adcs-edge", rel, src, dst)
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        severity=10,
                        category=f"ADCS {rel}",
                        title=f"{rel} on {dst_name}",
                        node_id=dst,
                        node_name=dst_name,
                        node_kind=_kind(G, dst),
                        evidence=f"{rel} edge from {src_name} to {dst_name}.",
                        commands=_commands_for_edge(G, src, dst, rel),
                        source="graph",
                    ))

            if (
                rel in DANGEROUS_RELATIONS
                and _is_high_value(G, dst)
                and not _is_expected_tier0_admin_control(G, src, dst)
            ):
                dangerous_by_pair.setdefault((src, dst), set()).add(rel)

    for (src, dst), rels in dangerous_by_pair.items():
        ordered_rels = sorted(rels, key=_dangerous_relation_sort_key)
        rel_label = ", ".join(ordered_rels)
        src_name = _display_name(G, src)
        dst_name = _display_name(G, dst)
        key = ("dangerous-acl", src, dst, tuple(ordered_rels))
        if key in seen:
            continue
        seen.add(key)
        if len(ordered_rels) == 1:
            title = f"{src_name} has {ordered_rels[0]} on high-value {dst_name}"
        else:
            title = f"{src_name} has {len(ordered_rels)} control rights on high-value {dst_name}"
        findings.append(Finding(
            severity=9,
            category="Dangerous ACL",
            title=title,
            node_id=dst,
            node_name=dst_name,
            node_kind=_kind(G, dst),
            evidence=f"{rel_label} from {src_name} to high-value target {dst_name}.",
            commands=_commands_for_edge(G, src, dst, ordered_rels[0]),
            source="graph",
        ))

    findings.sort(key=lambda f: (-f.severity, f.category, f.node_name, f.title))
    if limit is not None:
        return findings[:limit]
    return findings
