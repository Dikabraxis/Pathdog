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

    for category, items in quickwins.items():
        # ADCS quickwins come from graph edges too; keep the graph-sourced
        # finding because it carries better evidence and runnable commands.
        if category.startswith("ADCS "):
            continue
        base_category = "ADCS" if category.startswith("ADCS ") else category
        severity = SEVERITY_BY_CATEGORY.get(base_category, 5)
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

            if rel in DANGEROUS_RELATIONS and _is_high_value(G, dst):
                key = ("dangerous-acl", rel, src, dst)
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        severity=9,
                        category="Dangerous ACL",
                        title=f"{src_name} has {rel} on high-value {dst_name}",
                        node_id=dst,
                        node_name=dst_name,
                        node_kind=_kind(G, dst),
                        evidence=f"{rel} from {src_name} to high-value target {dst_name}.",
                        commands=_commands_for_edge(G, src, dst, rel),
                        source="graph",
                    ))

    findings.sort(key=lambda f: (-f.severity, f.category, f.node_name, f.title))
    if limit is not None:
        return findings[:limit]
    return findings
