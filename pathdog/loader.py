"""ZIP parsing: extracts nodes and edges from a BloodHound export archive.

Supports:
  - BloodHound legacy (v4): {data:[...], rels:[...]} or Aces-embedded
  - BloodHound CE (v5+):    {meta:{type,count,...}, data:[...]} with
    Members/LocalAdmins/Sessions/AllowedToDelegate arrays
"""

import json
import zipfile
from pathlib import Path

EXPECTED_PREFIXES = ("users", "computers", "groups", "domains", "gpos", "ous")


def _json_files(zf: zipfile.ZipFile) -> list[str]:
    return [
        name for name in zf.namelist()
        if name.lower().endswith(".json") and not name.startswith("__MACOSX")
    ]


def _classify(name: str, meta_type: str = "") -> str | None:
    """Return the node kind for a JSON file.

    Tries meta.type first (CE format), then filename matching.
    Handles CE timestamp-prefixed names like 20240101_users.json.
    """
    if meta_type:
        t = meta_type.lower()
        # normalize: "user" -> "users", "computer" -> "computers"
        if not t.endswith("s"):
            t += "s"
        if t in EXPECTED_PREFIXES:
            return t
    base = Path(name).stem.lower()
    for prefix in EXPECTED_PREFIXES:
        if base.startswith(prefix) or f"_{prefix}" in base:
            return prefix
    return None


def load_zip(path: str) -> tuple[list[dict], list[dict]]:
    """Return (nodes, edges) extracted from *path*.

    nodes: list of {"id": str, "kind": str, "props": dict}
    edges: list of {"src": str, "dst": str, "type": str}
    """
    if not zipfile.is_zipfile(path):
        raise ValueError(f"Not a valid ZIP file: {path}")

    nodes: list[dict] = []
    edges: list[dict] = []

    with zipfile.ZipFile(path, "r") as zf:
        json_files = _json_files(zf)
        if not json_files:
            raise ValueError(
                f"No JSON files found in {path}. "
                "Expected files matching: users*.json, computers*.json, etc."
            )

        found_kinds: set[str] = set()

        for fname in json_files:
            try:
                data = json.loads(zf.read(fname))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON in {fname}: {exc}") from exc

            meta_type = ""
            if isinstance(data, dict):
                meta_type = data.get("meta", {}).get("type", "")

            kind = _classify(fname, meta_type) or "unknown"
            if kind != "unknown":
                found_kinds.add(kind)

            objects = _extract_objects(data)
            rels = _extract_relationships(data, objects)

            for obj in objects:
                node_id = _node_id(obj)
                if node_id:
                    nodes.append({
                        "id": node_id,
                        "kind": kind,
                        "props": obj.get("Properties", {}),
                    })

            for rel in rels:
                src = rel.get("StartNode") or rel.get("SourceNode")
                dst = rel.get("EndNode") or rel.get("TargetNode")
                rtype = rel.get("RelationshipType") or rel.get("Type")
                if src and dst and rtype:
                    edges.append({"src": str(src), "dst": str(dst), "type": str(rtype)})

        missing = [p for p in EXPECTED_PREFIXES if p not in found_kinds]
        if missing:
            import sys
            print(
                f"[warn] ZIP missing expected file types: {', '.join(missing)}. "
                "Some attack paths may be incomplete.",
                file=sys.stderr,
            )

    return nodes, edges


def _extract_objects(data: dict | list) -> list[dict]:
    """Handle legacy {data:[...]}, CE {meta:..., data:[...]}, and bare lists."""
    if isinstance(data, list):
        return data
    for key in ("data", "nodes", "Data", "Nodes"):
        if key in data and isinstance(data[key], list):
            return data[key]
    return []


def _extract_relationships(data: dict | list, objects: list[dict]) -> list[dict]:
    """Extract all relationship edges from a JSON blob.

    Tries (in order):
    1. Top-level explicit array (legacy rels/edges or CE Relationships)
    2. Legacy ACE-embedded edges
    3. CE embedded arrays (Members, LocalAdmins, Sessions, etc.)
    """
    if isinstance(data, list):
        # Bare list of objects — only CE embedded extraction possible
        return _extract_legacy_aces(objects) + _extract_ce_arrays(objects)

    # Explicit top-level array
    for key in ("rels", "edges", "Rels", "Edges", "relationships", "Relationships"):
        if key in data and isinstance(data[key], list):
            return data[key]

    # Embedded extraction (both legacy and CE)
    return _extract_legacy_aces(objects) + _extract_ce_arrays(objects)


def _extract_legacy_aces(objects: list[dict]) -> list[dict]:
    """Extract ACE-based relationships (legacy BloodHound format)."""
    rels: list[dict] = []
    for obj in objects:
        src = _node_id(obj)
        if not src:
            continue
        for ace in obj.get("Aces", []):
            dst = ace.get("PrincipalSID") or ace.get("PrincipalName")
            rtype = ace.get("RightName") or ace.get("Type")
            if dst and rtype:
                # dst principal has rtype right ON src object
                rels.append({"StartNode": str(dst), "EndNode": str(src), "RelationshipType": str(rtype)})
    return rels


# CE relationship arrays on computer objects
_COMPUTER_ARRAYS = {
    "LocalAdmins":        "AdminTo",
    "RemoteDesktopUsers": "CanRDP",
    "DcomUsers":          "ExecuteDCOM",
    "PSRemoteUsers":      "CanPSRemote",
}


def _extract_ce_arrays(objects: list[dict]) -> list[dict]:
    """Extract CE (v5+) embedded relationship arrays from object fields."""
    rels: list[dict] = []

    for obj in objects:
        obj_id = _node_id(obj)
        if not obj_id:
            continue

        # Groups — Members: member -[MemberOf]→ group
        for member in obj.get("Members", []):
            mid = member.get("ObjectIdentifier") if isinstance(member, dict) else member
            if mid:
                rels.append({"StartNode": str(mid), "EndNode": obj_id, "RelationshipType": "MemberOf"})

        # Computers — privilege arrays: principal -[rel]→ computer
        for field, rel_type in _COMPUTER_ARRAYS.items():
            container = obj.get(field, {})
            results = (
                container.get("Results", []) if isinstance(container, dict)
                else container if isinstance(container, list)
                else []
            )
            for entry in results:
                eid = entry.get("ObjectIdentifier") if isinstance(entry, dict) else entry
                if eid:
                    rels.append({"StartNode": str(eid), "EndNode": obj_id, "RelationshipType": rel_type})

        # Sessions: computer -[HasSession]→ user
        # (BloodHound CE schema: Source=Computer, Destination=User. The edge
        # represents "an attacker on this computer can steal this user's
        # session" — direction follows the attack.)
        sessions_raw = obj.get("Sessions", {})
        sessions = sessions_raw.get("Results", []) if isinstance(sessions_raw, dict) else []
        for session in sessions:
            uid = session.get("UserSID")
            cid = session.get("ComputerSID") or obj_id
            if uid:
                rels.append({"StartNode": str(cid), "EndNode": str(uid), "RelationshipType": "HasSession"})

        # AllowedToDelegate: obj -[AllowedToDelegate]→ target
        # Some BloodHound exports list raw SPN strings here ("cifs/host.domain")
        # instead of ObjectIdentifiers — those don't resolve to graph nodes.
        for target in obj.get("AllowedToDelegate", []):
            t_id = target if isinstance(target, str) else target.get("ObjectIdentifier", "")
            if t_id and "/" not in t_id:
                rels.append({"StartNode": obj_id, "EndNode": str(t_id), "RelationshipType": "AllowedToDelegate"})

        # AllowedToAct (RBCD): principal -[AllowedToAct]→ obj
        for entry in obj.get("AllowedToAct", []):
            eid = entry.get("ObjectIdentifier") if isinstance(entry, dict) else entry
            if eid:
                rels.append({"StartNode": str(eid), "EndNode": obj_id, "RelationshipType": "AllowedToAct"})

        # Domain trusts
        # TrustDirection is int in legacy v4 (0/1/2/3) but BloodHound CE may
        # emit a string code ("Inbound"/"Outbound"/"Bidirectional"/"Disabled").
        for trust in obj.get("Trusts", []):
            target_sid = trust.get("TargetDomainSid")
            if not target_sid:
                continue
            raw = trust.get("TrustDirection", 0)
            if isinstance(raw, str):
                direction = {"inbound": 1, "outbound": 2, "bidirectional": 3}.get(raw.lower(), 0)
            else:
                direction = raw
            # 1=Inbound (target trusts us), 2=Outbound (we trust target), 3=Bidirectional
            if direction in (1, 3):
                rels.append({"StartNode": obj_id, "EndNode": str(target_sid), "RelationshipType": "TrustedBy"})
            if direction in (2, 3):
                rels.append({"StartNode": str(target_sid), "EndNode": obj_id, "RelationshipType": "TrustedBy"})

        # GPO Links: gpo -[GPLink]→ ou/domain
        for link in obj.get("Links", []):
            gpo_guid = link.get("GUID") or link.get("Guid")
            if gpo_guid:
                rels.append({"StartNode": str(gpo_guid), "EndNode": obj_id, "RelationshipType": "GPLink"})

        # OU/Domain Contains: container -[Contains]→ child
        for child in obj.get("ChildObjects", []):
            cid = child.get("ObjectIdentifier") if isinstance(child, dict) else child
            if cid:
                rels.append({"StartNode": obj_id, "EndNode": str(cid), "RelationshipType": "Contains"})

    return rels


def _node_id(obj: dict) -> str | None:
    """Return the canonical identity string for a node object."""
    for key in ("ObjectIdentifier", "objectidentifier", "SID", "sid"):
        val = obj.get(key)
        if val and isinstance(val, str):
            return val
    props = obj.get("Properties", {})
    for key in ("objectid", "name", "Name"):
        val = props.get(key)
        if val and isinstance(val, str):
            return val
    return None
