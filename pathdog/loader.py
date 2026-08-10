"""ZIP parsing: extracts nodes and edges from a BloodHound export archive.

Supports:
  - BloodHound legacy (v4): {data:[...], rels:[...]} or Aces-embedded
  - BloodHound CE (v5+):    {meta:{type,count,...}, data:[...]} with
    Members/LocalAdmins/Sessions/AllowedToDelegate arrays
"""

import json
import re
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import TextIOWrapper
from pathlib import Path

CORE_EXPECTED_PREFIXES = ("users", "computers", "groups", "domains", "gpos", "ous")

EXPECTED_PREFIXES = (
    "users",
    "computers",
    "groups",
    "domains",
    "gpos",
    "ous",
    "containers",
    "certtemplates",
    "enterprisecas",
    "rootcas",
    "aiacas",
    "ntauthstores",
    "issuancepolicies",
)


@dataclass(frozen=True)
class ZipSafetyLimits:
    """Bounds that reject implausible archives before JSON is allocated."""

    max_files: int = 2_048
    max_file_size: int = 512 * 1024 * 1024
    max_total_size: int = 4 * 1024 * 1024 * 1024
    max_compression_ratio: float = 1_000.0


DEFAULT_ZIP_LIMITS = ZipSafetyLimits()


@dataclass
class CollectionMetadata:
    path: str
    archive_size: int = 0
    uncompressed_size: int = 0
    json_files: int = 0
    file_types: set[str] = field(default_factory=set)
    collector_versions: set[str] = field(default_factory=set)
    collection_times: list[datetime] = field(default_factory=list)

    @property
    def earliest(self) -> datetime | None:
        return min(self.collection_times) if self.collection_times else None

    @property
    def latest(self) -> datetime | None:
        return max(self.collection_times) if self.collection_times else None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "archive_size": self.archive_size,
            "uncompressed_size": self.uncompressed_size,
            "json_files": self.json_files,
            "file_types": sorted(self.file_types),
            "collector_versions": sorted(self.collector_versions),
            "earliest": self.earliest.isoformat() if self.earliest else None,
            "latest": self.latest.isoformat() if self.latest else None,
        }


@dataclass
class LoadResult:
    nodes: list[dict]
    edges: list[dict]
    metadata: CollectionMetadata


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
    result = load_zip_detailed(path)
    return result.nodes, result.edges


def load_zip_detailed(
    path: str,
    *,
    limits: ZipSafetyLimits = DEFAULT_ZIP_LIMITS,
) -> LoadResult:
    """Load a ZIP and return graph data plus collection metadata."""
    if not zipfile.is_zipfile(path):
        raise ValueError(f"Not a valid ZIP file: {path}")

    nodes: list[dict] = []
    edges: list[dict] = []
    metadata = CollectionMetadata(
        path=str(path),
        archive_size=Path(path).stat().st_size,
    )

    with zipfile.ZipFile(path, "r") as zf:
        _validate_archive(zf, path, limits)
        json_files = _json_files(zf)
        if not json_files:
            raise ValueError(
                f"No JSON files found in {path}. "
                "Expected files matching: users*.json, computers*.json, etc."
            )

        metadata.json_files = len(json_files)
        metadata.uncompressed_size = sum(
            zf.getinfo(name).file_size for name in json_files
        )
        found_kinds: set[str] = set()

        for fname in json_files:
            try:
                with zf.open(fname) as raw:
                    data = json.load(TextIOWrapper(raw, encoding="utf-8-sig"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ValueError(f"Malformed JSON in {fname}: {exc}") from exc

            meta_type = ""
            if isinstance(data, dict):
                meta_type = data.get("meta", {}).get("type", "")
                _collect_metadata(metadata, fname, data.get("meta", {}))

            kind = _classify(fname, meta_type) or "unknown"
            if kind != "unknown":
                found_kinds.add(kind)
                metadata.file_types.add(kind)

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
                if kind == "domains":
                    nodes.extend(_trust_target_nodes(obj))

            for rel in rels:
                src = rel.get("StartNode") or rel.get("SourceNode")
                dst = rel.get("EndNode") or rel.get("TargetNode")
                rtype = rel.get("RelationshipType") or rel.get("Type")
                if src and dst and rtype:
                    edges.append({"src": str(src), "dst": str(dst), "type": str(rtype)})

        missing = [p for p in CORE_EXPECTED_PREFIXES if p not in found_kinds]
        if missing:
            print(
                f"[warn] ZIP missing expected file types: {', '.join(missing)}. "
                "Some attack paths may be incomplete.",
                file=sys.stderr,
            )

    return LoadResult(nodes=nodes, edges=edges, metadata=metadata)


def _validate_archive(
    zf: zipfile.ZipFile,
    path: str,
    limits: ZipSafetyLimits,
) -> None:
    infos = [info for info in zf.infolist() if not info.is_dir()]
    if len(infos) > limits.max_files:
        raise ValueError(
            f"ZIP contains {len(infos)} files; safety limit is {limits.max_files}: {path}"
        )

    total = sum(info.file_size for info in infos)
    if total > limits.max_total_size:
        raise ValueError(
            f"ZIP expands to {total} bytes; safety limit is "
            f"{limits.max_total_size}: {path}"
        )

    for info in infos:
        if info.file_size > limits.max_file_size:
            raise ValueError(
                f"ZIP member {info.filename!r} expands to {info.file_size} bytes; "
                f"per-file safety limit is {limits.max_file_size}"
            )
        ratio = info.file_size / max(info.compress_size, 1)
        if ratio > limits.max_compression_ratio:
            raise ValueError(
                f"ZIP member {info.filename!r} has suspicious compression ratio "
                f"{ratio:.0f}:1; safety limit is {limits.max_compression_ratio:.0f}:1"
            )


_FILENAME_TIMESTAMP = re.compile(r"(?:^|_)(\d{14})(?:_|$)")


def _parse_timestamp(value: object) -> datetime | None:
    if isinstance(value, (int, float)):
        try:
            timestamp = value / 1_000 if value > 10_000_000_000 else value
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)
    except ValueError:
        return None


def _collect_metadata(
    metadata: CollectionMetadata,
    filename: str,
    raw_meta: object,
) -> None:
    meta = raw_meta if isinstance(raw_meta, dict) else {}
    lowered = {str(key).lower(): value for key, value in meta.items()}
    for key in (
        "version",
        "collectorversion",
        "sharphoundversion",
        "collectionversion",
    ):
        value = lowered.get(key)
        if value:
            metadata.collector_versions.add(str(value))
    for key in (
        "starttime",
        "endtime",
        "collectiontime",
        "timestamp",
        "collectedat",
    ):
        parsed = _parse_timestamp(lowered.get(key))
        if parsed:
            metadata.collection_times.append(parsed)

    match = _FILENAME_TIMESTAMP.search(Path(filename).stem)
    if match:
        try:
            parsed = datetime.strptime(
                match.group(1), "%Y%m%d%H%M%S"
            ).replace(tzinfo=timezone.utc)
            metadata.collection_times.append(parsed)
        except ValueError:
            pass


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

    Explicit and embedded sources are additive. Duplicate relationships are
    removed after collection so a schema variant cannot hide valid edges.
    """
    if isinstance(data, list):
        # Bare list of objects — only CE embedded extraction possible
        return _deduplicate_relationships(
            _extract_legacy_aces(objects) + _extract_ce_arrays(objects)
        )

    rels: list[dict] = []
    for key in ("rels", "edges", "Rels", "Edges", "relationships", "Relationships"):
        if key in data and isinstance(data[key], list):
            rels.extend(data[key])

    rels.extend(_extract_legacy_aces(objects))
    rels.extend(_extract_ce_arrays(objects))
    return _deduplicate_relationships(rels)


def _deduplicate_relationships(rels: list[dict]) -> list[dict]:
    unique: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for rel in rels:
        if not isinstance(rel, dict):
            continue
        src = rel.get("StartNode") or rel.get("SourceNode")
        dst = rel.get("EndNode") or rel.get("TargetNode")
        rtype = rel.get("RelationshipType") or rel.get("Type")
        if not (src and dst and rtype):
            continue
        key = (str(src), str(dst), str(rtype))
        if key in seen:
            continue
        seen.add(key)
        unique.append(rel)
    return unique


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


def _trust_target_nodes(obj: dict) -> list[dict]:
    """Create the domain stubs BloodHound creates while ingesting trusts."""
    nodes: list[dict] = []
    for trust in obj.get("Trusts", []):
        if not isinstance(trust, dict):
            continue
        target_sid = trust.get("TargetDomainSid")
        if not target_sid:
            continue
        target_name = trust.get("TargetDomainName") or target_sid
        nodes.append({
            "id": str(target_sid),
            "kind": "domains",
            "props": {
                "name": str(target_name),
                "domainsid": str(target_sid),
            },
        })
    return nodes


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
        for array_name, rel_type in _COMPUTER_ARRAYS.items():
            container = obj.get(array_name, {})
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

        # Domain trusts. This mirrors BloodHound's ParseDomainTrusts logic:
        # raw CrossForestTrust is context-only; only SameForestTrust and the
        # derived cross-forest abuse edges can enter the attack graph.
        for trust in obj.get("Trusts", []):
            if not isinstance(trust, dict):
                continue
            target_sid = trust.get("TargetDomainSid")
            if not target_sid:
                continue
            raw = trust.get("TrustDirection", 0)
            if isinstance(raw, str):
                direction = {"inbound": 1, "outbound": 2, "bidirectional": 3}.get(raw.lower(), 0)
            else:
                direction = raw

            trust_type = str(trust.get("TrustType", ""))
            relation = (
                "SameForestTrust"
                if trust_type in {"ParentChild", "TreeRoot", "CrossLink"}
                else "CrossForestTrust"
            )
            tgt_delegation = _boolean(trust.get("TGTDelegationEnabled"))
            sid_filtering = _boolean(trust.get("SidFilteringEnabled"))

            # 1=Inbound: target -> current; 2=Outbound: current -> target.
            if direction in (1, 3):
                rels.append({
                    "StartNode": str(target_sid),
                    "EndNode": obj_id,
                    "RelationshipType": relation,
                })
                if relation == "CrossForestTrust" and tgt_delegation:
                    rels.append({
                        "StartNode": str(target_sid),
                        "EndNode": obj_id,
                        "RelationshipType": "AbuseTGTDelegation",
                    })
            if direction in (2, 3):
                rels.append({
                    "StartNode": obj_id,
                    "EndNode": str(target_sid),
                    "RelationshipType": relation,
                })
                if relation == "CrossForestTrust" and not sid_filtering:
                    rels.append({
                        "StartNode": str(target_sid),
                        "EndNode": obj_id,
                        "RelationshipType": "SpoofSIDHistory",
                    })

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


def _boolean(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)
