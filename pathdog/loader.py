"""ZIP parsing: extracts nodes and edges from a BloodHound export archive."""

import json
import zipfile
from pathlib import Path

EXPECTED_PREFIXES = ("users", "computers", "groups", "domains", "gpos", "ous")


def _json_files(zf: zipfile.ZipFile) -> list[str]:
    return [
        name for name in zf.namelist()
        if name.lower().endswith(".json") and not name.startswith("__MACOSX")
    ]


def _classify(name: str) -> str | None:
    base = Path(name).stem.lower()
    for prefix in EXPECTED_PREFIXES:
        if base.startswith(prefix):
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

        found_kinds = {_classify(f) for f in json_files} - {None}
        missing = [p for p in EXPECTED_PREFIXES if p not in found_kinds]
        if missing:
            import sys
            print(
                f"[warn] ZIP missing expected file types: {', '.join(missing)}. "
                "Some attack paths may be incomplete.",
                file=sys.stderr,
            )

        for fname in json_files:
            kind = _classify(fname) or "unknown"
            try:
                data = json.loads(zf.read(fname))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON in {fname}: {exc}") from exc

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

    return nodes, edges


def _extract_objects(data: dict | list) -> list[dict]:
    """Handle both legacy {data:[...]} and CE {nodes:[...]} layouts."""
    if isinstance(data, list):
        return data
    for key in ("data", "nodes", "Data", "Nodes"):
        if key in data and isinstance(data[key], list):
            return data[key]
    return []


def _extract_relationships(data: dict | list, objects: list[dict]) -> list[dict]:
    if isinstance(data, list):
        return []
    for key in ("rels", "edges", "Rels", "Edges", "relationships", "Relationships"):
        if key in data and isinstance(data[key], list):
            return data[key]

    # Legacy BloodHound: relationships embedded as Aces on each object
    rels: list[dict] = []
    for obj in objects:
        src = _node_id(obj)
        if not src:
            continue
        for ace in obj.get("Aces", []):
            dst = ace.get("PrincipalSID") or ace.get("PrincipalName")
            rtype = ace.get("RightName") or ace.get("Type")
            if dst and rtype:
                # dst principal has rtype right ON the src object
                rels.append({"StartNode": str(dst), "EndNode": str(src), "Type": str(rtype)})
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
