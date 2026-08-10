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
    "sessions",
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
                    props = _object_properties(obj, kind)
                    nodes.append({
                        "id": node_id,
                        "kind": kind,
                        "props": props,
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
            if dst and rtype and str(dst) != str(src):
                # dst principal has rtype right ON src object
                normalized = {
                    "Owns": "OwnsRaw",
                    "WriteOwner": "WriteOwnerRaw",
                }.get(str(rtype), str(rtype))
                rels.append({
                    "StartNode": str(dst),
                    "EndNode": str(src),
                    "RelationshipType": normalized,
                })

        # Enterprise CA security is collected from the CA registry and is the
        # authoritative source for ManageCA/ManageCertificates/Enroll rights.
        ca_security = obj.get("CARegistryData", {}).get("CASecurity", {})
        if isinstance(ca_security, dict) and ca_security.get("Collected"):
            for ace in ca_security.get("Data", []):
                if not isinstance(ace, dict):
                    continue
                dst = ace.get("PrincipalSID") or ace.get("PrincipalName")
                rtype = ace.get("RightName") or ace.get("Type")
                if dst and rtype and str(rtype) != "Owns":
                    rels.append({
                        "StartNode": str(dst),
                        "EndNode": str(src),
                        "RelationshipType": str(rtype),
                    })
    return rels


def _object_properties(obj: dict, kind: str) -> dict:
    """Merge SharpHound top-level/nested collection fields into node props."""
    props = dict(obj.get("Properties", {}))
    aliases = {
        "DomainSID": "domainsid",
        "IsDC": "isdc",
        "DoesAnyAceGrantOwnerRights": "doesanyacegrantownerrights",
        "DoesAnyInheritedAceGrantOwnerRights": "doesanyinheritedacegrantownerrights",
    }
    for source, target in aliases.items():
        if source in obj and obj[source] is not None:
            props[target] = obj[source]

    if kind == "enterprisecas":
        registry = obj.get("CARegistryData", {})
        restrictions = registry.get("EnrollmentAgentRestrictions") or {}
        san = registry.get("IsUserSpecifiesSanEnabled") or {}
        role_separation = registry.get("RoleSeparationEnabled") or {}
        if isinstance(restrictions, dict):
            props["enrollmentagentrestrictionscollected"] = _boolean(
                restrictions.get("Collected")
            )
            if restrictions.get("Collected"):
                props["hasenrollmentagentrestrictions"] = bool(
                    restrictions.get("Restrictions")
                )
        if isinstance(san, dict):
            props["isuserspecifiessanenabledcollected"] = _boolean(
                san.get("Collected")
            )
            if san.get("Collected"):
                props["isuserspecifiessanenabled"] = _boolean(san.get("Value"))
        if isinstance(role_separation, dict):
            props["roleseparationenabledcollected"] = _boolean(
                role_separation.get("Collected")
            )
            if role_separation.get("Collected"):
                props["roleseparationenabled"] = _boolean(
                    role_separation.get("Value")
                )

    if kind == "computers":
        registry = obj.get("DCRegistryData", {})
        mapping = registry.get("CertificateMappingMethods") or {}
        binding = registry.get("StrongCertificateBindingEnforcement") or {}
        if isinstance(mapping, dict) and mapping.get("Collected"):
            props["certificatemappingmethodsraw"] = mapping.get("Value")
        if isinstance(binding, dict) and binding.get("Collected"):
            props["strongcertificatebindingenforcementraw"] = binding.get("Value")
    return props


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
        # Dedicated sessions files contain bare session records without an
        # object identifier.
        if obj.get("ComputerSID") and obj.get("UserSID"):
            rels.append({
                "StartNode": str(obj["ComputerSID"]),
                "EndNode": str(obj["UserSID"]),
                "RelationshipType": "HasSession",
            })
            continue

        obj_id = _node_id(obj)
        if not obj_id:
            continue

        # Groups — Members: member -[MemberOf]→ group
        for member in obj.get("Members", []):
            mid = member.get("ObjectIdentifier") if isinstance(member, dict) else member
            if mid:
                rels.append({"StartNode": str(mid), "EndNode": obj_id, "RelationshipType": "MemberOf"})

        primary_group = obj.get("PrimaryGroupSID")
        if primary_group:
            rels.append({
                "StartNode": obj_id,
                "EndNode": str(primary_group),
                "RelationshipType": "MemberOf",
            })

        contained_by = obj.get("ContainedBy")
        if isinstance(contained_by, dict) and contained_by.get("ObjectIdentifier"):
            rels.append({
                "StartNode": str(contained_by["ObjectIdentifier"]),
                "EndNode": obj_id,
                "RelationshipType": "Contains",
            })

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
        for session_key in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
            sessions_raw = obj.get(session_key, {})
            sessions = (
                sessions_raw.get("Results", [])
                if isinstance(sessions_raw, dict) and sessions_raw.get("Collected", True)
                else []
            )
            for session in sessions:
                uid = session.get("UserSID")
                cid = session.get("ComputerSID") or obj_id
                if uid:
                    rels.append({
                        "StartNode": str(cid),
                        "EndNode": str(uid),
                        "RelationshipType": "HasSession",
                    })

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

        for array_name, relation in (
            ("HasSIDHistory", "HasSIDHistory"),
            ("DumpSMSAPassword", "DumpSMSAPassword"),
        ):
            for entry in obj.get(array_name, []):
                eid = entry.get("ObjectIdentifier") if isinstance(entry, dict) else entry
                if eid:
                    rels.append({
                        "StartNode": obj_id,
                        "EndNode": str(eid),
                        "RelationshipType": relation,
                    })

        props = _object_properties(obj, "")
        domain_sid = props.get("domainsid")
        unconstrained = _boolean(props.get("unconstraineddelegation"))
        if _boolean(obj.get("IsDC")) and domain_sid:
            rels.append({
                "StartNode": obj_id,
                "EndNode": str(domain_sid),
                "RelationshipType": "DCFor",
            })
        elif unconstrained and domain_sid:
            rels.append({
                "StartNode": obj_id,
                "EndNode": str(domain_sid),
                "RelationshipType": "CoerceToTGT",
            })

        for spn_target in obj.get("SPNTargets", []):
            if not isinstance(spn_target, dict):
                continue
            computer_sid = spn_target.get("ComputerSID")
            service = spn_target.get("Service")
            if computer_sid and service:
                rels.append({
                    "StartNode": obj_id,
                    "EndNode": str(computer_sid),
                    "RelationshipType": str(service),
                })

        # Local groups and user-right assignments collected on computers.
        for local_group in obj.get("LocalGroups", []):
            if not isinstance(local_group, dict):
                continue
            group_id = local_group.get("ObjectIdentifier")
            if not group_id or not (
                local_group.get("Results")
                or local_group.get("LocalNames")
                or local_group.get("Name") != "IGNOREME"
            ):
                continue
            rels.append({
                "StartNode": str(group_id),
                "EndNode": obj_id,
                "RelationshipType": "LocalToComputer",
            })
            for member in local_group.get("Results", []):
                member_id = (
                    member.get("ObjectIdentifier")
                    if isinstance(member, dict)
                    else member
                )
                if member_id:
                    rels.append({
                        "StartNode": str(member_id),
                        "EndNode": str(group_id),
                        "RelationshipType": "MemberOfLocalGroup",
                    })
        for assignment, relation in (
            ("RemoteDesktopUsers", "RemoteInteractiveLogonRight"),
            ("DcomUsers", "ExecuteDCOM"),
            ("PSRemoteUsers", "CanPSRemote"),
        ):
            value = obj.get(assignment, {})
            results = value.get("Results", []) if isinstance(value, dict) else []
            for principal in results:
                principal_id = principal.get("ObjectIdentifier")
                if principal_id:
                    rels.append({
                        "StartNode": str(principal_id),
                        "EndNode": obj_id,
                        "RelationshipType": relation,
                    })

        for user_right in obj.get("UserRights", []):
            if not isinstance(user_right, dict) or not user_right.get("Collected"):
                continue
            if user_right.get("Privilege") != "SeRemoteInteractiveLogonRight":
                continue
            for principal in user_right.get("Results", []):
                principal_id = (
                    principal.get("ObjectIdentifier")
                    if isinstance(principal, dict)
                    else principal
                )
                if principal_id:
                    rels.append({
                        "StartNode": str(principal_id),
                        "EndNode": obj_id,
                        "RelationshipType": "RemoteInteractiveLogonRight",
                    })

        # AD CS topology and enrollment restrictions.
        for template in obj.get("EnabledCertTemplates", []):
            template_id = (
                template.get("ObjectIdentifier")
                if isinstance(template, dict)
                else template
            )
            if template_id:
                rels.append({
                    "StartNode": str(template_id),
                    "EndNode": obj_id,
                    "RelationshipType": "PublishedTo",
                })
        hosting_computer = obj.get("HostingComputer")
        if hosting_computer:
            rels.append({
                "StartNode": str(hosting_computer),
                "EndNode": obj_id,
                "RelationshipType": "HostsCAService",
            })
        registry = obj.get("CARegistryData", {})
        restrictions = registry.get("EnrollmentAgentRestrictions") or {}
        if isinstance(restrictions, dict) and restrictions.get("Collected"):
            enabled = [
                item.get("ObjectIdentifier") if isinstance(item, dict) else item
                for item in obj.get("EnabledCertTemplates", [])
            ]
            for restriction in restrictions.get("Restrictions", []):
                if restriction.get("AccessType") != "AccessAllowedCallback":
                    continue
                agent = restriction.get("Agent") or {}
                agent_id = agent.get("ObjectIdentifier")
                template = restriction.get("Template") or {}
                templates = enabled if restriction.get("AllTemplates") else [
                    template.get("ObjectIdentifier")
                ]
                for template_id in templates:
                    if agent_id and template_id:
                        rels.append({
                            "StartNode": str(agent_id),
                            "EndNode": str(template_id),
                            "RelationshipType": "DelegatedEnrollmentAgent",
                        })

        domain_sid_top = obj.get("DomainSID")
        if domain_sid_top:
            relation = None
            properties = obj.get("Properties", {})
            if "certthumbprints" in {str(k).lower() for k in properties}:
                relation = "NTAuthStoreFor"
            elif "certthumbprint" in {str(k).lower() for k in properties} and not obj.get("HostingComputer"):
                relation = "RootCAFor"
            if relation:
                rels.append({
                    "StartNode": obj_id,
                    "EndNode": str(domain_sid_top),
                    "RelationshipType": relation,
                })

        group_link = obj.get("GroupLink")
        if isinstance(group_link, dict) and group_link.get("ObjectIdentifier"):
            rels.append({
                "StartNode": obj_id,
                "EndNode": str(group_link["ObjectIdentifier"]),
                "RelationshipType": "OIDGroupLink",
            })

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
