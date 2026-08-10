import json
import subprocess
import sys
import unittest
import zipfile
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from pathdog.cli import _resolve_source
from pathdog.commands import get_commands, quote_posix, quote_powershell
from pathdog.compat import analyze_compatibility
from pathdog.explanations import for_quickwin
from pathdog.graph import (
    build_graph,
    build_raw_graph,
    prune_to_target,
    resolve_target,
    target_candidates,
)
from pathdog.loader import ZipSafetyLimits, load_zip, load_zip_detailed
from pathdog.pathfinder import actionable_view, find_paths, find_pivot_candidates
from pathdog.quickwins import collect_all
from pathdog.report._helpers import _edge_commands
from pathdog.schema import TRAVERSABLE_EDGES
from pathdog.triage import collect_findings
from pathdog.weights import EDGE_WEIGHTS


def write_bh_zip(path: Path, files: dict[str, dict]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, json.dumps(data))
    return path


def node(oid: str, name: str, **props):
    return {
        "ObjectIdentifier": oid,
        "Properties": {"name": name, **props},
    }


def base_files(extra_rels=None, extra_files=None):
    rels = extra_rels or []
    files = {
        "users.json": {
            "meta": {"type": "users"},
            "data": [
                node("U1", "alice@corp.local"),
                node("U2", "svc_sql@corp.local", hasspn=True),
            ],
        },
        "groups.json": {
            "meta": {"type": "groups"},
            "data": [node("DA", "DOMAIN ADMINS@corp.local", highvalue=True)],
        },
        "domains.json": {
            "meta": {"type": "domains"},
            "data": [node("D1", "corp.local")],
            "rels": rels,
        },
        "computers.json": {"meta": {"type": "computers"}, "data": []},
        "gpos.json": {"meta": {"type": "gpos"}, "data": []},
        "ous.json": {"meta": {"type": "ous"}, "data": []},
    }
    if extra_files:
        files.update(extra_files)
    return files


class CoreTests(unittest.TestCase):
    def test_adcs_postprocessing_derives_esc1_and_pki_topology(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local", "domainsid": "S-1-5-21-1"}},
            {"id": "C1", "kind": "computers", "props": {"name": "CA01.corp.local", "domainsid": "S-1-5-21-1"}},
            {"id": "CA1", "kind": "enterprisecas", "props": {"name": "CORP-CA@corp.local", "domainsid": "S-1-5-21-1", "certthumbprint": "AABB", "certchain": ["AABB"]}},
            {"id": "ROOT1", "kind": "rootcas", "props": {"name": "CORP-ROOT@corp.local", "domainsid": "S-1-5-21-1", "certthumbprint": "AABB"}},
            {"id": "STORE1", "kind": "ntauthstores", "props": {"name": "NTAUTH@corp.local", "domainsid": "S-1-5-21-1", "certthumbprints": ["AABB"]}},
            {"id": "T1", "kind": "certtemplates", "props": {"name": "ESC1@corp.local", "domainsid": "S-1-5-21-1", "requiresmanagerapproval": False, "authenticationenabled": True, "enrolleesuppliessubject": True, "schemaversion": 2, "authorizedsignatures": 0, "effectiveekus": ["1.3.6.1.5.5.7.3.2"]}},
        ]
        edges = [
            {"src": "ROOT1", "dst": "D1", "type": "RootCAFor"},
            {"src": "STORE1", "dst": "D1", "type": "NTAuthStoreFor"},
            {"src": "T1", "dst": "CA1", "type": "PublishedTo"},
            {"src": "U1", "dst": "T1", "type": "Enroll"},
            {"src": "U1", "dst": "CA1", "type": "Enroll"},
            {"src": "C1", "dst": "CA1", "type": "HostsCAService"},
        ]
        raw = build_raw_graph(nodes, edges)
        self.assertFalse(raw.has_edge("U1", "D1"))
        graph = build_graph(nodes, edges)
        self.assertIn("EnterpriseCAFor", graph["CA1"]["ROOT1"]["relations"])
        self.assertIn("TrustedForNTAuth", graph["CA1"]["STORE1"]["relations"])
        self.assertIn("ADCSESC1", graph["U1"]["D1"]["relations"])
        self.assertIn("GoldenCert", graph["C1"]["D1"]["relations"])
        command_set, _ = _edge_commands(
            graph,
            {"src": "U1", "dst": "D1", "relation": "ADCSESC1"},
            "alice@corp.local",
        )
        command = "\n".join(command_set.commands)
        self.assertIn("-ca 'CORP-CA'", command)
        self.assertIn("-template 'ESC1'", command)
        self.assertNotIn("-template 'corp.local'", command)

    def test_adcs_postprocessing_fails_closed_on_incomplete_template(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local"}},
            {"id": "T1", "kind": "certtemplates", "props": {"name": "unknown@corp.local", "enrolleesuppliessubject": True}},
            {"id": "CA1", "kind": "enterprisecas", "props": {"name": "CA@corp.local"}},
        ]
        graph = build_graph(nodes, [
            {"src": "T1", "dst": "CA1", "type": "PublishedTo"},
            {"src": "U1", "dst": "T1", "type": "Enroll"},
            {"src": "U1", "dst": "CA1", "type": "Enroll"},
        ])
        self.assertFalse(graph.has_edge("U1", "D1"))

    def test_loader_adds_explicit_and_embedded_relationship_sources(self):
        with TemporaryDirectory() as tmp:
            zpath = Path(tmp) / "combined.zip"
            files = base_files()
            files["groups.json"] = {
                "meta": {"type": "groups"},
                "data": [
                    {
                        **node("DA", "DOMAIN ADMINS@corp.local", highvalue=True),
                        "Members": [{"ObjectIdentifier": "U1"}],
                    }
                ],
                "rels": [
                    {
                        "StartNode": "U2",
                        "EndNode": "DA",
                        "RelationshipType": "GenericWrite",
                    }
                ],
            }
            write_bh_zip(zpath, files)
            _, edges = load_zip(str(zpath))
            triples = {(edge["src"], edge["dst"], edge["type"]) for edge in edges}
            self.assertIn(("U1", "DA", "MemberOf"), triples)
            self.assertIn(("U2", "DA", "GenericWrite"), triples)

    def test_loader_rejects_archive_over_configured_size_limit(self):
        with TemporaryDirectory() as tmp:
            zpath = write_bh_zip(Path(tmp) / "large.zip", base_files())
            with self.assertRaisesRegex(ValueError, "per-file safety limit"):
                load_zip_detailed(
                    str(zpath),
                    limits=ZipSafetyLimits(max_file_size=10),
                )

    def test_loader_collects_version_and_timestamp_metadata(self):
        with TemporaryDirectory() as tmp:
            zpath = Path(tmp) / "metadata.zip"
            write_bh_zip(
                zpath,
                {
                    "20260810112233_users.json": {
                        "meta": {"type": "users", "version": "2.14.0"},
                        "data": [node("U1", "alice@corp.local")],
                    }
                },
            )
            with redirect_stderr(StringIO()):
                loaded = load_zip_detailed(str(zpath))
            self.assertEqual(loaded.metadata.collector_versions, {"2.14.0"})
            self.assertEqual(
                loaded.metadata.earliest.isoformat(),
                "2026-08-10T11:22:33+00:00",
            )

    def test_loader_models_current_bloodhound_trust_semantics(self):
        with TemporaryDirectory() as tmp:
            zpath = Path(tmp) / "trusts.zip"
            files = base_files()
            files["domains.json"]["data"] = [
                node("D2", "child.corp.local", functionallevel="2016"),
                {
                    **node("D1", "corp.local"),
                    "Trusts": [
                    {
                        "TargetDomainSid": "D2",
                        "TargetDomainName": "child.corp.local",
                        "TrustDirection": "Bidirectional",
                        "TrustType": "ParentChild",
                        "SidFilteringEnabled": False,
                        "TGTDelegationEnabled": True,
                    },
                    {
                        "TargetDomainSid": "D3",
                        "TargetDomainName": "external.local",
                        "TrustDirection": "Outbound",
                        "TrustType": "Forest",
                        "SidFilteringEnabled": False,
                        "TGTDelegationEnabled": False,
                    },
                    {
                        "TargetDomainSid": "D4",
                        "TargetDomainName": "partner.local",
                        "TrustDirection": "Inbound",
                        "TrustType": "External",
                        "SidFilteringEnabled": True,
                        "TGTDelegationEnabled": True,
                    },
                    ],
                },
            ]
            write_bh_zip(zpath, files)
            loaded = load_zip_detailed(str(zpath))
            graph = build_graph(loaded.nodes, loaded.edges)

            self.assertEqual(graph.nodes["D2"]["kind"], "domains")
            self.assertEqual(graph.nodes["D2"]["name"], "child.corp.local")
            self.assertEqual(graph.nodes["D2"]["props"]["functionallevel"], "2016")
            self.assertIn("SameForestTrust", graph["D1"]["D2"]["relations"])
            self.assertIn("SameForestTrust", graph["D2"]["D1"]["relations"])
            self.assertIn("CrossForestTrust", graph["D1"]["D3"]["relations"])
            self.assertIn("SpoofSIDHistory", graph["D3"]["D1"]["relations"])
            self.assertIn("AbuseTGTDelegation", graph["D4"]["D1"]["relations"])

            attack = actionable_view(graph)
            self.assertFalse(attack.has_edge("D1", "D3"))
            self.assertEqual(
                attack["D3"]["D1"]["relation"], "SpoofSIDHistory"
            )

    def test_has_trust_keys_is_synthesized_only_for_matching_trust_account(self):
        nodes = [
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local", "domainsid": "SID1", "netbios": "CORP"}},
            {"id": "D2", "kind": "domains", "props": {"name": "child.local", "domainsid": "SID2", "netbios": "CHILD"}},
            {"id": "U1", "kind": "users", "props": {"name": "CORP$@child.local", "domainsid": "SID2", "samaccountname": "CORP$"}},
            {"id": "U2", "kind": "users", "props": {"name": "OTHER$@child.local", "domainsid": "SID2", "samaccountname": "OTHER$"}},
        ]
        graph = build_graph(nodes, [{"src": "D1", "dst": "D2", "type": "SameForestTrust"}])
        self.assertIn("HasTrustKeys", graph["D1"]["U1"]["relations"])
        self.assertFalse(graph.has_edge("D1", "U2"))

    def test_compatibility_reports_unknown_edges(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local"}},
        ]
        with redirect_stderr(StringIO()):
            graph = build_graph(
                nodes,
                [{"src": "U1", "dst": "D1", "type": "FutureUnknownEdge"}],
            )
        report = analyze_compatibility(graph)
        self.assertFalse(report.compatible)
        self.assertEqual(report.unknown_edges, ["FutureUnknownEdge"])

    def test_target_resolution_is_safe_in_multiple_domains(self):
        nodes = [
            {
                "id": "U1",
                "kind": "users",
                "props": {"name": "alice@child.corp.local"},
            },
            {
                "id": "DA1",
                "kind": "groups",
                "props": {"name": "DOMAIN ADMINS@corp.local"},
            },
            {
                "id": "DA2",
                "kind": "groups",
                "props": {"name": "DOMAIN ADMINS@child.corp.local"},
            },
        ]
        graph = build_graph(nodes, [])
        self.assertEqual(target_candidates(graph, None), ["DA1", "DA2"])
        self.assertIsNone(resolve_target(graph, None))
        self.assertEqual(resolve_target(graph, None, source="U1"), "DA2")
        self.assertIsNone(resolve_target(graph, "DOMAIN ADMINS"))

    def test_source_resolution_never_chooses_partial_ambiguity(self):
        graph = build_graph(
            [
                {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
                {"id": "U2", "kind": "users", "props": {"name": "alice@dev.local"}},
            ],
            [],
        )
        self.assertEqual(_resolve_source(graph, "alice"), (None, False))
        self.assertEqual(
            _resolve_source(graph, "alice@corp.local"), ("U1", True)
        )

    def test_disabled_accounts_are_excluded_from_roasting(self):
        nodes = [
            {
                "id": "U1",
                "kind": "users",
                "props": {
                    "name": "disabled@corp.local",
                    "enabled": False,
                    "dontreqpreauth": True,
                    "hasspn": True,
                },
            }
        ]
        quickwins = collect_all(build_graph(nodes, []))
        self.assertNotIn("AS-REP roast", quickwins)
        self.assertNotIn("Kerberoast", quickwins)

    def test_protected_users_and_sensitive_flag_are_separate_findings(self):
        nodes = [
            {
                "id": "U1",
                "kind": "users",
                "props": {
                    "name": "admin1@corp.local",
                    "admincount": True,
                    "enabled": True,
                    "sensitive": False,
                },
            },
            {
                "id": "PU",
                "kind": "groups",
                "props": {"name": "PROTECTED USERS@corp.local"},
            },
        ]
        graph = build_graph(
            nodes,
            [{"src": "U1", "dst": "PU", "type": "MemberOf"}],
        )
        quickwins = collect_all(graph)
        self.assertIn("Privileged account allows delegation", quickwins)
        self.assertNotIn("Privileged account not in Protected Users", quickwins)

    def test_laps_deployment_alone_is_not_a_confirmed_pivot(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "owned@corp.local"}},
            {
                "id": "C1",
                "kind": "computers",
                "props": {"name": "ws01.corp.local", "haslaps": True},
            },
            {
                "id": "DA",
                "kind": "groups",
                "props": {"name": "DOMAIN ADMINS@corp.local"},
            },
        ]
        graph = build_graph(
            nodes,
            [{"src": "C1", "dst": "DA", "type": "GenericAll"}],
        )
        pruned = prune_to_target(graph, "DA")
        self.assertEqual(
            find_pivot_candidates(
                graph, "DA", pruned, excluded_sources={"U1"}
            ),
            [],
        )

        graph = build_graph(
            nodes,
            [
                {"src": "U1", "dst": "C1", "type": "ReadLAPSPassword"},
                {"src": "C1", "dst": "DA", "type": "GenericAll"},
            ],
        )
        pruned = prune_to_target(graph, "DA")
        pivots = find_pivot_candidates(
            graph, "DA", pruned, excluded_sources={"U1"}
        )
        self.assertEqual(pivots[0]["node"], "C1")
        self.assertEqual(pivots[0]["confidence"], "high")

    def test_cli_compatibility_mode_exports_json(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(tmp_path / "compat.zip", base_files())
            json_path = tmp_path / "compat.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pathdog.py",
                    "-z",
                    str(zpath),
                    "--compat",
                    "--export-json",
                    str(json_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertIn("BloodHound compatibility", proc.stdout)
            report = json.loads(json_path.read_text())
            self.assertTrue(report["compatible"])

    def test_pathfinding_is_fail_closed_for_context_and_unknown_edges(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local"}},
        ]
        for rel in (
            "Enroll",
            "GetChanges",
            "GetChangesAll",
            "GetChangesInFilteredSet",
            "WritePKINameFlag",
            "WritePKIEnrollmentFlag",
            "TrustedBy",
            "SomethingBloodHoundMayAddLater",
        ):
            with self.subTest(rel=rel), redirect_stderr(StringIO()):
                G = build_graph(nodes, [{"src": "U1", "dst": "D1", "type": rel}])
                self.assertEqual(find_paths(G, "U1", "D1"), [])

    def test_unknown_edge_warns_and_stays_context_only(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local"}},
        ]
        stderr = StringIO()
        with redirect_stderr(stderr):
            G = build_graph(
                nodes,
                [{"src": "U1", "dst": "D1", "type": "FutureUnknownEdge"}],
            )
        self.assertIn("FutureUnknownEdge", stderr.getvalue())
        self.assertEqual(G.graph["unknown_edge_types"], ["FutureUnknownEdge"])
        self.assertFalse(actionable_view(G).has_edge("U1", "D1"))

    def test_best_supported_traversable_relation_is_selected(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "U2", "kind": "users", "props": {"name": "bob@corp.local"}},
        ]
        G = build_graph(nodes, [
            {"src": "U1", "dst": "U2", "type": "Enroll"},
            {"src": "U1", "dst": "U2", "type": "GenericWrite"},
        ])
        attack = actionable_view(G)
        self.assertEqual(attack["U1"]["U2"]["relation"], "GenericWrite")
        self.assertEqual(attack["U1"]["U2"]["relations"], {"GenericWrite": 3})

    def test_pruning_uses_only_the_attack_graph(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local"}},
        ]
        G = build_graph(nodes, [{"src": "U1", "dst": "D1", "type": "Enroll"}])
        pruned = prune_to_target(G, "D1")
        self.assertNotIn("U1", pruned)
        self.assertIn("D1", pruned)

    def test_modern_traversable_edge_is_supported(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "C1", "kind": "users", "props": {"name": "gmsa$@corp.local"}},
        ]
        stderr = StringIO()
        with redirect_stderr(stderr):
            G = build_graph(
                nodes,
                [{"src": "U1", "dst": "C1", "type": "ReadGMSAPassword"}],
            )
        self.assertNotIn("not yet implemented", stderr.getvalue())
        paths = find_paths(G, "U1", "C1")
        self.assertEqual(paths[0].edges[0]["relation"], "ReadGMSAPassword")

    def test_every_current_traversable_edge_has_an_explicit_model(self):
        self.assertEqual(TRAVERSABLE_EDGES - set(EDGE_WEIGHTS), set())

    def test_dcsync_expands_split_group_rights_without_edge_explosion(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "u1@corp.local"}},
            {"id": "U2", "kind": "users", "props": {"name": "u2@corp.local"}},
            {"id": "G1", "kind": "groups", "props": {"name": "g1@corp.local"}},
            {"id": "G2", "kind": "groups", "props": {"name": "g2@corp.local"}},
            {"id": "G3", "kind": "groups", "props": {"name": "g3@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local"}},
        ]
        G = build_graph(nodes, [
            {"src": "U1", "dst": "G1", "type": "MemberOf"},
            {"src": "U1", "dst": "G2", "type": "MemberOf"},
            {"src": "U2", "dst": "G3", "type": "MemberOf"},
            {"src": "G3", "dst": "G2", "type": "MemberOf"},
            {"src": "G1", "dst": "D1", "type": "GetChanges"},
            {"src": "G2", "dst": "D1", "type": "GetChangesAll"},
            {"src": "G3", "dst": "D1", "type": "GetChanges"},
        ])
        self.assertIn("DCSync", G["U1"]["D1"]["relations"])
        self.assertIn("DCSync", G["G3"]["D1"]["relations"])
        self.assertFalse(G.has_edge("U2", "D1"))
        path = find_paths(G, "U2", "D1")[0]
        self.assertEqual([edge["relation"] for edge in path.edges], ["MemberOf", "DCSync"])

    def test_dcsync_group_membership_cycle_keeps_one_representative(self):
        nodes = [
            {"id": "G1", "kind": "groups", "props": {"name": "g1@corp.local"}},
            {"id": "G2", "kind": "groups", "props": {"name": "g2@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local"}},
        ]
        G = build_graph(nodes, [
            {"src": "G1", "dst": "G2", "type": "MemberOf"},
            {"src": "G2", "dst": "G1", "type": "MemberOf"},
            {"src": "G1", "dst": "D1", "type": "GetChanges"},
            {"src": "G2", "dst": "D1", "type": "GetChangesAll"},
        ])
        representatives = [
            principal
            for principal in ("G1", "G2")
            if G.has_edge(principal, "D1")
            and "DCSync" in G[principal]["D1"]["relations"]
        ]
        self.assertEqual(representatives, ["G1"])

    def test_sync_laps_targets_laps_computers_not_the_domain(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local"}},
            {
                "id": "C1",
                "kind": "computers",
                "props": {"name": "ws01.corp.local", "haslaps": True, "domain": "corp.local"},
            },
            {
                "id": "C2",
                "kind": "computers",
                "props": {"name": "ws02.corp.local", "haslaps": False, "domain": "corp.local"},
            },
        ]
        G = build_graph(nodes, [
            {"src": "U1", "dst": "D1", "type": "GetChanges"},
            {"src": "U1", "dst": "D1", "type": "GetChangesInFilteredSet"},
        ])
        self.assertIn("SyncLAPSPassword", G["U1"]["C1"]["relations"])
        self.assertFalse(G.has_edge("U1", "C2"))
        self.assertNotIn("SyncLAPSPassword", G["U1"]["D1"]["relations"])
        path = find_paths(G, "U1", "C1")[0]
        self.assertEqual(path.edges[0]["relation"], "SyncLAPSPassword")

    def test_dcsync_and_sync_laps_can_coexist(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local"}},
            {
                "id": "C1",
                "kind": "computers",
                "props": {"name": "ws01.corp.local", "haslaps": True, "domain": "corp.local"},
            },
        ]
        G = build_graph(nodes, [
            {"src": "U1", "dst": "D1", "type": "GetChanges"},
            {"src": "U1", "dst": "D1", "type": "GetChangesAll"},
            {"src": "U1", "dst": "D1", "type": "GetChangesInFilteredSet"},
        ])
        self.assertIn("DCSync", G["U1"]["D1"]["relations"])
        self.assertIn("SyncLAPSPassword", G["U1"]["C1"]["relations"])

    def test_raw_graph_does_not_contain_synthesized_edges(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local"}},
        ]
        G = build_raw_graph(nodes, [
            {"src": "U1", "dst": "D1", "type": "GetChanges"},
            {"src": "U1", "dst": "D1", "type": "GetChangesAll"},
        ])
        self.assertNotIn("DCSync", G["U1"]["D1"]["relations"])

    def test_sync_laps_guidance_is_distinct_from_direct_laps_read(self):
        direct, _ = get_commands(
            "ReadLAPSPassword", "U1", "C1", "alice@corp.local",
            "ws01.corp.local", "users", "computers", "alice@corp.local",
        )
        sync, _ = get_commands(
            "SyncLAPSPassword", "U1", "C1", "alice@corp.local",
            "ws01.corp.local", "users", "computers", "alice@corp.local",
        )
        self.assertNotEqual(direct.commands, sync.commands)
        self.assertTrue(any("Sync-LAPS" in command for command in sync.commands))

    def test_loader_classifies_adcs_node_types(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "adcs.zip",
                base_files(extra_files={
                    "certtemplates.json": {
                        "meta": {"type": "certtemplates"},
                        "data": [node("T1", "UserTemplate@corp.local")],
                    },
                    "enterprisecas.json": {
                        "meta": {"type": "enterprisecas"},
                        "data": [node("CA1", "CORP-CA@corp.local")],
                    },
                }),
            )
            nodes, _ = load_zip(str(zpath))
            kinds = {item["id"]: item["kind"] for item in nodes}
            self.assertEqual(kinds["T1"], "certtemplates")
            self.assertEqual(kinds["CA1"], "enterprisecas")

    def test_dcsync_requires_both_replication_rights(self):
        nodes = [
            {"id": "U1", "kind": "users", "props": {"name": "alice@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local"}},
        ]
        G = build_graph(nodes, [{"src": "U1", "dst": "D1", "type": "GetChangesAll"}])
        self.assertNotIn("DCSync", G["U1"]["D1"]["relations"])
        self.assertEqual(find_paths(G, "U1", "D1"), [])

        G = build_graph(nodes, [
            {"src": "U1", "dst": "D1", "type": "GetChanges"},
            {"src": "U1", "dst": "D1", "type": "GetChangesAll"},
        ])
        self.assertIn("DCSync", G["U1"]["D1"]["relations"])
        paths = find_paths(G, "U1", "D1")
        self.assertTrue(paths)
        self.assertEqual(paths[0].edges[0]["relation"], "DCSync")

    def test_adcs_edge_becomes_quickwin_and_finding(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "esc.zip",
                base_files(
                    extra_rels=[{"StartNode": "U1", "EndNode": "T1", "RelationshipType": "ADCSESC1"}],
                    extra_files={
                        "certtemplates.json": {
                            "meta": {"type": "certtemplates"},
                            "data": [node("T1", "UserTemplate@corp.local")],
                        },
                    },
                ),
            )
            nodes, edges = load_zip(str(zpath))
            G = build_graph(nodes, edges)
            quickwins = collect_all(G)
            findings = collect_findings(G, quickwins=quickwins)

            self.assertIn("ADCS ADCSESC1", quickwins)
            self.assertTrue(any(f.category == "ADCS ADCSESC1" for f in findings))
            self.assertTrue(any("certipy req" in " ".join(f.commands) for f in findings))
            self.assertEqual(
                sum(1 for f in findings if f.category == "ADCS ADCSESC1"),
                1,
            )

    def test_quickwin_explanations_cover_emitted_adcs_categories(self):
        # Quickwins emit categories like "ADCS ADCSESC1"; the explanation
        # lookup must use the same key so HTML reports never render an empty
        # explanation block.
        for rel in (
            "ADCSESC1", "ADCSESC3", "ADCSESC4",
            "ADCSESC6a", "ADCSESC6b",
            "ADCSESC9a", "ADCSESC9b",
            "ADCSESC10a", "ADCSESC10b",
            "ADCSESC13", "GoldenCert",
        ):
            self.assertTrue(
                for_quickwin(f"ADCS {rel}"),
                msg=f"missing explanation for category 'ADCS {rel}'",
            )

    def test_cli_triage_runs_without_owned_user_and_exports_json(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "triage.zip",
                base_files(extra_rels=[
                    {"StartNode": "U1", "EndNode": "D1", "RelationshipType": "GetChanges"},
                    {"StartNode": "U1", "EndNode": "D1", "RelationshipType": "GetChangesAll"},
                ]),
            )
            out_base = tmp_path / "report"
            json_path = tmp_path / "report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pathdog.py",
                    "-z",
                    str(zpath),
                    "--triage",
                    "-o",
                    str(out_base),
                    "--export-json",
                    str(json_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(json_path.read_text())
            self.assertTrue(data["findings"])
            self.assertTrue(any(f["category"] == "DCSync" for f in data["findings"]))

    def test_cli_node_visibility_exports_json(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "node.zip",
                base_files(extra_rels=[
                    {"StartNode": "U1", "EndNode": "DA", "RelationshipType": "GenericAll"},
                ]),
            )
            out_base = tmp_path / "node_report"
            json_path = tmp_path / "node_report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pathdog.py",
                    "-z",
                    str(zpath),
                    "--node",
                    "U1",
                    "-o",
                    str(out_base),
                    "--export-json",
                    str(json_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(json_path.read_text())
            self.assertEqual(data["node_visibility"]["node"]["id"], "U1")
            self.assertTrue(data["node_visibility"]["outbound_paths"])

    def test_cli_owned_user_does_not_include_triage_by_default(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "owned.zip",
                base_files(extra_rels=[
                    {"StartNode": "U1", "EndNode": "DA", "RelationshipType": "GenericAll"},
                ]),
            )
            json_path = tmp_path / "owned.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pathdog.py",
                    "-z",
                    str(zpath),
                    "-u",
                    "alice@corp.local",
                    "--export-json",
                    str(json_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(json_path.read_text())
            self.assertTrue(data["owned_results"][0]["paths"])
            self.assertEqual(data["findings"], [])
            self.assertEqual(data["quickwins"], {})

    def test_cli_owned_user_reports_outbound_object_control(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "owned_control.zip",
                base_files(extra_rels=[
                    {"StartNode": "U1", "EndNode": "U2", "RelationshipType": "GenericAll"},
                    {"StartNode": "U1", "EndNode": "DA", "RelationshipType": "CanPSRemote"},
                ]),
            )
            json_path = tmp_path / "owned_control.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pathdog.py",
                    "-z",
                    str(zpath),
                    "-u",
                    "alice@corp.local",
                    "--export-json",
                    str(json_path),
                    "-f",
                    "md",
                    "-o",
                    str(tmp_path / "owned_control"),
                ],
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertIn("Object control", proc.stdout)
            self.assertIn("GenericAll on svc_sql@corp.local", proc.stdout)
            data = json.loads(json_path.read_text())
            controls = data["owned_results"][0]["outbound_control"]
            self.assertEqual(controls[0]["relation"], "GenericAll")
            self.assertEqual(controls[0]["dst"]["name"], "svc_sql@corp.local")

    def test_cli_owned_user_with_triage_includes_findings(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = write_bh_zip(
                tmp_path / "owned_triage.zip",
                base_files(extra_rels=[
                    {"StartNode": "U1", "EndNode": "DA", "RelationshipType": "GenericAll"},
                ]),
            )
            json_path = tmp_path / "owned_triage.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pathdog.py",
                    "-z",
                    str(zpath),
                    "-u",
                    "alice@corp.local",
                    "--triage",
                    "--export-json",
                    str(json_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(json_path.read_text())
            self.assertTrue(data["owned_results"][0]["paths"])
            self.assertTrue(data["findings"])
            self.assertTrue(data["quickwins"])

    def test_triage_suppresses_expected_tier0_admin_acl_noise(self):
        nodes = [
            {"id": "ADMINS", "kind": "groups", "props": {"name": "ADMINISTRATORS@corp.local", "highvalue": True}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local", "highvalue": True}},
        ]
        edges = [
            {"src": "ADMINS", "dst": "D1", "type": rel}
            for rel in ("AllExtendedRights", "Owns", "WriteDacl", "WriteOwner")
        ]
        G = build_graph(nodes, edges)
        findings = collect_findings(G, quickwins={})
        self.assertFalse(any(f.category == "Dangerous ACL" for f in findings))

    def test_triage_suppresses_expected_tier0_admin_dcsync_noise(self):
        nodes = [
            {"id": "ADMINS", "kind": "groups", "props": {"name": "ADMINISTRATORS@corp.local", "highvalue": True}},
            {"id": "ETHAN", "kind": "users", "props": {"name": "ethan@corp.local"}},
            {"id": "D1", "kind": "domains", "props": {"name": "corp.local", "highvalue": True}},
        ]
        edges = [
            {"src": "ADMINS", "dst": "D1", "type": "GetChanges"},
            {"src": "ADMINS", "dst": "D1", "type": "GetChangesAll"},
            {"src": "ETHAN", "dst": "D1", "type": "GetChanges"},
            {"src": "ETHAN", "dst": "D1", "type": "GetChangesAll"},
        ]
        G = build_graph(nodes, edges)
        findings = [f for f in collect_findings(G, quickwins={}) if f.category == "DCSync"]
        self.assertEqual(len(findings), 1)
        self.assertIn("ethan@corp.local", findings[0].title)

    def test_triage_aggregates_multiple_dangerous_acls_per_pair(self):
        nodes = [
            {"id": "HELPDESK", "kind": "groups", "props": {"name": "HELPDESK@corp.local"}},
            {"id": "DA", "kind": "groups", "props": {"name": "DOMAIN ADMINS@corp.local", "highvalue": True}},
        ]
        edges = [
            {"src": "HELPDESK", "dst": "DA", "type": rel}
            for rel in ("WriteDacl", "WriteOwner", "AllExtendedRights")
        ]
        G = build_graph(nodes, edges)
        findings = [f for f in collect_findings(G, quickwins={}) if f.category == "Dangerous ACL"]
        self.assertEqual(len(findings), 1)
        self.assertIn("3 control rights", findings[0].title)
        self.assertIn("WriteDacl", findings[0].evidence)
        self.assertIn("WriteOwner", findings[0].evidence)
        self.assertIn("AllExtendedRights", findings[0].evidence)

    def test_every_weighted_relation_has_command_guidance(self):
        structural = {
            "ClaimSpecialIdentity",
            "Contains",
            "ContainsIdentity",
            "GPOAppliesTo",
            "HasSIDHistory",
            "MemberOf",
            "PropagatesACEsTo",
            "SameForestTrust",
            "SyncedToADUser",
            "SyncedToEntraUser",
        }
        for rel in EDGE_WEIGHTS:
            with self.subTest(rel=rel):
                cmd, _ = get_commands(
                    rel,
                    "SRC",
                    "DST",
                    "alice@corp.local",
                    "target.corp.local",
                    "users",
                    "computers",
                    "alice@corp.local",
                )
                self.assertTrue(cmd.description)
                if rel not in structural:
                    self.assertTrue(cmd.commands or cmd.preconditions, rel)

    def test_generic_control_guidance_depends_on_target_kind(self):
        generic_all_gpo, _ = get_commands(
            "GenericAll",
            "U1",
            "GPO1",
            "alice@corp.local",
            "Workstations Policy@corp.local",
            "users",
            "gpos",
            "alice@corp.local",
        )
        generic_all_group, _ = get_commands(
            "GenericAll",
            "U1",
            "G1",
            "alice@corp.local",
            "HELPDESK@corp.local",
            "users",
            "groups",
            "alice@corp.local",
        )
        generic_write_template, _ = get_commands(
            "GenericWrite",
            "U1",
            "T1",
            "alice@corp.local",
            "UserTemplate@corp.local",
            "users",
            "certtemplates",
            "alice@corp.local",
        )
        self.assertIn("pygpoabuse", " ".join(generic_all_gpo.commands))
        self.assertNotIn("groupMember", " ".join(generic_all_gpo.commands))
        self.assertIn("groupMember", " ".join(generic_all_group.commands))
        self.assertIn("certipy template", " ".join(generic_write_template.commands))

    def test_command_values_are_quoted_or_neutralized(self):
        self.assertEqual(quote_posix("Jean O'Brien"), "'Jean O'\"'\"'Brien'")
        self.assertEqual(quote_powershell("Jean O'Brien"), "'Jean O''Brien'")
        command_set, _ = get_commands(
            "WriteSPN",
            "U1",
            "U2",
            "attacker;touch /tmp/pwned@corp.local",
            "Jean O'Brien@corp.local",
            "users",
            "users",
            "attacker;touch /tmp/pwned@corp.local",
        )
        rendered = "\n".join(command_set.commands)
        self.assertNotIn("touch /tmp/pwned", rendered)
        self.assertNotIn("O'Brien", rendered)
        self.assertIn("<SRC_ACCOUNT>", rendered)
        self.assertIn("<TARGET_OBJECT>", rendered)

    def test_templates_do_not_embed_example_passwords(self):
        source = Path("pathdog/commands.py").read_text(encoding="utf-8")
        self.assertNotIn("NewP@ssw0rd", source)
        self.assertNotIn("Pwn3dP@ss", source)
        self.assertNotIn("certipy-ad", source)
        self.assertNotIn("-list-requests", source)

    def test_has_session_commands_target_source_host(self):
        cmd, next_actor = get_commands(
            "HasSession",
            "C1",
            "DAUSER",
            "WS01.corp.local",
            "admin@corp.local",
            "computers",
            "users",
            "alice@corp.local",
        )
        self.assertIn("@WS01.corp.local", cmd.commands[0])
        self.assertNotIn("@admin@corp.local", cmd.commands[0])
        self.assertEqual(next_actor, "admin@corp.local")

    def test_dcfor_commands_target_source_dc(self):
        cmd, _ = get_commands(
            "DCFor",
            "DC1",
            "D1",
            "DC01.corp.local",
            "corp.local",
            "computers",
            "domains",
            "alice@corp.local",
        )
        self.assertIn("@DC01.corp.local", cmd.commands[0])

    def test_computer_takeover_edges_switch_to_machine_identity(self):
        for rel in ("GenericWrite", "GenericAll"):
            with self.subTest(rel=rel):
                _, next_actor = get_commands(
                    rel,
                    "U1",
                    "C1",
                    "alice@corp.local",
                    "WS01.corp.local",
                    "users",
                    "computers",
                    "alice@corp.local",
                )
                self.assertEqual(next_actor, "WS01$@corp.local")

    def test_delegation_edges_use_target_domain_for_administrator(self):
        for rel in ("AllowedToDelegate", "AllowedToAct", "WriteAccountRestrictions"):
            with self.subTest(rel=rel):
                _, next_actor = get_commands(
                    rel,
                    "U1",
                    "C1",
                    "alice@corp.local",
                    "APP01.child.corp.local",
                    "users",
                    "computers",
                    "alice@corp.local",
                )
                self.assertEqual(next_actor, "Administrator@child.corp.local")


if __name__ == "__main__":
    unittest.main()
