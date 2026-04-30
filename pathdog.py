#!/usr/bin/env python3
"""pathdog — BloodHound attack path analyzer CLI."""

import argparse
import os
import sys
from datetime import datetime

from pathdog.loader import load_zip
from pathdog.graph import build_graph, resolve_target, prune_to_target, graph_stats
from pathdog.json_export import build_json_report, write_json_report
from pathdog.pathfinder import (
    find_paths, suggest_similar_nodes, find_intermediate_targets,
    find_pivot_candidates, find_inbound_sources,
    find_outbound_object_control, find_inbound_object_control,
)
from pathdog.quickwins import collect_all as collect_quickwins
from pathdog.triage import collect_findings
from pathdog.report import (
    render_markdown_multi, render_html_multi, print_paths_console,
    print_intermediate_targets, print_quickwins, print_findings_console,
    print_pivot_candidates,
    print_node_visibility_console,
    render_html_node_visibility, render_markdown_node_visibility,
    render_html_combined,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pathdog",
        description="Analyze BloodHound ZIP exports to find attack paths to Domain Admin.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  pathdog -z corp.zip -u john.doe@corp.local
  pathdog -z dump1.zip dump2.zip -u john@corp.local svc_backup@corp.local
  pathdog -z dump1.zip dump2.zip -u owned_users.txt -k 5 -f html -v
  pathdog -z corp.zip --triage -f both --export-json
  pathdog -z corp.zip --list users
  pathdog -z corp.zip --node svc_backup@corp.local
  pathdog -z corp.zip -u john.doe@corp.local --node svc_backup@corp.local -f html --export-json
        """,
    )
    p.add_argument("-z", "--zip", required=True, metavar="FILE", nargs="+",
                   dest="zips", help="BloodHound ZIP export(s), e.g. -z a.zip b.zip")
    p.add_argument("-u", "--user", metavar="USER", nargs="+", default=[],
                   dest="users",
                   help="Owned user(s) or a .txt file with one user per line")
    p.add_argument("-t", "--target", default=None, metavar="TARGET",
                   help="Target node — default: auto-detect DOMAIN ADMINS")
    p.add_argument("-k", "--paths", type=int, default=3, metavar="K",
                   help="Number of paths to find per user (default: 3)")
    p.add_argument("-o", "--output", default="pathdog_report", metavar="BASENAME",
                   help="Output file base name (default: pathdog_report)")
    p.add_argument("-f", "--format", choices=["md", "html", "both"], default="html",
                   dest="fmt", help="Output format (default: html)")
    p.add_argument("-l", "--list", metavar="KIND", nargs="?", const="all",
                   dest="list_kind",
                   help="List nodes and exit. KIND: users, computers, groups, domains, gpos, ous, containers, certtemplates, enterprisecas, rootcas, aiacas, ntauthstores, all")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show graph statistics")
    p.add_argument("--triage", action="store_true",
                   help="Run global prioritized triage without requiring -u")
    p.add_argument("--export-json", nargs="?", const="", metavar="FILE",
                   help="Write a structured JSON report. Optional FILE defaults to <output>.json")
    p.add_argument("--no-fallback", action="store_true",
                   help="Disable intermediate-target suggestions when no DA path is found")
    p.add_argument("--no-quickwins", action="store_true",
                   help="Disable domain-wide quick-wins scan (AS-REP, Kerberoast, etc.)")
    p.add_argument("--no-pivots", action="store_true",
                   help="Disable pivot-candidate scan (principals with a path to DA, attackable out-of-band)")
    p.add_argument("--fallback-top", type=int, default=10, metavar="N",
                   help="Max intermediate targets per user (default: 10)")
    p.add_argument("--pivots-top", type=int, default=15, metavar="N",
                   help="Max pivot candidates to surface (default: 15)")
    p.add_argument("--node", metavar="NODE", default=None,
                   help="Show outbound (what this node can reach) and inbound "
                        "(who can reach this node) path visibility — no -u required")
    return p


def _expand_users(raw: list[str]) -> tuple[list[str], int]:
    """Expand .txt files into user lists. Returns (users, exit_code)."""
    users: list[str] = []
    for entry in raw:
        if entry.lower().endswith(".txt"):
            try:
                with open(entry, encoding="utf-8") as fh:
                    from_file = [
                        line.strip() for line in fh
                        if line.strip() and not line.lstrip().startswith("#")
                    ]
                print(f"[*] Loaded {len(from_file)} user(s) from {entry}")
                users.extend(from_file)
            except OSError as exc:
                print(f"[!] Cannot read user file '{entry}': {exc}", file=sys.stderr)
                return [], 1
        else:
            users.append(entry)
    return users, 0


def _load_graph(zips: list[str]) -> tuple | None:
    """Load and merge all ZIPs. Returns (nodes, edges) or None on error."""
    all_nodes: list[dict] = []
    all_edges: list[dict] = []
    for zip_path in zips:
        print(f"[*] Loading {zip_path} ...")
        try:
            nodes, edges = load_zip(zip_path)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return None
        print(f"    → {len(nodes)} nodes, {len(edges)} edges")
        all_nodes.extend(nodes)
        all_edges.extend(edges)
    if len(zips) > 1:
        print(f"[*] Merged: {len(all_nodes)} nodes, {len(all_edges)} edges (before dedup)")
    return all_nodes, all_edges


def _resolve_source(G, user: str):
    """Find user node; return (node_id, exact_match: bool)."""
    if user in G:
        return user, True
    user_lower = user.lower()
    for nid in G.nodes:
        if user_lower == nid.lower():
            return nid, True
        name = G.nodes[nid].get("name", "")
        if user_lower == name.lower():
            return nid, True
    for nid in G.nodes:
        if user_lower in nid.lower():
            return nid, False
        name = G.nodes[nid].get("name", "")
        if name and user_lower in name.lower():
            return nid, False
    return None, False


def _do_list(G, kind: str) -> None:
    """Print nodes filtered by kind and exit."""
    kinds = {
        "all", "users", "computers", "groups", "domains", "gpos", "ous",
        "containers", "certtemplates", "enterprisecas", "rootcas",
        "aiacas", "ntauthstores",
    }
    if kind not in kinds:
        print(f"[!] Unknown kind '{kind}'. Choose from: {', '.join(sorted(kinds))}",
              file=sys.stderr)
        sys.exit(1)

    print(f"\n{'Node ID':<60} {'Kind':<12} Name")
    print("─" * 100)
    count = 0
    for nid in sorted(G.nodes):
        node_kind = G.nodes[nid].get("kind", "unknown")
        if kind != "all" and node_kind != kind:
            continue
        name = G.nodes[nid].get("name", "")
        display_id = nid if len(nid) <= 58 else nid[:55] + "..."
        print(f"{display_id:<60} {node_kind:<12} {name}")
        count += 1
    print(f"\n{count} node(s) listed.")


def _collect_node_data(G, args) -> dict | None:
    """Collect all node visibility data. Returns a dict or None if node not found."""
    node_id, exact = _resolve_source(G, args.node)
    if not node_id:
        print(f"[!] Node '{args.node}' not found in graph.", file=sys.stderr)
        suggestions = suggest_similar_nodes(G, args.node, top_n=3)
        if suggestions:
            print("    Did you mean one of:", file=sys.stderr)
            for s in suggestions:
                print(f"      - {s}", file=sys.stderr)
        return None
    if not exact:
        print(f"[~] Fuzzy match for '{args.node}' → '{node_id}'")
    print(f"[*] Node visibility for: {node_id}")

    target = resolve_target(G, args.target)
    if args.target and not target:
        print(f"[!] Target '{args.target}' not found — outbound will show intermediate targets.",
              file=sys.stderr)
    elif target:
        print(f"[*] Outbound target: {target}")

    outbound_paths: list = []
    outbound_intermediate: list[dict] = []
    pruned = None

    if target:
        pruned = prune_to_target(G, target)
        if node_id in pruned:
            print("[*] Computing outbound paths ...")
            try:
                outbound_paths = find_paths(pruned, node_id, target, k=args.paths)
            except ValueError:
                pass
        print("[*] Computing reachable high-value targets ...")
        outbound_intermediate = find_intermediate_targets(
            G, node_id, excluded={target}, top_n=args.fallback_top,
        )
    else:
        outbound_intermediate = find_intermediate_targets(
            G, node_id, excluded=set(), top_n=args.fallback_top,
        )

    print("[*] Computing inbound paths ...")
    inbound_sources = find_inbound_sources(G, node_id, top_n=10)
    if inbound_sources:
        print(f"[*] Inbound: {len(inbound_sources)} principal(s) with a path to this node")

    print("[*] Computing object control ...")
    outbound_control = find_outbound_object_control(G, node_id)
    inbound_control = find_inbound_object_control(G, node_id)
    if outbound_control:
        direct = sum(1 for e in outbound_control if e["via_group"] is None)
        print(f"[*] Outbound control: {direct} direct, "
              f"{len(outbound_control) - direct} via group(s)")

    node_stats = None
    if args.verbose and pruned is not None:
        node_stats = graph_stats(G, pruned)

    return {
        "node_id": node_id,
        "target": target,
        "outbound_paths": outbound_paths,
        "outbound_intermediate": outbound_intermediate,
        "inbound_sources": inbound_sources,
        "outbound_control": outbound_control,
        "inbound_control": inbound_control,
        "stats": node_stats,
    }


def _do_node_visibility(G, args) -> int:
    """Handle standalone --node mode: collect data, print console, write report."""
    data = _collect_node_data(G, args)
    if data is None:
        return 1

    print_node_visibility_console(
        G, data["node_id"], data["target"],
        data["outbound_paths"], data["outbound_intermediate"],
        data["inbound_sources"], data["outbound_control"], data["inbound_control"],
    )

    written: list[str] = []
    base = args.output
    extensions = [e for e in (".md", ".html") if args.fmt in (e[1:], "both")]
    if any(os.path.exists(f"{base}{ext}") for ext in extensions):
        base = f"{base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    if args.fmt in ("md", "both"):
        md_path = f"{base}.md"
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown_node_visibility(
                G, data["node_id"], data["target"],
                data["outbound_paths"], data["outbound_intermediate"],
                data["inbound_sources"], data["stats"],
                data["outbound_control"], data["inbound_control"],
            ))
        written.append(md_path)

    if args.fmt in ("html", "both"):
        html_path = f"{base}.html"
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(render_html_node_visibility(
                G, data["node_id"], data["target"],
                data["outbound_paths"], data["outbound_intermediate"],
                data["inbound_sources"], data["stats"],
                data["outbound_control"], data["inbound_control"],
            ))
        written.append(html_path)

    json_path = _json_path(args, base)
    if json_path:
        write_json_report(json_path, build_json_report(
            G=G, target=data["target"], results=[], stats=data["stats"],
            node_data=data,
        ))
        written.append(json_path)

    if written:
        print(f"\n[+] Report(s) written: {', '.join(written)}")

    return 0


def _json_path(args, base: str) -> str | None:
    """Return JSON output path, or None when JSON export is disabled."""
    if args.export_json is None:
        return None
    return args.export_json or f"{base}.json"


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # ── Load & merge all ZIPs ─────────────────────────────────────────────────
    result = _load_graph(args.zips)
    if result is None:
        return 1
    all_nodes, all_edges = result

    print("[*] Building graph ...")
    G = build_graph(all_nodes, all_edges)
    print(f"[*] Graph: {G.number_of_nodes()} unique nodes, {G.number_of_edges()} unique edges")

    # ── --list mode (no -u required) ──────────────────────────────────────────
    if args.list_kind:
        _do_list(G, args.list_kind)
        return 0

    # ── --triage mode (no -u required) ───────────────────────────────────────
    if args.triage:
        target = resolve_target(G, args.target)
        if target:
            print(f"[*] Triage target context: {target}")
            pruned = prune_to_target(G, target)
            stats = graph_stats(G, pruned)
        else:
            target = args.target or ""
            stats = {
                "total_nodes": G.number_of_nodes(),
                "total_edges": G.number_of_edges(),
                "pruned_nodes": G.number_of_nodes(),
                "pruned_edges": G.number_of_edges(),
                "reduction_pct": 0.0,
            }
            if args.target:
                print(f"[!] Target '{args.target}' not found — triage will still run.",
                      file=sys.stderr)

        quickwins = {} if args.no_quickwins else collect_quickwins(G)
        findings = collect_findings(G, quickwins=quickwins)

        if findings:
            print_findings_console(findings)
        if quickwins:
            print_quickwins(G, quickwins)

        written: list[str] = []
        base = args.output
        extensions = [e for e in (".md", ".html") if args.fmt in (e[1:], "both")]
        if any(os.path.exists(f"{base}{ext}") for ext in extensions):
            base = f"{base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        if args.fmt in ("md", "both"):
            md_path = f"{base}.md"
            with open(md_path, "w", encoding="utf-8") as fh:
                fh.write(render_markdown_multi(
                    [], G, target, stats if args.verbose else None,
                    quickwins=quickwins, findings=findings,
                ))
            written.append(md_path)

        if args.fmt in ("html", "both"):
            html_path = f"{base}.html"
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(render_html_multi(
                    [], G, target, stats if args.verbose else None,
                    quickwins=quickwins, findings=findings,
                ))
            written.append(html_path)

        json_path = _json_path(args, base)
        if json_path:
            write_json_report(json_path, build_json_report(
                G=G, target=target, results=[], stats=stats,
                quickwins=quickwins, findings=findings,
            ))
            written.append(json_path)

        if written:
            print(f"\n[+] Report(s) written: {', '.join(written)}")
        return 0 if findings or quickwins else 2

    # ── --node mode: collect data (standalone) or store for combined report ────
    node_data = None
    if args.node:
        if not args.users:
            return _do_node_visibility(G, args)
        node_data = _collect_node_data(G, args)
        if node_data:
            print_node_visibility_console(
                G, node_data["node_id"], node_data["target"],
                node_data["outbound_paths"], node_data["outbound_intermediate"],
                node_data["inbound_sources"], node_data["outbound_control"],
                node_data["inbound_control"],
            )
            print()

    # ── Validate -u is provided for path-finding ──────────────────────────────
    if not args.users:
        parser.error("argument -u/--user is required unless --list or --node is used")

    # ── Expand user list ──────────────────────────────────────────────────────
    users, rc = _expand_users(args.users)
    if rc:
        return rc
    if not users:
        print("[!] No owned users provided.", file=sys.stderr)
        return 1

    # ── Resolve target ────────────────────────────────────────────────────────
    target = resolve_target(G, args.target)
    if not target:
        hint = args.target or "DOMAIN ADMINS"
        print(
            f"[!] Could not locate target node matching '{hint}'.\n"
            "    Try -t with the exact name or SID, or use --list to browse nodes.",
            file=sys.stderr,
        )
        return 1
    print(f"[*] Target node: {target}")

    # ── Prune graph ───────────────────────────────────────────────────────────
    print("[*] Pruning graph to ancestors of target ...")
    pruned = prune_to_target(G, target)
    stats = graph_stats(G, pruned)
    print(f"[*] Pruned: {stats['pruned_nodes']} nodes, {stats['pruned_edges']} edges "
          f"({stats['reduction_pct']}% reduction)")

    if args.verbose:
        print(
            f"[v] Full stats — total: {stats['total_nodes']} nodes / "
            f"{stats['total_edges']} edges | "
            f"pruned: {stats['pruned_nodes']} / {stats['pruned_edges']}"
        )

    # ── Resolve owned users ───────────────────────────────────────────────────
    sources: list[str] = []
    for user in users:
        source, exact = _resolve_source(G, user)
        if not source:
            print(f"[!] User '{user}' not found in graph.", file=sys.stderr)
            suggestions = suggest_similar_nodes(G, user, top_n=3)
            if suggestions:
                print("    Did you mean one of:", file=sys.stderr)
                for s in suggestions:
                    print(f"      - {s}", file=sys.stderr)
            continue
        if not exact:
            print(f"[~] Fuzzy match for '{user}' → '{source}'")
        print(f"[*] Owned user: {source}")
        sources.append(source)

    if not sources:
        print("[!] No valid owned users found. Aborting.", file=sys.stderr)
        return 1

    # ── Find paths ────────────────────────────────────────────────────────────
    all_results: list[tuple[str, list]] = []
    intermediates: dict[str, list[dict]] = {}
    any_path_found = False

    for source in sources:
        if source not in pruned:
            src_display = G.nodes[source].get("name", source)
            print(f"\n[!] No path from '{src_display}' — not connected to DA subgraph.")
            all_results.append((source, []))
            if not args.no_fallback:
                intermediates[source] = find_intermediate_targets(
                    G, source, excluded={target}, top_n=args.fallback_top,
                )
            continue

        print(f"[*] Computing up to {args.paths} path(s) from {source} ...")
        try:
            paths = find_paths(pruned, source, target, k=args.paths)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            all_results.append((source, []))
            continue

        if paths:
            any_path_found = True
        if not args.no_fallback:
            intermediates[source] = find_intermediate_targets(
                G, source, excluded={target}, top_n=args.fallback_top,
            )
        all_results.append((source, paths))

    # ── Quick wins (domain-wide, computed once) ───────────────────────────────
    quickwins = None
    if not args.no_quickwins:
        print("[*] Scanning domain-wide quick wins ...")
        quickwins = collect_quickwins(G)
        if quickwins:
            total = sum(len(v) for v in quickwins.values())
            print(f"[*] Quick wins: {total} finding(s) across {len(quickwins)} categor(ies)")

    print("[*] Building prioritized findings ...")
    findings = collect_findings(G, quickwins=quickwins or {})
    if findings:
        print(f"[*] Findings: {len(findings)} prioritized item(s)")

    # ── Pivot candidates (principals in DA-subgraph attackable out-of-band) ───
    pivots: list[dict] = []
    if not args.no_pivots:
        print("[*] Scanning pivot candidates (path to DA + out-of-band vectors) ...")
        pivots = find_pivot_candidates(
            G, target, pruned,
            top_n=args.pivots_top,
            excluded_sources=set(sources),
        )
        if pivots:
            print(f"[*] Pivot candidates: {len(pivots)} principal(s) with a path to DA + a compromise vector")

    # ── Console output ────────────────────────────────────────────────────────
    for source, paths in all_results:
        if len(sources) > 1:
            src_label = G.nodes[source].get("name", source)
            print(f"\n{'═' * 60}")
            print(f"  Owned user: {src_label}")
            print(f"{'═' * 60}")
        print_paths_console(paths, G, source, target)
        if source in intermediates:
            print_intermediate_targets(G, source, intermediates[source])

    if pivots:
        print_pivot_candidates(G, pivots)

    if findings:
        print_findings_console(findings)

    if quickwins:
        print_quickwins(G, quickwins)

    # ── Write reports ─────────────────────────────────────────────────────────
    written: list[str] = []
    report_stats = stats if args.verbose else None

    base = args.output
    extensions = [e for e in (".md", ".html") if args.fmt in (e[1:], "both")]
    if any(os.path.exists(f"{base}{ext}") for ext in extensions):
        base = f"{base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    if args.fmt in ("md", "both"):
        md_path = f"{base}.md"
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown_multi(
                all_results, G, target, report_stats,
                intermediates=intermediates, quickwins=quickwins, pivots=pivots,
                findings=findings,
            ))
        written.append(md_path)

    if args.fmt in ("html", "both"):
        html_path = f"{base}.html"
        with open(html_path, "w", encoding="utf-8") as fh:
            if node_data:
                fh.write(render_html_combined(
                    all_results, G, target, node_data, report_stats,
                    intermediates=intermediates, quickwins=quickwins, pivots=pivots,
                    findings=findings,
                ))
            else:
                fh.write(render_html_multi(
                    all_results, G, target, report_stats,
                    intermediates=intermediates, quickwins=quickwins, pivots=pivots,
                    findings=findings,
                ))
        written.append(html_path)

    json_path = _json_path(args, base)
    if json_path:
        write_json_report(json_path, build_json_report(
            G=G, target=target, results=all_results, stats=stats,
            intermediates=intermediates, quickwins=quickwins, pivots=pivots,
            findings=findings, node_data=node_data,
        ))
        written.append(json_path)

    if written:
        print(f"\n[+] Report(s) written: {', '.join(written)}")

    # Exit 0 = paths found, 2 = ran OK but no paths
    return 0 if any_path_found else 2


if __name__ == "__main__":
    sys.exit(main())
