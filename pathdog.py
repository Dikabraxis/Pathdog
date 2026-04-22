#!/usr/bin/env python3
"""pathdog — BloodHound attack path analyzer CLI."""

import argparse
import sys

from pathdog.loader import load_zip
from pathdog.graph import build_graph, resolve_target, prune_to_target, graph_stats
from pathdog.pathfinder import find_paths, suggest_similar_nodes
from pathdog.report import render_markdown, render_html, print_paths_console


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pathdog",
        description="Analyze BloodHound ZIP exports to find attack paths to Domain Admin.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  pathdog -z corp_bloodhound.zip -u john.doe@corp.local
  pathdog -z dump.zip -u svc_backup@evil.corp -k 5 -f html -o report
  pathdog -z ad.zip -u alice@acme.local -t "DOMAIN ADMINS@acme.local" -v
        """,
    )
    p.add_argument("-z", "--zip", required=True, metavar="FILE",
                   help="Path to BloodHound ZIP export")
    p.add_argument("-u", "--user", required=True, metavar="USER",
                   help="Owned user identity (e.g. john.doe@corp.local)")
    p.add_argument("-t", "--target", default=None, metavar="TARGET",
                   help="Target node — default: auto-detect DOMAIN ADMINS")
    p.add_argument("-k", "--paths", type=int, default=3, metavar="K",
                   help="Number of paths to find (default: 3)")
    p.add_argument("-o", "--output", default="pathdog_report", metavar="BASENAME",
                   help="Output file base name (default: pathdog_report)")
    p.add_argument("-f", "--format", choices=["md", "html", "both"], default="both",
                   dest="fmt", help="Output format (default: both)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show graph statistics")
    return p


def resolve_source(G, user: str):
    """Find the user node; return (node_id, exact_match: bool)."""
    if user in G:
        return user, True
    # Case-insensitive substring search
    user_lower = user.lower()
    for nid in G.nodes:
        if user_lower == nid.lower():
            return nid, True
        name = G.nodes[nid].get("name", "")
        if user_lower == name.lower():
            return nid, True
    # Partial match
    for nid in G.nodes:
        if user_lower in nid.lower():
            return nid, False
        name = G.nodes[nid].get("name", "")
        if name and user_lower in name.lower():
            return nid, False
    return None, False


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # ── Load ──────────────────────────────────────────────────────────────────
    print(f"[*] Loading {args.zip} ...")
    try:
        nodes, edges = load_zip(args.zip)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(f"[*] Loaded {len(nodes)} nodes, {len(edges)} edges")

    # ── Build graph ───────────────────────────────────────────────────────────
    G = build_graph(nodes, edges)

    # ── Resolve target ────────────────────────────────────────────────────────
    target = resolve_target(G, args.target)
    if not target:
        hint = args.target or "DOMAIN ADMINS"
        print(
            f"[!] Could not locate target node matching '{hint}'.\n"
            "    Try specifying -t with the exact node name or SID.",
            file=sys.stderr,
        )
        return 1
    print(f"[*] Target node: {target}")

    # ── Resolve source ────────────────────────────────────────────────────────
    source, exact = resolve_source(G, args.user)
    if not source:
        print(f"[!] User '{args.user}' not found in graph.", file=sys.stderr)
        suggestions = suggest_similar_nodes(G, args.user, top_n=3)
        if suggestions:
            print("    Did you mean one of:", file=sys.stderr)
            for s in suggestions:
                print(f"      - {s}", file=sys.stderr)
        return 1
    if not exact:
        print(f"[~] Fuzzy match for '{args.user}' → '{source}'")
    print(f"[*] Source node: {source}")

    # ── Prune graph ───────────────────────────────────────────────────────────
    pruned = prune_to_target(G, target)
    stats = graph_stats(G, pruned)

    if args.verbose:
        print(
            f"[v] Graph stats — total: {stats['total_nodes']} nodes / "
            f"{stats['total_edges']} edges | "
            f"pruned: {stats['pruned_nodes']} nodes / "
            f"{stats['pruned_edges']} edges | "
            f"reduction: {stats['reduction_pct']}%"
        )

    if source not in pruned:
        src_display = G.nodes[source].get("name", source)
        tgt_display = G.nodes[target].get("name", target)
        print(
            f"\n[!] No path found from '{src_display}' to '{tgt_display}'.\n"
            "    The owned user may not have any edges leading to DA in this dump."
        )
        return 0

    # ── Find paths ────────────────────────────────────────────────────────────
    print(f"[*] Computing up to {args.paths} path(s) ...")
    try:
        paths = find_paths(pruned, source, target, k=args.paths)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    # ── Console output ────────────────────────────────────────────────────────
    print_paths_console(paths, G, source, target)

    # ── Write reports ─────────────────────────────────────────────────────────
    written: list[str] = []

    if args.fmt in ("md", "both"):
        md_path = f"{args.output}.md"
        md_content = render_markdown(paths, G, source, target, stats if args.verbose else None)
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(md_content)
        written.append(md_path)

    if args.fmt in ("html", "both"):
        html_path = f"{args.output}.html"
        html_content = render_html(paths, G, source, target, stats if args.verbose else None)
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        written.append(html_path)

    if written:
        print(f"\n[+] Report(s) written: {', '.join(written)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
