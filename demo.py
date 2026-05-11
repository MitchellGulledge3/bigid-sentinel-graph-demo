#!/usr/bin/env python3
"""
VS Code demo runner for the BigID x Sentinel Graph queries.

Usage:
    python3 demo.py            # interactive menu
    python3 demo.py 1          # run query #1
    python3 demo.py all        # run all 5 in sequence

After each run, writes a Mermaid graph to output/<n>-<slug>.md.
Open it in VS Code with Cmd+Shift+V (Markdown preview) to see the
graph rendered. Install "Markdown Preview Mermaid Support"
(bierner.markdown-mermaid) for native rendering.

Requires: Azure CLI (`az`) logged in. Stdlib only.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

WORKSPACE_ID = os.environ.get(
    "BIGID_GRAPH_WORKSPACE_ID", "77429a58-865a-4764-8429-aaacdfe3cb73"
)

QUERIES = [
    ("01", "Sensitive Data Blast Radius",
     "Top identities ranked by reachable regulated assets"),
    ("02", "External Exposure Paths",
     "Shortest paths from external parties to PII/PHI/PCI/Financial"),
    ("03", "Orphan Cluster Detection",
     "Clusters of orphaned sensitive assets sharing data source + last accessor"),
    ("04", "Threat Lateral Movement",
     "Paths from malicious source IPs through threats onto regulated data"),
    ("05", "Cross-Source Leakage",
     "Owners with the same regulated classification across 3+ data sources"),
]

ROOT = Path(__file__).parent
QDIR = ROOT / "graph-queries"
OUTDIR = ROOT / "output"
OUTDIR.mkdir(exist_ok=True)


def find_query(num: str) -> Path:
    matches = sorted(QDIR.glob(f"{num}-*.kql"))
    if not matches:
        sys.exit(f"❌ No query found matching '{num}-*.kql' in {QDIR}")
    return matches[0]


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def mid(s: str) -> str:
    """Mermaid-safe node ID."""
    return "n_" + re.sub(r"[^A-Za-z0-9]", "_", str(s))[:40]


def trunc(s, n=42):
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def viz_blast_radius(rows):
    """Q1: identity -> sample assets (top 6 identities)."""
    top = rows[:6]
    lines = ["flowchart LR"]
    for r in top:
        ident = r.get("identity_id", "?")
        score = r.get("blast_score", 0)
        itype = r.get("identity_type", "User")
        ic = "external" if itype == "ExternalParty" else "user"
        lines.append(f'    {mid(ident)}["👤 {trunc(ident)}<br/>blast {score}"]:::{ic}')
        assets = r.get("sample_assets") or []
        if isinstance(assets, str):
            try:
                assets = json.loads(assets)
            except Exception:
                assets = [assets]
        for a in assets[:4]:
            cls = trunc(", ".join(json.loads(r.get("classifications") or "[]")[:2])
                       if isinstance(r.get("classifications"), str) else "", 30)
            lines.append(f'    {mid(a)}["📦 {trunc(a)}<br/>{cls}"]:::sensitive')
            lines.append(f"    {mid(ident)} -->|reaches| {mid(a)}")
    lines += [
        "    classDef external fill:#0969da,color:#fff,stroke:#0969da;",
        "    classDef user fill:#1f6feb,color:#fff,stroke:#1f6feb;",
        "    classDef sensitive fill:#cf222e,color:#fff,stroke:#cf222e;",
    ]
    return "\n".join(lines)


def viz_exposure_paths(rows):
    """Q2: external -> assets, top 8."""
    top = rows[:10]
    lines = ["flowchart LR"]
    for r in top:
        ext = r.get("external_party", "?")
        cls = r.get("classification", "")
        assets = r.get("sample_paths") or []
        if isinstance(assets, str):
            try:
                assets = json.loads(assets)
            except Exception:
                assets = [assets]
        lines.append(f'    {mid(ext)}["🌐 {trunc(ext)}"]:::external')
        # Each path string: "ext -[edge]-> asset"
        for path in assets[:3]:
            target = path.split("-> ", 1)[-1] if "-> " in path else path
            lines.append(f'    {mid(target+ext)}["📦 {trunc(target)}<br/>{trunc(cls,20)}"]:::sensitive')
            lines.append(f"    {mid(ext)} --> {mid(target+ext)}")
    lines += [
        "    classDef external fill:#0969da,color:#fff,stroke:#0969da;",
        "    classDef sensitive fill:#cf222e,color:#fff,stroke:#cf222e;",
    ]
    return "\n".join(lines)


def viz_orphans(rows):
    """Q3: data_source <- sample orphan assets."""
    top = rows[:6]
    lines = ["flowchart LR"]
    for r in top:
        ds = r.get("data_source", "?")
        n = r.get("orphan_count", 0)
        lines.append(f'    {mid(ds)}["🗄️ {trunc(ds)}<br/>{n} orphans"]:::ds')
        assets = r.get("sample_assets") or []
        if isinstance(assets, str):
            try:
                assets = json.loads(assets)
            except Exception:
                assets = [assets]
        for a in assets[:3]:
            lines.append(f'    {mid(a+ds)}["📦 {trunc(a)}"]:::orphan')
            lines.append(f"    {mid(a+ds)} -->|stored in| {mid(ds)}")
    lines += [
        "    classDef ds fill:#bf8700,color:#fff,stroke:#bf8700;",
        "    classDef orphan fill:#6e7781,color:#fff,stroke:#6e7781;",
    ]
    return "\n".join(lines)


def viz_threats(rows):
    """Q4: source_ip -> threat -> sample assets."""
    top = rows[:6]
    lines = ["flowchart LR"]
    for r in top:
        ip = r.get("source_ip", "?")
        thr = r.get("threat_category", "?")
        hits = r.get("hits", 0)
        thrnode = f"{ip}::{thr}"
        lines.append(f'    {mid(ip)}["📡 {trunc(ip)}"]:::ip')
        lines.append(f'    {mid(thrnode)}["⚠️ {trunc(thr)}<br/>{hits} hits"]:::threat')
        lines.append(f"    {mid(ip)} -->|attacked| {mid(thrnode)}")
        assets = r.get("sample_assets") or []
        if isinstance(assets, str):
            try:
                assets = json.loads(assets)
            except Exception:
                assets = [assets]
        for a in assets[:3]:
            lines.append(f'    {mid(a+thrnode)}["📦 {trunc(a)}"]:::regulated')
            lines.append(f"    {mid(thrnode)} -->|targeted| {mid(a+thrnode)}")
    lines += [
        "    classDef ip fill:#cf222e,color:#fff,stroke:#cf222e;",
        "    classDef threat fill:#8250df,color:#fff,stroke:#8250df;",
        "    classDef regulated fill:#bf8700,color:#fff,stroke:#bf8700;",
    ]
    return "\n".join(lines)


def viz_leakage(rows):
    """Q5: owner -> classification -> data sources."""
    top = rows[:6]
    lines = ["flowchart LR"]
    for r in top:
        owner = r.get("owner_id", "?")
        cls = r.get("classification", "?")
        sources = r.get("sources") or []
        if isinstance(sources, str):
            try:
                sources = json.loads(sources)
            except Exception:
                sources = [sources]
        cls_node = f"{owner}::{cls}"
        lines.append(f'    {mid(owner)}["👤 {trunc(owner)}"]:::user')
        lines.append(f'    {mid(cls_node)}["🏷️ {trunc(cls)}"]:::cls')
        lines.append(f"    {mid(owner)} -->|owns| {mid(cls_node)}")
        for s in sources[:5]:
            lines.append(f'    {mid(s+cls_node)}["🗄️ {trunc(s)}"]:::ds')
            lines.append(f"    {mid(cls_node)} -->|in| {mid(s+cls_node)}")
    lines += [
        "    classDef user fill:#1f6feb,color:#fff,stroke:#1f6feb;",
        "    classDef cls fill:#cf222e,color:#fff,stroke:#cf222e;",
        "    classDef ds fill:#bf8700,color:#fff,stroke:#bf8700;",
    ]
    return "\n".join(lines)


VIZZERS = {
    "01": viz_blast_radius,
    "02": viz_exposure_paths,
    "03": viz_orphans,
    "04": viz_threats,
    "05": viz_leakage,
}


def write_viz(num: str, title: str, rows: list[dict]) -> Path:
    viz = VIZZERS[num](rows) if rows else "%% no rows"
    out = OUTDIR / f"{num}-{slug(title)}.md"
    body = [
        f"# {num} — {title}",
        "",
        f"> Auto-generated from `demo.py {int(num)}` against the live workspace.",
        f"> Open this file in VS Code and press `⇧⌘V` (Mac) / `Ctrl+Shift+V` to view rendered.",
        "",
        "## Graph",
        "",
        "```mermaid",
        viz,
        "```",
        "",
        f"## Top {min(len(rows), 10)} rows",
        "",
    ]
    if rows:
        cols = list(rows[0].keys())
        body.append("| " + " | ".join(cols) + " |")
        body.append("| " + " | ".join("---" for _ in cols) + " |")
        for r in rows[:10]:
            body.append("| " + " | ".join(trunc(r.get(c), 60).replace("|", "\\|") for c in cols) + " |")
    else:
        body.append("_No rows returned._")
    out.write_text("\n".join(body))
    return out


def run(num: str) -> None:
    qpath = find_query(num)
    title = next((t for n, t, _ in QUERIES if n == num), qpath.stem)

    print()
    print("=" * 78)
    print(f"▶ Query {num}: {title}")
    print(f"  File: {qpath.relative_to(ROOT)}")
    print("=" * 78)

    kql = qpath.read_text()
    cmd = [
        "az", "monitor", "log-analytics", "query",
        "--workspace", WORKSPACE_ID,
        "--analytics-query", kql,
        "-o", "json",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("❌ Query failed:")
        print(result.stderr)
        return

    try:
        rows = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        print(result.stdout)
        return

    out = write_viz(num, title, rows)
    print(f"✅ {len(rows)} row(s)")
    print(f"📈 Visualization → {out.relative_to(ROOT)}")
    print(f"   In VS Code: open the file and press ⇧⌘V (Mac) / Ctrl+Shift+V to render.")

    if rows:
        cols = list(rows[0].keys())[:5]  # first 5 cols only in terminal

        def cell(v):
            if isinstance(v, (list, dict)):
                s = json.dumps(v, ensure_ascii=False)
            else:
                s = "" if v is None else str(v)
            return s if len(s) <= 50 else s[:47] + "…"

        widths = {c: min(60, max(len(c), max(len(cell(r.get(c))) for r in rows[:10]))) for c in cols}
        print()
        print(" | ".join(c.ljust(widths[c]) for c in cols))
        print("-+-".join("-" * widths[c] for c in cols))
        for r in rows[:10]:
            print(" | ".join(cell(r.get(c)).ljust(widths[c]) for c in cols))
        if len(rows) > 10:
            print(f"... ({len(rows) - 10} more rows — see {out.name})")


def menu() -> None:
    print("\nBigID x Sentinel Graph — VS Code Demo")
    print("Workspace:", WORKSPACE_ID)
    print()
    for n, t, d in QUERIES:
        print(f"  {n}. {t}")
        print(f"      {d}")
    print("  all. Run all five in sequence")
    print("    q. Quit")
    while True:
        choice = input("\ngraph-demo> ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            return
        if choice == "all":
            for n, _, _ in QUERIES:
                run(n)
            continue
        if choice.isdigit():
            choice = choice.zfill(2)
        if any(choice == n for n, _, _ in QUERIES):
            run(choice)
        else:
            print("Pick 1-5, 'all', or 'q'.")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        menu()
    elif sys.argv[1] == "all":
        for n, _, _ in QUERIES:
            run(n)
    else:
        arg = sys.argv[1]
        if arg.isdigit():
            arg = arg.zfill(2)
        run(arg)
