"""Generates 5 Jupyter notebooks (one per graph query)."""
import json
import nbformat as nbf
from pathlib import Path

ROOT = Path(__file__).parent.parent
QDIR = ROOT / "graph-queries"
OUT = ROOT / "notebooks"
OUT.mkdir(exist_ok=True)

QUERIES = [
    ("01", "Sensitive Data Blast Radius", "blast-radius",
     "For each identity, count the regulated assets reachable via OWNED_BY / SHARED_WITH / LAST_ACCESSED_BY edges.",
     "identity_id", "sample_assets", "blast_score"),
    ("02", "External Exposure Paths", "external-exposure",
     "Show every path from an ExternalParty to a regulated asset.",
     "external_party", "sample_paths", "assets_count"),
    ("03", "Orphan Cluster Detection", "orphan-clusters",
     "Find clusters of orphaned sensitive assets that share a data source.",
     "data_source", "sample_assets", "orphan_count"),
    ("04", "Threat Lateral Movement", "threat-movement",
     "Trace paths from malicious source IPs through threats onto regulated data.",
     "source_ip", "sample_assets", "hits"),
    ("05", "Cross-Source Leakage", "cross-source-leakage",
     "Owners with the same regulated classification across 3+ data sources.",
     "owner_id", "sources", "distinct_data_sources"),
]

WORKSPACE_ID = "77429a58-865a-4764-8429-aaacdfe3cb73"

SETUP_CODE = '''import subprocess, json, os
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path

WORKSPACE_ID = os.environ.get("BIGID_GRAPH_WORKSPACE_ID", "{ws}")
KQL_FILE = Path("../graph-queries/{kql_file}")
print("Workspace:", WORKSPACE_ID)
print("Query file:", KQL_FILE.name)'''

RUN_CODE = '''kql = KQL_FILE.read_text()
result = subprocess.run(
    ["az", "monitor", "log-analytics", "query",
     "--workspace", WORKSPACE_ID,
     "--analytics-query", kql, "-o", "json"],
    capture_output=True, text=True
)
if result.returncode != 0:
    print("Query failed:")
    print(result.stderr)
    rows = []
else:
    rows = json.loads(result.stdout) if result.stdout.strip() else []
print(f"{{len(rows)}} rows returned")
df = pd.DataFrame(rows)
df.head(10)'''

VIZ_CODE = '''G = nx.DiGraph()
top = rows[:6]
node_colors = {{}}
COLOR_LEFT = "#1f6feb"
COLOR_RIGHT = "#cf222e"

for r in top:
    left = str(r.get("{left}", ""))[:38]
    weight = r.get("{weight}", 0)
    left_label = f"{{left}}\\n({{weight}})"
    G.add_node(left_label)
    node_colors[left_label] = COLOR_LEFT
    rights = r.get("{right}") or []
    if isinstance(rights, str):
        try: rights = json.loads(rights)
        except: rights = [rights]
    for rt in rights[:4]:
        rt_s = str(rt)
        if "-> " in rt_s:
            rt_s = rt_s.split("-> ")[-1]
        rt_label = rt_s[:36]
        G.add_node(rt_label)
        node_colors[rt_label] = COLOR_RIGHT
        G.add_edge(left_label, rt_label)

fig, ax = plt.subplots(figsize=(14, 9))
pos = nx.spring_layout(G, k=1.8, iterations=80, seed=42)
nx.draw_networkx_nodes(G, pos,
    node_color=[node_colors[n] for n in G.nodes()],
    node_size=2400, alpha=0.95, ax=ax)
nx.draw_networkx_edges(G, pos, edge_color="#57606a",
    arrows=True, arrowsize=18, width=1.5, ax=ax)
nx.draw_networkx_labels(G, pos, font_size=8, font_color="white",
    font_weight="bold", ax=ax)
ax.set_title("{title}", fontsize=15, fontweight="bold", pad=18)
ax.axis("off")
plt.tight_layout()
plt.show()'''

for num, title, slug, desc, left, right, weight in QUERIES:
    kql_files = sorted(QDIR.glob(f"{num}-*.kql"))
    kql_file = kql_files[0].name if kql_files else f"{num}-???.kql"

    nb = nbf.v4.new_notebook()
    nb.cells = [
        nbf.v4.new_markdown_cell(
            f"# {num} — {title}\n\n"
            f"> {desc}\n\n"
            f"**KQL source:** [`graph-queries/{kql_file}`](../graph-queries/{kql_file})  \n"
            f"**Run it:** click **Run All** above, or `Shift+Enter` through each cell."
        ),
        nbf.v4.new_markdown_cell("## 1. Setup"),
        nbf.v4.new_code_cell(SETUP_CODE.format(ws=WORKSPACE_ID, kql_file=kql_file)),
        nbf.v4.new_markdown_cell("## 2. Run the KQL graph query"),
        nbf.v4.new_code_cell(RUN_CODE),
        nbf.v4.new_markdown_cell(f"## 3. Render the graph\n\nBlue = `{left}`, red = related assets/sources."),
        nbf.v4.new_code_cell(VIZ_CODE.format(left=left, right=right, weight=weight, title=title)),
    ]
    out = OUT / f"{num}-{slug}.ipynb"
    nbf.write(nb, out)
    print(f"✅ wrote {out.name}")
