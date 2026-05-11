"""Generate PySpark notebooks for the Microsoft Sentinel data lake VS Code extension.

These notebooks use MicrosoftSentinelProvider to read BigID DSPM data from the lake,
build NetworkX graphs, and render visualizations with matplotlib.

Run: python3 _generate.py
"""
from __future__ import annotations
import json
from pathlib import Path

HERE = Path(__file__).parent

# Update this to match your Sentinel workspace name in the data lake
WORKSPACE = "<YOUR_SENTINEL_WORKSPACE_NAME>"
TABLE = "BigIDDSPMCatalog_CL"


def md(source: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": source.splitlines(keepends=True)}


def code(source: str) -> dict:
    return {
        "cell_type": "code",
        "metadata": {},
        "execution_count": None,
        "outputs": [],
        "source": source.splitlines(keepends=True),
    }


def setup_cell() -> dict:
    return code(f"""# === Setup: connect to the Microsoft Sentinel data lake ===
from sentinel_lake.providers import MicrosoftSentinelProvider
from pyspark.sql import functions as F
from pyspark.sql.types import StringType

data_provider = MicrosoftSentinelProvider(spark)

WORKSPACE = "{WORKSPACE}"
TABLE = "{TABLE}"

# Pull last 30 days of BigID catalog rows
df = data_provider.read_table(TABLE, WORKSPACE)
df = df.filter(F.col("TimeGenerated") > F.expr("current_timestamp() - INTERVAL 30 DAYS"))
df.printSchema()
print("Row count:", df.count())
""")


def viz_cell(title: str) -> dict:
    return code(f"""# === Visualize as a graph ===
import matplotlib.pyplot as plt
import networkx as nx

pdf = result.toPandas()
print(f"Edges to draw: {{len(pdf)}}")
display(pdf.head(50))

G = nx.DiGraph()
for _, row in pdf.iterrows():
    src = str(row.iloc[0])
    dst = str(row.iloc[1])
    G.add_edge(src, dst)

plt.figure(figsize=(14, 9))
pos = nx.spring_layout(G, seed=42, k=0.6)
nx.draw_networkx_nodes(
    G, pos,
    nodelist=[n for n in G.nodes if n in pdf.iloc[:, 0].values],
    node_color="#1f77b4", node_size=900, alpha=0.85,
)
nx.draw_networkx_nodes(
    G, pos,
    nodelist=[n for n in G.nodes if n in pdf.iloc[:, 1].values and n not in pdf.iloc[:, 0].values],
    node_color="#d62728", node_size=900, alpha=0.85,
)
nx.draw_networkx_edges(G, pos, arrows=True, edge_color="#888", alpha=0.6, width=1.2)
nx.draw_networkx_labels(G, pos, font_size=8)
plt.title("{title}", fontsize=14, fontweight="bold")
plt.axis("off")
plt.tight_layout()
plt.show()
""")


# ---------- Notebook 1: Blast Radius ----------
nb1 = {
    "cells": [
        md("# Sensitive Data Blast Radius (BigID × Sentinel Data Lake)\n\n"
           "**Question:** If a single identity is compromised, how many sensitive BigID assets are at risk?\n\n"
           "Builds a graph of `User → Asset` edges where the user has Read/Write/FullControl over "
           "PHI / GDPR / Confidential / Restricted classified data, then computes per-user blast radius.\n"),
        setup_cell(),
        md("## Build the User → Asset edges"),
        code("""# Explode AssetPermissions (JSON) into flat (User, Asset, Classification) rows.
from pyspark.sql.functions import from_json, expr, col, explode, lit
from pyspark.sql.types import MapType, ArrayType

perm_schema = "Read array<string>, Write array<string>, FullControl array<string>"

sens = (
    df
    .withColumn("perms", from_json(col("AssetPermissions"), perm_schema))
    .filter(
        (col("Classification").contains("PHI")) |
        (col("Classification").contains("GDPR")) |
        (col("Classification").contains("Restricted")) |
        (col("Classification").contains("Confidential"))
    )
    .select(
        "AssetID", "AssetSource", "Classification",
        F.array_union(
            F.coalesce(col("perms.Read"), F.array()),
            F.array_union(
                F.coalesce(col("perms.Write"), F.array()),
                F.coalesce(col("perms.FullControl"), F.array()),
            ),
        ).alias("Users"),
    )
)

edges = sens.withColumn("User", explode(col("Users"))).select("User", "AssetID", "Classification", "AssetSource")
edges.show(20, truncate=False)
"""),
        md("## Compute blast radius (top 25 users by sensitive assets reachable)"),
        code("""result = (
    edges.groupBy("User")
    .agg(
        F.countDistinct("AssetID").alias("SensitiveAssetsReachable"),
        F.collect_set("Classification").alias("Classifications"),
        F.collect_set("AssetSource").alias("Sources"),
    )
    .orderBy(F.desc("SensitiveAssetsReachable"))
    .limit(25)
)
result.show(truncate=False)

# For graph viz: flatten back to User → AssetID edges, limited
result = (
    edges.join(result.select("User"), "User", "inner")
    .select("User", "AssetID")
    .limit(150)
)
"""),
        md("## Visualize"),
        viz_cell("Sensitive Data Blast Radius — Top Users → BigID Assets"),
    ],
    "metadata": {
        "kernelspec": {"display_name": "Microsoft Sentinel", "language": "python", "name": "sentinel-lake-pyspark"},
        "language_info": {"name": "python"},
    },
    "nbformat": 4,
    "nbformat_minor": 5,
}

# ---------- Notebook 2: External Exposure ----------
nb2 = {
    "cells": [
        md("# External Exposure Paths (BigID × Sentinel Data Lake)\n\n"
           "**Question:** Which sensitive assets are accessible to identities outside the corporate domain?\n"
           "Looks for non-`@contoso.com` UPNs holding any permission on classified assets."),
        setup_cell(),
        md("## Find external-party edges"),
        code("""from pyspark.sql.functions import from_json, col, explode, array_union, coalesce, array, lower

perm_schema = "Read array<string>, Write array<string>, FullControl array<string>"

sens = (
    df.withColumn("perms", from_json(col("AssetPermissions"), perm_schema))
      .filter(
          (col("Classification").contains("PHI")) |
          (col("Classification").contains("GDPR")) |
          (col("Classification").contains("Restricted")) |
          (col("Classification").contains("Confidential"))
      )
      .select(
          "AssetID", "AssetSource", "Classification",
          array_union(
              coalesce(col("perms.Read"), array()),
              array_union(
                  coalesce(col("perms.Write"), array()),
                  coalesce(col("perms.FullControl"), array()),
              ),
          ).alias("Users"),
      )
)

edges = (
    sens.withColumn("User", explode(col("Users")))
        .filter(lower(col("User")).contains("@"))
        .filter(~lower(col("User")).contains("@contoso.com"))
        .select("User", "AssetID", "Classification", "AssetSource")
)
edges.show(50, truncate=False)
"""),
        md("## Roll up — top external parties by exposure"),
        code("""result = (
    edges.groupBy("User")
    .agg(
        F.countDistinct("AssetID").alias("ExposedAssets"),
        F.collect_set("Classification").alias("Classifications"),
        F.collect_set("AssetSource").alias("Sources"),
    )
    .orderBy(F.desc("ExposedAssets"))
    .limit(20)
)
result.show(truncate=False)
result = edges.join(result.select("User"), "User", "inner").select("User", "AssetID").limit(120)
"""),
        md("## Visualize"),
        viz_cell("External Exposure — Third Parties → BigID Sensitive Assets"),
    ],
    "metadata": {
        "kernelspec": {"display_name": "Microsoft Sentinel", "language": "python", "name": "sentinel-lake-pyspark"},
        "language_info": {"name": "python"},
    },
    "nbformat": 4, "nbformat_minor": 5,
}

# ---------- Notebook 3: Orphan Clusters ----------
nb3 = {
    "cells": [
        md("# Orphan Sensitive Data Clusters (BigID × Sentinel Data Lake)\n\n"
           "**Question:** Which sensitive assets have unclear ownership (`unknown` UPN) and who *is* touching them?\n"
           "Crucial for data-governance remediation programs."),
        setup_cell(),
        md("## Find orphan assets and recent accessors"),
        code("""from pyspark.sql.functions import from_json, col, lower

orphans = (
    df.withColumn("owner_obj", from_json(col("AssetOwner"), "AccountUpn string, DisplayName string, Department string"))
      .filter(
          (col("owner_obj.AccountUpn").isNull()) |
          (lower(col("owner_obj.AccountUpn")) == "unknown") |
          (col("owner_obj.AccountUpn") == "")
      )
      .filter(
          (col("Classification").contains("PHI")) |
          (col("Classification").contains("GDPR")) |
          (col("Classification").contains("Restricted")) |
          (col("Classification").contains("Confidential"))
      )
      .select("AssetID", "AssetSource", "Classification", "UserName")
      .filter(col("UserName").isNotNull())
)

# Source → Asset edges so the graph clusters by AssetSource
result = orphans.select("AssetSource", "AssetID").limit(120)
result.show(20, truncate=False)
print("Distinct orphan assets:", orphans.select("AssetID").distinct().count())
"""),
        md("## Visualize"),
        viz_cell("Orphan Sensitive Data Clusters — Source → Asset (no clear owner)"),
    ],
    "metadata": {
        "kernelspec": {"display_name": "Microsoft Sentinel", "language": "python", "name": "sentinel-lake-pyspark"},
        "language_info": {"name": "python"},
    },
    "nbformat": 4, "nbformat_minor": 5,
}

# ---------- Notebook 4: Threat Lateral Movement ----------
nb4 = {
    "cells": [
        md("# Threat Lateral Movement (BigID × Sentinel Data Lake)\n\n"
           "**Question:** Which suspicious source IPs touched sensitive assets, and which downstream users also touched those same assets?\n"
           "Joins BigID `RequestSourceIP` to `UserName` via shared `AssetID` to surface candidate lateral-movement paths."),
        setup_cell(),
        md("## Build IP → Asset → User chains"),
        code("""from pyspark.sql.functions import col

threat_rows = (
    df.filter(col("ThreatCategory").isNotNull() & (col("ThreatCategory") != ""))
      .select("RequestSourceIP", "AssetID", "ThreatCategory")
      .filter(col("RequestSourceIP").isNotNull())
)

asset_users = df.select("AssetID", "UserName").filter(col("UserName").isNotNull())

chains = (
    threat_rows.alias("t")
        .join(asset_users.alias("u"), "AssetID")
        .select("t.RequestSourceIP", "t.AssetID", "u.UserName", "t.ThreatCategory")
        .distinct()
)
chains.show(30, truncate=False)
print("Total chain rows:", chains.count())
"""),
        md("## Flatten to edges for visualization"),
        code("""# Two-hop graph: IP -> Asset, Asset -> User. Concatenate into a single edge list.
edges1 = chains.select(col("RequestSourceIP").alias("src"), col("AssetID").alias("dst"))
edges2 = chains.select(col("AssetID").alias("src"), col("UserName").alias("dst"))
result = edges1.union(edges2).distinct().limit(150)
result.show(20, truncate=False)
"""),
        md("## Visualize"),
        viz_cell("Threat Lateral Movement — Suspicious IP → Asset → User"),
    ],
    "metadata": {
        "kernelspec": {"display_name": "Microsoft Sentinel", "language": "python", "name": "sentinel-lake-pyspark"},
        "language_info": {"name": "python"},
    },
    "nbformat": 4, "nbformat_minor": 5,
}

# ---------- Notebook 5: Cross-Source Leakage ----------
nb5 = {
    "cells": [
        md("# Cross-Source Sensitive Data Leakage (BigID × Sentinel Data Lake)\n\n"
           "**Question:** Which users touched the same classification across *multiple* data sources (e.g. PHI in both Snowflake AND Box)?\n"
           "Multi-source access patterns flag data exfiltration risk."),
        setup_cell(),
        md("## Find cross-source classification access"),
        code("""from pyspark.sql.functions import col, countDistinct

sensitive = df.filter(
    (col("Classification").contains("PHI")) |
    (col("Classification").contains("GDPR")) |
    (col("Classification").contains("Restricted")) |
    (col("Classification").contains("Confidential"))
).filter(col("UserName").isNotNull())

user_class_sources = (
    sensitive.groupBy("UserName", "Classification")
    .agg(countDistinct("AssetSource").alias("SourceCount"),
         F.collect_set("AssetSource").alias("Sources"),
         F.countDistinct("AssetID").alias("Assets"))
    .filter(col("SourceCount") >= 2)
    .orderBy(F.desc("SourceCount"), F.desc("Assets"))
)
user_class_sources.show(50, truncate=False)
"""),
        md("## Edges: User → AssetSource (limited to multi-source users)"),
        code("""multi = user_class_sources.select("UserName").distinct()
result = (
    sensitive.join(multi, "UserName")
    .select(col("UserName").alias("User"), col("AssetSource").alias("Source"))
    .distinct()
    .limit(120)
)
result.show(20, truncate=False)
"""),
        md("## Visualize"),
        viz_cell("Cross-Source Leakage — Users → Multiple Sensitive Data Sources"),
    ],
    "metadata": {
        "kernelspec": {"display_name": "Microsoft Sentinel", "language": "python", "name": "sentinel-lake-pyspark"},
        "language_info": {"name": "python"},
    },
    "nbformat": 4, "nbformat_minor": 5,
}

notebooks = {
    "01-blast-radius-pyspark.ipynb": nb1,
    "02-external-exposure-pyspark.ipynb": nb2,
    "03-orphan-clusters-pyspark.ipynb": nb3,
    "04-threat-movement-pyspark.ipynb": nb4,
    "05-cross-source-leakage-pyspark.ipynb": nb5,
}

for name, nb in notebooks.items():
    out = HERE / name
    out.write_text(json.dumps(nb, indent=1))
    print(f"Wrote {out}")

print("Done.")
