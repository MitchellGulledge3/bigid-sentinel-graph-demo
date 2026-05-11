# PySpark Notebooks for the Sentinel Data Lake VS Code Extension

These 5 notebooks are designed to run inside the **Microsoft Sentinel VS Code extension** against the **Sentinel data lake** using the `MicrosoftSentinelProvider` PySpark API.

> 📚 Docs: [Run notebooks on the Microsoft Sentinel data lake](https://learn.microsoft.com/azure/sentinel/datalake/notebooks) · [`MicrosoftSentinelProvider` class reference](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-provider-class-reference)

## Prerequisites

1. **Onboard your Sentinel workspace to the data lake** (preview). See: [Onboarding to Microsoft Sentinel data lake](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-lake-onboarding). After onboarding it can take **up to 24h** before lake tables are populated.
2. **Install the Microsoft Sentinel VS Code extension** from the marketplace.
3. **Sign in** via the Sentinel icon in the activity bar; allow Microsoft auth.
4. Make sure `BigIDDSPMCatalog_CL` is visible under **Lake tables → \<your workspace\> → Custom tables**.

## Wire each notebook to your workspace

Each notebook hard-codes a placeholder `WORKSPACE = "<YOUR_SENTINEL_WORKSPACE_NAME>"`. **You must change this** to match your workspace name as it appears in the extension's Lake-tables tree.

```python
WORKSPACE = "my-sentinel-ws"     # <-- your workspace name from the extension
TABLE     = "BigIDDSPMCatalog_CL"
```

## Run a notebook

1. Open any `.ipynb` in this folder.
2. Click **Select Kernel** in the top-right.
3. Choose **Microsoft Sentinel** → **Medium** runtime pool.
4. Wait 3–5 minutes for the Spark session to spin up the first time.
5. **Run All** — each notebook executes 3 cells (setup → query → visualize) and renders a NetworkX graph at the bottom.

## What's in each notebook

| File | Question it answers |
|------|---------------------|
| `01-blast-radius-pyspark.ipynb` | If one identity is compromised, how many sensitive BigID assets are at risk? |
| `02-external-exposure-pyspark.ipynb` | Which sensitive assets are reachable by non-`@contoso.com` identities? |
| `03-orphan-clusters-pyspark.ipynb` | Which sensitive assets have unknown ownership but active accessors? |
| `04-threat-movement-pyspark.ipynb` | Which suspicious source IPs share assets with downstream users (lateral movement)? |
| `05-cross-source-leakage-pyspark.ipynb` | Which users touch the same classification across multiple data sources? |

## Regenerate

If you want to tweak the cell templates:

```bash
python3 _generate.py
```

## Notebook NOT showing up in the Sentinel extension panel?

The Sentinel extension's **left panel** shows **Lake tables** and **Jobs** — *not* notebook files. Notebooks themselves live in your regular VS Code file explorer (`Cmd/Ctrl + Shift + E`). They just need the Sentinel **Spark kernel** selected to run against the data lake.

## Don't have the data lake onboarded yet?

Use the sibling [`notebooks/`](../notebooks) folder instead — those notebooks run **locally** via the `az` CLI against your existing Log Analytics workspace, no Spark required. The visualizations are equivalent.
