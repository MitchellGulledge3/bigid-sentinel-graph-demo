# Graph model

This repo derives a security graph **at query time** from the existing `BigIDDSPMAssetStoreDemo_CL` table. No new ingestion, no Cosmos, no Neo4j — just KQL `make-graph` over a `let`-projected node and edge set.

## Node types

| Node type | Source column(s) | Notes |
| --- | --- | --- |
| `Asset` | `AssetId`, `AssetName`, `Sensitivity`, `Classification` | One per BigID-discovered asset row |
| `User` (internal) | `Owner`, `LastAccessedBy` | Identities with internal-domain emails |
| `ExternalParty` | `ExposedToUsers` items containing `anonymous`, `link`, or non-corp domains | One per external email or share link token |
| `DataSource` | `DataSource` | e.g. `AWS S3`, `Salesforce`, `Workday` |
| `Classification` | `Classification` | `PII`, `PHI`, `PCI`, `Financial`, `Confidential`, etc. |
| `Threat` | `ThreatCategory` (when non-empty) | One per asset+category pairing |
| `SourceIP` | `ThreatSourceIP` | Threat origin IP |

## Edge types

| Edge | From → To | Derivation |
| --- | --- | --- |
| `OWNED_BY` | `Asset` → `User` | When `Owner` is set and looks internal |
| `SHARED_WITH` | `Asset` → `User` ∪ `ExternalParty` | `mv-expand ExposedToUsers` |
| `STORED_IN` | `Asset` → `DataSource` | From `DataSource` column |
| `CLASSIFIED_AS` | `Asset` → `Classification` | From `Classification` |
| `TARGETED_BY` | `Asset` → `Threat` | When `ThreatCategory` is non-empty |
| `ORIGINATED_FROM` | `Threat` → `SourceIP` | From `ThreatSourceIP` |
| `LAST_ACCESSED_BY` | `Asset` → `User` | From `LastAccessedBy` |

## Why derive at query time

- Zero new infra — sales/SE friendly, ships in any tenant in minutes.
- Always fresh — the graph reflects the same row count Sentinel sees right now.
- Composable — every `.kql` is a self-contained MCP tool candidate.

If you wanted a persistent graph instead, the same projection could land in a Sentinel **graph snapshot** (preview) — same shape, different storage layer.
