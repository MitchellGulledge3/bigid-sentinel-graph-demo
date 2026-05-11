# Use cases — talk track per query

Use this in the BigID conversation when you switch from the flat-KQL MCP demo to the graph demo.

---

### 1. Sensitive Data Blast Radius — `01-sensitive-data-blast-radius.kql`

**Audience:** CISO / Head of Insider Risk
**Story:** "If alice@contoso.com clicks one phishing link, what is the legal/regulatory exposure?" The query scores every identity by the count + maximum sensitivity of assets reachable via OWNED_BY or SHARED_WITH within 2 hops.
**Why graph:** Flat KQL can count assets per owner. Only graph can chain `owner → asset → re-shared → asset` and aggregate the classification along the path.

### 2. External Exposure Paths — `02-external-exposure-paths.kql`

**Audience:** Privacy / Data Governance Officer
**Story:** "Show me every path from somebody outside the company to a PII / PHI / PCI asset, in 1–3 hops." Returns the shortest path and the regulated classification at the end.
**Why graph:** Re-shared assets create transitive exposure. Flat KQL only sees the first hop; graph traversal sees the full reachability.

### 3. Orphan Cluster Detection — `03-orphan-cluster-detection.kql`

**Audience:** Data Steward / DSPM lead
**Story:** Orphaned assets with no owner are bad enough — but orphaned assets that **share the same data source and a common last-accessor** are a silent risk pile (often a former employee + an unmaintained share).
**Why graph:** Cluster detection across two pivots (DataSource + LastAccessor) is a graph join, not a flat aggregate.

### 4. Threat Lateral Movement — `04-threat-lateral-movement.kql`

**Audience:** SOC manager
**Story:** "Trace every path from a known-bad source IP, through a threat hit, onto regulated data, in ≤ 3 hops." Surfaces the regulated assets at risk **right now** because of an active threat.
**Why graph:** Joins three independent signals (IP reputation, threat detection, data sensitivity) along a path — flat KQL would need 3 nested joins and would lose the path itself.

### 5. Cross-Source Leakage — `05-cross-source-leakage.kql`

**Audience:** CISO / Compliance
**Story:** "Where is the same regulated classification (e.g. PCI) sprawling across 3+ data sources via the same owner?" That is the textbook DLP-failure pattern — and the question regulators ask.
**Why graph:** Group-by-owner-and-classification is flat KQL — but **counting distinct DataSources reachable from each owner** through the assets they own is a 2-hop graph traversal.
