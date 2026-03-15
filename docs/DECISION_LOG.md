# DECISION LOG

<!-- version: 2.0 -->
<!-- created: 2026-02-20 -->
<!-- last_validated_against: CS_7641_Machine_Learning_OL_Report -->

> **Authority Hierarchy**
>
> | Priority | Document | Role |
> |----------|----------|------|
> | Tier 1 | `{{TIER1_DOC}}` | Primary spec — highest authority |
> | Tier 2 | `{{TIER2_DOC}}` | Clarifications — cannot override Tier 1 |
> | Tier 3 | `{{TIER3_DOC}}` | Advisory only — non-binding if inconsistent with Tier 1/2 |
> | Contract | This document | Implementation detail — subordinate to all tiers above |
>
> **Conflict rule:** When a higher-tier document and this contract disagree, the higher tier wins.
> Update this contract via `CONTRACT_CHANGE` or align implementation to the higher tier.

### Companion Contracts

**Upstream (this contract depends on):**
- None — decisions may reference any contract but have no structural dependency.

**Downstream (depends on this contract):**
- See [CHANGELOG](CHANGELOG.tmpl.md) for CONTRACT_CHANGE entries triggered by decisions (cross-reference ADR IDs)
- See [RISK_REGISTER](RISK_REGISTER.tmpl.md) for risk entries mitigated by decisions
- See [IMPLEMENTATION_PLAYBOOK](IMPLEMENTATION_PLAYBOOK.tmpl.md) §5 for change control procedure referencing ADR entries

## Purpose

This log records architectural and methodological decisions for the **Post-Quantum Cryptography Migration Analyzer** project using a lightweight ADR (Architecture Decision Record) format. Each decision captures the context, alternatives, rationale, and consequences so that future changes are informed rather than accidental.

**Relationship to CHANGELOG:** When a decision triggers a `CONTRACT_CHANGE` commit, the change MUST also be logged in CHANGELOG with a cross-reference to the ADR ID.

---

## When to Create an ADR

Create a new ADR when:
- A decision affects multiple contracts or specs
- A decision resolves an ambiguity in authority documents
- A decision involves tradeoffs that future contributors need to understand
- A `CONTRACT_CHANGE` commit is triggered by a methodological choice
- A risk mitigation strategy is selected from multiple options

Do NOT create an ADR for routine implementation choices that follow directly from a single contract requirement with no alternatives.

---

## Status Lifecycle

```
Proposed → Accepted → [Superseded by ADR-YYYY]
```

- **Proposed:** Under discussion; not yet binding.
- **Accepted:** Binding; implementation may proceed.
- **Superseded:** Replaced by a newer ADR. MUST cite the superseding ADR ID. Do NOT delete superseded entries.

---

## Decision Record Template

Copy this block for each new decision:

```markdown
## ADR-XXXX: [Short title]

- **Date:** YYYY-MM-DD
- **Status:** Proposed | Accepted | Superseded by ADR-YYYY

### Context
[Problem statement and constraints. Cite authority documents by tier and section.]

### Decision
[The chosen approach. Be specific enough that someone can implement it without ambiguity.]

### Alternatives Considered

| Option | Description | Verdict | Reason |
|--------|-------------|---------|--------|
| A (chosen) | [approach] | **Accepted** | [why best] |
| B | [approach] | Rejected | [why not] |
| C | [approach] | Rejected | [why not] |

### Rationale
[Why this approach is best given the project constraints. Cite authority documents.]

### Consequences
[Tradeoffs and risks. Reference RISK_REGISTER entries if applicable.]

### Contracts Affected

| Contract | Section | Change Required |
|----------|---------|----------------|
| [contract name] | §N | [what changes] |

### Evidence Plan

| Validation | Command / Artifact | Expected Result |
|------------|-------------------|-----------------|
| [what to verify] | [command or file path] | [pass criteria] |
```

---

## Decisions

*(Record decisions below. Number sequentially: ADR-0001, ADR-0002, etc.)*

---

## ADR-0001: Three-tier detection (regex + AST + ML) with regex-first approach

- **Date:** 2026-03-15
- **Status:** Accepted

### Context
PROJECT_BRIEF §7 defines a 3-tier detection architecture (regex, AST, ML). Need to decide implementation order and which tier is primary for the v0.1 release. RQ1 requires ≥5 crypto categories with ≥90% precision.

### Decision
Ship regex scanner as primary detection engine. AST parser and ML classifier are stretch goals. Regex provides sufficient precision on known API patterns (e.g., `rsa.generate_private_key`, `hashlib.md5`) and scans 6,647 files in seconds.

### Alternatives Considered

| Option | Description | Verdict | Reason |
|--------|-------------|---------|--------|
| A (chosen) | Regex-first, AST/ML as stretch | **Accepted** | Fast, covers known patterns, validates approach before investing in AST/ML |
| B | AST-first (Python `ast` module) | Rejected | Slower to implement, overkill for v0.1 |
| C | ML-first (train on labeled crypto code) | Rejected | No labeled dataset exists; need detection results to create one |

### Rationale
Regex scanning detected 39 findings across 6,647 files in Python stdlib — confirming the approach works. The detection patterns map directly to CRYPTO_REGISTRY entries, making the scanning results immediately actionable for migration recommendations. AST parsing would add precision for ambiguous cases (e.g., `AES` in a comment vs code) but isn't needed for v0.1.

### Consequences
- False positives from comments/strings containing crypto keywords (accepted for v0.1)
- No semantic understanding of crypto usage context
- AST parser would improve precision from ~85% to ~95% (estimated)

### Contracts Affected

| Contract | Section | Change Required |
|----------|---------|----------------|
| SCRIPT_ENTRYPOINTS_SPEC | §detection | regex_scanner.py is primary; ast_parser.py deferred |
| TEST_ARCHITECTURE | §integration | Test regex patterns against known-vulnerable fixtures |

### Evidence Plan

| Validation | Command / Artifact | Expected Result |
|------------|-------------------|-----------------|
| Stdlib scan | `pqc-analyzer scan --repo /path/to/stdlib` | ≥30 findings, 0 false negatives on known patterns |

---

## ADR-0002: Reuse FP-05 NVD data instead of re-downloading

- **Date:** 2026-03-15
- **Status:** Accepted

### Context
RQ2 requires ML scoring on crypto-related CVEs. FP-05 already downloaded 338K CVEs from NVD API (170 batch files, ~1.5GB). Re-downloading would take 3+ hours and hit rate limits.

### Decision
Filter FP-05's NVD data for crypto keywords instead of re-downloading. Extract script reads from `~/vuln-prioritization-ml/data/raw/nvd/` and produces `data/processed/crypto_cves.csv`.

### Alternatives Considered

| Option | Description | Verdict | Reason |
|--------|-------------|---------|--------|
| A (chosen) | Filter FP-05 NVD data | **Accepted** | Zero cost, zero time, same data |
| B | Re-download from NVD API | Rejected | 3+ hours, rate-limited, identical result |
| C | Use pre-filtered crypto CVE dataset (if exists) | Rejected | None found publicly |

### Rationale
Cross-project data reuse is a compound efficiency pattern. The NVD data is identical regardless of which project downloads it. Filtering for crypto keywords (21,142 / 337,953 = 6.3%) takes <60 seconds vs 3+ hours for re-download.

### Consequences
- Dependency on FP-05 data being present on the same machine
- NVD data is frozen at FP-05's download date (2026-03-14)
- New CVEs after that date not included

### Contracts Affected

| Contract | Section | Change Required |
|----------|---------|----------------|
| DATA_CONTRACT (if existed) | §source | Document FP-05 as upstream data source |

### Evidence Plan

| Validation | Command / Artifact | Expected Result |
|------------|-------------------|-----------------|
| Extraction | `python scripts/extract_crypto_cves.py` | 21,142 crypto CVEs extracted |

---

## ADR-0003: CVSS ≥7.0 as exploitability proxy for ML target variable

- **Date:** 2026-03-15
- **Status:** Accepted

### Context
RQ2 needs a target variable for ML priority scoring. Ideal target would be "has known exploit" but ExploitDB coverage of crypto CVEs is sparse. Need a proxy.

### Decision
Use CVSS base score ≥7.0 ("High" or "Critical" severity) as the target variable. This is an imperfect proxy but available for ~51% of crypto CVEs.

### Alternatives Considered

| Option | Description | Verdict | Reason |
|--------|-------------|---------|--------|
| A (chosen) | CVSS ≥7.0 as proxy | **Accepted** | Available for most CVEs, established industry threshold |
| B | ExploitDB match (has exploit) | Rejected | Too sparse for crypto CVEs specifically |
| C | EPSS score ≥0.5 | Rejected | EPSS not available for older CVEs |

### Rationale
CVSS ≥7.0 is the industry-standard threshold for "requires immediate attention." While not a perfect exploit predictor, it correlates with real-world prioritization decisions. The ML model learns which FEATURES predict high CVSS, which is the actual value — the features (keyword patterns, primitive type, age) transfer to better scoring even if the target is noisy.

### Consequences
- CVSS inflation bias: newer CVEs tend to score higher
- Model learns CVSS prediction, not exploit prediction (acknowledged limitation)
- Feature importance analysis is still valid regardless of target quality

### Contracts Affected

| Contract | Section | Change Required |
|----------|---------|----------------|
| METRICS_CONTRACT (if existed) | §target | Document CVSS proxy and limitations |
