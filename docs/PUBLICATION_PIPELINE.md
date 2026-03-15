# PUBLICATION PIPELINE — Post-Quantum Cryptography Migration Analyzer

<!-- version: 2.0 -->
<!-- created: 2026-03-15 -->

> **Authority:** Subordinate to PROJECT_BRIEF (Tier 1)

---

## 1) Target Venue

- [x] Blog (canonical home — Hugo site)
- [x] Conference CFP: BSides / Real World Crypto
- [ ] LinkedIn article

---

## 2) Content Identity

| Property | Value |
|----------|-------|
| **Working title** | I Built a PQC Migration Scanner: Here's What Your Codebase Is Hiding |
| **Content pillar** | AI Security Architecture (40%) |
| **Target audience** | P1: Security engineers evaluating PQC migration. P2: CISOs planning quantum readiness. P3: Hiring managers (crypto × AI signal). |
| **One-line thesis** | Classical exploit risk — not quantum vulnerability — should drive PQC migration priority, and most crypto in your codebase isn't yours to change. |
| **What was shipped** | github.com/rexcoleman/pqc-migration-analyzer — open-source CLI scanner |

### Voice Check

| Test | Pass? |
|------|-------|
| References something you built | [x] CLI tool, 21K CVE dataset, ML scorer |
| Shows work (code, data, architecture) | [x] Detection engine, scoring results, controllability matrix |
| Avoids "5 Tips" / "Why You Should" framing | [x] "Here's What Your Codebase Is Hiding" = showing work |
| Includes at least one architecture diagram | [ ] Need to create |
| Links to GitHub repo | [x] |

---

## 3) Draft Structure

| # | Section | Content | Length | Status |
|---|---------|---------|-------|--------|
| 1 | Hook | "I scanned Python's standard library for quantum-vulnerable crypto. Found 39 findings." | 2 sentences | Pending |
| 2 | Context | NIST PQC standards finalized (2024), but nobody knows what's in their codebase | 1 paragraph | Pending |
| 3 | Architecture | 3-tier detection + ML scoring + controllability analysis diagram | 2 paragraphs + diagram | Pending |
| 4 | Key Findings | (a) 21K crypto CVEs, (b) ML +14pp vs rules, (c) 70% library-controlled, (d) classical > quantum for priority | 4 subsections | Pending |
| 5 | Code Example | `pqc-analyzer scan --repo ~/my-project` output | 1 code block | Pending |
| 6 | What I Learned | Controllability determines migration actionability. 4th domain for ACA. | 2 paragraphs | Pending |
| 7 | Conclusion | Repo link, govML link | 1 paragraph | Pending |

---

## 4) Evidence Inventory

| Claim | Evidence | Source |
|-------|---------|-------|
| 21,142 crypto CVEs (6.3% of NVD) | Extraction count | `data/processed/crypto_cves.csv` |
| 39 findings in Python stdlib | Scan result | `outputs/stdlib_scan.json` |
| 19 critical (Shor-vulnerable) | Scan summary | Same |
| ML +14.0pp vs rule-based | GradientBoosting AUC | `outputs/scoring/summary_seed42.json` |
| Classical features dominate over Shor flag | Feature importance | Same |
| 70% library-controlled | Controllability analysis | FINDINGS.md §RQ4 |
| 4th domain ACA validation | Cross-project comparison | FINDINGS.md §RQ4 |

---

## 5) Distribution Checklist

### 5.1 Pre-Publication
- [ ] Draft reviewed for builder voice
- [ ] Architecture diagram finalized
- [ ] Code example tested and runnable
- [x] All claims traceable to evidence inventory
- [ ] No anti-claims (grep for "superior", "prove", "novel", "always", "never", "best")

### 5.2 Publish
- [ ] Hugo site (canonical URL)
- [ ] Substack email
- [ ] Canonical URL in metadata

### 5.3 Cross-Post (24h)
- [ ] dev.to with canonical URL
- [ ] Hashnode with canonical URL
- [ ] LinkedIn native post
- [ ] Blog link as first comment

### 5.4 Post-Publication (48h)
- [ ] Hacker News (strong technical post — YES, PQC is high-interest)
- [ ] Respond to comments
- [ ] Update govML LESSONS_LEARNED
