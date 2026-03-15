# PROJECT BRIEF — Post-Quantum Cryptography Migration Analyzer

<!-- version: 1.0 -->
<!-- created: 2026-03-15 -->

> **Authority Hierarchy**
>
> | Priority | Document | Role |
> |----------|----------|------|
> | Tier 1 | `docs/PROJECT_BRIEF.md` | Primary spec — highest authority |
> | Tier 2 | — | No external FAQ |
> | Tier 3 | `docs/ADVERSARIAL_EVALUATION.md` | Advisory — adversarial methodology |

---

## 1) Thesis Statement

**Post-quantum cryptography migration is a measurable, scorable risk — not a vague future concern. By scanning codebases for quantum-vulnerable cryptographic primitives and scoring migration urgency using ML on CVE/exploit data, organizations can prioritize PQC migration based on actual exploitability rather than theoretical vulnerability.**

This project combines three domains that rarely overlap: cryptographic security (NIST PQC standards), vulnerability intelligence (NVD/CVE), and ML-based risk scoring — producing a tool at the C5 scarcity intersection (10-50 people globally have all three).

---

## 2) Research Questions

| # | Question | How You'll Answer It | Success Criteria |
|---|----------|---------------------|-----------------|
| RQ1 | What quantum-vulnerable crypto primitives are commonly used in real codebases? | Scan open-source repos for RSA, ECDSA, DH, DSA, SHA-1, MD5, 3DES usage patterns. Classify by primitive type, key size, and usage context. | Detection engine identifies ≥5 crypto primitive categories with ≥90% precision on known-vulnerable patterns |
| RQ2 | Can ML improve migration priority scoring beyond rule-based CVSS? | Train ML models on NVD crypto CVEs with exploit availability as target. Compare against rule-based scoring (CVSS, key-size-only). | ML model outperforms rule-based baseline on AUC-ROC by ≥5 percentage points |
| RQ3 | What are the migration paths from vulnerable to PQC-safe primitives? | Map each detected primitive to NIST-approved PQC replacement (ML-KEM, ML-DSA, SLH-DSA). Score migration difficulty by API compatibility, performance impact, and ecosystem readiness. | Migration recommendation engine covers ≥80% of detected primitives with specific NIST replacement + difficulty score |
| RQ4 | Does the adversarial control analysis methodology apply to crypto migration? | Classify crypto usage by controllability: developer-controlled (can change), library-controlled (depends on upstream), protocol-controlled (standard mandates). | Clear controllability matrix showing which migrations are actionable vs blocked |

---

## 3) Scope Definition

### In Scope
- Regex + AST-based crypto primitive detection in Python codebases
- ML priority scoring on NVD crypto-related CVEs
- NIST PQC migration mapping (vulnerable primitive → approved replacement)
- Controllability analysis (developer vs library vs protocol controlled)
- Open-source CLI tool: `pqc-analyzer scan --repo <path>`

### Out of Scope
- Scanning compiled binaries or non-Python languages (stretch: Java, Go)
- Cryptanalysis or breaking crypto (detection only)
- Network traffic analysis for crypto usage
- Compliance certification or audit reporting

### Stretch Goals
- Multi-language support (Java crypto API, Go crypto/tls)
- GitHub Action for CI/CD integration
- Performance benchmarking (PQC vs classical runtime/size comparisons)

---

## 4) Data / Workload Definition

| Property | Value |
|----------|-------|
| **Primary data** | NVD API: crypto-related CVEs (filter: RSA, AES, DH, ECDSA, SHA, MD5, 3DES, DSA) |
| **Secondary data** | GitHub code search: crypto API usage patterns in popular Python repos |
| **Reference data** | NIST PQC standards (FIPS 203, 204, 205) — ML-KEM, ML-DSA, SLH-DSA |
| **Download method** | NVD API (rate-limited), GitHub API (rate-limited), NIST PDFs (manual) |
| **Cost** | Free (public APIs + open-source repos) |
| **Known issues** | NVD rate limits, GitHub search bias toward popular repos |

---

## 5) Skill Cluster Targets

| Cluster | Current | Target | How |
|---------|---------|--------|-----|
| **L** | L3+ | L4 | ML pipeline: NLP on CVE descriptions + structured prediction |
| **S** | S3 | S3+ | Novel tool in emerging PQC domain. 4th domain for controllability analysis. |
| **P** | P3-adj | P3 | CLI tool: `pqc-analyzer scan`. pip installable. |
| **D** | D4 | D4+ | PQC migration tradeoff analysis (security vs performance vs compatibility) |
| **V** | V1 | V2 | Blog post on highest-demand security topic (NIST PQC deadline approaching) |

---

## 6) Publication Target

| Property | Value |
|----------|-------|
| **Blog title** | "I Built a PQC Migration Scanner: Here's What Your Codebase Is Hiding" |
| **Content pillar** | AI Security Architecture (40%) |
| **Conference CFP** | BSides / Real World Crypto |
| **Target publish date** | Build now, publish with brand infra |

---

## 7) Technical Approach

### Architecture

```
Input: Python codebase (local path or GitHub URL)
    │
    ├── Detection Engine
    │     regex_scanner.py    — Fast pattern matching (RSA, AES, DH, etc.)
    │     ast_parser.py       — AST-based analysis for crypto API calls
    │     ml_classifier.py    — ML model for ambiguous cases
    │
    ├── Priority Scoring
    │     rule_based.py       — CVSS-based (baseline)
    │     ml_scorer.py        — Trained on NVD crypto CVEs + exploit availability
    │     hybrid.py           — Rules + ML combined
    │
    ├── Migration Recommendations
    │     nist_mapping.py     — Vulnerable primitive → PQC replacement
    │     risk_weighted.py    — Difficulty score by controllability
    │
    └── Output
          scan_report.json    — Per-file findings
          migration_plan.md   — Prioritized migration roadmap
          FINDINGS.md         — Research summary
```

### Controllability Analysis (RQ4)

| Crypto Usage | Controllability | Migration Difficulty |
|-------------|----------------|---------------------|
| Direct API call (e.g., `rsa.generate_private_key()`) | Developer-controlled | Low — change the call |
| Library dependency (e.g., `requests` uses OpenSSL) | Library-controlled | Medium — wait for upstream |
| Protocol mandate (e.g., TLS 1.2 requires RSA/ECDSA) | Protocol-controlled | High — wait for standard update |
| Hardware module (e.g., HSM with RSA-only) | Hardware-controlled | Very high — replace hardware |

### Key Technical Decisions (pre-project)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language scope | Python only (stretch: Java, Go) | Fastest to prototype; `ast` module gives free AST parsing |
| Detection approach | Regex + AST + ML (3-tier) | Regex is fast but noisy; AST is precise but slow; ML handles ambiguous cases |
| Priority scoring | ML on NVD vs rule-based baseline | Validates RQ2: does ML add value beyond simple rules? |
| PQC mapping source | NIST FIPS 203/204/205 | Only finalized PQC standards (2024) |

---

## 8) Definition of Done

- [ ] Detection engine identifies ≥5 crypto primitive categories with ≥90% precision
- [ ] ML priority scorer outperforms rule-based baseline by ≥5pp AUC-ROC
- [ ] Migration recommendations cover ≥80% of detected primitives
- [ ] Controllability matrix documented (4th domain validation)
- [ ] CLI tool: `pqc-analyzer scan --repo <path>` works
- [ ] All code on GitHub
- [ ] FINDINGS.md with key results + architecture diagram
- [ ] DECISION_LOG has all tradeoff decisions
- [ ] PUBLICATION_PIPELINE filled, blog draft started
- [ ] LESSONS_LEARNED updated in govML
- [ ] Conference abstract ready
