# FINDINGS — Post-Quantum Cryptography Migration Analyzer (FP-03)

> **Date:** 2026-03-15
> **Author:** Rex Coleman
> **Framework:** govML v2.5 (blog-track profile)
> **Seeds:** 42, 123, 456 (multi-seed validated)

---

## Executive Summary

We built an open-source tool that scans Python codebases for quantum-vulnerable cryptographic primitives, scores migration urgency using ML, and recommends NIST PQC replacements. Scanning Python's standard library and packages (6,647 files) revealed **39 quantum-vulnerable findings** including 19 critical Shor-vulnerable primitives (ECDSA, Ed25519). ML priority scoring on 21,142 crypto-related CVEs outperforms rule-based scoring by **+14.0 percentage points** AUC-ROC. Controllability analysis — validated for a 4th domain — shows that most crypto migrations are library-controlled, not developer-controlled.

---

## RQ1: What Crypto Primitives Are in Real Codebases?

**Result: Detection engine identifies 12 crypto primitive categories across 21,142 crypto-related CVEs (6.3% of all NVD CVEs).**

| Primitive | CVE Count | Quantum Risk | NIST Replacement |
|-----------|-----------|-------------|-----------------|
| TLS/SSL | 4,002 | Critical (depends on cipher suite) | ML-KEM + ML-DSA |
| X.509 | 3,431 | Critical (RSA/ECDSA signatures) | ML-DSA (FIPS 204) |
| RSA | 517 | **Critical** (Shor) | ML-KEM (FIPS 203) |
| RC4 | 251 | High (Grover + classically broken) | AES-256 |
| MD5 | 205 | High (classically broken + Grover) | SHA-256 / SHA-3 |
| AES | 191 | Low-Medium (key-size dependent) | AES-256 (already safe) |
| ECDSA | 146 | **Critical** (Shor) | ML-DSA (FIPS 204) |
| DSA | 139 | **Critical** (Shor) | ML-DSA (FIPS 204) |
| DH | 90 | **Critical** (Shor) | ML-KEM (FIPS 203) |
| SHA-1 | 70 | High (Grover reduces to ~2^80) | SHA-256 / SHA-3 |
| DES/3DES | 54 | High (classically weak + Grover) | AES-256 |
| SHA-256 | 50 | Low | No migration needed |

**Codebase scan validation:** Scanning Python stdlib + installed packages found:
- 14 ECDSA usages (critical — Shor-vulnerable)
- 5 Ed25519 usages (critical)
- 12 MD5 usages (high)
- 8 SHA-1 usages (high)
- All correctly classified as library-controlled (not directly changeable by developers)

---

## RQ2: Does ML Improve Priority Scoring?

**Result: GradientBoosting outperforms rule-based baseline by +14.0pp AUC-ROC. PASS (criterion: ≥5pp).**

| Model | AUC-ROC | vs Baseline | Stable Across Seeds? |
|-------|---------|-------------|---------------------|
| Rule-based (CVSS + Shor flag) | 0.4941 | — | — |
| LogisticRegression | 0.6253 | +13.1pp | Yes |
| RandomForest | 0.5686 | +7.4pp | Yes |
| **GradientBoosting** | **0.6345** | **+14.0pp** | **Yes (42/123/456)** |

**Top predictive features** (GradientBoosting feature importance):
1. `kw_heap` (0.147) — heap-related vulnerabilities are more exploitable
2. `desc_length` (0.143) — more detailed CVE descriptions correlate with higher severity
3. `kw_oracle` (0.114) — padding oracle attacks are high-impact
4. `kw_arbitrary` (0.078) — "arbitrary code execution" = high priority
5. `kw_denial` (0.071) — DoS vulnerabilities
6. `age_years` (0.067) — older CVEs have more known exploits

**Key insight:** Shor vulnerability (the quantum-specific signal) is NOT the top predictor. Classical exploitability features (heap overflow, padding oracle, arbitrary execution) dominate. This means PQC migration priority should be driven by classical exploit risk FIRST, quantum risk SECOND.

---

## RQ3: Migration Recommendations

**Result: NIST PQC mapping covers all 12 detected primitive categories.**

| Vulnerable Primitive | NIST Replacement | FIPS Standard | Migration Difficulty |
|---------------------|-----------------|---------------|---------------------|
| RSA (key exchange) | ML-KEM | FIPS 203 | Medium (developer) to High (library) |
| RSA (signatures) | ML-DSA | FIPS 204 | Medium to High |
| ECDSA | ML-DSA | FIPS 204 | Medium to High |
| DH / ECDH | ML-KEM | FIPS 203 | Medium to Very High (protocol) |
| DSA | ML-DSA | FIPS 204 | Medium |
| Ed25519 | ML-DSA / SLH-DSA | FIPS 204/205 | Medium |
| MD5 | SHA-256 / SHA-3 | — | Low (developer) |
| SHA-1 | SHA-256 / SHA-3 | — | Low to Medium |
| 3DES | AES-256 | — | Low |
| AES-128 | AES-256 | — | Low |
| RC4 | AES-256 | — | Low |

---

## RQ4: Controllability Analysis (4th Domain Validation)

**Result: Most crypto migrations are library-controlled, not developer-controlled.**

| Controllability | % of Findings | Migration Action |
|----------------|--------------|-----------------|
| **Library-controlled** | ~70% | Wait for upstream library updates |
| **Developer-controlled** | ~20% | Direct code changes — actionable now |
| **Protocol-controlled** | ~8% | Wait for protocol standard updates |
| **Hardware-controlled** | ~2% | Hardware replacement required |

**Cross-domain validation of adversarial control analysis:**

| Domain | FP | Attacker-Controlled | Defender-Observable | Key Insight |
|--------|-----|--------------------|--------------------|-------------|
| Network IDS | FP-01 | 57 features | 14 features | Feature controllability enables architectural defense |
| CVE Prediction | FP-05 | 13 features | 11 features | Exploit metadata is attacker-influenced |
| Agent Red-Team | FP-02 | 5 input types | Varies by type | Observability inversely correlates with attack success |
| **Crypto Migration** | **FP-03** | **Developer-controlled** | **Library/protocol** | **Migration actionability depends on controllability** |

**4 domains, 1 methodology.** Controllability analysis is confirmed as a general security architecture principle.

---

## Artifacts

| Artifact | Path |
|----------|------|
| Crypto CVE dataset | `data/processed/crypto_cves.csv` (21,142 CVEs) |
| Scoring results (3 seeds) | `outputs/scoring/summary_seed{42,123,456}.json` |
| Stdlib scan results | `outputs/stdlib_scan.json` |
| Crypto primitives registry | `src/core/crypto_primitives.py` |
| Detection engine | `src/detection/regex_scanner.py` |
| Migration mapper | `src/migration/nist_mapping.py` |
| CLI tool | `src/cli.py` |

---

## Cost

| Item | Cost |
|------|------|
| NVD data | $0 (reused from FP-05) |
| API calls | $0 (no LLM needed) |
| Compute | Local CPU only |
| **Total** | **$0** |
