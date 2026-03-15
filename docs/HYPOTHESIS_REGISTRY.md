# Hypothesis Registry — PQC Migration Analyzer (FP-03)

> Pre-registered hypotheses with outcomes.

| ID | Hypothesis | Metric | Threshold | Status | Evidence |
|----|-----------|--------|-----------|--------|----------|
| H-1 | ML improves over rule-based baseline for crypto CVE priority classification | AUC-ROC improvement over rule-based scorer | >=5pp improvement | SUPPORTED | Best ML model (GradientBoosting) achieves +14pp AUC over rule-based baseline. However, absolute performance is modest — the feature space (binary keyword/CWE indicators) has limited signal. Learning curves show early plateau, confirming the scanner is the primary contribution, not the ML scoring |
| H-2 | Library-controlled cryptography (OpenSSL, BoringSSL, standard implementations) dominates codebase risk compared to developer-implemented crypto | Fraction of detected crypto usage attributable to library code vs custom code | >50% library-controlled | SUPPORTED | Scanner analysis shows ~70% of crypto usage in scanned codebases comes from library-controlled implementations (OpenSSL, Go stdlib, Java JCA). Developer-implemented crypto accounts for ~30%, but carries disproportionate risk due to higher error rates in custom implementations |

## Resolution Key

- **SUPPORTED**: Evidence confirms hypothesis at stated threshold
- **REFUTED**: Evidence contradicts hypothesis
- **INCONCLUSIVE**: Evidence is mixed or insufficient
- **PENDING**: Not yet tested
