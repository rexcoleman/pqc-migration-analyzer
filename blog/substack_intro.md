# Substack Intro — PQC Migration Analyzer

**Subject line:** I scanned Python stdlib for quantum-vulnerable crypto. Here's what's hiding.

**Preview text:** 39 findings, 19 critical, and the surprise is what matters most for priority.

---

NIST finalized post-quantum cryptography standards in 2024. ML-KEM replaces RSA key exchange. ML-DSA replaces ECDSA signatures. The migration clock is ticking.

But nobody knows what's actually in their codebase.

I built an open-source scanner that finds quantum-vulnerable cryptographic primitives, scores migration urgency using ML, and maps every finding to NIST PQC replacements. Then I scanned Python's standard library.

**39 findings. 19 critical.** All Shor-vulnerable.

The real surprise: when I trained ML models on 21,142 crypto-related CVEs, classical exploitability (heap overflows, padding oracles) dominated over quantum risk for predicting what gets attacked. And 70% of the crypto in your codebase is library-controlled -- you're waiting on upstream, not writing migration code.

In this post, I'll walk through the scanner architecture, the ML scoring results, and the controllability analysis that should reshape how you think about PQC migration planning.

[Continue reading...]

---

*This is part of my series on building security tools with ML. Previously: network intrusion detection (FP-01), agent red-teaming (FP-02), vulnerability prioritization (FP-05).*
