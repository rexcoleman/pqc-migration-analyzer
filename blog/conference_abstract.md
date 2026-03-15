# Conference Abstract — BSides / Real World Crypto

## Title
Classical Risk Before Quantum Risk: ML-Driven PQC Migration Priority Scoring

## Abstract (250 words)

NIST finalized post-quantum cryptography standards in 2024 (FIPS 203-205), but organizations lack tools to assess what's actually in their codebases and what to migrate first. We present an open-source PQC migration analyzer that scans Python codebases for quantum-vulnerable cryptographic primitives, scores migration urgency using machine learning, and recommends NIST-approved replacements.

Scanning Python's standard library and installed packages (6,647 files) revealed 39 quantum-vulnerable findings, including 19 critical Shor-vulnerable primitives (ECDSA, Ed25519). Extracting 21,142 crypto-related CVEs from the NVD (6.3% of all CVEs), we trained ML models to predict migration priority. Gradient Boosting outperformed rule-based scoring by +14.0 percentage points AUC-ROC across 3 seeds.

Our most significant finding: **classical exploit risk dominates over quantum-specific vulnerability in predicting migration priority.** The top features are heap overflows, padding oracle attacks, and arbitrary code execution — not Shor vulnerability flags. This suggests organizations should prioritize PQC migration based on real-world exploitability, not theoretical quantum risk.

We apply **controllability analysis** — classifying crypto usage by who controls migration (developer, library, protocol, hardware) — and find that ~70% of crypto in real codebases is library-controlled, meaning developers cannot migrate it directly. This is the fourth domain validation of controllability analysis as a general security architecture methodology, following network IDS, vulnerability prediction, and AI agent red-teaming.

Scanner and all results are open source: github.com/rexcoleman/pqc-migration-analyzer

## Keywords
post-quantum cryptography, PQC migration, NIST FIPS 203/204/205, vulnerability prioritization, controllability analysis, ML-KEM, ML-DSA

## Bio
Rex Coleman is an MS Computer Science student (Machine Learning) at Georgia Tech, building at the intersection of AI security and ML systems engineering. Previously 15 years in cybersecurity (FireEye/Mandiant — analytics, enterprise sales, cross-functional leadership). CFA charterholder. Creator of govML (open-source ML governance framework).
