# Post-Quantum Cryptography Migration Analyzer

**Scan Python codebases for quantum-vulnerable cryptographic primitives, score migration urgency with ML, and get NIST PQC replacement recommendations.**

## Key Results

| Metric | Value |
|--------|-------|
| GradientBoosting AUC | 0.6345 (+14pp over rule-based baseline) |
| Crypto CVEs scanned | 21,142 (6.3% of all NVD CVEs) |
| Primitives detected | 12 categories (RSA, ECDSA, DH, AES, etc.) |
| Shor-vulnerable (critical) | 19 findings in Python stdlib scan |
| Controllability | 70% library-controlled, 20% developer-controlled |

**Core insight:** Classical exploit risk dominates over quantum risk in migration prioritization. Organizations should fix known crypto CVEs before worrying about quantum threats.

## Quick Start

```bash
git clone https://github.com/rexcoleman/pqc-migration-analyzer.git
cd pqc-migration-analyzer
conda env create -f environment.yml
conda activate pqc-analyzer

# Scan a Python project
python src/cli.py scan --repo ~/your-project

# Generate JSON report
python src/cli.py scan --repo ~/your-project --output report.json
```

## Architecture

```
src/
  cli.py                  # CLI entry point
  detection/
    regex_scanner.py      # Regex-based crypto primitive scanner (19 primitives)
  scoring/                # ML priority scoring (rule-based + GradientBoosting)
  migration/
    nist_mapping.py       # NIST PQC mapping + controllability analysis
  core/
    crypto_primitives.py  # Crypto primitives registry, risk types
```

## Methodology

This project validates the **adversarial controllability analysis** methodology (4th domain). Cryptographic migration risk factors are classified by controllability:
- **Library-controlled (70%):** algorithm choice, key length — fixed by library update
- **Developer-controlled (20%):** implementation patterns, configuration — requires code changes
- **Uncontrollable (10%):** protocol-level constraints — requires ecosystem migration

See [FINDINGS.md](FINDINGS.md) for detailed results.

## Governed by [govML](https://github.com/rexcoleman/govML)

Built with reproducibility and decision traceability enforced across the entire pipeline.

## License

[MIT](LICENSE)
