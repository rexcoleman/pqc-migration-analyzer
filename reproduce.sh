#!/usr/bin/env bash
set -euo pipefail
echo "=== FP-03: PQC Migration Analyzer — Reproduction ==="

echo "1. Install dependencies"
pip install -r requirements.txt 2>/dev/null || pip install -e .

echo "2. Extract crypto CVEs from NVD data"
python scripts/extract_crypto_cves.py

echo "3. Run ML scoring (seed 42)"
python scripts/run_scoring.py --seed 42

echo "4. Run learning curves"
python scripts/run_learning_curves.py

echo "5. Generate figures"
python scripts/make_report_figures.py

echo "=== Reproduction complete ==="
echo "Outputs: outputs/scoring/, outputs/diagnostics/, outputs/figures/, blog/images/"
