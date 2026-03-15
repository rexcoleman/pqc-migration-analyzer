#!/usr/bin/env python
"""Generate learning curves for PQC migration ML scoring.

Purpose: Show where the ML model PLATEAUS. In a scanner project where the
primary contribution is the rule-based analyzer, demonstrating that ML
quickly saturates is actually valuable evidence — it confirms the feature
space has limited signal and the scanner itself is the main contribution.

Seeds: [42, 123, 456, 789, 1024]
Fractions: [0.1, 0.25, 0.5, 0.75, 1.0]

Outputs:
  outputs/diagnostics/learning_curves_seed{seed}.json
  outputs/diagnostics/learning_curves_summary.json

Usage:
    python scripts/run_learning_curves.py
    python scripts/run_learning_curves.py --seeds 42 --sample-frac 0.5
    python scripts/run_learning_curves.py --project-dir ~/pqc-migration-analyzer
"""

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).parent.parent))


FRACTIONS = [0.1, 0.25, 0.5, 0.75, 1.0]
DEFAULT_SEEDS = [42, 123, 456, 789, 1024]


def load_and_engineer(input_path, sample_frac):
    """Load crypto CVEs and engineer features (mirrors run_scoring.py)."""
    df = pd.read_csv(input_path)
    if sample_frac and sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=42)

    df["high_priority"] = (df["cvss_score"] >= 7.0).astype(int)
    df["has_cvss"] = (df["cvss_score"] > 0).astype(int)
    df["shor_vulnerable"] = df["shor_vulnerable"].astype(int)
    df["grover_vulnerable"] = df["grover_vulnerable"].astype(int)
    df["year"] = pd.to_datetime(df["published"], errors="coerce").dt.year.fillna(2020).astype(int)
    df["age_years"] = 2026 - df["year"]
    df["desc_length"] = df["description"].str.len().fillna(0)
    df["num_primitives"] = df["primitives"].str.count(",") + 1
    df["num_primitives"] = df["num_primitives"].where(df["primitives"].notna(), 0)

    crypto_keywords = [
        "remote", "overflow", "injection", "denial", "authentication",
        "bypass", "execute", "arbitrary", "privilege", "escalation",
        "buffer", "memory", "heap", "stack", "use-after-free",
        "certificate", "validation", "verification", "signature",
        "key", "encrypt", "decrypt", "padding", "oracle",
    ]
    for kw in crypto_keywords:
        df[f"kw_{kw}"] = df["description"].str.contains(kw, case=False, na=False).astype(int)

    primitive_cats = ["RSA", "ECDSA", "DH", "DSA", "AES", "DES", "MD5", "SHA-1", "RC4", "TLS/SSL", "X.509"]
    for prim in primitive_cats:
        df[f"prim_{prim}"] = df["primitives"].str.contains(prim, na=False).astype(int)

    common_cwes = ["CWE-310", "CWE-295", "CWE-326", "CWE-327", "CWE-20", "CWE-119"]
    for cwe in common_cwes:
        df[f"cwe_{cwe}"] = df["cwes"].str.contains(cwe, na=False).astype(int)

    feature_cols = (
        ["shor_vulnerable", "grover_vulnerable", "age_years", "desc_length", "num_primitives"]
        + [f"kw_{kw}" for kw in crypto_keywords]
        + [f"prim_{prim}" for prim in primitive_cats]
        + [f"cwe_{cwe}" for cwe in common_cwes]
    )

    df_labeled = df[df["has_cvss"] == 1].copy()
    X = df_labeled[feature_cols].fillna(0)
    y = df_labeled["high_priority"]

    return X, y, feature_cols, df_labeled


def get_models(seed):
    """Return model configs."""
    return {
        "LogisticRegression": LogisticRegression(max_iter=500, random_state=seed),
        "RandomForest": RandomForestClassifier(n_estimators=100, random_state=seed, n_jobs=1),
        "GradientBoosting": GradientBoostingClassifier(n_estimators=100, random_state=seed),
    }


def run_learning_curves(project_dir, seeds, sample_frac):
    """Run learning curves — expect early plateau confirming limited feature signal."""
    proj = Path(project_dir).resolve()
    input_path = proj / "data" / "processed" / "crypto_cves.csv"

    if not input_path.exists():
        print(f"ERROR: {input_path} not found. Run scripts/extract_crypto_cves.py first.")
        sys.exit(1)

    output_dir = proj / "outputs" / "diagnostics"
    output_dir.mkdir(parents=True, exist_ok=True)

    all_results = []

    for seed in seeds:
        print(f"\n{'='*60}")
        print(f"Seed {seed}")
        print(f"{'='*60}")

        np.random.seed(seed)

        X, y, feature_cols, df = load_and_engineer(str(input_path), sample_frac)

        # Temporal split at 2023
        train_mask = df["year"] < 2023
        test_mask = df["year"] >= 2023
        X_train_full = X[train_mask]
        y_train_full = y[train_mask]
        X_test = X[test_mask]
        y_test = y[test_mask]

        if len(X_test) < 10 or y_test.nunique() < 2:
            print(f"  WARNING: Insufficient test data ({len(X_test)} rows), skipping seed {seed}")
            continue

        scaler = StandardScaler()
        X_train_full_s = scaler.fit_transform(X_train_full)
        X_test_s = scaler.transform(X_test)

        seed_results = {"seed": seed, "fractions": FRACTIONS, "curves": {}}

        for model_name, model in get_models(seed).items():
            print(f"\n  {model_name}:")
            train_aucs, test_aucs, test_f1s = [], [], []
            n_samples_list = []

            for frac in FRACTIONS:
                n = max(10, int(len(X_train_full_s) * frac))
                X_sub = X_train_full_s[:n]
                y_sub = y_train_full.iloc[:n]

                if y_sub.nunique() < 2:
                    print(f"    frac={frac:.2f} n={n}: single class, skipping")
                    train_aucs.append(0.5)
                    test_aucs.append(0.5)
                    test_f1s.append(0.0)
                    n_samples_list.append(n)
                    continue

                from sklearn.base import clone
                m = clone(model)

                start = time.time()
                m.fit(X_sub, y_sub)
                elapsed = time.time() - start

                y_train_prob = m.predict_proba(X_sub)[:, 1]
                train_auc = roc_auc_score(y_sub, y_train_prob)

                y_test_prob = m.predict_proba(X_test_s)[:, 1]
                y_test_pred = m.predict(X_test_s)
                test_auc = roc_auc_score(y_test, y_test_prob)
                test_f1 = f1_score(y_test, y_test_pred, zero_division=0)

                train_aucs.append(round(float(train_auc), 4))
                test_aucs.append(round(float(test_auc), 4))
                test_f1s.append(round(float(test_f1), 4))
                n_samples_list.append(n)

                print(f"    frac={frac:.2f} n={n:>5}  "
                      f"train_auc={train_auc:.4f}  test_auc={test_auc:.4f}  "
                      f"test_f1={test_f1:.4f}  ({elapsed:.1f}s)")

            seed_results["curves"][model_name] = {
                "train_auc": train_aucs,
                "test_auc": test_aucs,
                "test_f1": test_f1s,
                "n_samples": n_samples_list,
            }

        seed_path = output_dir / f"learning_curves_seed{seed}.json"
        with open(seed_path, "w") as f:
            json.dump(seed_results, f, indent=2)
        print(f"\n  Saved: {seed_path}")
        all_results.append(seed_results)

    if not all_results:
        print("ERROR: No seeds produced results.")
        sys.exit(1)

    # Summary
    summary = {
        "experiment": "learning_curves",
        "purpose": "Show ML plateau — confirms scanner is primary contribution, not ML",
        "seeds": seeds,
        "fractions": FRACTIONS,
        "models": list(get_models(42).keys()),
        "per_seed": all_results,
    }

    for model_name in summary["models"]:
        for metric in ["train_auc", "test_auc", "test_f1"]:
            means, stds = [], []
            for i in range(len(FRACTIONS)):
                vals = [r["curves"][model_name][metric][i]
                        for r in all_results if model_name in r["curves"]]
                if vals:
                    means.append(round(float(np.mean(vals)), 4))
                    stds.append(round(float(np.std(vals)), 4))
            summary[f"{model_name}_{metric}_mean"] = means
            summary[f"{model_name}_{metric}_std"] = stds

    summary_path = output_dir / "learning_curves_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary saved: {summary_path}")
    print("\nExpected finding: curves plateau early, confirming limited feature-space signal.")
    print("This supports the 'scanner is the primary contribution' reframe.")


def main():
    parser = argparse.ArgumentParser(description="Generate learning curves (FP-03)")
    parser.add_argument("--project-dir", default=".", help="Project root directory")
    parser.add_argument("--seeds", type=int, nargs="+", default=DEFAULT_SEEDS,
                        help="Random seeds")
    parser.add_argument("--sample-frac", type=float, default=None,
                        help="Data sampling fraction for smoke testing")
    args = parser.parse_args()
    run_learning_curves(args.project_dir, args.seeds, args.sample_frac)


if __name__ == "__main__":
    main()
