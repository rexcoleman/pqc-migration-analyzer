#!/usr/bin/env python
"""Phase 2: ML priority scoring on crypto CVEs.

Compares ML model vs rule-based baseline for migration priority scoring.
Target: predict which crypto CVEs have known exploits (exploitability proxy).

Usage:
    python scripts/run_scoring.py --seed 42
    python scripts/run_scoring.py --seed 42 --sample-frac 0.01
    python scripts/run_scoring.py --dry-run
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).parent.parent))


def load_and_engineer_features(csv_path: str, sample_frac: float = 1.0) -> tuple:
    """Load crypto CVEs and engineer features for ML scoring."""
    df = pd.read_csv(csv_path)

    if sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=42)
        print(f"  Sampled {len(df)} rows ({sample_frac*100:.0f}%)")

    # Target: high CVSS as proxy for exploitability (≥7.0 = high priority)
    df["high_priority"] = (df["cvss_score"] >= 7.0).astype(int)

    # Features
    df["has_cvss"] = (df["cvss_score"] > 0).astype(int)
    df["shor_vulnerable"] = df["shor_vulnerable"].astype(int)
    df["grover_vulnerable"] = df["grover_vulnerable"].astype(int)
    df["year"] = pd.to_datetime(df["published"], errors="coerce").dt.year.fillna(2020).astype(int)
    df["age_years"] = 2026 - df["year"]
    df["desc_length"] = df["description"].str.len().fillna(0)
    df["num_primitives"] = df["primitives"].str.count(",") + 1
    df["num_primitives"] = df["num_primitives"].where(df["primitives"].notna(), 0)

    # Keyword features from description
    crypto_keywords = [
        "remote", "overflow", "injection", "denial", "authentication",
        "bypass", "execute", "arbitrary", "privilege", "escalation",
        "buffer", "memory", "heap", "stack", "use-after-free",
        "certificate", "validation", "verification", "signature",
        "key", "encrypt", "decrypt", "padding", "oracle",
    ]
    for kw in crypto_keywords:
        df[f"kw_{kw}"] = df["description"].str.contains(kw, case=False, na=False).astype(int)

    # Primitive one-hot
    primitive_cats = ["RSA", "ECDSA", "DH", "DSA", "AES", "DES", "MD5", "SHA-1", "RC4", "TLS/SSL", "X.509"]
    for prim in primitive_cats:
        df[f"prim_{prim}"] = df["primitives"].str.contains(prim, na=False).astype(int)

    # CWE features
    common_cwes = ["CWE-310", "CWE-295", "CWE-326", "CWE-327", "CWE-20", "CWE-119"]
    for cwe in common_cwes:
        df[f"cwe_{cwe}"] = df["cwes"].str.contains(cwe, na=False).astype(int)

    # Feature columns
    feature_cols = (
        ["shor_vulnerable", "grover_vulnerable", "age_years", "desc_length", "num_primitives"]
        + [f"kw_{kw}" for kw in crypto_keywords]
        + [f"prim_{prim}" for prim in primitive_cats]
        + [f"cwe_{cwe}" for cwe in common_cwes]
    )

    # Drop rows without CVSS (can't label)
    df_labeled = df[df["has_cvss"] == 1].copy()

    X = df_labeled[feature_cols].fillna(0)
    y = df_labeled["high_priority"]

    return X, y, feature_cols, df_labeled


def rule_based_scorer(df: pd.DataFrame) -> np.ndarray:
    """Baseline: rule-based priority using Shor vulnerability + age."""
    scores = np.zeros(len(df))
    scores += df["shor_vulnerable"].values * 0.5
    scores += df["grover_vulnerable"].values * 0.3
    scores += (df["age_years"].values > 5).astype(float) * 0.2
    return scores


def main():
    parser = argparse.ArgumentParser(description="ML priority scoring on crypto CVEs")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sample-frac", type=float, default=1.0)
    parser.add_argument("--input", default="data/processed/crypto_cves.csv")
    parser.add_argument("--output-dir", default="outputs/scoring")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print("=" * 60)
    print("PQC Migration Priority Scoring")
    print("=" * 60)

    if args.dry_run:
        print("[dry-run] Would load data, engineer features, train models.")
        return

    # Load and engineer features
    print(f"\nLoading {args.input}...")
    X, y, feature_cols, df = load_and_engineer_features(args.input, args.sample_frac)
    print(f"  Labeled samples: {len(X):,}")
    print(f"  High priority (CVSS≥7): {y.sum():,} ({y.mean()*100:.1f}%)")
    print(f"  Features: {len(feature_cols)}")

    # Temporal split (realistic: train on old, test on new)
    split_year = 2023
    train_mask = df["year"] < split_year
    test_mask = df["year"] >= split_year

    X_train, y_train = X[train_mask], y[train_mask]
    X_test, y_test = X[test_mask], y[test_mask]

    print(f"\n  Temporal split at {split_year}:")
    print(f"  Train: {len(X_train):,} ({y_train.mean()*100:.1f}% positive)")
    print(f"  Test:  {len(X_test):,} ({y_test.mean()*100:.1f}% positive)")

    if len(X_test) < 10 or y_test.nunique() < 2:
        print("ERROR: Insufficient test data. Try --sample-frac 1.0")
        sys.exit(1)

    # Scale
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    # Rule-based baseline
    print("\n--- Rule-Based Baseline ---")
    rule_scores = rule_based_scorer(df[test_mask])
    rule_auc = roc_auc_score(y_test, rule_scores)
    print(f"  AUC-ROC: {rule_auc:.4f}")

    # ML models
    models = {
        "LogisticRegression": LogisticRegression(max_iter=500, random_state=args.seed),
        "RandomForest": RandomForestClassifier(n_estimators=100, random_state=args.seed, n_jobs=-1),
        "GradientBoosting": GradientBoostingClassifier(n_estimators=100, random_state=args.seed),
    }

    results = {"rule_based": {"auc": rule_auc}}

    for name, model in models.items():
        print(f"\n--- {name} ---")
        model.fit(X_train_s, y_train)

        y_prob = model.predict_proba(X_test_s)[:, 1]
        y_pred = model.predict(X_test_s)

        auc = roc_auc_score(y_test, y_prob)
        f1 = f1_score(y_test, y_pred)
        improvement = (auc - rule_auc) * 100

        print(f"  AUC-ROC: {auc:.4f} ({improvement:+.1f}pp vs baseline)")
        print(f"  F1: {f1:.4f}")

        results[name] = {"auc": auc, "f1": f1, "improvement_pp": improvement}

        # Feature importance for tree models
        if hasattr(model, "feature_importances_"):
            importances = sorted(
                zip(feature_cols, model.feature_importances_),
                key=lambda x: -x[1]
            )[:10]
            print(f"  Top features: {', '.join(f'{n} ({v:.3f})' for n, v in importances)}")

    # Summary
    print(f"\n{'='*60}")
    print("SCORING RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"\n{'Model':<25} {'AUC-ROC':>10} {'vs Baseline':>12}")
    print("-" * 50)
    print(f"{'Rule-based (baseline)':<25} {rule_auc:>10.4f} {'—':>12}")
    for name in models:
        r = results[name]
        print(f"{name:<25} {r['auc']:>10.4f} {r['improvement_pp']:>+10.1f}pp")

    best_model = max(models.keys(), key=lambda n: results[n]["auc"])
    best_auc = results[best_model]["auc"]
    best_improvement = results[best_model]["improvement_pp"]
    rq2_pass = best_improvement >= 5.0

    print(f"\nBest model: {best_model} (AUC {best_auc:.4f}, {best_improvement:+.1f}pp)")
    print(f"RQ2 criterion (≥5pp improvement): {'PASS' if rq2_pass else 'FAIL'}")

    # Save results
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "seed": args.seed,
        "train_size": len(X_train),
        "test_size": len(X_test),
        "split_year": split_year,
        "features": len(feature_cols),
        "results": results,
        "best_model": best_model,
        "best_auc": best_auc,
        "best_improvement_pp": best_improvement,
        "rq2_pass": rq2_pass,
    }
    with open(output_dir / f"summary_seed{args.seed}.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved to: {output_dir}/summary_seed{args.seed}.json")


if __name__ == "__main__":
    main()
