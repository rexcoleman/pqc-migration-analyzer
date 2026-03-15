#!/usr/bin/env python
"""Generate publication-ready figures for FP-03."""

import sys
from pathlib import Path

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
except ImportError:
    print("pip install matplotlib numpy")
    sys.exit(1)


def primitives_chart():
    """Bar chart: crypto primitive distribution in NVD CVEs."""
    primitives = ["TLS/SSL", "X.509", "RSA", "RC4", "MD5", "AES", "ECDSA", "DSA", "DH", "SHA-1", "DES"]
    counts = [4002, 3431, 517, 251, 205, 191, 146, 139, 90, 70, 54]
    risks = ["critical", "critical", "critical", "high", "high", "low", "critical", "critical", "critical", "high", "high"]
    colors = {"critical": "#e74c3c", "high": "#e67e22", "low": "#2ecc71"}

    fig, ax = plt.subplots(figsize=(12, 6))
    bar_colors = [colors[r] for r in risks]
    bars = ax.barh(primitives[::-1], counts[::-1], color=bar_colors[::-1], edgecolor="#2c3e50", linewidth=0.8)

    for bar, count in zip(bars, counts[::-1]):
        ax.text(bar.get_width() + 50, bar.get_y() + bar.get_height()/2,
                f"{count:,}", va="center", fontsize=10)

    ax.set_xlabel("CVE Count", fontsize=12)
    ax.set_title("Quantum-Vulnerable Crypto Primitives in NVD (21,142 crypto CVEs)", fontsize=13, fontweight="bold")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    legend_elements = [
        mpatches.Patch(facecolor="#e74c3c", label="Critical (Shor-vulnerable)"),
        mpatches.Patch(facecolor="#e67e22", label="High (Grover-weakened)"),
        mpatches.Patch(facecolor="#2ecc71", label="Low (quantum-safe at current key size)"),
    ]
    ax.legend(handles=legend_elements, loc="lower right", fontsize=9)

    plt.tight_layout()
    for p in ["outputs/figures/primitives_distribution.png", "blog/images/primitives_distribution.png"]:
        Path(p).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(p, dpi=150)
    print("Generated: primitives_distribution.png")


def scoring_chart():
    """Bar chart: ML model comparison for priority scoring."""
    models = ["Rule-based\n(baseline)", "Logistic\nRegression", "Random\nForest", "Gradient\nBoosting"]
    aucs = [0.4941, 0.6253, 0.5686, 0.6345]
    improvements = [0, 13.1, 7.4, 14.0]
    colors = ["#95a5a6", "#3498db", "#3498db", "#2ecc71"]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(models, aucs, color=colors, edgecolor="#2c3e50", linewidth=1.2)

    for bar, auc, imp in zip(bars, aucs, improvements):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f"{auc:.4f}", ha="center", va="bottom", fontweight="bold", fontsize=11)
        if imp > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() - 0.03,
                    f"+{imp:.1f}pp", ha="center", va="top", fontsize=9, color="white", fontweight="bold")

    ax.axhline(y=0.5, color="#e74c3c", linestyle="--", linewidth=1, alpha=0.5)
    ax.text(3.5, 0.505, "random chance", fontsize=8, color="#e74c3c", ha="right", style="italic")

    ax.set_ylabel("AUC-ROC", fontsize=12)
    ax.set_title("PQC Migration Priority Scoring: ML vs Rule-Based", fontsize=13, fontweight="bold")
    ax.set_ylim(0.4, 0.72)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    ax.text(0.98, 0.95, "Best: GradientBoosting\n+14.0pp vs baseline",
            transform=ax.transAxes, fontsize=11, fontweight="bold",
            ha="right", va="top",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#2ecc71", alpha=0.3))

    plt.tight_layout()
    for p in ["outputs/figures/scoring_comparison.png", "blog/images/scoring_comparison.png"]:
        plt.savefig(p, dpi=150)
    print("Generated: scoring_comparison.png")


def controllability_chart():
    """Pie chart: controllability distribution of crypto migrations."""
    labels = ["Library-controlled\n(~70%)", "Developer-controlled\n(~20%)", "Protocol-controlled\n(~8%)", "Hardware-controlled\n(~2%)"]
    sizes = [70, 20, 8, 2]
    colors = ["#e67e22", "#2ecc71", "#e74c3c", "#8e44ad"]
    explode = (0, 0.05, 0, 0)

    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, texts, autotexts = ax.pie(
        sizes, explode=explode, labels=labels, colors=colors,
        autopct='%1.0f%%', startangle=90, textprops={'fontsize': 11},
    )
    for at in autotexts:
        at.set_fontweight("bold")
        at.set_color("white")

    ax.set_title("Who Controls Your Crypto Migration?", fontsize=14, fontweight="bold", pad=20)

    # Annotation
    ax.text(0, -1.4, "70% of crypto in your codebase isn't yours to change.\nMost migrations depend on upstream library updates.",
            ha="center", fontsize=10, style="italic", color="#7f8c8d")

    plt.tight_layout()
    for p in ["outputs/figures/controllability_pie.png", "blog/images/controllability_pie.png"]:
        plt.savefig(p, dpi=150)
    print("Generated: controllability_pie.png")


def cross_domain_chart():
    """4-domain controllability analysis comparison."""
    domains = ["FP-01\nNetwork IDS", "FP-05\nCVE Prediction", "FP-02\nAgent Red-Team", "FP-03\nCrypto Migration"]
    attacker = [57, 13, 3, 20]  # attacker-controlled features/inputs
    defender = [14, 11, 2, 70]   # defender-observable or controlled
    x = np.arange(len(domains))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    bars1 = ax.bar(x - width/2, attacker, width, label="Attacker-Controlled", color="#e74c3c", edgecolor="#2c3e50")
    bars2 = ax.bar(x + width/2, defender, width, label="Defender-Observable", color="#3498db", edgecolor="#2c3e50")

    for bar, val in zip(bars1, attacker):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, str(val), ha="center", fontsize=10, fontweight="bold")
    for bar, val in zip(bars2, defender):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, str(val), ha="center", fontsize=10, fontweight="bold")

    ax.set_ylabel("Count (features / input types / %)", fontsize=11)
    ax.set_title("Adversarial Control Analysis: 4 Domains, 1 Methodology", fontsize=13, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(domains, fontsize=10)
    ax.legend(fontsize=11)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    for p in ["outputs/figures/cross_domain_aca.png", "blog/images/cross_domain_aca.png"]:
        plt.savefig(p, dpi=150)
    print("Generated: cross_domain_aca.png")


if __name__ == "__main__":
    print("Generating FP-03 figures...")
    primitives_chart()
    scoring_chart()
    controllability_chart()
    cross_domain_chart()
    print("Done.")
