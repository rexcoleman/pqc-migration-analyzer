#!/usr/bin/env python
"""Extract crypto-related CVEs from FP-05's NVD data.

Reuses ~/vuln-prioritization-ml/data/raw/nvd/ (170 batch files, ~338K CVEs)
instead of re-downloading. Filters for crypto-related keywords.

Usage:
    python scripts/extract_crypto_cves.py
    python scripts/extract_crypto_cves.py --min-year 2015
"""

import argparse
import json
import re
import sys
from pathlib import Path

import pandas as pd

NVD_SOURCE = Path.home() / "vuln-prioritization-ml" / "data" / "raw" / "nvd"

# Keywords that indicate crypto-related CVEs
CRYPTO_KEYWORDS = [
    r"\bRSA\b", r"\bECDSA\b", r"\bDSA\b", r"\bECDH\b", r"\bDiffie.Hellman\b",
    r"\bAES\b", r"\bDES\b", r"\b3DES\b", r"\bTripleDES\b", r"\bBlowfish\b",
    r"\bRC4\b", r"\bRC2\b",
    r"\bSHA.?1\b", r"\bSHA.?256\b", r"\bSHA.?512\b", r"\bMD5\b", r"\bMD4\b",
    r"\bcryptograph", r"\bencrypt", r"\bdecrypt", r"\bcipher",
    r"\bcertificate", r"\bX\.509\b", r"\bPKCS\b", r"\bPEM\b",
    r"\bTLS\b", r"\bSSL\b", r"\bOpenSSL\b",
    r"\bkey.?exchange\b", r"\bdigital.?signature\b", r"\bpublic.?key\b",
    r"\bprivate.?key\b", r"\bkey.?size\b", r"\bkey.?length\b",
    r"\bquantum\b", r"\bpost.?quantum\b", r"\bPQC\b",
]

COMPILED_KEYWORDS = [re.compile(kw, re.IGNORECASE) for kw in CRYPTO_KEYWORDS]


def extract_cve_record(vuln: dict) -> dict | None:
    """Extract relevant fields from an NVD vulnerability record."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")

    # Get description
    descriptions = cve.get("descriptions", [])
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    if not desc:
        return None

    # Check if crypto-related
    is_crypto = any(kw.search(desc) for kw in COMPILED_KEYWORDS)
    if not is_crypto:
        # Also check references
        refs = cve.get("references", [])
        ref_text = " ".join(r.get("url", "") + " " + r.get("tags", [""])[0] if r.get("tags") else r.get("url", "") for r in refs)
        is_crypto = any(kw.search(ref_text) for kw in COMPILED_KEYWORDS)

    if not is_crypto:
        return None

    # Extract CVSS
    metrics = cve.get("metrics", {})
    cvss_v31 = metrics.get("cvssMetricV31", [{}])
    cvss_score = cvss_v31[0].get("cvssData", {}).get("baseScore", 0) if cvss_v31 else 0
    cvss_severity = cvss_v31[0].get("cvssData", {}).get("baseSeverity", "") if cvss_v31 else ""

    # Extract CWE
    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    # Published date
    published = cve.get("published", "")[:10]

    # Classify crypto primitives mentioned
    primitives_found = []
    for name, patterns in [
        ("RSA", [r"\bRSA\b"]),
        ("ECDSA", [r"\bECDSA\b", r"\bECC\b", r"\belliptic.curve\b"]),
        ("DH", [r"\bDiffie.Hellman\b", r"\bDH\b", r"\bECDH\b"]),
        ("DSA", [r"\bDSA\b"]),
        ("AES", [r"\bAES\b"]),
        ("DES", [r"\bDES\b", r"\b3DES\b", r"\bTripleDES\b"]),
        ("MD5", [r"\bMD5\b"]),
        ("SHA-1", [r"\bSHA.?1\b"]),
        ("SHA-256", [r"\bSHA.?256\b"]),
        ("RC4", [r"\bRC4\b"]),
        ("TLS/SSL", [r"\bTLS\b", r"\bSSL\b", r"\bOpenSSL\b"]),
        ("X.509", [r"\bX\.509\b", r"\bcertificate\b"]),
    ]:
        if any(re.search(p, desc, re.IGNORECASE) for p in patterns):
            primitives_found.append(name)

    return {
        "cve_id": cve_id,
        "published": published,
        "description": desc[:500],
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cwes": ",".join(cwes),
        "primitives": ",".join(primitives_found),
        "shor_vulnerable": any(p in primitives_found for p in ["RSA", "ECDSA", "DH", "DSA"]),
        "grover_vulnerable": any(p in primitives_found for p in ["AES", "DES", "MD5", "SHA-1", "RC4"]),
    }


def main():
    parser = argparse.ArgumentParser(description="Extract crypto CVEs from NVD data")
    parser.add_argument("--min-year", type=int, default=2010, help="Earliest CVE year")
    parser.add_argument("--output", default="data/processed/crypto_cves.csv", help="Output CSV")
    args = parser.parse_args()

    if not NVD_SOURCE.exists():
        print(f"NVD data not found at {NVD_SOURCE}")
        print("Run FP-05 data ingestion first, or download NVD data manually.")
        sys.exit(1)

    batch_files = sorted(NVD_SOURCE.glob("nvd_batch_*.json"))
    print(f"Processing {len(batch_files)} NVD batch files...")

    records = []
    total_cves = 0

    for batch_file in batch_files:
        with open(batch_file) as f:
            data = json.load(f)

        # Handle both formats: list of vulns or {"vulnerabilities": [...]}
        if isinstance(data, list):
            vulns = data
        else:
            vulns = data.get("vulnerabilities", [])
        total_cves += len(vulns)

        for vuln in vulns:
            record = extract_cve_record(vuln)
            if record and record["published"][:4] >= str(args.min_year):
                records.append(record)

    df = pd.DataFrame(records)

    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    print(f"\nExtraction complete:")
    print(f"  Total CVEs scanned: {total_cves:,}")
    print(f"  Crypto-related: {len(df):,} ({len(df)/total_cves*100:.1f}%)")
    print(f"  Shor-vulnerable: {df['shor_vulnerable'].sum():,}")
    print(f"  Grover-vulnerable: {df['grover_vulnerable'].sum():,}")
    print(f"  Date range: {df['published'].min()} to {df['published'].max()}")
    print(f"\nPrimitives distribution:")
    all_prims = df["primitives"].str.split(",").explode()
    print(all_prims.value_counts().head(15).to_string())
    print(f"\nSaved to: {output_path}")


if __name__ == "__main__":
    main()
