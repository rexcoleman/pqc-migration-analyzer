"""Basic tests for FP-03 PQC migration analyzer."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_crypto_registry():
    from src.core.crypto_primitives import CRYPTO_REGISTRY, QuantumRisk
    assert "RSA" in CRYPTO_REGISTRY
    assert CRYPTO_REGISTRY["RSA"].quantum_risk == QuantumRisk.CRITICAL
    assert CRYPTO_REGISTRY["RSA"].shor_vulnerable is True
    assert CRYPTO_REGISTRY["AES-256"].quantum_risk == QuantumRisk.LOW


def test_scanner_on_empty_dir(tmp_path):
    from src.detection.regex_scanner import scan_directory
    result = scan_directory(str(tmp_path))
    assert result.files_scanned == 0
    assert result.total_findings == 0


def test_scanner_finds_rsa(tmp_path):
    from src.detection.regex_scanner import scan_directory
    (tmp_path / "test.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key()")
    result = scan_directory(str(tmp_path))
    assert result.total_findings > 0
    assert any(f.primitive == "RSA" for f in result.findings)


def test_migration_mapping():
    from src.detection.regex_scanner import CryptoFinding
    from src.migration.nist_mapping import generate_recommendations
    finding = CryptoFinding("test.py", 1, "rsa.generate_private_key()", "RSA", "key_exchange", "critical", r"rsa\.generate", "high")
    recs = generate_recommendations([finding])
    assert len(recs) > 0
    assert "ML-KEM" in recs[0].recommended_replacement


def test_findings_exists():
    assert Path("FINDINGS.md").exists()
