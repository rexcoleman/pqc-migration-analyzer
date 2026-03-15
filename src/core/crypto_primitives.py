"""Post-quantum vulnerability classification for cryptographic primitives.

Maps classical crypto to quantum vulnerability status and NIST PQC replacements.
Source: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA).
"""

from dataclasses import dataclass
from enum import Enum


class QuantumRisk(Enum):
    """Quantum vulnerability level."""
    CRITICAL = "critical"      # Broken by Shor's algorithm (RSA, ECC, DH, DSA)
    HIGH = "high"              # Weakened by Grover's (AES-128, SHA-1, 3DES)
    MEDIUM = "medium"          # Needs larger key (AES-192 → AES-256)
    LOW = "low"                # Quantum-safe at current key sizes (AES-256, SHA-256+)
    SAFE = "safe"              # NIST PQC approved


class Controllability(Enum):
    """Who controls whether this crypto usage can be migrated."""
    DEVELOPER = "developer"          # Direct API call — change the code
    LIBRARY = "library"              # Dependency uses it — wait for upstream
    PROTOCOL = "protocol"            # Standard mandates it — wait for standard update
    HARDWARE = "hardware"            # HSM/TPM locked — replace hardware


@dataclass
class CryptoPrimitive:
    """A cryptographic primitive with quantum vulnerability assessment."""
    name: str
    category: str               # key_exchange, signature, hash, cipher, mac
    quantum_risk: QuantumRisk
    shor_vulnerable: bool       # Broken by Shor's algorithm (asymmetric)
    grover_vulnerable: bool     # Weakened by Grover's algorithm (symmetric)
    nist_replacement: str | None  # NIST PQC recommended replacement
    migration_notes: str


# Master registry of crypto primitives and their quantum status
CRYPTO_REGISTRY: dict[str, CryptoPrimitive] = {
    # === Key Exchange (Shor-vulnerable) ===
    "RSA": CryptoPrimitive(
        "RSA", "key_exchange", QuantumRisk.CRITICAL, True, False,
        "ML-KEM (FIPS 203)", "All RSA key sizes broken by Shor's. Migrate to ML-KEM."),
    "DH": CryptoPrimitive(
        "Diffie-Hellman", "key_exchange", QuantumRisk.CRITICAL, True, False,
        "ML-KEM (FIPS 203)", "DH key exchange broken by Shor's. Migrate to ML-KEM."),
    "ECDH": CryptoPrimitive(
        "ECDH", "key_exchange", QuantumRisk.CRITICAL, True, False,
        "ML-KEM (FIPS 203)", "Elliptic curve DH broken by Shor's. Migrate to ML-KEM."),

    # === Digital Signatures (Shor-vulnerable) ===
    "DSA": CryptoPrimitive(
        "DSA", "signature", QuantumRisk.CRITICAL, True, False,
        "ML-DSA (FIPS 204)", "DSA broken by Shor's. Migrate to ML-DSA or SLH-DSA."),
    "ECDSA": CryptoPrimitive(
        "ECDSA", "signature", QuantumRisk.CRITICAL, True, False,
        "ML-DSA (FIPS 204)", "ECDSA broken by Shor's. Migrate to ML-DSA or SLH-DSA."),
    "Ed25519": CryptoPrimitive(
        "Ed25519", "signature", QuantumRisk.CRITICAL, True, False,
        "ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)", "Ed25519 broken by Shor's."),

    # === Hashes (Grover-weakened) ===
    "MD5": CryptoPrimitive(
        "MD5", "hash", QuantumRisk.HIGH, False, True,
        "SHA-256 or SHA-3", "Already broken classically. Grover halves remaining security."),
    "SHA-1": CryptoPrimitive(
        "SHA-1", "hash", QuantumRisk.HIGH, False, True,
        "SHA-256 or SHA-3", "Collision attacks known. Grover reduces to ~2^80."),
    "SHA-256": CryptoPrimitive(
        "SHA-256", "hash", QuantumRisk.LOW, False, True,
        None, "Grover reduces to ~2^128 — still sufficient. No migration needed."),
    "SHA-384": CryptoPrimitive(
        "SHA-384", "hash", QuantumRisk.LOW, False, True,
        None, "Quantum-safe at current security level."),
    "SHA-512": CryptoPrimitive(
        "SHA-512", "hash", QuantumRisk.LOW, False, True,
        None, "Quantum-safe at current security level."),
    "SHA-3": CryptoPrimitive(
        "SHA-3", "hash", QuantumRisk.SAFE, False, False,
        None, "Quantum-resistant by design."),

    # === Symmetric Ciphers (Grover-weakened) ===
    "3DES": CryptoPrimitive(
        "3DES", "cipher", QuantumRisk.HIGH, False, True,
        "AES-256", "Effective 112-bit key → ~56-bit post-Grover. Migrate immediately."),
    "AES-128": CryptoPrimitive(
        "AES-128", "cipher", QuantumRisk.MEDIUM, False, True,
        "AES-256", "Grover reduces to ~64-bit effective. Upgrade to AES-256."),
    "AES-256": CryptoPrimitive(
        "AES-256", "cipher", QuantumRisk.LOW, False, True,
        None, "Grover reduces to ~128-bit — still sufficient. No migration needed."),
    "ChaCha20": CryptoPrimitive(
        "ChaCha20", "cipher", QuantumRisk.LOW, False, True,
        None, "256-bit key. Grover reduces to ~128-bit. Sufficient."),

    # === PQC Standards (Safe) ===
    "ML-KEM": CryptoPrimitive(
        "ML-KEM", "key_exchange", QuantumRisk.SAFE, False, False,
        None, "NIST FIPS 203. Quantum-safe key encapsulation."),
    "ML-DSA": CryptoPrimitive(
        "ML-DSA", "signature", QuantumRisk.SAFE, False, False,
        None, "NIST FIPS 204. Quantum-safe digital signature."),
    "SLH-DSA": CryptoPrimitive(
        "SLH-DSA", "signature", QuantumRisk.SAFE, False, False,
        None, "NIST FIPS 205. Hash-based quantum-safe signature."),
}


# Python library patterns → primitive mapping
PYTHON_CRYPTO_PATTERNS: dict[str, list[str]] = {
    "RSA": [
        r"rsa\.generate_private_key",
        r"RSA\.generate",
        r"PKCS1_v1_5",
        r"PKCS1_OAEP",
        r"from\s+Crypto\.PublicKey\s+import\s+RSA",
        r"from\s+cryptography.*rsa",
    ],
    "ECDSA": [
        r"ec\.generate_private_key",
        r"ECDSA",
        r"ec\.SECP256R1",
        r"ec\.SECP384R1",
        r"from\s+cryptography.*ec\b",
        r"from\s+ecdsa\s+import",
    ],
    "Ed25519": [
        r"Ed25519PrivateKey",
        r"ed25519",
        r"from\s+cryptography.*ed25519",
    ],
    "DH": [
        r"dh\.generate_parameters",
        r"DHParameterNumbers",
        r"from\s+cryptography.*dh\b",
    ],
    "DSA": [
        r"dsa\.generate_private_key",
        r"from\s+cryptography.*dsa\b",
        r"from\s+Crypto\.PublicKey\s+import\s+DSA",
    ],
    "MD5": [
        r"hashlib\.md5",
        r"MD5\.new",
        r"hashes\.MD5",
    ],
    "SHA-1": [
        r"hashlib\.sha1",
        r"SHA\.new",
        r"SHA1\.new",
        r"hashes\.SHA1",
    ],
    "3DES": [
        r"algorithms\.TripleDES",
        r"DES3\.new",
        r"triple_des",
    ],
    "AES-128": [
        r"AES\.new.*16\)",   # 16-byte = 128-bit key
        r"algorithms\.AES.*key_size.*128",
    ],
    "AES-256": [
        r"AES\.new.*32\)",   # 32-byte = 256-bit key
        r"algorithms\.AES.*key_size.*256",
    ],
}
