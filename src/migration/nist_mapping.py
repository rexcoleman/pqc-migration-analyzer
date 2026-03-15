"""NIST PQC migration mapping.

Maps detected quantum-vulnerable primitives to NIST-approved replacements
with migration difficulty scoring based on controllability analysis.
"""

from dataclasses import dataclass

from ..core.crypto_primitives import CRYPTO_REGISTRY, QuantumRisk, Controllability
from ..detection.regex_scanner import CryptoFinding


@dataclass
class MigrationRecommendation:
    """A specific migration action for a detected primitive."""
    finding: CryptoFinding
    current_primitive: str
    recommended_replacement: str
    migration_difficulty: str    # low, medium, high, very_high
    controllability: str         # developer, library, protocol, hardware
    action: str                  # Human-readable migration instruction
    nist_standard: str           # FIPS reference


# Heuristics for controllability classification based on code patterns
LIBRARY_PATTERNS = [
    "requests", "urllib", "httplib", "ssl", "paramiko", "fabric",
    "boto3", "google.cloud", "azure", "jwt", "oauth",
]

PROTOCOL_PATTERNS = [
    "ssl.PROTOCOL", "TLSVersion", "PROTOCOL_TLS", "SSH",
]


def classify_controllability(finding: CryptoFinding) -> Controllability:
    """Determine who controls whether this crypto usage can be changed."""
    line = finding.line_content.lower()
    file_path = finding.file_path.lower()

    # Protocol-level: SSL/TLS configuration
    if any(p.lower() in line for p in PROTOCOL_PATTERNS):
        return Controllability.PROTOCOL

    # Library-level: imported from a third-party library
    if any(lib in file_path or lib in line for lib in LIBRARY_PATTERNS):
        return Controllability.LIBRARY

    # Default: developer-controlled (direct API call)
    return Controllability.DEVELOPER


def get_migration_difficulty(controllability: Controllability, quantum_risk: QuantumRisk) -> str:
    """Score migration difficulty based on controllability + risk level."""
    difficulty_matrix = {
        (Controllability.DEVELOPER, QuantumRisk.CRITICAL): "medium",
        (Controllability.DEVELOPER, QuantumRisk.HIGH): "low",
        (Controllability.DEVELOPER, QuantumRisk.MEDIUM): "low",
        (Controllability.LIBRARY, QuantumRisk.CRITICAL): "high",
        (Controllability.LIBRARY, QuantumRisk.HIGH): "medium",
        (Controllability.LIBRARY, QuantumRisk.MEDIUM): "low",
        (Controllability.PROTOCOL, QuantumRisk.CRITICAL): "very_high",
        (Controllability.PROTOCOL, QuantumRisk.HIGH): "high",
        (Controllability.HARDWARE, QuantumRisk.CRITICAL): "very_high",
    }
    return difficulty_matrix.get((controllability, quantum_risk), "medium")


def generate_recommendations(findings: list[CryptoFinding]) -> list[MigrationRecommendation]:
    """Generate migration recommendations for all findings."""
    recommendations = []

    for finding in findings:
        info = CRYPTO_REGISTRY.get(finding.primitive)
        if not info or info.quantum_risk in (QuantumRisk.LOW, QuantumRisk.SAFE):
            continue  # No migration needed

        controllability = classify_controllability(finding)
        difficulty = get_migration_difficulty(controllability, info.quantum_risk)

        replacement = info.nist_replacement or "Upgrade to larger key size"
        nist_ref = ""
        if "ML-KEM" in (replacement or ""):
            nist_ref = "FIPS 203"
        elif "ML-DSA" in (replacement or ""):
            nist_ref = "FIPS 204"
        elif "SLH-DSA" in (replacement or ""):
            nist_ref = "FIPS 205"

        action = _generate_action(finding, info, controllability)

        recommendations.append(MigrationRecommendation(
            finding=finding,
            current_primitive=finding.primitive,
            recommended_replacement=replacement,
            migration_difficulty=difficulty,
            controllability=controllability.value,
            action=action,
            nist_standard=nist_ref,
        ))

    return recommendations


def _generate_action(finding: CryptoFinding, info, controllability: Controllability) -> str:
    """Generate human-readable migration action."""
    if controllability == Controllability.DEVELOPER:
        return f"Replace {finding.primitive} with {info.nist_replacement} in {finding.file_path}:{finding.line_number}"
    elif controllability == Controllability.LIBRARY:
        return f"Monitor upstream library for PQC support. {finding.primitive} used via library dependency."
    elif controllability == Controllability.PROTOCOL:
        return f"Await protocol standard update for PQC support. {finding.primitive} mandated by protocol."
    else:
        return f"Hardware replacement required. {finding.primitive} locked to hardware module."
