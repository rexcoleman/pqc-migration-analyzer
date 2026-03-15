"""Regex-based crypto primitive detection.

Fast first pass: scan Python files for known crypto API patterns.
High recall, moderate precision — AST parser refines results.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from ..core.crypto_primitives import PYTHON_CRYPTO_PATTERNS, CRYPTO_REGISTRY, QuantumRisk


@dataclass
class CryptoFinding:
    """A single detected crypto primitive usage."""
    file_path: str
    line_number: int
    line_content: str
    primitive: str            # e.g., "RSA", "SHA-1"
    category: str             # e.g., "key_exchange", "hash"
    quantum_risk: str         # e.g., "critical", "high"
    pattern_matched: str      # The regex that matched
    confidence: str           # "high" (exact API match) or "medium" (keyword)


@dataclass
class ScanResult:
    """Aggregated results from scanning a codebase."""
    root_path: str
    files_scanned: int
    files_with_findings: int
    total_findings: int
    findings: list[CryptoFinding] = field(default_factory=list)
    by_primitive: dict[str, int] = field(default_factory=dict)
    by_risk: dict[str, int] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return self.by_risk.get("critical", 0)

    @property
    def high_count(self) -> int:
        return self.by_risk.get("high", 0)


def scan_file(file_path: Path) -> list[CryptoFinding]:
    """Scan a single Python file for crypto primitive usage."""
    findings = []
    try:
        content = file_path.read_text(errors="ignore")
        lines = content.splitlines()
    except Exception:
        return findings

    for primitive, patterns in PYTHON_CRYPTO_PATTERNS.items():
        info = CRYPTO_REGISTRY.get(primitive)
        if not info:
            continue

        for pattern in patterns:
            compiled = re.compile(pattern)
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    findings.append(CryptoFinding(
                        file_path=str(file_path),
                        line_number=i,
                        line_content=line.strip(),
                        primitive=primitive,
                        category=info.category,
                        quantum_risk=info.quantum_risk.value,
                        pattern_matched=pattern,
                        confidence="high",
                    ))

    return findings


def scan_directory(root: str, exclude_dirs: set[str] | None = None) -> ScanResult:
    """Scan all Python files in a directory tree."""
    root_path = Path(root)
    exclude = exclude_dirs or {".git", "__pycache__", ".tox", "venv", ".venv", "node_modules"}

    all_findings = []
    files_scanned = 0
    files_with = set()

    for py_file in _iter_python_files(root_path, exclude):
        files_scanned += 1
        findings = scan_file(py_file)
        if findings:
            files_with.add(str(py_file))
            all_findings.extend(findings)

    # Aggregate
    by_primitive: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    for f in all_findings:
        by_primitive[f.primitive] = by_primitive.get(f.primitive, 0) + 1
        by_risk[f.quantum_risk] = by_risk.get(f.quantum_risk, 0) + 1

    return ScanResult(
        root_path=str(root_path),
        files_scanned=files_scanned,
        files_with_findings=len(files_with),
        total_findings=len(all_findings),
        findings=all_findings,
        by_primitive=by_primitive,
        by_risk=by_risk,
    )


def _iter_python_files(root: Path, exclude: set[str]) -> Iterator[Path]:
    """Yield all .py files under root, excluding specified directories."""
    for path in root.rglob("*.py"):
        if any(part in exclude for part in path.parts):
            continue
        yield path
