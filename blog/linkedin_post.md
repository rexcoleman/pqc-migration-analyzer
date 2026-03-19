# LinkedIn Post — PQC Migration Analyzer

**Your PQC migration plan is 70% "wait."**

I scanned Python's standard library for quantum-vulnerable cryptography. Found 39 findings -- 19 critical Shor-vulnerable primitives (ECDSA, Ed25519, RSA).

Then I trained ML models on 21,142 crypto-related CVEs to score migration priority.

Two findings that should change how you plan:

**1. Classical exploit risk matters more than quantum risk.**
The top predictive features for migration priority are heap overflows, padding oracles, and arbitrary code execution -- NOT Shor vulnerability. Quantum risk ranks 6th. Fix the padding oracles before the RSA key exchange.

**2. 70% of your crypto isn't yours to change.**
I classified every finding by controllability -- who controls whether it can be migrated:
- Library-controlled: ~70% (wait for upstream updates)
- Developer-controlled: ~20% (you can fix today)
- Protocol-controlled: ~8% (wait for standard updates)
- Hardware-controlled: ~2% (replace hardware)

Your migration plan should start with the 20% you control, then track upstream timelines for the rest.

This is the 4th project where controllability analysis produces actionable security architecture insights. The methodology transfers across network IDS, CVE prediction, agent red-teaming, and now crypto migration.

Scanner is open source: https://github.com/rexcoleman/pqc-migration-analyzer

Built with govML v2.5. Total cost: $0.

#PostQuantum #PQC #Cybersecurity #NIST #QuantumComputing #AIForSecurity
