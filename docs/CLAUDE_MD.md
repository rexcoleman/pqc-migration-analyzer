# Post-Quantum Cryptography Migration Analyzer — Claude Code Context

> **govML v2.5** | Profile: blog-track (blog-track)

## Project Purpose

I Built a PQC Migration Scanner: Here's What Your Codebase Is Hiding

- **Context:** Self-directed research (Post-Quantum Cryptography Migration Analyzer)
- **Profile:** blog-track
- **Python:** 3.11 | **Env:** pqc-analyzer
- **Brand pillar:** AI Security Architecture
- **Workload type:** cpu_bound

## Authority Hierarchy

| Tier | Source | Path |
|------|--------|------|
| 1 (highest) | Project Brief | `docs/PROJECT_BRIEF.md` |
| 2 | — | No external FAQ |
| 3 | Advisory methodology | `docs/ADVERSARIAL_EVALUATION.md` |
| Contracts | Governance docs | `docs/*.md` |

## Current Phase

**Phase:** 0 — Environment & Setup

### Phase Progression

| Phase | Name | Status |
|-------|------|--------|
| 0 | Phase 0 — Environment & Data Acquisition | **CURRENT** |
| 1 | Phase 1 — Crypto Detection Engine | Not started |
| 2 | Phase 2 — Priority Scoring | Not started |
| 3 | Phase 3 — Migration Recommendations & Findings | Not started |

## Experiment Summary

Seeds: [42, 123, 456]

- **crypto_detection:** regex_scanner, ast_parser, ml_classifier
- **priority_scoring:** rule_based, ml_scorer, hybrid
- **migration_recommendation:** nist_mapping, risk_weighted

## Key Files

| File | Purpose |
|------|---------|
| `docs/PROJECT_BRIEF.md` | **READ FIRST** — thesis, RQs, scope |
| `docs/PUBLICATION_PIPELINE.md` | Blog post governance + distribution |
| `docs/DECISION_LOG.md` | All tradeoff decisions (mandatory at every phase gate) |
| `config/base.yaml` | Experiment configuration |

## AI Division of Labor

### Permitted
- **Claude Code:** Coding copilot, test generation, script execution, NVD API ingestion
  - Prohibited: Must not interpret migration risk levels (human security judgment). Must not scan private repos without authorization.

### Prohibited (all projects)
- Modifying PROJECT_BRIEF thesis or research questions
- Writing interpretation/analysis prose (human insight)

## Conventions

- **Seeds:** [42, 123, 456]
- **Smoke test first:** `--sample-frac 0.01` or `--dry-run` before full runs
- **Decisions:** Log in DECISION_LOG at every phase gate (mandatory per v2.5)
- **Commit early:** Phase 0a scaffold → commit → Phase 0b research → commit
