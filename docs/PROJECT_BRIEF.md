# PROJECT BRIEF

<!-- version: 1.0 -->
<!-- created: 2026-03-14 -->
<!-- last_validated_against: adversarial-ids-ml (FP-01) -->

> **Authority Hierarchy**
>
> | Priority | Document | Role |
> |----------|----------|------|
> | Tier 1 | `{{TIER1_DOC}}` | Primary spec — highest authority |
> | Tier 2 | `{{TIER2_DOC}}` | Clarifications — cannot override Tier 1 |
> | Tier 3 | `{{TIER3_DOC}}` | Advisory only — non-binding if inconsistent with Tier 1/2 |
> | Contract | This document | Implementation detail — subordinate to all tiers above |
>
> **Conflict rule:** When a higher-tier document and this contract disagree, the higher tier wins.
> Update this contract via `CONTRACT_CHANGE` or align implementation to the higher tier.

### Companion Contracts

**Upstream (this contract depends on):**
- None — this is a foundational project definition document.

**Downstream (depends on this contract):**
- See [HYPOTHESIS_CONTRACT](../core/HYPOTHESIS_CONTRACT.tmpl.md) for research questions → testable hypotheses
- See [EXPERIMENT_CONTRACT](../core/EXPERIMENT_CONTRACT.tmpl.md) for experiment design derived from thesis
- See [DATA_CONTRACT](../core/DATA_CONTRACT.tmpl.md) for dataset/workload definition
- See [PUBLICATION_PIPELINE](PUBLICATION_PIPELINE.tmpl.md) for publication target and content pillar
- See [IMPLEMENTATION_PLAYBOOK](../management/IMPLEMENTATION_PLAYBOOK.tmpl.md) for phase execution
- See [DECISION_LOG](../management/DECISION_LOG.tmpl.md) for architectural decisions

## Customization Guide

Fill in all `{{PLACEHOLDER}}` values before use. Delete this section when customization is complete.

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `{{PROJECT_NAME}}` | Project name | Adversarial ML on IDS |
| `{{THESIS_STATEMENT}}` | One-sentence thesis | Feature controllability constraints make adversarial attacks on IDS detectable |
| `{{TIER1_DOC}}` | Tier 1 authority document | Course spec (academic) or null (self-directed) |
| `{{TIER2_DOC}}` | Tier 2 authority document | FAQ or null |
| `{{TIER3_DOC}}` | Tier 3 authority document | Advisory or null |

---

## 1) Thesis Statement

**{{THESIS_STATEMENT}}**

*(One sentence: what are you building and what will it prove? This is the project's reason to exist. Every design decision, experiment, and finding should trace back to this statement.)*

---

## 2) Research Questions

| # | Question | How You'll Answer It | Success Criteria |
|---|----------|---------------------|-----------------|
| RQ1 | | | |
| RQ2 | | | |
| RQ3 | | | |

*(Each RQ should be answerable with data/experiments. Avoid questions that require external validation or opinion.)*

---

## 3) Scope Definition

### In Scope
- *(what you will build/investigate)*

### Out of Scope
- *(what you explicitly will NOT do — prevents scope creep)*

### Stretch Goals (only if core scope complete)
- *(nice-to-haves that don't block the core deliverable)*

---

## 4) Data / Workload Definition

| Property | Value |
|----------|-------|
| **Dataset or workload** | *(name, version)* |
| **Source** | *(URL, portal, API, Kaggle)* |
| **Download method** | *(direct URL / API / Kaggle CLI / manual portal / scp)* |
| **Size** | *(rows × columns, or file size)* |
| **License** | *(MIT, CC BY, proprietary, etc.)* |
| **Known issues** | *(column quirks, missing values, class imbalance, etc.)* |

*(If download method is not a direct URL, document the manual steps required. See ISS-007.)*

---

## 5) Skill Cluster Targets

Which clusters does this project advance? *(from skills_development_guide.md)*

| Cluster | Current Level | Target After Project | How This Project Advances It |
|---------|-------------|---------------------|---------------------------|
| **L** (AI System) | | | |
| **S** (AI Security) | | | |
| **P** (Product Eng.) | | | |
| **D** (Tech Depth) | | | |
| **V** (Distribution) | | | |

---

## 6) Publication Target

| Property | Value |
|----------|-------|
| **Blog post title (working)** | |
| **Content pillar** | *(AI Security Architecture / ML Systems Governance / Builder-in-Public)* |
| **Conference CFP (if applicable)** | *(BSides, DEF CON AI Village, etc.)* |
| **Target publish date** | |

---

## 7) Technical Approach

### Architecture Overview

*(High-level description of the system you'll build. Include a preliminary architecture diagram if possible.)*

### Key Technical Decisions (pre-project)

| Decision | Options Considered | Choice | Rationale |
|----------|-------------------|--------|-----------|
| | | | |

*(These decisions seed the DECISION_LOG. More will be added during execution.)*

---

## 8) Definition of Done

- [ ] All research questions answered with evidence
- [ ] All code in version-controlled repo (GitHub)
- [ ] FINDINGS.md written with key results
- [ ] Architecture diagram created
- [ ] DECISION_LOG has all tradeoff decisions from every phase
- [ ] PUBLICATION_PIPELINE.md filled and draft started
- [ ] LESSONS_LEARNED.md updated with issues and wins
- [ ] govML templates improved based on project friction

---

## 9) Change Control Triggers

The following changes require a `CONTRACT_CHANGE` commit:

- Thesis statement
- Research questions (additions, removals, or significant rewording)
- Scope changes (in/out of scope)
- Dataset or workload
- Publication target
