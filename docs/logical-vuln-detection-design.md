# Logical Vulnerability Detection — Design Document

**Status:** Design proposal (not yet implemented)  
**Target version:** Post-v0.2  
**Paper limitation addressed:** Liu et al. (2026) explicitly state the system "does not yet support the detection of logical flaws" and note that core/official institutional websites are most prone to these.

---

## 1. Problem Statement

The current LLM-EduAttackGraph system detects **technical vulnerabilities** (buffer overflows, SQL injection, weak credentials, unauthorized endpoint access) by matching fingerprint vectors against a historical CVE knowledge base. It cannot detect **logical/business-flow vulnerabilities** because:

- Logical flaws are not caused by a specific component version or configuration — they arise from **how components interact at runtime**
- The Awesome-POC corpus does not contain logical flaw signatures (it is CVE-centric)
- A single-scan fingerprint cannot capture multi-step business flows (login → session → action → authorization check)

The paper's exact words: *"the framework does not yet support the detection of logical flaws... future research could integrate access control policy mining and behavioral sequence analysis."*

---

## 2. Key Insight: We Already Have the Data

The LLM-EduAttackGraph system collects and stores, **per target over time**:

| Data already collected | Where stored |
|------------------------|-------------|
| All `VALIDATED` findings per target, with their category | `findings` table, `status=VALIDATED` |
| Evidence type per finding (`OBSERVED`, `RETRIEVED`, `INFERRED`) | `findings.evidence_type` |
| Port/service observations per scan | `ports`, `services` tables |
| Fingerprint raw data (open endpoints, headers, CMS) | `fingerprints.raw_data` JSON |
| Timestamps of each scan | `scans.created_at` |
| Full audit trail of every state change | `audit_events` |

Logical flaws reveal themselves as **cross-finding inconsistencies over multiple scans of the same target**. We do not need to discover them from scratch — we need to **detect contradictions in what we already know**.

---

## 3. Proposed Detection Approach: Cross-Finding Consistency Checker

### 3.1 Architecture

```
After each scan completes (status → completed):
    └─► ConsistencyChecker.run(target_id)
            │
            ├─► Load all VALIDATED findings for this target (all-time)
            ├─► Load latest fingerprint raw_data for this target
            │
            ├─► Apply rule set (Section 4)
            │       ├── Rule A: Auth-Bypass Persistence
            │       ├── Rule B: Credential/Token Chain
            │       ├── Rule C: Info-Disclosure ↔ Attack Path
            │       └── Rule D: Missing Authentication Context
            │
            └─► For each triggered rule:
                    Create Finding(
                        evidence_type = LOGICAL_FLAG,   ← new enum value
                        status = PENDING_REVIEW,
                        category = O4_UNAUTHORIZED | O5_TOKEN_TAMPERING,
                        title = "Logical Inconsistency: <rule name>",
                        description = human-readable explanation,
                        validation_required = True
                    )
                    Create AuditEvent("logical_flag_generated", rule=..., scan_id=...)
```

### 3.2 New Evidence Type

Add `LOGICAL_FLAG` to the `EvidenceType` enum:

```python
class EvidenceType(str, PyEnum):
    OBSERVED  = "observed"      # Direct reconnaissance
    RETRIEVED = "retrieved"     # From knowledge base (RAG)
    INFERRED  = "inferred"      # LLM inference
    VALIDATED = "validated"     # Human-accepted
    LOGICAL_FLAG = "logical_flag"  # NEW: cross-finding inconsistency signal
```

`LOGICAL_FLAG` findings start as `PENDING_REVIEW` — they are **never** auto-validated. They indicate "the system detected an inconsistency; a human should investigate."

---

## 4. Detection Rule Set (v1)

Each rule operates on the set of `VALIDATED` findings for a given `target_id` plus the current scan's `fingerprint.raw_data`.

### Rule A — Auth-Bypass Persistence

**Trigger:** A `VALIDATED` finding with category `O4_UNAUTHORIZED` exists for endpoint X. The current scan's fingerprint still shows endpoint X reachable without credential evidence (no `Authorization` header challenge observed, no login redirect detected).

**Signal:** The unauthorized access path that was previously confirmed is still present — but may not have been remediated.

**Output finding title:** `"Logical Inconsistency: Unpatched Unauthorized Access Path Still Observable"`

**Why it matters:** Validates whether O4 remediation actually occurred, or whether the finding was validated and forgotten.

---

### Rule B — Credential/Token Inconsistency

**Trigger:** A `VALIDATED` O3 (Weak Password) finding AND a `VALIDATED` O5 (Token Tampering) finding exist for the same target.

**Signal:** A weak credential flow (O3) upstream of a token-issuing endpoint creates a compound attack path — an attacker who exploits weak credentials can then tamper with the token issued. The two findings together are more severe than either alone.

**Output finding title:** `"Logical Inconsistency: Weak Credential → Token Tampering Attack Chain"`

**Severity escalation:** Each finding may be `medium` individually; the compound path should be flagged `high`.

---

### Rule C — Information Disclosure Enabling Attack Path

**Trigger:** A `VALIDATED` O6 (Info Disclosure) finding exists AND the disclosed information matches technology/endpoint data referenced in any other `VALIDATED` finding of category O1, O2, or O4.

**Example:** O6 finding: "Spring actuator `/actuator/env` exposes DB credentials." O2 finding (separate scan): "SQL injection in login endpoint." → The disclosed credentials could be used to bypass or amplify the SQL injection.

**Output finding title:** `"Logical Inconsistency: Info Disclosure Enables <other category> Attack Path"`

---

### Rule D — Missing Authentication Context

**Trigger:** The current fingerprint's `raw_data` shows endpoints under `/admin/`, `/api/v1/internal/`, or similar high-privilege paths responding with HTTP 200 (no auth challenge). No `VALIDATED` O4 finding exists yet for this target. No login page is detected in the fingerprint.

**Signal:** An endpoint that should require authentication appears to be responding without it, but no human has validated this. This is a *prospective* flag, not a contradiction of existing knowledge.

**Output finding title:** `"Logical Flag: Potentially Unauthenticated High-Privilege Endpoint"`

**Note:** This rule generates findings without any existing VALIDATED context — it is pattern-based on the fingerprint alone, not a cross-finding inconsistency. It is included here because it fills the gap the paper describes: "core/official institutional websites are more prone to logical flaws." Admin paths responding without auth are exactly this class of flaw.

---

## 5. Implementation Plan (Scoped)

### Phase 1 — Data Model (1 day)
- Add `LOGICAL_FLAG` to `EvidenceType` enum in `models/models.py`
- Add `logical_flags` JSON column to `findings` table (stores: rule_id, triggered_by_finding_ids, scan_id)
- DB schema recreate (no Alembic yet — drop + restart)

### Phase 2 — ConsistencyChecker service (2 days)
- Create `backend/app/services/consistency/checker.py`
- Implement `ConsistencyChecker` class with `run(target_id, current_scan_id, db)` async method
- Implement each of the four rules (Rules A-D)
- All rule outputs are `Finding` rows with `evidence_type=LOGICAL_FLAG`, `status=PENDING_REVIEW`

### Phase 3 — Integration (1 day)
- Hook `ConsistencyChecker.run()` into the end of the scan pipeline in `scans.py` (after status → `completed`)
- Add `GET /api/v1/findings?evidence_type=logical_flag` filter support (already partially there)

### Phase 4 — Frontend (1 day)
- Add `LOGICAL_FLAG` badge style to `Findings.tsx` (distinct color — orange/amber)
- Add plain-English explainer card in `vulnExplainer.ts` for logical flag findings
- Show the `triggered_by_finding_ids` as "Related findings" links

---

## 6. What This Does NOT Do

| Out of scope | Reason |
|-------------|--------|
| Dynamic application logic testing | Requires authenticated session replay — not safe to automate |
| Business rule mining | Requires source code or formal specification |
| Multi-step exploit chain validation | Would constitute autonomous exploitation (prohibited) |
| Discovering new logical flaws not related to existing VALIDATED findings | Rules A-C require prior VALIDATED context; only Rule D is prospective |

The design deliberately stays within the system's existing safety boundaries: **no autonomous exploitation, no unauthenticated probing beyond what fingerprinting already does, all outputs require human review.**

---

## 7. Example Output

```json
{
  "id": "flag-abc123",
  "title": "Logical Inconsistency: Unpatched Unauthorized Access Path Still Observable",
  "evidence_type": "logical_flag",
  "status": "pending_review",
  "category": "O4_UNAUTHORIZED",
  "severity": "high",
  "description": "A VALIDATED finding (ID: finding-xyz789, validated 2026-09-15) confirmed unauthorized access to /admin/api on this target. The current scan (2026-10-01) still observes /admin/api responding with HTTP 200 without credential challenge. This may indicate the vulnerability was not remediated, or that a different code path is still exposed.",
  "logical_flags": {
    "rule_id": "A",
    "triggered_by_finding_ids": ["finding-xyz789"],
    "current_scan_id": "scan-456",
    "days_since_validation": 16
  },
  "validation_required": true,
  "plain_english": "A security problem that was confirmed earlier still seems to be present. Someone should check if the fix was actually applied."
}
```

---

## 8. Relation to Paper's Future Work

The paper states as future work:
> *"access control policy mining and behavioral sequence analysis"*

This design addresses the access-control dimension (Rules A, B, D) at a scope appropriate for a single-researcher personal project — without requiring full policy mining infrastructure. The behavioral sequence dimension (multi-step flow testing) is explicitly left out of scope as it requires session replay capabilities.

---

*Design document version 1.0 — 2026-10-02*  
*Author: Athul Titus*  
*Status: Awaiting review before implementation*
