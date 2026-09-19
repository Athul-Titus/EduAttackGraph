"""
Findings API — Human-in-the-loop validation workflow

Paper: "human-in-the-loop assistant"
Every finding starts as POTENTIAL (INFERRED). Human validates → VALIDATED/REJECTED.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import Finding, Validation, FindingStatus, EvidenceType, AuditEvent
from app.schemas.schemas import FindingResponse, ValidationCreate, ValidationResponse
from app.services.analysis.engine import ValidationService

router = APIRouter()
validation_svc = ValidationService()


@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    scan_id: Optional[str] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List findings, optionally filtered by scan or status."""
    query = select(Finding).order_by(Finding.created_at.desc())
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    if status:
        try:
            status_enum = FindingStatus(status)
            query = query.where(Finding.status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.post("/{finding_id}/submit-for-review", response_model=FindingResponse)
async def submit_for_review(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Submit a POTENTIAL finding for human review."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        validation_svc.validate_transition(finding.status.value, "pending_review")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    old_status = finding.status.value
    finding.status = FindingStatus.PENDING_REVIEW
    finding.updated_at = datetime.utcnow()

    db.add(AuditEvent(
        event_type="finding_submitted_for_review",
        entity_type="finding",
        entity_id=finding_id,
        description=f"Finding submitted for review: {old_status} → pending_review",
    ))
    await db.flush()
    await db.refresh(finding)
    return finding


@router.post("/{finding_id}/validate", response_model=ValidationResponse, status_code=201)
async def validate_finding(
    finding_id: str,
    payload: ValidationCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Human analyst validates a finding.
    Valid transitions: pending_review → validated | rejected | needs_more_evidence
    """
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Determine new status from comment content or request body
    new_status_str = payload.additional_evidence_requested and "needs_more_evidence" or "validated"
    # This should be in the payload; let's support it via the endpoint path instead

    raise HTTPException(
        status_code=400,
        detail="Use /validate/accept or /validate/reject or /validate/needs-more-evidence",
    )


@router.post("/{finding_id}/validate/accept", response_model=ValidationResponse, status_code=201)
async def accept_finding(
    finding_id: str,
    payload: ValidationCreate,
    db: AsyncSession = Depends(get_db),
):
    """Human analyst accepts finding as a real vulnerability (VALIDATED)."""
    return await _transition_finding(finding_id, "validated", payload, db)


@router.post("/{finding_id}/validate/reject", response_model=ValidationResponse, status_code=201)
async def reject_finding(
    finding_id: str,
    payload: ValidationCreate,
    db: AsyncSession = Depends(get_db),
):
    """Human analyst rejects finding as false positive (REJECTED)."""
    return await _transition_finding(finding_id, "rejected", payload, db)


@router.post("/{finding_id}/validate/needs-more-evidence", response_model=ValidationResponse, status_code=201)
async def needs_more_evidence(
    finding_id: str,
    payload: ValidationCreate,
    db: AsyncSession = Depends(get_db),
):
    """Human analyst requests more evidence (NEEDS_MORE_EVIDENCE)."""
    return await _transition_finding(finding_id, "needs_more_evidence", payload, db)


async def _transition_finding(
    finding_id: str,
    new_status_str: str,
    payload: ValidationCreate,
    db: AsyncSession,
) -> Validation:
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        validation_svc.validate_transition(finding.status.value, new_status_str)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    old_status = finding.status.value
    finding.status = FindingStatus(new_status_str)
    finding.updated_at = datetime.utcnow()

    # Update evidence type if validated
    if new_status_str == "validated":
        finding.evidence_type = EvidenceType.VALIDATED

    # Create validation record
    validation = Validation(
        finding_id=finding_id,
        reviewer=payload.reviewer,
        old_status=FindingStatus(old_status),
        new_status=FindingStatus(new_status_str),
        comment=payload.comment,
        additional_evidence_requested=payload.additional_evidence_requested,
    )
    db.add(validation)

    db.add(AuditEvent(
        event_type=f"finding_{new_status_str}",
        entity_type="finding",
        entity_id=finding_id,
        actor=payload.reviewer,
        description=f"Finding {old_status} → {new_status_str} by {payload.reviewer}",
        data={"comment": payload.comment},
    ))
    await db.flush()
    await db.refresh(validation)
    return validation


@router.get("/{finding_id}/validations", response_model=List[ValidationResponse])
async def get_finding_validations(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Get full validation history for a finding."""
    result = await db.execute(
        select(Validation)
        .where(Validation.finding_id == finding_id)
        .order_by(Validation.review_timestamp)
    )
    return result.scalars().all()
