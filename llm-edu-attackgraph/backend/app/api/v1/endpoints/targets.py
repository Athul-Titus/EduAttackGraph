"""
Targets API Endpoints
"""
from __future__ import annotations

from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import Target, AuditEvent
from app.schemas.schemas import TargetCreate, TargetResponse
from app.core.authorization import AuthorizationManager, AuthorizationError
from app.config import settings

router = APIRouter()
auth_mgr = AuthorizationManager(
    mode=settings.AUTHORIZED_TARGET_MODE,
    allowlist=settings.allowed_targets,
)


@router.get("/", response_model=List[TargetResponse])
async def list_targets(db: AsyncSession = Depends(get_db)):
    """List all registered authorized targets."""
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=TargetResponse, status_code=201)
async def register_target(payload: TargetCreate, db: AsyncSession = Depends(get_db)):
    """
    Register an authorized target for scanning.
    Validates the target against the authorization allowlist.
    """
    try:
        validated = auth_mgr.validate_target(payload.hostname)
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))

    target = Target(
        hostname=validated,
        description=payload.description,
        authorization_note=payload.authorization_note,
        authorized=True,
    )
    db.add(target)

    audit = AuditEvent(
        event_type="target_registered",
        entity_type="target",
        description=f"Target registered: {validated}",
        data={"hostname": validated},
    )
    db.add(audit)
    await db.flush()
    await db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await db.delete(target)
