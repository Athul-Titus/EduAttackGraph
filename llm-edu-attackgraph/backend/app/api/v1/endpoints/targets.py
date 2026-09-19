"""
Targets API Endpoints
"""
from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import Target, AuditEvent, User
from app.schemas.schemas import TargetCreate, TargetResponse
from app.core.authorization import AuthorizationManager, AuthorizationError
from app.core.auth import get_current_user_optional, require_admin
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
async def register_target(
    payload: TargetCreate,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db),
):
    """
    Register an authorized target for scanning.
    If authenticated as Admin, allows direct authorization of the target.
    Otherwise, validates against system allowlist.
    """
    is_admin = bool(current_user and current_user.role == "admin")
    try:
        validated = auth_mgr.validate_target(payload.hostname, is_admin=is_admin)
    except AuthorizationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{str(e)} Please log in as Admin to authorize this target directly."
        )

    # Check if target already exists
    existing = await db.execute(select(Target).where(Target.hostname == validated))
    target = existing.scalar_one_or_none()

    if target:
        # Re-authorize if already exists
        target.authorized = True
        if payload.description:
            target.description = payload.description
        if payload.authorization_note:
            target.authorization_note = payload.authorization_note
    else:
        target = Target(
            hostname=validated,
            description=payload.description,
            authorization_note=payload.authorization_note or ("Authorized by Admin" if is_admin else "Authorized target"),
            authorized=True,
        )
        db.add(target)

    actor_info = current_user.email if current_user else "system"
    audit = AuditEvent(
        event_type="target_registered",
        entity_type="target",
        actor=actor_info,
        description=f"Target registered: {validated} (admin={is_admin})",
        data={"hostname": validated, "is_admin": is_admin},
    )
    db.add(audit)
    await db.commit()
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
async def delete_target(
    target_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db),
):
    """Delete a target from the system."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await db.delete(target)
    await db.commit()


@router.patch("/{target_id}/toggle-auth", response_model=TargetResponse)
async def toggle_target_auth(
    target_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db),
):
    """Toggle target authorization status."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.authorized = not target.authorized
    await db.commit()
    await db.refresh(target)
    return target
