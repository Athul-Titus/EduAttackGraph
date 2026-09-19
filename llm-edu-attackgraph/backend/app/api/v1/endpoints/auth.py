"""
Authentication API Endpoints
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import (
    auto_seed_admin,
    create_access_token,
    get_current_user,
    verify_password,
)
from app.db.session import get_db
from app.models.models import User

router = APIRouter()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    role: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate admin and return JWT access token."""
    # Ensure admin exists
    await auto_seed_admin(db)

    result = await db.execute(select(User).where(User.email == payload.email, User.is_active == True))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token = create_access_token(user_id=user.id, email=user.email, role=user.role)
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(id=user.id, email=user.email, role=user.role),
    )


@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
    """Return authenticated admin profile."""
    return UserResponse(id=user.id, email=user.email, role=user.role)
