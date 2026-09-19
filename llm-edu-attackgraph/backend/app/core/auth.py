"""
Authentication & Security Utilities for LLM-EduAttackGraph
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Optional, Dict, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.session import get_db
from app.models.models import User

# HTTP Bearer authentication scheme
security_scheme = HTTPBearer(auto_error=False)

TOKEN_EXPIRY_SECONDS = 86400 * 7  # 7 days


def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with salt."""
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return f"{salt}${key.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verify password against stored salt$hash."""
    try:
        salt, key_hex = stored_hash.split('$', 1)
        test_key = hashlib.pbkdf2_hmac(
            'sha256',
            plain_password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        return hmac.compare_digest(test_key.hex(), key_hex)
    except Exception:
        return False


def create_access_token(user_id: str, email: str, role: str = "admin") -> str:
    """Create a secure signed JWT-style token."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": int(time.time()) + TOKEN_EXPIRY_SECONDS,
        "iat": int(time.time()),
    }

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    message = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(settings.SECRET_KEY.encode(), message, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and verify access token."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, sig_b64 = parts
        message = f"{header_b64}.{payload_b64}".encode()
        expected_sig = hmac.new(settings.SECRET_KEY.encode(), message, hashlib.sha256).digest()

        # Add padding back
        pad = len(sig_b64) % 4
        if pad:
            sig_b64 += "=" * (4 - pad)
        actual_sig = base64.urlsafe_b64decode(sig_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        pad_payload = len(payload_b64) % 4
        if pad_payload:
            payload_b64 += "=" * (4 - pad_payload)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())

        if payload.get("exp", 0) < time.time():
            return None

        return payload
    except Exception:
        return None


async def get_current_user_optional(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Get current user from Bearer token if provided."""
    if not auth or not auth.credentials:
        return None

    payload = decode_access_token(auth.credentials)
    if not payload or "sub" not in payload:
        return None

    user_id = payload["sub"]
    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    return result.scalar_one_or_none()


async def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Require valid authenticated user."""
    user = await get_current_user_optional(auth, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    """Require administrator role."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required.",
        )
    return user


async def auto_seed_admin(db: AsyncSession) -> None:
    """Ensure the user's admin account exists with requested credentials."""
    admin_email = "titusathul8@gmail.com"
    admin_pass = "ATHUL321"

    result = await db.execute(select(User).where(User.email == admin_email))
    admin_user = result.scalar_one_or_none()

    if not admin_user:
        hashed = hash_password(admin_pass)
        new_admin = User(
            email=admin_email,
            hashed_password=hashed,
            role="admin",
            is_active=True,
        )
        db.add(new_admin)
        await db.commit()
    else:
        # Ensure password matches updated requirement
        if not verify_password(admin_pass, admin_user.hashed_password):
            admin_user.hashed_password = hash_password(admin_pass)
            db.add(admin_user)
            await db.commit()
