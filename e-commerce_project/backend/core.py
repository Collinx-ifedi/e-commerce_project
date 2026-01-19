# core.py
# Production-level core system logic
# - Async JWT Authentication (Access & Refresh tokens)
# - Role-Based Access Control (RBAC)
# - Global Configuration Management
# - Cryptography & Security Helpers

import os
import logging
from datetime import datetime, timedelta
from typing import Optional, Union, List, Any

from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseSettings, ValidationError

from db import get_db
from models_schemas import User, Admin, AdminRole

# ======================================================
# 1. ROBUST CONFIGURATION (Settings Pattern)
# ======================================================

class Settings(BaseSettings):
    """
    Centralized configuration management.
    Validates environment variables on startup.
    """
    # Security
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Admin Seeding (Loaded from Env)
    ADMIN_PASS_1: Optional[str] = None
    ADMIN_PASS_2: Optional[str] = None
    ADMIN_PASS_3: Optional[str] = None
    ADMIN_PASS_4: Optional[str] = None
    ADMIN_PASS_5: Optional[str] = None

    class Config:
        env_file = ".env"
        case_sensitive = True

try:
    settings = Settings()
except ValidationError as e:
    # Fail fast if critical env vars are missing
    logging.critical(f"Missing critical environment variables: {e}")
    raise RuntimeError("System configuration failed. Check environment variables.")

# ======================================================
# 2. CRYPTOGRAPHY SETUP
# ======================================================

# Recommended for production: 'bcrypt' is standard, 'argon2' is more secure but slower.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_scheme = HTTPBearer()

logger = logging.getLogger("core.security")

def hash_password(password: str) -> str:
    """Hashes a plain password using bcrypt."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the stored hash."""
    return pwd_context.verify(plain_password, hashed_password)

# ======================================================
# 3. JWT TOKEN LOGIC
# ======================================================

def create_access_token(
    subject: Union[str, int],
    role: str = "user",
    expires_delta: Optional[timedelta] = None
) -> str:
    """Generates a short-lived access token."""
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {
        "sub": str(subject),
        "role": role,
        "type": "access",
        "exp": expire,
        "iat": datetime.utcnow()
    }
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def create_refresh_token(subject: Union[str, int], role: str = "user") -> str:
    """Generates a long-lived refresh token."""
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode = {
        "sub": str(subject),
        "role": role,
        "type": "refresh",
        "exp": expire,
        "iat": datetime.utcnow()
    }
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> dict:
    """Decodes and validates a JWT token."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError as e:
        logger.warning(f"Token decode failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# ======================================================
# 4. ASYNC AUTH DEPENDENCIES
# ======================================================

async def get_current_user(
    token: HTTPAuthorizationCredentials = Depends(auth_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Validates token and retrieves the current user from DB asynchronously.
    """
    payload = decode_token(token.credentials)
    
    # 1. Validate Token Type and Role
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    if payload.get("role") != "user":
        raise HTTPException(status_code=403, detail="Not authorized as user")
        
    user_id_str = payload.get("sub")
    if user_id_str is None:
        raise HTTPException(status_code=401, detail="Token missing subject")

    try:
        user_id = int(user_id_str)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid user ID format")

    # 2. Async DB Query
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    # 3. Security Checks
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_banned:
        raise HTTPException(status_code=403, detail="User account is banned")
        
    return user

async def get_current_admin(
    token: HTTPAuthorizationCredentials = Depends(auth_scheme),
    db: AsyncSession = Depends(get_db)
) -> Admin:
    """
    Validates token and retrieves the current admin from DB asynchronously.
    """
    payload = decode_token(token.credentials)

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    
    # Check if role is ANY admin role
    role = payload.get("role")
    if role not in [r.value for r in AdminRole]: 
        # Fallback for legacy tokens or "admin" string
        if role != "admin":
            raise HTTPException(status_code=403, detail="Not authorized as admin")

    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Token missing subject")

    # Async DB Query
    result = await db.execute(select(Admin).where(Admin.username == username))
    admin = result.scalar_one_or_none()

    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    if not admin.is_active:
        raise HTTPException(status_code=403, detail="Admin account is inactive")
        
    return admin

# ======================================================
# 5. ROLE-BASED ACCESS CONTROL (RBAC)
# ======================================================

class RoleChecker:
    """
    Dependency for granular role permission.
    Usage: Depends(RoleChecker([AdminRole.SUPERADMIN, AdminRole.MANAGER]))
    """
    def __init__(self, allowed_roles: List[AdminRole]):
        self.allowed_roles = allowed_roles

    def __call__(self, admin: Admin = Depends(get_current_admin)) -> Admin:
        if admin.role not in self.allowed_roles:
            logger.warning(f"Admin {admin.username} (Role: {admin.role}) attempted unauthorized access.")
            raise HTTPException(
                status_code=403, 
                detail=f"Operation requires one of the following roles: {[r.value for r in self.allowed_roles]}"
            )
        return admin

# Pre-configured Dependencies
require_superadmin = RoleChecker([AdminRole.SUPERADMIN])
require_support = RoleChecker([AdminRole.SUPERADMIN, AdminRole.ADMIN, AdminRole.SUPPORT])

# ======================================================
# 6. UTILITIES & SECURITY HELPERS
# ======================================================

def generate_random_token(length: int = 32) -> str:
    import secrets
    return secrets.token_urlsafe(length)

def current_utc_time() -> datetime:
    return datetime.utcnow()