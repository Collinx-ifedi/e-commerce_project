# core.py
# Production-level core system logic
# - Async JWT Authentication (Access & Refresh tokens)
# - Role-Based Access Control (RBAC)
# - Global Configuration Management (Pydantic V2)
# - Cryptography: Switched to Argon2 (No length limit, GPU-resistant)

import os
import logging
from datetime import datetime, timedelta
from typing import Optional, Union, List, Dict, Any

from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

# Pydantic V2 Settings
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import ValidationError, Field

from db import get_db
from models_schemas import User, Admin, AdminRole

# ======================================================
# 1. ROBUST CONFIGURATION (Settings Pattern - Pydantic V2)
# ======================================================

class Settings(BaseSettings):
    """
    Centralized configuration management.
    Validates environment variables on startup.
    """
    # --- Security ---
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # --- Admin Configuration (CSV Strings from Env) ---
    ADMIN_USERNAMES: str = Field(default="")
    ADMIN_PASSWORDS: str = Field(default="")
    SUPERADMIN_USERNAME: str = Field(default="admin")
    
    # --- CORS & Frontend ---
    ADMIN_FRONTEND_URL: Optional[str] = None
    FRONTEND_URL: Optional[str] = None
    
    # --- Infrastructure ---
    DATABASE_URL: str
    
    # Pydantic V2 Configuration
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        extra="ignore", # Prevents crash if unrelated env vars exist
        case_sensitive=True
    )

# Initialize Settings
try:
    settings = Settings()
except ValidationError as e:
    logging.critical(f"System configuration failed. Missing or invalid environment variables: {e}")
    raise RuntimeError("System configuration failed.")

# ======================================================
# 2. COMPUTED CONFIGURATION & PARSING
# ======================================================

logger = logging.getLogger("core.security")

def _parse_admin_credentials() -> Dict[str, str]:
    """
    Parses comma-separated usernames and passwords from env
    into a dictionary {username: password} for bootstrapping.
    """
    users = [u.strip() for u in settings.ADMIN_USERNAMES.split(",") if u.strip()]
    pwds = [p.strip() for p in settings.ADMIN_PASSWORDS.split(",") if p.strip()]
    
    if len(users) != len(pwds):
        logger.warning("Mismatch between ADMIN_USERNAMES and ADMIN_PASSWORDS count. Admins may fail to seed.")
    
    # Zip strictly pairs them up to the length of the shortest list
    return dict(zip(users, pwds))

# Exported for services.py to use during bootstrapping
ADMIN_PASSWORDS = _parse_admin_credentials()

# ======================================================
# 3. CRYPTOGRAPHY SETUP (ARGON2)
# ======================================================

# Switched to Argon2 for superior security and no length limits.
# Parameters tuned for production security (RFC 9106 recommendations).
pwd_context = CryptContext(
    schemes=["argon2"], 
    deprecated="auto",
    # Tuning: 64MB memory, 4 threads, 3 iterations
    argon2__memory_cost=65536,
    argon2__parallelism=4,
    argon2__time_cost=3
)

auth_scheme = HTTPBearer()

def hash_password(password: str) -> str:
    """
    Hashes a plain password using Argon2.
    No truncation or length limit is applied.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain password against the stored hash.
    Passlib automatically handles transition from bcrypt if old hashes exist.
    """
    if not hashed_password:
        return False
    return pwd_context.verify(plain_password, hashed_password)

# ======================================================
# 4. JWT TOKEN LOGIC
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
# 5. ASYNC AUTH DEPENDENCIES
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
    
    # Determine if the role string matches any valid Enum value
    valid_admin_roles = [r.value for r in AdminRole]
    if role not in valid_admin_roles and role != "admin": # Allow "admin" for legacy
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
# 6. ROLE-BASED ACCESS CONTROL (RBAC)
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
                detail=f"Operation requires one of: {[r.value for r in self.allowed_roles]}"
            )
        return admin

# Pre-configured Dependencies
require_superadmin = RoleChecker([AdminRole.SUPERADMIN])
require_support = RoleChecker([AdminRole.SUPERADMIN, AdminRole.ADMIN, AdminRole.SUPPORT])

# ======================================================
# 7. UTILITIES & SECURITY HELPERS
# ======================================================

def generate_random_token(length: int = 32) -> str:
    import secrets
    return secrets.token_urlsafe(length)

def current_utc_time() -> datetime:
    return datetime.utcnow()