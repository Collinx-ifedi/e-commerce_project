# main.py
# Production-level Entry Point
# - Fixes: Routing for auth.html, products, cart, etc.
# - Adds: Missing API endpoints for Banners and Products to fix 404s
# - robust Path Resolution for Docker/Render

import os
import logging
import time
import shutil
import uuid
from pathlib import Path
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request,
    status,
    APIRouter,
    UploadFile,
    File,
    Query
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

# --- LOCAL MODULES ---
from .db import get_db, init_db, ping_db, add_product_codes_from_file
from .core import settings, get_current_admin, require_superadmin
from .utils import logger

# --- SERVICES ---
from .services import (
    create_user_service,
    verify_user_email_service,
    admin_login_service,
    bootstrap_admins,
    create_order_service,
    handle_nowpayments_webhook,
    handle_binance_webhook,
    handle_bybit_webhook
)

# --- SCHEMAS & MODELS ---
from .models_schemas import (
    UserCreateSchema, 
    AdminLoginSchema, 
    MultiProductOrderCreate, 
    Admin,
    Product, 
    ProductSchema,
    Banner,
    BannerSchema
)

# =========================================================
# 1. SETUP & PATH RESOLUTION
# =========================================================

# Robust path resolution using pathlib
BASE_DIR = Path(__file__).resolve().parent      # .../backend
PROJECT_ROOT = BASE_DIR.parent                  # .../root
FRONTEND_DIR = PROJECT_ROOT / "frontend"        # .../root/frontend
UPLOAD_DIR = BASE_DIR / "temp_uploads"

# Ensure temp directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Validate Frontend Directory
if not FRONTEND_DIR.exists():
    logger.critical(f"CRITICAL: Frontend directory not found at {FRONTEND_DIR}")

# =========================================================
# 2. LIFESPAN MANAGEMENT
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages startup/shutdown lifecycle.
    """
    # --- STARTUP ---
    logger.info("System startup initiated...")
    
    # 1. Database Init
    await init_db()
    
    # 2. Bootstrap Admins
    async for db in get_db():
        await bootstrap_admins(db)
        break 
    
    logger.info(f"System startup complete. Version: {app.version}")
    
    yield
    
    # --- SHUTDOWN ---
    logger.info("System shutting down...")
    # Cleanup temp files
    if UPLOAD_DIR.exists():
        shutil.rmtree(UPLOAD_DIR, ignore_errors=True)

# =========================================================
# 3. APPLICATION FACTORY
# =========================================================

app = FastAPI(
    title="KeyVault Backend",
    version="2.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# =========================================================
# 4. MIDDLEWARE
# =========================================================

app.add_middleware(GZipMiddleware, minimum_size=1000)

origins = []
if settings.ADMIN_FRONTEND_URL:
    origins.append(settings.ADMIN_FRONTEND_URL)
if settings.FRONTEND_URL:
    origins.append(settings.FRONTEND_URL)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}"
    return response

# =========================================================
# 5. API ROUTERS
# =========================================================

# --- A. CATALOG ROUTES (Fixes 404s on Index) ---
catalog_router = APIRouter(prefix="/api", tags=["Catalog"])

@catalog_router.get("/products", response_model=List[ProductSchema])
async def get_products(
    platform: Optional[str] = None, 
    limit: int = 20, 
    db: AsyncSession = Depends(get_db)
):
    """Fetch products for the frontend grid."""
    query = select(Product).where(Product.is_deleted == False)
    
    if platform:
        query = query.where(Product.platform == platform)
    
    # Default sort by ID desc (newest first)
    query = query.order_by(desc(Product.id)).limit(limit)
    
    result = await db.execute(query)
    products = result.scalars().all()
    return products

@catalog_router.get("/products/{product_id}", response_model=ProductSchema)
async def get_product_detail(product_id: int, db: AsyncSession = Depends(get_db)):
    """Fetch single product details."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

@catalog_router.get("/banners", response_model=List[BannerSchema])
async def get_banners(active: bool = True, db: AsyncSession = Depends(get_db)):
    """Fetch hero slider banners."""
    query = select(Banner)
    if active:
        query = query.where(Banner.is_active == True)
    
    query = query.order_by(Banner.display_order)
    result = await db.execute(query)
    return result.scalars().all()


# --- B. AUTH ROUTES ---
auth_router = APIRouter(prefix="/api/auth", tags=["Auth"])

@auth_router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(data: UserCreateSchema, db: AsyncSession = Depends(get_db)):
    """Register user & trigger OTP email."""
    try:
        await create_user_service(db, data.email, data.password, data.country)
        return {"message": "Account created. Check email for OTP."}
    except HTTPException as he:
        raise he

@auth_router.post("/login")
async def login_user(request: Request):
    """
    Placeholder for user login. 
    In production, implement check against User table similar to Admin login.
    """
    # NOTE: You need to implement user_login_service in services.py
    # For now, return a mock token to allow frontend testing
    return {
        "access_token": "mock-user-token-xyz", 
        "token_type": "bearer",
        "user": {"email": "user@example.com", "full_name": "Demo User", "balance_usd": 0.0}
    }

@auth_router.post("/verify-email")
async def verify_email(payload: dict, db: AsyncSession = Depends(get_db)):
    """Verify account with OTP."""
    email = payload.get("email")
    otp = payload.get("otp")
    return await verify_user_email_service(db, email, otp)


# --- C. ORDER ROUTES ---
order_router = APIRouter(prefix="/api/orders", tags=["Orders"])

@order_router.post("/checkout", status_code=status.HTTP_201_CREATED)
async def checkout_route(
    order_data: MultiProductOrderCreate,
    request: Request,
    user_id: int = 1, # Placeholder: Replace with Depends(get_current_user)
    db: AsyncSession = Depends(get_db),
):
    try:
        checkout_url = await create_order_service(db, user_id, order_data)
        return {"checkout_url": checkout_url}
    except Exception as e:
        logger.error(f"Checkout failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@order_router.get("")
async def get_user_orders(user_id: int = 1, db: AsyncSession = Depends(get_db)):
    """Fetch order history for profile page."""
    # Placeholder: Implement actual DB query
    return []


# --- D. ADMIN ROUTES ---
admin_router = APIRouter(prefix="/api/admin", tags=["Admin"])

@admin_router.post("/login")
async def admin_login_route(data: AdminLoginSchema, db: AsyncSession = Depends(get_db)):
    token = await admin_login_service(db, data.username, data.password)
    return {"access_token": token, "token_type": "bearer"}

@admin_router.post("/products/{product_id}/upload-codes")
async def upload_product_codes(
    product_id: int,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(get_current_admin)
):
    if not file.filename.endswith(('.txt', '.csv')):
        raise HTTPException(status_code=400, detail="Only .txt or .csv files allowed")

    temp_filename = f"{uuid.uuid4()}_{file.filename}"
    file_path = UPLOAD_DIR / temp_filename
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        count = await add_product_codes_from_file(str(file_path), product_id, db)
        return {"status": "success", "codes_added": count}
        
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to process file")
    finally:
        if file_path.exists():
            os.remove(file_path)


# --- E. WEBHOOKS ---
webhook_router = APIRouter(prefix="/api/webhooks", tags=["Webhooks"])

@webhook_router.post("/nowpayments")
async def nowpayments_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    sig = request.headers.get("x-nowpayments-sig")
    payload = await request.json()
    await handle_nowpayments_webhook(db, payload, sig)
    return {"status": "ok"}


# =========================================================
# 6. REGISTER API ROUTERS
# =========================================================

app.include_router(catalog_router) # Products & Banners
app.include_router(auth_router)
app.include_router(order_router)
app.include_router(admin_router)
app.include_router(webhook_router)

# =========================================================
# 7. FRONTEND PAGE ROUTES (The Fix)
# =========================================================
# Explicitly mapping routes avoids 404s when clicking links

@app.get("/")
async def serve_index():
    return FileResponse(FRONTEND_DIR / "index.html")

@app.get("/index.html")
async def serve_index_file():
    return FileResponse(FRONTEND_DIR / "index.html")

@app.get("/auth.html")
async def serve_auth():
    return FileResponse(FRONTEND_DIR / "auth.html")

@app.get("/login") # Alias for cleanliness
async def serve_login():
    return FileResponse(FRONTEND_DIR / "auth.html")

@app.get("/register") # Alias for cleanliness
async def serve_register():
    return FileResponse(FRONTEND_DIR / "auth.html")

@app.get("/product.html")
async def serve_product():
    return FileResponse(FRONTEND_DIR / "product.html")

@app.get("/cart.html")
async def serve_cart():
    return FileResponse(FRONTEND_DIR / "cart.html")

@app.get("/cart") # Alias
async def serve_cart_clean():
    return FileResponse(FRONTEND_DIR / "cart.html")

@app.get("/checkout.html")
async def serve_checkout():
    return FileResponse(FRONTEND_DIR / "checkout.html")

@app.get("/profile.html")
async def serve_profile():
    return FileResponse(FRONTEND_DIR / "profile.html")

@app.get("/profile") # Alias
async def serve_profile_clean():
    return FileResponse(FRONTEND_DIR / "profile.html")

# =========================================================
# 8. STATIC FILES (Last Resort)
# =========================================================
# This catches any other file requests (images, css) inside frontend/

if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

# =========================================================
# EXECUTION
# =========================================================

if __name__ == "__main__":
    import uvicorn
    # 0.0.0.0 is required for Docker/Cloud
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)