# main.py
# Production-level Entry Point
# - Integrated Cloudinary for Image Persistence (via CLOUDINARY_URL)
# - Multipart Form Data support for Admin CRUD
# - Dynamic Platform handling
# - Robust Path Resolution for Docker/Render
# - OTP Recovery Endpoint
# - Automatic Background Cleanup of Unverified Users

import os
import shutil
import uuid
import time
import logging
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import asynccontextmanager
from typing import List, Optional

import cloudinary
import cloudinary.uploader
from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request,
    status,
    APIRouter,
    UploadFile,
    File,
    Form,
    Query
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, delete

# --- LOCAL MODULES ---
from .db import get_db, init_db, add_product_codes_from_file
from .core import (
    settings, 
    get_current_admin, 
    get_current_user,
    verify_password,
    create_access_token, 
    require_superadmin
)
from .utils import logger

# --- SERVICES ---
from .services import (
    create_user_service,
    resend_otp_service,
    verify_user_email_service,
    admin_login_service,
    bootstrap_admins,
    create_order_service,
    create_product_service,
    create_banner_service,
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
    User,
    Product, 
    ProductSchema,
    Banner,
    BannerSchema
)

# =========================================================
# 1. SETUP & CONFIGURATION
# =========================================================

# Robust path resolution using pathlib
BASE_DIR = Path(__file__).resolve().parent      # .../backend
PROJECT_ROOT = BASE_DIR.parent                  # .../root
FRONTEND_DIR = PROJECT_ROOT / "frontend"        # .../root/frontend
UPLOAD_DIR = BASE_DIR / "temp_uploads"          # For CSV/TXT processing only

# Ensure temp directory exists for CSV processing
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Validate Frontend Directory
if not FRONTEND_DIR.exists():
    logger.critical(f"CRITICAL: Frontend directory not found at {FRONTEND_DIR}")

# --- CLOUDINARY CONFIGURATION ---
# Best Practice: Use CLOUDINARY_URL env var (cloudinary://api_key:api_secret@cloud_name)
# We also enforce secure=True to ensure all delivered URLs use HTTPS.
cloudinary_url = os.getenv("CLOUDINARY_URL")

if cloudinary_url:
    cloudinary.config(cloudinary_url=cloudinary_url, secure=True)
    logger.info("Cloudinary initialized successfully via CLOUDINARY_URL.")
else:
    # Log a critical warning if missing, but do not crash immediately to allow API to start
    logger.critical("WARNING: CLOUDINARY_URL not found in environment variables. Image uploads will fail.")

# =========================================================
# 2. LIFESPAN MANAGEMENT & BACKGROUND TASKS
# =========================================================

async def cleanup_unverified_users():
    """
    Background task to remove users who registered but never 
    verified their email within the expiration window (e.g., 24 hours).
    This keeps the database clean of abandoned registrations.
    """
    while True:
        try:
            # We must create a new session generator for the background task
            # Using the same logic as get_db but manually managing the context
            async for db in get_db():
                # Define expiration threshold (users created > 24 hours ago)
                expiration_limit = datetime.utcnow() - timedelta(hours=24)
                
                # Delete users who are unverified AND older than the limit
                stmt = (
                    delete(User)
                    .where(User.is_verified == False)
                    .where(User.created_at < expiration_limit)
                )
                
                result = await db.execute(stmt)
                await db.commit()
                
                if result.rowcount > 0:
                    logger.info(f"Cleanup: Removed {result.rowcount} unverified/abandoned accounts.")
                # Break after one iteration since we just needed one session
                break 
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")
        
        # Run cleanup every hour (3600 seconds)
        await asyncio.sleep(3600)

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
    
    # 3. Start Background Cleanup Task
    cleanup_task = asyncio.create_task(cleanup_unverified_users())
    logger.info("Background task started: Cleanup unverified users.")
    
    logger.info(f"System startup complete. Version: {app.version}")
    
    yield
    
    # --- SHUTDOWN ---
    logger.info("System shutting down...")
    
    # Cancel background task
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        logger.info("Background cleanup task cancelled.")

    # Cleanup temp CSV files
    if UPLOAD_DIR.exists():
        shutil.rmtree(UPLOAD_DIR, ignore_errors=True)

# =========================================================
# 3. APPLICATION FACTORY
# =========================================================

app = FastAPI(
    title="KeyVault Backend",
    version="2.3.2",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# =========================================================
# 4. MIDDLEWARE
# =========================================================

app.add_middleware(GZipMiddleware, minimum_size=1000)

origins = ["*"] # Default to open for dev, restrict in prod via settings
if settings.ADMIN_FRONTEND_URL:
    origins.append(settings.ADMIN_FRONTEND_URL)
if settings.FRONTEND_URL:
    origins.append(settings.FRONTEND_URL)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
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

# --- A. CATALOG ROUTES ---
catalog_router = APIRouter(prefix="/api", tags=["Catalog"])

@catalog_router.get("/products", response_model=List[ProductSchema])
async def get_products(
    platform: Optional[str] = None, 
    limit: int = 50, 
    db: AsyncSession = Depends(get_db)
):
    """Fetch products for the frontend grid."""
    query = select(Product).where(Product.is_deleted == False)
    
    if platform:
        query = query.where(Product.platform == platform)
    
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
    try:
        await create_user_service(db, data.email, data.password, data.country)
        return {"message": "Account created. Check email for OTP."}
    except HTTPException as he:
        raise he

@auth_router.post("/login")
async def login_user(data: AdminLoginSchema, db: AsyncSession = Depends(get_db)):
    # 1. Fetch User
    result = await db.execute(select(User).where(User.email == data.username))
    user = result.scalar_one_or_none()

    # 2. Verify Creds
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    if user.is_banned:
        raise HTTPException(status_code=403, detail="Account suspended")

    # 3. Create Token
    access_token = create_access_token(subject=user.id, role="user")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "email": user.email,
            "full_name": user.full_name or "Valued Customer",
            "balance_usd": user.balance_usd,
            "country": user.country
        }
    }

@auth_router.get("/me")
async def get_my_profile(user: User = Depends(get_current_user)):
    return {
        "email": user.email,
        "full_name": user.full_name,
        "balance_usd": user.balance_usd,
        "country": user.country,
        "avatar_url": user.avatar_url
    }

@auth_router.post("/verify-email")
async def verify_email(payload: dict, db: AsyncSession = Depends(get_db)):
    email = payload.get("email")
    otp = payload.get("otp")
    return await verify_user_email_service(db, email, otp)

@auth_router.post("/resend-otp")
async def resend_otp(payload: dict, db: AsyncSession = Depends(get_db)):
    """Allows unverified users to request a new OTP code."""
    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    return await resend_otp_service(db, email)


# --- C. ORDER ROUTES ---
order_router = APIRouter(prefix="/api/orders", tags=["Orders"])

@order_router.post("/checkout", status_code=status.HTTP_201_CREATED)
async def checkout_route(
    order_data: MultiProductOrderCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        checkout_url = await create_order_service(db, user.id, order_data)
        return {"checkout_url": checkout_url}
    except Exception as e:
        logger.error(f"Checkout failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@order_router.get("")
async def get_user_orders(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Fetch order history for the current user."""
    # This matches the frontend profile call
    from .models_schemas import Order
    stmt = select(Order).where(Order.user_id == user.id).order_by(desc(Order.created_at))
    result = await db.execute(stmt)
    return result.scalars().all()


# --- D. ADMIN ROUTES (Updated with Cloudinary & Form Data) ---
admin_router = APIRouter(prefix="/api/admin", tags=["Admin"])

@admin_router.post("/login")
async def admin_login_route(data: AdminLoginSchema, db: AsyncSession = Depends(get_db)):
    token = await admin_login_service(db, data.username, data.password)
    return {"access_token": token, "token_type": "bearer"}

# 1. CREATE PRODUCT (Multipart Form + Cloudinary)
@admin_router.post("/products", response_model=ProductSchema)
async def create_product(
    name: str = Form(...),
    platform: str = Form(...),  # Dynamic String
    price_usd: float = Form(...),
    stock_quantity: int = Form(0),
    discount_percent: int = Form(0),
    description: Optional[str] = Form(None),
    file: UploadFile = File(...), # Required for new product
    is_featured: bool = Form(False),
    is_trending: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(get_current_admin)
):
    # Upload Image to Cloudinary
    try:
        # Note: cloudinary.uploader automatically uses the configured CLOUDINARY_URL
        upload_result = cloudinary.uploader.upload(file.file, folder="keyvault_products")
        secure_url = upload_result.get("secure_url")
    except Exception as e:
        logger.error(f"Cloudinary upload failed: {e}")
        raise HTTPException(status_code=502, detail="Image upload failed")

    return await create_product_service(
        db, name, platform, price_usd, description, secure_url, 
        stock_quantity, discount_percent, is_featured, is_trending
    )

# 2. CREATE BANNER (Multipart + Cloudinary)
@admin_router.post("/banners", response_model=BannerSchema)
async def create_banner(
    title: Optional[str] = Form(None),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(get_current_admin)
):
    try:
        upload_result = cloudinary.uploader.upload(file.file, folder="keyvault_banners")
        secure_url = upload_result.get("secure_url")
    except Exception as e:
        raise HTTPException(status_code=502, detail="Banner upload failed")

    return await create_banner_service(db, title, secure_url)

# 3. UPLOAD CODES (Kept Local for CSV Processing Efficiency)
@admin_router.post("/products/{product_id}/upload-codes")
async def upload_product_codes(
    product_id: int,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(get_current_admin)
):
    if not file.filename.endswith(('.txt', '.csv')):
        raise HTTPException(status_code=400, detail="Only .txt or .csv files allowed")

    # Use local temp storage for CSV parsing (faster than cloud round-trip)
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

@webhook_router.post("/binance")
async def binance_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    payload = await request.json()
    headers = request.headers
    await handle_binance_webhook(db, payload, headers)
    return {"status": "SUCCESS"} # Binance expects uppercase string

@webhook_router.post("/bybit")
async def bybit_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    payload = await request.json()
    await handle_bybit_webhook(db, payload)
    return {"status": "success"}


# =========================================================
# 6. REGISTER API ROUTERS
# =========================================================

app.include_router(catalog_router)
app.include_router(auth_router)
app.include_router(order_router)
app.include_router(admin_router)
app.include_router(webhook_router)

# =========================================================
# 7. FRONTEND PAGE ROUTES (Clean URLs)
# =========================================================

@app.get("/")
async def serve_index(): return FileResponse(FRONTEND_DIR / "index.html")

@app.get("/login")
async def serve_login(): return FileResponse(FRONTEND_DIR / "auth.html")

@app.get("/register")
async def serve_register(): return FileResponse(FRONTEND_DIR / "auth.html")

@app.get("/product")
async def serve_product_clean(): return FileResponse(FRONTEND_DIR / "product.html")

@app.get("/cart")
async def serve_cart_clean(): return FileResponse(FRONTEND_DIR / "cart.html")

@app.get("/checkout")
async def serve_checkout_clean(): return FileResponse(FRONTEND_DIR / "checkout.html")

@app.get("/profile")
async def serve_profile_clean(): return FileResponse(FRONTEND_DIR / "profile.html")

# Fallback for explicit .html extensions and other pages
@app.get("/{page_name}.html")
async def serve_html_pages(page_name: str):
    file_path = FRONTEND_DIR / f"{page_name}.html"
    if file_path.exists():
        return FileResponse(file_path)
    return JSONResponse(status_code=404, content={"detail": "Page not found"})

# =========================================================
# 8. STATIC FILES (Final Catch-All)
# =========================================================

if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

# =========================================================
# EXECUTION
# =========================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)