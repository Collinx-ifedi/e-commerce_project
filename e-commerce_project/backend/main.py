# main.py
# Production-level Entry Point
# - Integrated Cloudinary for Image Persistence (via CLOUDINARY_URL)
# - Multipart Form Data support for Admin CRUD
# - Dynamic Platform handling
# - Robust Path Resolution for Docker/Render
# - OTP Recovery Endpoint
# - Automatic Background Cleanup of Unverified Users
# - Wallet System Integration (Profile & Deposit)

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
    Query,
    Body  # Added for Wallet Deposit
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, delete, func, case, update, or_
from sqlalchemy.orm import selectinload

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
    create_deposit_service,  # Used for Wallet Deposit
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
    UserResponse,   # Added for Profile Response
    Product, 
    OrderItem,
    ProductSchema,
    Banner,
    BannerSchema,
    Order,
    OrderResponse,
    OrderStatus,
    PaymentMethod   # Added for Deposit Validation
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
cloudinary_url = os.getenv("CLOUDINARY_URL")

if cloudinary_url:
    cloudinary.config(cloudinary_url=cloudinary_url, secure=True)
    logger.info("Cloudinary initialized successfully via CLOUDINARY_URL.")
else:
    logger.critical("WARNING: CLOUDINARY_URL not found in environment variables. Image uploads will fail.")

# =========================================================
# 2. LIFESPAN MANAGEMENT & BACKGROUND TASKS
# =========================================================

async def cleanup_unverified_users():
    """
    Background task to remove users who registered but never 
    verified their email within the expiration window (e.g., 24 hours).
    """
    while True:
        try:
            async for db in get_db():
                expiration_limit = datetime.utcnow() - timedelta(hours=24)
                
                stmt = (
                    delete(User)
                    .where(User.is_verified == False)
                    .where(User.created_at < expiration_limit)
                )
                
                result = await db.execute(stmt)
                await db.commit()
                
                if result.rowcount > 0:
                    logger.info(f"Cleanup: Removed {result.rowcount} unverified/abandoned accounts.")
                break 
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")
        
        await asyncio.sleep(3600)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages startup/shutdown lifecycle."""
    # --- STARTUP ---
    logger.info("System startup initiated...")
    
    await init_db()
    
    async for db in get_db():
        await bootstrap_admins(db)
        break 
    
    cleanup_task = asyncio.create_task(cleanup_unverified_users())
    logger.info("Background task started: Cleanup unverified users.")
    
    logger.info(f"System startup complete. Version: {app.version}")
    
    yield
    
    # --- SHUTDOWN ---
    logger.info("System shutting down...")
    
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        logger.info("Background cleanup task cancelled.")

    if UPLOAD_DIR.exists():
        shutil.rmtree(UPLOAD_DIR, ignore_errors=True)

# =========================================================
# 3. APPLICATION FACTORY
# =========================================================

app = FastAPI(
    title="KeyVault Backend",
    version="2.4.0", # Bumped version for Wallet Integration
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# =========================================================
# 4. MIDDLEWARE
# =========================================================

app.add_middleware(GZipMiddleware, minimum_size=1000)

origins = ["*"] 
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

# --- A. CATALOG ROUTER ---
catalog_router = APIRouter(prefix="/api", tags=["Catalog"])

@catalog_router.get("/products", response_model=List[ProductSchema])
async def get_products(
    platform: Optional[str] = None, 
    limit: int = 50, 
    db: AsyncSession = Depends(get_db)
):
    """Fetch active products for the frontend grid."""
    query = select(Product).where(
        or_(Product.is_deleted == False, Product.is_deleted.is_(None))
    )
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


# --- B. AUTH ROUTER ---
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
    result = await db.execute(select(User).where(User.email == data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    if user.is_banned:
        raise HTTPException(status_code=403, detail="Account suspended")

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
    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    return await resend_otp_service(db, email)


# --- C. USER & WALLET ROUTER (NEW) ---
user_router = APIRouter(prefix="/api/user", tags=["User Profile"])
wallet_router = APIRouter(prefix="/api/wallet", tags=["Wallet"])

# 1. User Profile Endpoint
@user_router.get("/profile", response_model=UserResponse)
async def get_user_profile(user: User = Depends(get_current_user)):
    """
    Returns full profile data including current wallet balance.
    UserResponse schema automatically serializes balance_usd.
    """
    return user

# 2. Wallet Deposit Endpoint
@wallet_router.post("/deposit", status_code=status.HTTP_201_CREATED)
async def create_deposit(
    amount: float = Body(..., gt=1.0, embed=True),
    gateway: PaymentMethod = Body(..., embed=True),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Initiates a wallet top-up via crypto gateways.
    Returns a payment link (checkout_url).
    """
    if gateway == PaymentMethod.WALLET:
        raise HTTPException(status_code=400, detail="Cannot deposit using Wallet balance.")

    try:
        checkout_url = await create_deposit_service(
            db, 
            user_id=user.id, 
            amount=amount, 
            gateway=gateway
        )
        return {"checkout_url": checkout_url}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Deposit Error: {e}")
        raise HTTPException(status_code=500, detail="Could not create deposit link.")


# --- D. ORDER ROUTER ---
order_router = APIRouter(prefix="/api/orders", tags=["Orders"])

@order_router.post("/checkout", status_code=status.HTTP_201_CREATED)
async def checkout_route(
    order_data: MultiProductOrderCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Handles Checkout for both Products and Wallet payments.
    Compatible with PaymentMethod.WALLET via create_order_service.
    """
    try:
        checkout_url = await create_order_service(db, user.id, order_data)
        return {"checkout_url": checkout_url}
    except Exception as e:
        logger.error(f"Checkout failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@order_router.get("")
async def get_user_orders(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Fetch order history for the current user."""
    stmt = select(Order).where(Order.user_id == user.id).order_by(desc(Order.created_at))
    result = await db.execute(stmt)
    return result.scalars().all()


# --- E. ADMIN ROUTER ---
admin_router = APIRouter(prefix="/api/admin", tags=["Admin"])

@admin_router.post("/login")
async def admin_login_route(data: AdminLoginSchema, db: AsyncSession = Depends(get_db)):
    token = await admin_login_service(db, data.username, data.password)
    return {"access_token": token, "token_type": "bearer"}

# -- ADMIN STATS --
@admin_router.get("/stats")
async def get_admin_stats(db: AsyncSession = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    revenue_query = select(func.sum(Order.total_amount_usd)).where(
        Order.status.in_([OrderStatus.PAID, OrderStatus.COMPLETED])
    )
    revenue_res = await db.execute(revenue_query)
    total_revenue = revenue_res.scalar() or 0.0

    orders_res = await db.execute(select(func.count(Order.id)))
    total_orders = orders_res.scalar() or 0

    users_res = await db.execute(select(func.count(User.id)))
    total_users = users_res.scalar() or 0

    products_res = await db.execute(
        select(func.count(Product.id)).where(
            or_(Product.is_deleted == False, Product.is_deleted.is_(None))
        )
    )
    total_products = products_res.scalar() or 0

    return {
        "total_sales": total_revenue,
        "total_orders": total_orders,
        "total_users": total_users,
        "total_products": total_products
    }

# -- ADMIN PRODUCTS LIST --
@admin_router.get("/products", response_model=List[ProductSchema])
async def get_admin_products(db: AsyncSession = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    query = (
        select(Product)
        .where(or_(Product.is_deleted == False, Product.is_deleted.is_(None)))
        .order_by(desc(Product.id))
    )
    result = await db.execute(query)
    return result.scalars().all()

# -- ADMIN BANNERS LIST --
@admin_router.get("/banners", response_model=List[BannerSchema])
async def get_admin_banners(db: AsyncSession = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    query = select(Banner).order_by(desc(Banner.id))
    result = await db.execute(query)
    return result.scalars().all()

# -- ADMIN ORDERS LIST --
@admin_router.get("/orders", response_model=List[OrderResponse])
async def get_admin_orders(limit: int = 50, db: AsyncSession = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    try:
        query = (
            select(Order)
            .options(
                selectinload(Order.items).selectinload(OrderItem.product) 
            )
            .order_by(desc(Order.created_at))
            .limit(limit)
        )
        result = await db.execute(query)
        return result.scalars().all()
    except Exception as e:
        logger.error(f"Order Fetch Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error while fetching orders.")

# -- CREATE PRODUCT --
@admin_router.post("/products", response_model=ProductSchema)
async def create_product(
    name: str = Form(...),
    platform: str = Form(...),
    price_usd: float = Form(...),
    stock_quantity: int = Form(0),
    discount_percent: int = Form(0),
    description: Optional[str] = Form(None),
    file: UploadFile = File(...),
    is_featured: bool = Form(False),
    is_trending: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(get_current_admin)
):
    try:
        logger.info(f"Attempting Cloudinary upload for file: {file.filename}")
        upload_result = cloudinary.uploader.upload(file.file, folder="keyvault_products")
        secure_url = upload_result.get("secure_url")
    except Exception as e:
        logger.error(f"Cloudinary upload failed: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Image Provider Error: {str(e)}")

    return await create_product_service(
        db, name, platform, price_usd, description, secure_url, 
        stock_quantity, discount_percent, is_featured, is_trending
    )

# -- UPDATE PRODUCT (PUT) --
@admin_router.put("/products/{product_id}", response_model=ProductSchema)
async def update_product(
    product_id: int,
    name: str = Form(...),
    platform: str = Form(...),
    price_usd: float = Form(...),
    stock_quantity: int = Form(...),
    discount_percent: int = Form(0),
    description: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    is_featured: bool = Form(False),
    is_trending: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(get_current_admin)
):
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    if file:
        try:
            logger.info(f"Updating image for product {product_id}")
            upload_result = cloudinary.uploader.upload(file.file, folder="keyvault_products")
            product.image_url = upload_result.get("secure_url")
        except Exception as e:
            logger.error(f"Cloudinary upload failed: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Image Update Error: {str(e)}")

    product.name = name
    product.platform = platform
    product.price_usd = price_usd
    product.stock_quantity = stock_quantity
    product.discount_percent = discount_percent
    product.description = description
    product.is_featured = is_featured
    product.is_trending = is_trending
    product.in_stock = (stock_quantity > 0)

    await db.commit()
    await db.refresh(product)
    return product

# -- DELETE PRODUCT --
@admin_router.delete("/products/{product_id}")
async def delete_product(product_id: int, db: AsyncSession = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
        
    product.is_deleted = True
    product.deleted_at = datetime.utcnow()
    await db.commit()
    return {"message": "Product deleted successfully"}

# -- CREATE BANNER --
@admin_router.post("/banners", response_model=BannerSchema)
async def create_banner(
    title: Optional[str] = Form(None),
    subtitle: Optional[str] = Form(None),
    target_url: Optional[str] = Form(None),
    btn_text: str = Form("Shop Now"),
    is_active: bool = Form(True),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(get_current_admin)
):
    try:
        logger.info(f"Attempting Banner upload: {file.filename}")
        upload_result = cloudinary.uploader.upload(file.file, folder="keyvault_banners")
        secure_url = upload_result.get("secure_url")
    except Exception as e:
        logger.error(f"Banner upload failed: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Image Provider Error: {str(e)}")

    new_banner = Banner(
        title=title,
        subtitle=subtitle,
        target_url=target_url,
        btn_text=btn_text,
        image_url=secure_url,
        is_active=is_active,
        start_date=datetime.utcnow()
    )
    db.add(new_banner)
    await db.commit()
    await db.refresh(new_banner)
    return new_banner

# -- UPDATE BANNER (PUT) --
@admin_router.put("/banners/{banner_id}", response_model=BannerSchema)
async def update_banner(
    banner_id: int,
    title: Optional[str] = Form(None),
    subtitle: Optional[str] = Form(None),
    target_url: Optional[str] = Form(None),
    btn_text: str = Form("Shop Now"),
    is_active: bool = Form(True),
    file: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(get_current_admin)
):
    result = await db.execute(select(Banner).where(Banner.id == banner_id))
    banner = result.scalar_one_or_none()
    if not banner:
        raise HTTPException(status_code=404, detail="Banner not found")
        
    if file:
        try:
            logger.info(f"Updating image for banner {banner_id}")
            upload_result = cloudinary.uploader.upload(file.file, folder="keyvault_banners")
            banner.image_url = upload_result.get("secure_url")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Image Update Error: {str(e)}")

    banner.title = title
    banner.subtitle = subtitle
    banner.target_url = target_url
    banner.btn_text = btn_text
    banner.is_active = is_active
    
    await db.commit()
    await db.refresh(banner)
    return banner

# -- DELETE BANNER --
@admin_router.delete("/banners/{banner_id}")
async def delete_banner(banner_id: int, db: AsyncSession = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    result = await db.execute(select(Banner).where(Banner.id == banner_id))
    banner = result.scalar_one_or_none()
    
    if not banner:
        raise HTTPException(status_code=404, detail="Banner not found")
        
    await db.delete(banner)
    await db.commit()
    return {"message": "Banner deleted successfully"}

# -- UPLOAD CODES --
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


# --- F. WEBHOOK ROUTER ---
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
    return {"status": "SUCCESS"}

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
app.include_router(user_router)    # REGISTERED: Profile Access
app.include_router(wallet_router)  # REGISTERED: Deposit Functionality
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

@app.get("/terms")
async def serve_terms(): return FileResponse(FRONTEND_DIR / "terms.html")

@app.get("/privacy")
async def serve_privacy(): return FileResponse(FRONTEND_DIR / "privacy.html")

@app.get("/contact")
async def serve_contact(): return FileResponse(FRONTEND_DIR / "contact.html")

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