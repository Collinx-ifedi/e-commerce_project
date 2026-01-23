# main.py
# Production-level Entry Point
# - Integrated Cloudinary for Image Persistence (via CLOUDINARY_URL)
# - Multipart Form Data support for Admin CRUD
# - Dynamic Platform handling
# - Robust Path Resolution for Docker/Render
# - OTP Recovery Endpoint
# - Automatic Background Cleanup of Unverified Users
# - Wallet System Integration (Profile & Deposit)
# - Manual Delivery & Top-up Workflow Support
# - Flexible Blog Creation (Server-side Defaults)

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
    Body
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
    create_deposit_service,
    # create_product_service, # Replaced by inline logic to support new fields
    create_banner_service,
    handle_nowpayments_webhook,
    handle_binance_webhook,
    handle_bybit_webhook,
    process_admin_order_action # NEW: Manual Fulfillment Service
)

# --- SCHEMAS & MODELS ---
from .models_schemas import (
    UserCreateSchema, 
    AdminLoginSchema, 
    MultiProductOrderCreate, 
    Admin,
    User,
    UserResponse,
    Product, 
    OrderItem,
    ProductSchema,
    Banner,
    BannerSchema,
    Order,
    OrderResponse,
    OrderStatus,
    PaymentMethod,
    ProductCategory, # NEW: For Categorization
    # --- BLOG SYSTEM MODELS & SCHEMAS ---
    BlogPost,
    BlogComment,
    BlogResponse,
    BlogDetailResponse,
    CommentCreate
)

# =========================================================
# 1. SETUP & CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent      
PROJECT_ROOT = BASE_DIR.parent                  
FRONTEND_DIR = PROJECT_ROOT / "frontend"        
UPLOAD_DIR = BASE_DIR / "temp_uploads"          

os.makedirs(UPLOAD_DIR, exist_ok=True)

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
    logger.info("System startup initiated...")
    await init_db()
    async for db in get_db():
        await bootstrap_admins(db)
        break 
    cleanup_task = asyncio.create_task(cleanup_unverified_users())
    logger.info("Background task started: Cleanup unverified users.")
    logger.info(f"System startup complete. Version: {app.version}")
    yield
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
    version="2.6.2", # Bumped for Blog Route Fix
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
    category: Optional[str] = None, # NEW: Filter by Category Enum
    limit: int = 50, 
    db: AsyncSession = Depends(get_db)
):
    """Fetch active products with optional platform or category filters."""
    query = select(Product).where(
        or_(Product.is_deleted == False, Product.is_deleted.is_(None))
    )
    if platform:
        query = query.where(Product.platform == platform)
    
    if category:
        # Match against ProductCategory enum value
        query = query.where(Product.product_category == category)
    
    query = query.order_by(desc(Product.id)).limit(limit)
    result = await db.execute(query)
    products = result.scalars().all()
    return products

@catalog_router.get("/products/{product_id}", response_model=ProductSchema)
async def get_product_detail(product_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

@catalog_router.get("/banners", response_model=List[BannerSchema])
async def get_banners(active: bool = True, db: AsyncSession = Depends(get_db)):
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


# --- C. USER & WALLET ROUTER ---
user_router = APIRouter(prefix="/api/user", tags=["User Profile"])
wallet_router = APIRouter(prefix="/api/wallet", tags=["Wallet"])

@user_router.get("/profile", response_model=UserResponse)
async def get_user_profile(user: User = Depends(get_current_user)):
    return user

@wallet_router.post("/deposit", status_code=status.HTTP_201_CREATED)
async def create_deposit(
    amount: float = Body(..., gt=1.0, embed=True),
    gateway: PaymentMethod = Body(..., embed=True),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
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
    Handles Checkout. Now supports capturing 'player_id' for Direct Topup.
    """
    try:
        checkout_url = await create_order_service(db, user.id, order_data)
        return {"checkout_url": checkout_url}
    except Exception as e:
        logger.error(f"Checkout failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@order_router.get("")
async def get_user_orders(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    stmt = select(Order).where(Order.user_id == user.id).order_by(desc(Order.created_at))
    result = await db.execute(stmt)
    return result.scalars().all()


# --- E. ADMIN ROUTER ---
admin_router = APIRouter(prefix="/api/admin", tags=["Admin"])

@admin_router.post("/login")
async def admin_login_route(data: AdminLoginSchema, db: AsyncSession = Depends(get_db)):
    token = await admin_login_service(db, data.username, data.password)
    result = await db.execute(select(Admin).where(Admin.username == data.username))
    admin = result.scalar_one_or_none()
    role = admin.role.value if admin and hasattr(admin.role, 'value') else "admin"
    
    return {
        "access_token": token, 
        "token_type": "bearer",
        "admin": {
            "username": data.username,
            "role": role
        }
    }

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

    open_orders_res = await db.execute(
        select(func.count(Order.id)).where(Order.status == OrderStatus.IN_PROGRESS)
    )
    open_orders = open_orders_res.scalar() or 0

    return {
        "total_sales": total_revenue,
        "total_orders": total_orders,
        "total_users": total_users,
        "total_products": total_products,
        "open_orders": open_orders
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

# -- NEW: ADMIN MANUAL ORDER ACTION --
@admin_router.post("/orders/{order_id}/action")
async def admin_order_action(
    order_id: int,
    payload: dict = Body(...),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(get_current_admin)
):
    """
    Approve or Reject an order manually.
    Payload: {"action": "complete" | "reject", "manual_content": "codes..."}
    """
    action = payload.get("action")
    manual_content = payload.get("manual_content")
    
    if action not in ["complete", "reject"]:
        raise HTTPException(status_code=400, detail="Invalid action")
        
    return await process_admin_order_action(db, order_id, action, manual_content)

# -- CREATE PRODUCT (Updated for New Categories) --
@admin_router.post("/products", response_model=ProductSchema)
async def create_product(
    name: str = Form(...),
    platform: str = Form(...),
    price_usd: float = Form(...),
    stock_quantity: int = Form(0),
    discount_percent: int = Form(0),
    # NEW FIELDS:
    product_category: ProductCategory = Form(ProductCategory.OTHERS),
    requires_player_id: bool = Form(False),
    
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

    # Inline Creation to ensure new fields are saved
    new_product = Product(
        name=name,
        platform=platform,
        product_category=product_category, # New field
        requires_player_id=requires_player_id, # New field
        price_usd=price_usd,
        stock_quantity=stock_quantity,
        in_stock=(stock_quantity > 0),
        discount_percent=discount_percent,
        description=description,
        image_url=secure_url,
        is_featured=is_featured,
        is_trending=is_trending
    )
    db.add(new_product)
    await db.commit()
    await db.refresh(new_product)
    return new_product

# -- UPDATE PRODUCT (PUT) --
@admin_router.put("/products/{product_id}", response_model=ProductSchema)
async def update_product(
    product_id: int,
    name: str = Form(...),
    platform: str = Form(...),
    price_usd: float = Form(...),
    stock_quantity: int = Form(...),
    discount_percent: int = Form(0),
    # NEW FIELDS:
    product_category: Optional[ProductCategory] = Form(None),
    requires_player_id: bool = Form(False),
    
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
    
    # Update new fields
    if product_category:
        product.product_category = product_category
    product.requires_player_id = requires_player_id

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

    return await create_banner_service(db, title, secure_url)

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

# --- G. BLOG ROUTER (Public) ---
blog_router = APIRouter(prefix="/api/blog", tags=["Blog (Public)"])

@blog_router.get("/posts", response_model=List[BlogResponse])
async def get_blog_posts(db: AsyncSession = Depends(get_db)):
    stmt = (
        select(BlogPost)
        .where(BlogPost.is_published == True, BlogPost.is_deleted == False)
        .options(selectinload(BlogPost.author))
        .order_by(desc(BlogPost.created_at))
    )
    result = await db.execute(stmt)
    return result.scalars().all()

# --- FIXED ROUTE: Replaced '/posts/detail/{slug}' with '/posts/{slug}' to match frontend ---
@blog_router.get("/posts/{slug}", response_model=BlogDetailResponse)
async def get_post_details(slug: str, db: AsyncSession = Depends(get_db)):
    stmt = (
        select(BlogPost)
        # Added explicit 'is_published' check for public access security
        .where(BlogPost.slug == slug, BlogPost.is_deleted == False, BlogPost.is_published == True)
        .options(
            selectinload(BlogPost.author),
            selectinload(BlogPost.comments).selectinload(BlogComment.user)
        )
    )
    result = await db.execute(stmt)
    post = result.scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="Blog post not found")
    return post

@blog_router.post("/posts/{post_id}/comments")
async def add_comment(
    post_id: int,
    content: str = Body(..., embed=True),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(BlogPost).where(BlogPost.id == post_id)
    result = await db.execute(stmt)
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Post not found")

    new_comment = BlogComment(post_id=post_id, user_id=user.id, content=content)
    db.add(new_comment)
    await db.commit()
    return {"status": "success"}

@blog_router.delete("/comments/{comment_id}")
async def delete_comment(
    comment_id: int,
    admin: Admin = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db)
):
    await db.execute(delete(BlogComment).where(BlogComment.id == comment_id))
    await db.commit()
    return {"detail": "Comment removed"}

# --- H. ADMIN BLOG ROUTER (Protected) ---
# New router to handle Admin Blog Management
admin_blog_router = APIRouter(prefix="/api/admin/blog", tags=["Admin Blog"])

@admin_blog_router.get("/posts", response_model=List[BlogResponse])
async def get_admin_blog_posts(
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(get_current_admin)
):
    """List ALL blog posts (Published & Drafts) for Admin Table"""
    stmt = (
        select(BlogPost)
        .where(BlogPost.is_deleted == False)
        .options(selectinload(BlogPost.author))
        .order_by(desc(BlogPost.created_at))
    )
    result = await db.execute(stmt)
    return result.scalars().all()

@admin_blog_router.post("/posts")
async def create_blog_post(
    title: Optional[str] = Form(None),
    content: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
    is_published: bool = Form(True),
    current_admin: Admin = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Create a new Blog Post (Admin) with Robust Defaults"""
    
    # Apply defaults if fields are missing or empty
    final_title = title.strip() if title and title.strip() else f"Untitled Post {datetime.utcnow().strftime('%Y-%m-%d')}"
    final_content = content.strip() if content and content.strip() else "No content provided."

    img_url = None
    if image:
        try:
            upload_result = cloudinary.uploader.upload(image.file, folder="keyvault_blog")
            img_url = upload_result.get("secure_url")
        except Exception as e:
            logger.error(f"Cloudinary upload failed: {e}")
            raise HTTPException(status_code=400, detail="Image upload failed")

    # Generate a secure slug, appending unique ID if it's a generic title
    base_slug = final_title.lower().replace(" ", "-")[:50]
    unique_suffix = f"-{int(time.time())}"
    slug = f"{base_slug}{unique_suffix}"
    
    new_post = BlogPost(
        title=final_title,
        slug=slug,
        content=final_content,
        image_url=img_url,
        is_published=is_published,
        author_id=current_admin.id
    )
    db.add(new_post)
    await db.commit()
    await db.refresh(new_post)
    
    return {"status": "success", "slug": slug, "post": new_post}

@admin_blog_router.put("/posts/{post_id}")
async def update_blog_post(
    post_id: int,
    title: str = Body(None),
    content: str = Body(None),
    is_published: bool = Body(None),
    image_url: str = Body(None), # For frontend sending existing or new URL
    current_admin: Admin = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Update Blog Post (Admin)"""
    stmt = select(BlogPost).where(BlogPost.id == post_id)
    result = await db.execute(stmt)
    post = result.scalar_one_or_none()
    
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
        
    if title: post.title = title
    if content: post.content = content
    if is_published is not None: post.is_published = is_published
    if image_url: post.image_url = image_url
    
    await db.commit()
    return {"status": "updated"}

@admin_blog_router.delete("/posts/{post_id}")
async def delete_blog_post(
    post_id: int,
    admin: Admin = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Soft Delete Blog Post (Admin)"""
    stmt = update(BlogPost).where(BlogPost.id == post_id).values(
        is_deleted=True,
        deleted_at=datetime.utcnow()
    )
    result = await db.execute(stmt)
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Post not found")
        
    await db.commit()
    return {"detail": "Post deleted"}

@admin_blog_router.get("/comments")
async def get_all_comments(
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(get_current_admin)
):
    """List ALL comments for moderation"""
    # Fetch comments with related User and Post info
    stmt = (
        select(BlogComment)
        .options(
            selectinload(BlogComment.user),
            selectinload(BlogComment.post)
        )
        .order_by(desc(BlogComment.created_at))
    )
    result = await db.execute(stmt)
    comments = result.scalars().all()
    
    # Manually construct response to include needed fields for table
    return [
        {
            "id": c.id,
            "content": c.content,
            "created_at": c.created_at,
            "username": c.user.email if c.user else "Anonymous",
            "post_title": c.post.title if c.post else "Unknown Post",
            "post_id": c.post_id
        } 
        for c in comments
    ]

@admin_blog_router.delete("/comment/{comment_id}")
async def admin_delete_comment(
    comment_id: int,
    admin: Admin = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Delete specific comment (Admin Moderation)"""
    await db.execute(delete(BlogComment).where(BlogComment.id == comment_id))
    await db.commit()
    return {"detail": "Comment removed"}


# =========================================================
# 6. REGISTER API ROUTERS
# =========================================================

app.include_router(catalog_router)
app.include_router(auth_router)
app.include_router(user_router)    
app.include_router(wallet_router)  
app.include_router(order_router)
app.include_router(admin_router)
app.include_router(webhook_router)
app.include_router(blog_router)
app.include_router(admin_blog_router) # Registered new admin blog router

# =========================================================
# 7. FRONTEND PAGE ROUTES
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

@app.get("/blog")
async def serve_blog_clean(): return FileResponse(FRONTEND_DIR / "blog.html")

@app.get("/blog-post")
async def serve_blog_post_clean(): return FileResponse(FRONTEND_DIR / "blog-post.html")

@app.get("/{page_name}.html")
async def serve_html_pages(page_name: str):
    file_path = FRONTEND_DIR / f"{page_name}.html"
    if file_path.exists():
        return FileResponse(file_path)
    return JSONResponse(status_code=404, content={"detail": "Page not found"})

# =========================================================
# 8. STATIC FILES
# =========================================================

if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

# =========================================================
# EXECUTION
# =========================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)