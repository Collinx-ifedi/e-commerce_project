# main.py
# Production-level Entry Point
# - Lifespan Management (Startup/Shutdown)
# - Gzip Compression & Performance Caching
# - Modular API Routers with RBAC
# - Global Exception Handling
# - Structured Logging Integration
# - Digital Asset Management

import os
import shutil
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import List

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request,
    status,
    APIRouter,
    UploadFile,
    File,
    BackgroundTasks
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession

# --- LOCAL MODULES ---
from .db import get_db, init_db, ping_db, add_product_codes_from_file
from .core import settings, get_current_admin, require_superadmin
from .utils import logger  # Structured JSON logger

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

# --- SCHEMAS ---
from .models_schemas import (
    UserCreateSchema, 
    AdminLoginSchema, 
    MultiProductOrderCreate, 
    Admin
)

# =========================================================
# 1. SETUP & CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))
UPLOAD_DIR = os.path.join(BASE_DIR, "temp_uploads")

# Ensure temp directory exists for code uploads
os.makedirs(UPLOAD_DIR, exist_ok=True)

# In-Memory Cache for HTML files to avoid Disk I/O on every request
HTML_CACHE = {}

def load_html_files():
    """
    Pre-loads HTML files into memory on startup.
    Drastically reduces latency for high-traffic frontend routes.
    """
    logger.info("Pre-loading frontend assets into memory...")
    pages = ["index.html", "product.html", "cart.html", "profile.html", "checkout.html", "login.html"]
    for page in pages:
        path = os.path.join(FRONTEND_DIR, page)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                HTML_CACHE[page] = f.read()
        else:
            logger.warning(f"Frontend file not found: {path}")

# =========================================================
# 2. LIFESPAN MANAGEMENT (Startup/Shutdown)
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages the application lifecycle.
    1. Initialize DB tables.
    2. Seed Admin users.
    3. Load HTML cache.
    """
    # --- STARTUP ---
    logger.info("System startup initiated...")
    
    # 1. Database Init
    await init_db()
    
    # 2. Bootstrap Admins (Idempotent)
    async for db in get_db():
        await bootstrap_admins(db)
        break 
    
    # 3. Load Frontend Cache
    load_html_files()
    
    logger.info(f"System startup complete. Version: {app.version}")
    
    yield
    
    # --- SHUTDOWN ---
    logger.info("System shutting down...")
    # Cleanup temp files
    if os.path.exists(UPLOAD_DIR):
        for f in os.listdir(UPLOAD_DIR):
            try:
                os.remove(os.path.join(UPLOAD_DIR, f))
            except Exception:
                pass

# =========================================================
# 3. APPLICATION FACTORY
# =========================================================

app = FastAPI(
    title="E-Commerce Backend",
    version="2.0.0", # Bumped for Architecture Shift (Removed BTCPay)
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Frontend", "description": "HTML Page serving"},
        {"name": "Auth", "description": "User authentication"},
        {"name": "Admin", "description": "Back-office & Inventory"},
        {"name": "Orders", "description": "Cart checkout & Fulfillment"},
        {"name": "Webhooks", "description": "Payment Gateway Integrations"},
    ]
)

# =========================================================
# 4. MIDDLEWARE (Security & Performance)
# =========================================================

# A. Performance: Compress responses > 1000 bytes
app.add_middleware(GZipMiddleware, minimum_size=1000)

# B. Security: CORS
# Strictly validate origins in production using settings
origins = []
if settings.ADMIN_FRONTEND_URL:
    origins.append(settings.ADMIN_FRONTEND_URL)
if settings.FRONTEND_URL:
    origins.append(settings.FRONTEND_URL)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins else ["*"], # Warn: '*' is dev only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# C. Monitoring: Process Time Header
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}"
    return response

# =========================================================
# 5. GLOBAL ERROR HANDLING
# =========================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catches unhandled errors, logs them with stack trace, 
    and returns a sanitized JSON to client.
    """
    logger.error(f"Global Exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error. Our engineering team has been notified."},
    )

# =========================================================
# 6. ROUTERS
# =========================================================

# --- A. FRONTEND ROUTES (Served from Memory) ---
view_router = APIRouter(tags=["Frontend"])

@view_router.get("/", response_class=HTMLResponse)
async def home():
    return HTML_CACHE.get("index.html", "<h1>Maintenance Mode</h1>")

@view_router.get("/product", response_class=HTMLResponse)
async def product_page():
    return HTML_CACHE.get("product.html", "<h1>Not Found</h1>")

@view_router.get("/cart", response_class=HTMLResponse)
async def cart_page():
    return HTML_CACHE.get("cart.html", "<h1>Not Found</h1>")

@view_router.get("/checkout", response_class=HTMLResponse)
async def checkout_page():
    return HTML_CACHE.get("checkout.html", "<h1>Not Found</h1>")

@view_router.get("/profile", response_class=HTMLResponse)
async def profile_page():
    return HTML_CACHE.get("profile.html", "<h1>Not Found</h1>")

@view_router.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTML_CACHE.get("login.html", "<h1>Not Found</h1>")


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

@auth_router.post("/verify-email")
async def verify_email(email: str, otp: str, db: AsyncSession = Depends(get_db)):
    """Verify account with OTP."""
    return await verify_user_email_service(db, email, otp)


# --- C. ADMIN ROUTES (Protected) ---
admin_router = APIRouter(prefix="/api/admin", tags=["Admin"])

@admin_router.post("/login")
async def admin_login_route(data: AdminLoginSchema, db: AsyncSession = Depends(get_db)):
    """Admin Login returning JWT Access Token."""
    token = await admin_login_service(db, data.username, data.password)
    return {"access_token": token, "token_type": "bearer"}

@admin_router.post("/products/{product_id}/upload-codes")
async def upload_product_codes(
    product_id: int,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(get_current_admin) # RBAC Protected
):
    """
    Upload .txt or .csv containing digital codes.
    Parses file, removes duplicates, and updates stock count atomically.
    """
    if not file.filename.endswith(('.txt', '.csv')):
        raise HTTPException(status_code=400, detail="Only .txt or .csv files allowed")

    # Save to temp file to handle large uploads without memory exhaustion
    temp_filename = f"{uuid.uuid4()}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, temp_filename)
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # Call DB Utility
        count = await add_product_codes_from_file(file_path, product_id, db)
        return {"status": "success", "codes_added": count}
        
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to process file")
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)


# --- D. ORDER ROUTES (Multi-Product Cart) ---
order_router = APIRouter(prefix="/api/orders", tags=["Orders"])

@order_router.post("/checkout", status_code=status.HTTP_201_CREATED)
async def checkout_route(
    order_data: MultiProductOrderCreate,
    request: Request,
    # In production, derive user_id from JWT via Depends(get_current_user)
    # user: User = Depends(get_current_user), 
    user_id: int = 1, # Placeholder for dev
    db: AsyncSession = Depends(get_db),
):
    """
    Process cart checkout.
    1. Validates stock for all items.
    2. locks price at purchase time.
    3. Returns Payment Gateway URL (NowPayments/Binance/Bybit).
    """
    try:
        checkout_url = await create_order_service(
            db=db,
            user_id=user_id,
            order_data=order_data 
        )
        return {"checkout_url": checkout_url}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Checkout failed: {e}")
        raise HTTPException(status_code=500, detail="Checkout processing failed.")


# --- E. WEBHOOKS (Payment Integration) ---
webhook_router = APIRouter(prefix="/api/webhooks", tags=["Webhooks"])

@webhook_router.post("/nowpayments")
async def nowpayments_webhook_route(request: Request, db: AsyncSession = Depends(get_db)):
    """Handle NowPayments IPN."""
    sig = request.headers.get("x-nowpayments-sig")
    payload = await request.json()
    await handle_nowpayments_webhook(db, payload, sig)
    return {"status": "ok"}

@webhook_router.post("/binance")
async def binance_webhook_route(request: Request, db: AsyncSession = Depends(get_db)):
    """Handle Binance Pay notifications."""
    # Binance sends headers for validation
    headers = dict(request.headers)
    payload = await request.json()
    await handle_binance_webhook(db, payload, headers)
    return {"status": "ok"}

@webhook_router.post("/bybit")
async def bybit_webhook_route(request: Request, db: AsyncSession = Depends(get_db)):
    """Handle Bybit Pay notifications."""
    payload = await request.json()
    await handle_bybit_webhook(db, payload)
    return {"status": "ok"}


# --- F. HEALTH CHECK ---
@app.get("/health", tags=["System"])
async def health_check():
    """Verifies DB connection and System status."""
    db_status = await ping_db()
    if not db_status:
        raise HTTPException(status_code=503, detail="Database Unavailable")
    return {
        "status": "healthy", 
        "database": "connected", 
        "version": app.version,
        "timestamp": time.time()
    }

# =========================================================
# 7. INCLUDE ROUTERS & STATIC FILES
# =========================================================

app.include_router(view_router)
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(order_router)
app.include_router(webhook_router)

# Mount Static Files (CSS/JS/Images)
# Guard against missing directory crashing startup
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
else:
    logger.warning(f"Static directory not found at {FRONTEND_DIR}. Assets will fail.")

# =========================================================
# EXECUTION
# =========================================================

if __name__ == "__main__":
    import uvicorn
    # 0.0.0.0 is required for Docker/Cloud
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, log_level="info")
