# db.py
# Production-level Database Engine & Utilities (Async + High Concurrency)

import os
import logging
import csv
import asyncio
from typing import AsyncGenerator, Optional, List

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
    AsyncEngine
)
from sqlalchemy import text, select, update, func
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv

# Import ProductCategory to ensure Enum types are registered in Metadata for init_db
from models_schemas import Base, Product, ProductCode, ProductCategory

# ======================================================
# CONFIGURATION & LOGGING
# ======================================================

load_dotenv()

# Configure structured logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("db.engine")

# 1. Fetch URL
raw_db_url = os.getenv("DATABASE_URL", "")

if not raw_db_url:
    raise RuntimeError("DATABASE_URL is missing! System cannot start.")

# 2. Production Protocol Fix
# Cloud providers (Heroku/Render/AWS) often give 'postgres://' 
# but SQLAlchemy Async requires 'postgresql+asyncpg://'
if raw_db_url.startswith("postgres://"):
    DATABASE_URL = raw_db_url.replace("postgres://", "postgresql+asyncpg://", 1)
elif raw_db_url.startswith("postgresql://"):
    DATABASE_URL = raw_db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
else:
    DATABASE_URL = raw_db_url

# ======================================================
# ASYNC ENGINE
# ======================================================

# 3. High-Performance Connection Pool
engine: AsyncEngine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to False in production for speed
    future=True,
    pool_size=20,           # Hold 20 permanent connections
    max_overflow=40,        # Allow 40 temporary spikes (total 60)
    pool_timeout=60,        # Wait 60s for a connection before failing
    pool_pre_ping=True,     # Check connection health before handing it out
    pool_recycle=1800,      # Recycle connections every 30 mins
)

# ======================================================
# SESSION FACTORY
# ======================================================

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    autoflush=False,
    expire_on_commit=False,
)

# ======================================================
# DEPENDENCY (FASTAPI)
# ======================================================

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency: Provides an async database session per request.
    Automatically handles commit/rollback and cleanup.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            # Note: We do not commit here automatically. 
            # Services should verify logic success before committing.
        except Exception as e:
            logger.error(f"Database session error: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()

# ======================================================
# INITIALIZATION & HEALTH
# ======================================================

async def init_db() -> None:
    """
    Creates tables if they don't exist.
    Ensures new Enum types (ProductCategory) are correctly registered in Postgres.
    Run this on startup (or use Alembic for migrations in strict prod).
    """
    try:
        async with engine.begin() as conn:
            # await conn.run_sync(Base.metadata.drop_all) # UNCOMMENT TO RESET DB
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables verified/created successfully.")
    except Exception as e:
        logger.critical(f"Failed to initialize database: {e}")
        raise

async def ping_db() -> bool:
    """
    Health check function. Returns True if DB is responsive.
    """
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False

# ======================================================
# PRODUCT CODE HELPERS (BATCH & CONCURRENCY)
# ======================================================

def _parse_codes_sync(file_path: str) -> List[str]:
    """
    Helper to parse TXT or CSV files synchronously.
    Intended to be run in a thread executor to avoid blocking the loop.
    """
    codes = []
    ext = os.path.splitext(file_path)[1].lower()
    
    try:
        with open(file_path, mode='r', encoding='utf-8-sig') as f:
            if ext == '.csv':
                reader = csv.reader(f)
                for row in reader:
                    if row: # Skip empty rows
                        codes.append(row[0].strip())
            else: # Assume .txt or other line-based format
                for line in f:
                    clean_line = line.strip()
                    if clean_line:
                        codes.append(clean_line)
        return codes
    except Exception as e:
        logger.error(f"File parsing error for {file_path}: {e}")
        return []

async def add_product_codes_from_file(file_path: str, product_id: int, db: AsyncSession) -> int:
    """
    Reads a file (TXT/CSV), parses codes, and bulk inserts them into the DB.
    Updates the Product's stock_quantity counter upon success.
    
    Now includes validation for Product existence and category checks (e.g. Direct Topup warnings).
    
    Args:
        file_path: Path to the local file.
        product_id: ID of the product to associate codes with.
        db: Active AsyncSession.
        
    Returns:
        int: Number of codes successfully inserted.
    """
    # 1. Run file parsing in a separate thread to avoid blocking the async loop
    try:
        codes = await asyncio.to_thread(_parse_codes_sync, file_path)
        
        if not codes:
            logger.warning(f"No codes found in file: {file_path}")
            return 0

        # 2. Validate Product Existence & Category
        # We fetch the product to ensure we aren't adding codes to a soft-deleted item
        # or misconfigured category.
        stmt = select(Product).where(Product.id == product_id)
        result = await db.execute(stmt)
        product = result.scalar_one_or_none()

        if not product:
            logger.error(f"Product ID {product_id} not found. Cannot add codes.")
            return 0
        
        if product.is_deleted:
             logger.error(f"Product ID {product_id} is soft-deleted. Cannot add codes.")
             return 0

        # Optional Warning for Direct Topup
        # Usually Direct Topup (requires_player_id) is manual, but some use "Voucher Codes".
        # We log this for audit purposes.
        if product.product_category == ProductCategory.DIRECT_TOPUP:
            logger.info(f"Adding stock codes to DIRECT_TOPUP product (ID: {product_id}). Ensure these are valid vouchers.")

        # 3. Prepare Code Objects
        new_code_objects = [
            ProductCode(product_id=product_id, code_value=code, is_used=False) 
            for code in codes
        ]
        
        # 4. Bulk Insert with Conflict Handling
        # Filter existing codes first to avoid integrity errors breaking the batch
        existing_res = await db.execute(
            select(ProductCode.code_value)
            .where(ProductCode.code_value.in_(codes))
        )
        existing_codes = set(existing_res.scalars().all())
        
        filtered_objects = [
            obj for obj in new_code_objects 
            if obj.code_value not in existing_codes
        ]
        
        if not filtered_objects:
            logger.info("All codes in file already exist in DB.")
            return 0

        db.add_all(filtered_objects)
        await db.flush() # Check for errors before committing

        # 5. Update Product Stock Counter
        # Only update if the product is not deleted (redundant check, but safe for concurrency)
        count_added = len(filtered_objects)
        
        await db.execute(
            update(Product)
            .where(Product.id == product_id)
            .where(Product.is_deleted == False) 
            .values(
                stock_quantity=Product.stock_quantity + count_added,
                in_stock=True # Re-enable stock if it was 0
            )
        )

        await db.commit()
        logger.info(f"Successfully added {count_added} codes for Product ID {product_id} ({product.product_category.value}).")
        return count_added

    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to batch add codes: {e}")
        return 0

async def get_unused_code(product_id: int, db: AsyncSession) -> Optional[str]:
    """
    Fetches a single unused code for automatic delivery.
    Uses 'SKIP LOCKED' to prevent race conditions where two concurrent requests 
    grab the same code before marking it used.
    """
    try:
        # Postgres-specific: FOR UPDATE SKIP LOCKED
        # This skips rows currently locked by other transactions, finding the next available one.
        stmt = (
            select(ProductCode.code_value)
            .where(ProductCode.product_id == product_id)
            .where(ProductCode.is_used == False)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        
        result = await db.execute(stmt)
        code_value = result.scalar_one_or_none()
        
        if code_value:
            logger.debug(f"Reserved code for product {product_id}: {code_value[:4]}***")
        else:
            logger.warning(f"No unused codes available for product {product_id}")
            
        return code_value

    except Exception as e:
        logger.error(f"Error fetching unused code for Product {product_id}: {e}")
        return None

async def mark_code_as_used(code_value: str, db: AsyncSession) -> bool:
    """
    Marks a specific code as used. atomic update.
    Typically called immediately after `get_unused_code` inside the same transaction.
    """
    try:
        # 1. Mark as used
        result = await db.execute(
            update(ProductCode)
            .where(ProductCode.code_value == code_value)
            .where(ProductCode.is_used == False) # Safety check
            .values(
                is_used=True,
                used_at=func.now()
            )
        )
        
        if result.rowcount == 0:
            logger.warning(f"Attempted to mark code used, but it was not found or already used: {code_value}")
            return False

        # Note: We do NOT decrement Product.stock_quantity here.
        # That logic usually lives in the Service layer (handle_btcpay_webhook) 
        # because one order might contain multiple items, and we update stock per product.
        
        await db.flush() # Ensure update is pending
        logger.info(f"Code marked as used: {code_value[:4]}***")
        return True

    except Exception as e:
        logger.error(f"Error marking code as used: {e}")
        return False