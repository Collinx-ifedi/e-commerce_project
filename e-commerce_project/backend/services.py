# services.py
# Production-level Business Logic Layer
# - User Auth & Recovery
# - Cloudinary Content Management
# - Atomic Order Fulfillment (Wallet + Gateways)
# - Payment Gateway Integration
# - Manual Delivery & Top-up Workflow
# - Denomination & Code Management
# - UPDATED: Admin Messaging & User Moderation

import os
import hmac
import hashlib
import json
import logging
import httpx
import time
import random
import string
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import update, delete, and_, or_, case, func

# IMPORT MODELS
from .models_schemas import (
    User,
    Admin,
    Product,
    Denomination,
    ProductCode,
    Order,
    OrderItem,
    Transaction,
    Banner,
    Notification,
    OrderStatus,
    PaymentMethod,
    OTPPurpose,
    MultiProductOrderCreate,
    ProductCategory,
    InboxMessage
)

# IMPORT UTILS & CORE
from .utils import (
    generate_otp,
    send_email_otp,
    send_email_async,
    send_fulfillment_email,
    save_otp_to_db,
    log_action,
    format_currency
)

from .core import (
    create_access_token,
    hash_password,
    verify_password,
    settings
)

# IMPORT DB HELPERS
from .db import (
    get_unused_code, 
    mark_code_as_used, 
    add_denomination_codes_from_file,
    # New Helpers for Messaging & Moderation
    insert_message,
    fetch_user_messages,
    mark_message_read,
    set_user_ban_state
)

# =========================================================
# CONFIG & LOGGING
# =========================================================

logger = logging.getLogger("services")
logger.setLevel(logging.INFO)

# --- PAYMENT GATEWAY CONFIG ---
NOWPAYMENTS_API_KEY = os.getenv("NOWPAYMENTS_API_KEY")
NOWPAYMENTS_BASE_URL = "https://api.nowpayments.io/v1"

BINANCE_PAY_API_KEY = os.getenv("BINANCE_PAY_API_KEY")
BINANCE_PAY_SECRET_KEY = os.getenv("BINANCE_PAY_SECRET_KEY")
BINANCE_PAY_BASE_URL = "https://bpay.binanceapi.com"

BYBIT_API_KEY = os.getenv("BYBIT_API_KEY")
BYBIT_SECRET_KEY = os.getenv("BYBIT_SECRET_KEY")

# =========================================================
# 1. USER AUTHENTICATION & RECOVERY SERVICES
# =========================================================

async def create_user_service(db: AsyncSession, email: str, password: str, country: str):
    """
    Registers a new user. 
    Handles 'User Exists' states:
    1. If user exists and is VERIFIED -> Raise Error.
    2. If user exists and is UNVERIFIED -> Update creds, regen OTP, resend email (Allow retry).
    """
    result = await db.execute(select(User).where(User.email == email))
    existing_user = result.scalar_one_or_none()

    # Pre-calculate hash and OTP for use in either path
    hashed_pw = hash_password(password)
    otp_code = generate_otp()
    otp_expiry_dt = datetime.utcnow() + timedelta(minutes=10)

    if existing_user:
        if existing_user.is_verified:
            # Case 1: Strictly block verified users
            raise HTTPException(status_code=400, detail="User with this email already exists.")
        
        # Case 2: User exists but abandoned verification.
        # Action: Treat as a new attempt. Update password/country to match current request.
        existing_user.password_hash = hashed_pw
        existing_user.country = country
        existing_user.email_otp = otp_code
        existing_user.otp_expiry = otp_expiry_dt
        
        # We do not change is_verified (remains False)
        await db.commit()
        
        # Resend Email
        try:
            await send_email_otp(email, otp_code, OTPPurpose.EMAIL_VERIFY)
        except Exception as e:
            logger.error(f"Failed to resend welcome email to {email}: {e}")
        
        # Return existing user object
        return existing_user

    # Case 3: Fresh User
    new_user = User(
        email=email,
        password_hash=hashed_pw,
        country=country,
        email_otp=otp_code,
        otp_expiry=otp_expiry_dt,
        is_verified=False,
        balance_usd=0.0
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    try:
        await send_email_otp(email, otp_code, OTPPurpose.EMAIL_VERIFY)
    except Exception as e:
        logger.error(f"Failed to send welcome email to {email}: {e}")
    
    return new_user

async def resend_otp_service(db: AsyncSession, email: str):
    """Allows an unverified user to request a new OTP."""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    if user.is_verified:
        raise HTTPException(status_code=400, detail="Account is already verified. Please log in.")

    new_otp = generate_otp()
    user.email_otp = new_otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    
    await db.commit()

    try:
        await send_email_otp(email, new_otp, OTPPurpose.EMAIL_VERIFY)
    except Exception as e:
        logger.error(f"Failed to resend OTP to {email}: {e}")
        raise HTTPException(status_code=500, detail="Failed to send email.")

    return {"message": "Verification code sent."}

async def verify_user_email_service(db: AsyncSession, email: str, otp: str):
    """Verifies a user's email address and clears the OTP fields."""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.is_verified:
        return {"message": "User already verified"}
    
    if user.email_otp != otp:
        raise HTTPException(status_code=400, detail="Invalid verification code")
    
    if user.otp_expiry and datetime.utcnow() > user.otp_expiry:
        raise HTTPException(status_code=400, detail="Verification code has expired.")

    user.is_verified = True
    user.email_otp = None
    user.otp_expiry = None
    
    await db.commit()
    return {"message": "Email verified successfully"}

# =========================================================
# 2. ADMIN & CATALOG SERVICES
# =========================================================

async def bootstrap_admins(db: AsyncSession):
    """Seeds admin accounts on startup."""
    from .core import ADMIN_PASSWORDS 
    
    for username, password in ADMIN_PASSWORDS.items():
        result = await db.execute(select(Admin).where(Admin.username == username))
        if not result.scalar_one_or_none():
            logger.info(f"Seeding admin: {username}")
            role = "superadmin" if username == settings.SUPERADMIN_USERNAME else "admin"
            new_admin = Admin(
                username=username, 
                password_hash=hash_password(password), 
                role=role, 
                is_active=True
            )
            db.add(new_admin)
            
    await db.commit()

async def admin_login_service(db: AsyncSession, username: str, password: str):
    """Authenticates admin."""
    result = await db.execute(select(Admin).where(Admin.username == username))
    admin = result.scalar_one_or_none()
    
    if not admin or not verify_password(password, admin.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not admin.is_active:
        raise HTTPException(status_code=403, detail="Account inactive")
    
    admin.last_login = datetime.utcnow()
    await db.commit()
    
    return create_access_token(
        subject=admin.username, 
        role=admin.role.value if hasattr(admin.role, 'value') else "admin"
    )

async def create_product_service(
    db: AsyncSession, 
    name: str, 
    platform: str, 
    product_category: ProductCategory,
    requires_player_id: bool,
    description: str, 
    image_url: str,
    is_featured: bool = False,
    is_trending: bool = False
):
    """
    Creates a product. 
    NOTE: Products no longer have direct price/stock. Those belong to Denominations.
    """
    new_product = Product(
        name=name,
        platform=platform, 
        product_category=product_category,
        requires_player_id=requires_player_id,
        description=description,
        image_url=image_url, 
        is_featured=is_featured,
        is_trending=is_trending
    )
    db.add(new_product)
    await db.commit()
    await db.refresh(new_product)
    return new_product

async def create_banner_service(db: AsyncSession, title: Optional[str], image_url: str):
    new_banner = Banner(
        title=title,
        image_url=image_url,
        is_active=True,
        start_date=datetime.utcnow()
    )
    db.add(new_banner)
    await db.commit()
    await db.refresh(new_banner)
    return new_banner

# --- DENOMINATION MANAGEMENT SERVICES ---

async def create_denomination_service(
    db: AsyncSession,
    product_id: int,
    label: str,
    price_usd: float,
    discount_percent: int = 0
):
    """
    Creates a new denomination (variant) for a product.
    """
    # 1. Validate Product Exists
    product_res = await db.execute(select(Product).where(Product.id == product_id))
    product = product_res.scalar_one_or_none()
    
    if not product:
        raise HTTPException(status_code=404, detail="Parent product not found.")

    # 2. Create Denomination
    new_denom = Denomination(
        denomination_id=denomination_id,
        label=label,
        price_usd=price_usd,
        discount_percent=discount_percent,
        stock_quantity=0, # Starts with 0 until codes are uploaded
        in_stock=False
    )
    db.add(new_denom)
    await db.commit()
    await db.refresh(new_denom)
    return new_denom

async def get_product_denominations_service(db: AsyncSession, product_id: int):
    """
    Lists all denominations for a specific product.
    """
    stmt = (
        select(Denomination)
        .where(Denomination.product_id == product_id)
        .where(or_(Denomination.is_deleted == False, Denomination.is_deleted.is_(None)))
        .order_by(Denomination.price_usd)
    )
    result = await db.execute(stmt)
    denoms = result.scalars().all()
    return denoms

async def upload_denomination_codes_service(
    db: AsyncSession, 
    denomination_id: int, 
    file_path: str
) -> int:
    """
    Bulk uploads codes to a specific denomination.
    Uses db.py helper to handle parsing and integrity checks.
    """
    count = await add_denomination_codes_from_file(file_path, Denomination, db)
    return count

async def get_all_orders_service(db: AsyncSession, limit: int = 100):
    """
    Admin helper to fetch orders with summary data.
    """
    stmt = (
        select(Order)
        .options(selectinload(Order.user))
        .order_by(Order.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    return result.scalars().all()

# =========================================================
# 3. PAYMENT GATEWAY HELPERS
# =========================================================

def _generate_random_string(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# --- NOWPAYMENTS ---
async def create_nowpayments_invoice(order: Order, user_email: str) -> str:
    if not NOWPAYMENTS_API_KEY:
        raise HTTPException(status_code=500, detail="NowPayments config missing")

    url = f"{NOWPAYMENTS_BASE_URL}/invoice"
    headers = {"x-api-key": NOWPAYMENTS_API_KEY, "Content-Type": "application/json"}
    frontend_url = settings.FRONTEND_URL or "http://localhost:3000"
    
    desc = "Wallet Deposit" if order.is_deposit else f"Order {order.order_reference}"

    payload = {
        "price_amount": order.total_amount_usd,
        "price_currency": "usd",
        "order_id": order.order_reference,
        "order_description": desc,
        "ipn_callback_url": f"{settings.ADMIN_FRONTEND_URL or 'http://localhost:8000'}/api/webhooks/nowpayments",
        "success_url": f"{frontend_url}/checkout/success",
        "cancel_url": f"{frontend_url}/checkout/fail"
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(url, json=payload, headers=headers, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            return data["invoice_url"]
        except Exception as e:
            logger.error(f"NowPayments API Error: {e}")
            raise HTTPException(status_code=502, detail="Payment gateway unavailable")

# --- BINANCE PAY ---
async def create_binance_order(order: Order) -> str:
    if not BINANCE_PAY_API_KEY or not BINANCE_PAY_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Binance Pay config missing")

    frontend_url = settings.FRONTEND_URL or "http://localhost:3000"
    
    goods_name = "Wallet Deposit" if order.is_deposit else "Digital Products"
    goods_detail = "Balance Top-up" if order.is_deposit else str(order.id)

    payload = {
        "env": {"terminalType": "WEB"},
        "merchantTradeNo": order.order_reference,
        "orderAmount": round(order.total_amount_usd, 2),
        "currency": "USDT", 
        "goods": {
            "goodsType": "02",
            "goodsCategory": "Z000",
            "referenceGoodsId": goods_detail,
            "goodsName": goods_name,
        },
        "returnUrl": f"{frontend_url}/checkout/success",
        "cancelUrl": f"{frontend_url}/checkout/fail",
        "webhookUrl": f"{settings.ADMIN_FRONTEND_URL or 'http://localhost:8000'}/api/webhooks/binance"
    }

    timestamp = str(int(time.time() * 1000))
    nonce = _generate_random_string(32)
    payload_json = json.dumps(payload)
    
    sign_payload = f"{timestamp}\n{nonce}\n{payload_json}\n"
    signature = hmac.new(BINANCE_PAY_SECRET_KEY.encode(), sign_payload.encode(), hashlib.sha512).hexdigest().upper()

    headers = {
        "Content-Type": "application/json",
        "BinancePay-Timestamp": timestamp,
        "BinancePay-Nonce": nonce,
        "BinancePay-Certificate-SN": BINANCE_PAY_API_KEY, 
        "BinancePay-Signature": signature
    }

    url = f"{BINANCE_PAY_BASE_URL}/binancepay/openapi/v2/order"

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(url, content=payload_json, headers=headers, timeout=10.0)
            data = resp.json()
            if data.get("status") == "SUCCESS":
                return data["data"]["checkoutUrl"]
            else:
                logger.error(f"Binance Pay Error: {data}")
                raise Exception("Binance Pay returned error status")
        except Exception as e:
            logger.error(f"Binance API Exception: {e}")
            return f"{frontend_url}/checkout/pending?ref={order.order_reference}"

# --- BYBIT PAY ---
async def create_bybit_order(order: Order) -> str:
    if not BYBIT_API_KEY or not BYBIT_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Bybit Pay config missing")
    frontend_url = settings.FRONTEND_URL or "http://localhost:3000"
    return f"{frontend_url}/checkout/mock-provider?ref={order.order_reference}&provider=bybit"

# =========================================================
# 4. ORDER FULFILLMENT SERVICES (INTERNAL)
# =========================================================

async def _fulfill_order_items(db: AsyncSession, order: Order):
    """
    Internal Helper: Iterates through order items and attempts to assign codes.
    If codes are found, it decrements stock and updates the item status.
    Returns: A list of assigned codes for email delivery.
    """
    assigned_codes_for_email = []
    all_items_fulfilled = True
    
    # Pre-fetch items with denomination and product if not already loaded
    # (Assuming passed 'order' object has items loaded, but safety check is good)
    
    for item in order.items:
        # Skip if already delivered (idempotency)
        # Note: OrderItem doesn't have a status, we check if code is associated via ProductCode table
        # But for simplicity in this flow, we assume we are processing a paid order.
        
        # Determine quantity needed
        qty_needed = item.quantity
        
        # Check how many codes are already assigned to this order & denomination
        stmt_existing = (
            select(func.count(ProductCode.id))
            .where(ProductCode.order_id == order.id)
            .where(ProductCode.denomination_id == item.denomination_id)
        )
        existing_count = (await db.execute(stmt_existing)).scalar() or 0
        
        qty_to_fetch = qty_needed - existing_count
        
        if qty_to_fetch <= 0:
            continue # Already fulfilled this item

        # Fetch codes one by one to ensure atomic locking
        for _ in range(qty_to_fetch):
            code_value = await get_unused_code(item.denomination_id, db)
            
            if code_value:
                # Mark Used
                success = await mark_code_as_used(code_value, db)
                if success:
                    # Link to Order
                    await db.execute(
                        update(ProductCode)
                        .where(ProductCode.code_value == code_value)
                        .values(order_id=order.id)
                    )
                    
                    # Decrement Stock
                    await db.execute(
                        update(Denomination)
                        .where(Denomination.id == item.denomination_id)
                        .values(stock_quantity=Denomination.stock_quantity - 1)
                    )
                    
                    assigned_codes_for_email.append(code_value)
                else:
                    all_items_fulfilled = False
            else:
                # No code available (Stock race condition or Direct Topup type)
                # If product is Direct Topup, we don't expect codes, so we don't fail flag.
                if item.product.product_category == ProductCategory.DIRECT_TOPUP:
                    pass # Handled via manual admin action later
                else:
                    all_items_fulfilled = False
                    logger.error(f"Stock mismatch during fulfillment for Denomination {item.denomination_id}")

    return assigned_codes_for_email, all_items_fulfilled

async def process_admin_order_action(
    db: AsyncSession, 
    order_id: int, 
    action: str, 
    manual_content: Optional[str] = None
):
    """
    Handles Admin manual 'Complete' or 'Reject'.
    """
    stmt = (
        select(Order)
        .options(
            selectinload(Order.items).selectinload(OrderItem.product),
            selectinload(Order.user)
        )
        .where(Order.id == order_id)
    )
    result = await db.execute(stmt)
    order = result.scalar_one_or_none()

    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if order.status == OrderStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Order is already completed")

    # --- REJECT ---
    if action == "reject":
        order.status = OrderStatus.REJECTED
        await db.commit()
        return {"status": "rejected", "detail": "Order marked as rejected."}

    # --- COMPLETE ---
    if action == "complete":
        # 1. Try to auto-fulfill any pending codes (if admin added stock manually)
        assigned_codes, all_fulfilled = await _fulfill_order_items(db, order)
        
        # 2. Check for Direct Topup items (requires manual text usually)
        is_direct_topup = any(i.product.product_category == ProductCategory.DIRECT_TOPUP for i in order.items)
        
        if is_direct_topup and not manual_content:
             # If strictly manual topup, we might require content. 
             # But we allow completion if admin did it outside system.
             pass

        # 3. Update Status
        order.status = OrderStatus.COMPLETED
        order.fulfillment_note = manual_content or "Delivered via Admin"
        order.updated_at = datetime.utcnow()
        
        # 4. Construct Email
        # We use the unified email helper from utils
        await send_fulfillment_email(
            user_email=order.user.email,
            product_name="Your Order", # Generic name for multi-item
            order_reference=order.order_reference,
            codes=assigned_codes,
            manual_text=manual_content,
            player_id=order.order_metadata.get('player_id')
        )

        await db.commit()
        return {"status": "completed", "detail": "Order completed.", "codes_delivered": len(assigned_codes)}

    raise HTTPException(status_code=400, detail="Invalid action")

# =========================================================
# 5. ORDER CREATION SERVICES (Checkout & Deposits)
# =========================================================

async def create_order_service(db: AsyncSession, user_id: int, order_data: MultiProductOrderCreate) -> str:
    """
    Orchestrates order creation for Multiple Items.
    1. Validates Denomination Existence & Stock.
    2. Calculates Total.
    3. Creates Order & OrderItems.
    4. Handles Payment (Wallet Instant vs Gateway Async).
    """
    if not order_data.items:
        raise HTTPException(status_code=400, detail="Cart is empty")

    # Group requested items by denomination_id
    requested_map = {}
    for item in order_data.items:
        requested_map[item.denomination_id] = requested_map.get(item.denomination_id, 0) + item.quantity

    # Fetch Denominations with Product info
    denom_ids = list(requested_map.keys())
    stmt = (
        select(Denomination)
        .options(selectinload(Denomination.product))
        .where(Denomination.id.in_(denom_ids))
        .where(or_(Denomination.is_deleted == False, Denomination.is_deleted.is_(None)))
    )
    result = await db.execute(stmt)
    denoms_db = result.scalars().all()
    
    if len(denoms_db) != len(denom_ids):
        raise HTTPException(status_code=404, detail="One or more products/denominations not found.")

    total_amount_usd = 0.0
    order_items_objects = []

    # 1. Validation & Calculation
    for denom in denoms_db:
        qty_requested = requested_map[denom.id]
        
        # Check Stock (Pre-payment check)
        # Skip stock check for Direct Topup if configured, otherwise strictly enforce
        is_direct = denom.product.product_category == ProductCategory.DIRECT_TOPUP
        if not is_direct and (not denom.in_stock or denom.stock_quantity < qty_requested):
            raise HTTPException(status_code=400, detail=f"Insufficient stock for '{denom.product.name} - {denom.label}'")
        
        unit_price = denom.final_price
        total_amount_usd += unit_price * qty_requested
        
        # Prepare OrderItem
        # Snapshotting names/labels is crucial for history if product/denom is deleted later
        order_items_objects.append(
            OrderItem(
                denomination_id=denom.id,
                quantity=qty_requested,
                unit_price_at_purchase=unit_price,
                product_name_snapshot=denom.product.name,
                variant_label_snapshot=denom.label
            )
        )

    # 2. Check Wallet Balance
    user_res = await db.execute(select(User).where(User.id == user_id))
    user = user_res.scalar_one_or_none()

    if order_data.payment_method == PaymentMethod.WALLET:
        if user.balance_usd < total_amount_usd:
            raise HTTPException(status_code=400, detail="Insufficient wallet balance.")

    # 3. Create Order
    order_ref = generate_otp(length=10)
    metadata = {}
    if order_data.player_id:
        metadata["player_id"] = order_data.player_id

    new_order = Order(
        user_id=user_id,
        order_reference=order_ref,
        total_amount_usd=round(total_amount_usd, 2),
        status=OrderStatus.PENDING,
        payment_method=order_data.payment_method,
        customer_ip="0.0.0.0",
        is_deposit=False,
        order_metadata=metadata
    )
    db.add(new_order)
    await db.flush() # Get ID

    for item in order_items_objects:
        item.order_id = new_order.id
        db.add(item)
    
    # Reload order with items/products for fulfillment usage
    # (Not strictly necessary here but good for safety if logic expands)
    
    # 4. Handle Payment & Fulfillment
    try:
        # A) WALLET (Instant)
        if order_data.payment_method == PaymentMethod.WALLET:
            # Deduct Balance
            user.balance_usd -= total_amount_usd
            
            # Record Transaction
            db.add(Transaction(
                user_id=user.id, order_id=new_order.id, amount_usd=total_amount_usd,
                status="confirmed", provider="Wallet", tx_hash=f"INT-{order_ref}"
            ))
            
            # Attempt Instant Fulfillment
            assigned_codes, all_fulfilled = await _fulfill_order_items(db, new_order)
            
            # Determine Final Status
            if all_fulfilled:
                new_order.status = OrderStatus.COMPLETED
                new_order.payment_reference = f"WALLET-{order_ref}"
                
                # Send Email
                await send_fulfillment_email(
                    user_email=user.email,
                    product_name="Your Digital Order",
                    order_reference=order_ref,
                    codes=assigned_codes,
                    player_id=order_data.player_id
                )
            else:
                # Stock issue or Manual Topup needed
                new_order.status = OrderStatus.IN_PROGRESS
                new_order.payment_reference = f"WALLET-{order_ref}"

            await db.commit()
            
            frontend_url = settings.FRONTEND_URL or "http://localhost:3000"
            return f"{frontend_url}/checkout/success?ref={order_ref}"

        # B) GATEWAYS (Async)
        elif order_data.payment_method == PaymentMethod.NOWPAYMENTS:
            checkout_url = await create_nowpayments_invoice(new_order, user.email)
        elif order_data.payment_method == PaymentMethod.BINANCE:
            checkout_url = await create_binance_order(new_order)
        elif order_data.payment_method == PaymentMethod.BYBIT:
            checkout_url = await create_bybit_order(new_order)
        else:
            raise HTTPException(status_code=400, detail="Unsupported payment method")

        await db.commit()
        return checkout_url

    except Exception as e:
        await db.rollback()
        logger.error(f"Order creation failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to initialize payment gateway.")

async def create_deposit_service(db: AsyncSession, user_id: int, amount: float, gateway: str) -> str:
    """
    Creates a 'Deposit' order to fund the user's wallet.
    """
    user_res = await db.execute(select(User).where(User.id == user_id))
    user = user_res.scalar_one_or_none()

    order_ref = f"DEP-{generate_otp(length=8)}"
    
    new_order = Order(
        user_id=user_id,
        order_reference=order_ref,
        total_amount_usd=amount,
        status=OrderStatus.PENDING,
        payment_method=gateway,
        customer_ip="0.0.0.0",
        is_deposit=True,
        order_metadata={}
    )
    db.add(new_order)
    await db.commit()
    await db.refresh(new_order)

    try:
        if gateway == PaymentMethod.NOWPAYMENTS:
            return await create_nowpayments_invoice(new_order, user.email)
        elif gateway == PaymentMethod.BINANCE:
            return await create_binance_order(new_order)
        elif gateway == PaymentMethod.BYBIT:
            return await create_bybit_order(new_order)
        else:
            raise HTTPException(status_code=400, detail="Invalid gateway for deposit")
    except Exception as e:
        await db.rollback()
        logger.error(f"Deposit setup failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to create deposit link")

# =========================================================
# 6. WEBHOOKS
# =========================================================

async def handle_nowpayments_webhook(db: AsyncSession, payload: dict, signature: str):
    if not signature: raise HTTPException(status_code=400, detail="No signature")
    if payload.get("payment_status") == "finished":
        await _process_successful_payment(db, payload.get("order_id"), "NowPayments", payload.get("payment_id"))

async def handle_binance_webhook(db: AsyncSession, payload: dict, headers: dict):
    if payload.get("bizStatus") == "PAY_SUCCESS":
        await _process_successful_payment(db, payload.get("merchantTradeNo"), "BinancePay", payload.get("prepayId"))

async def handle_bybit_webhook(db: AsyncSession, payload: dict):
    if payload.get("status") == "COMPLETED":
        await _process_successful_payment(db, payload.get("order_id"), "BybitPay", payload.get("trade_no"))

async def _process_successful_payment(db: AsyncSession, order_ref: str, provider: str, tx_hash: str):
    """
    Central handler for successful payments (Gateway Callbacks).
    - If Deposit: Funds Wallet.
    - If Purchase: Triggers Fulfillment (Assign Codes).
    """
    # Eager load items -> denomination -> product
    stmt = (
        select(Order)
        .where(Order.order_reference == order_ref)
        .options(
            selectinload(Order.user), 
            selectinload(Order.items).selectinload(OrderItem.product)
        )
    )
    result = await db.execute(stmt)
    order = result.scalar_one_or_none()

    # Idempotency Check
    if not order or order.status in [OrderStatus.PAID, OrderStatus.COMPLETED, OrderStatus.IN_PROGRESS]:
        return

    # Record Transaction Log
    db.add(Transaction(
        user_id=order.user_id, order_id=order.id, amount_usd=order.total_amount_usd,
        status="confirmed", provider=provider, tx_hash=str(tx_hash)
    ))

    # --- BRANCHING LOGIC ---
    if order.is_deposit:
        # Fund Wallet
        order.status = OrderStatus.COMPLETED
        order.payment_reference = str(tx_hash)
        order.user.balance_usd += order.total_amount_usd
        logger.info(f"Wallet Funded: {order.user.email} +${order.total_amount_usd}")
        await db.commit()
    else:
        # Product Purchase: Attempt Fulfillment
        assigned_codes, all_fulfilled = await _fulfill_order_items(db, order)
        
        order.payment_reference = str(tx_hash)
        
        if all_fulfilled:
            order.status = OrderStatus.COMPLETED
            # Send Success Email
            await send_fulfillment_email(
                user_email=order.user.email,
                product_name="Your Digital Order",
                order_reference=order_ref,
                codes=assigned_codes,
                player_id=order.order_metadata.get('player_id')
            )
        else:
            # Requires Manual Intervention (Direct Topup or Stock Error)
            order.status = OrderStatus.IN_PROGRESS
            logger.warning(f"Order {order_ref} paid but not fully auto-fulfilled. Status: IN_PROGRESS")

        await db.commit()

# =========================================================
# 7. MESSAGING & MODERATION SERVICES
# =========================================================

async def send_user_message_service(
    db: AsyncSession, 
    user_id: int, 
    subject: str, 
    body: str, 
    sender: str = "admin"
):
    """
    Sends a one-way persistent message to a user's inbox.
    Typically used by Admins to notify users about top-ups or moderation.
    """
    # 1. Validation
    if not body or not body.strip():
        raise HTTPException(status_code=400, detail="Message body cannot be empty.")

    # 2. Check User Exists
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="Target user not found.")

    # 3. Persist Message
    success = await insert_message(user_id, subject, body, db, sender)
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to persist message.")
    
    # Commit the transaction (insert_message does a flush, but we need to commit)
    await db.commit()
    
    # Audit Log
    log_action("send_message", actor=sender, metadata={"target_user_id": user_id, "subject": subject})
    
    return {"status": "success", "detail": "Message sent successfully."}

async def get_user_inbox_service(db: AsyncSession, user_id: int, limit: int = 50) -> List[InboxMessage]:
    """
    Retrieves the inbox for a specific user.
    """
    messages = await fetch_user_messages(user_id, db, limit)
    return messages

async def mark_inbox_message_read_service(db: AsyncSession, message_id: int, user_id: int):
    """
    Marks a specific message as read. 
    Securely ensures the message belongs to the requesting user.
    """
    success = await mark_message_read(message_id, user_id, db)
    if not success:
        # Could mean message doesn't exist OR belongs to another user
        raise HTTPException(status_code=404, detail="Message not found or access denied.")
    
    await db.commit()
    return {"status": "success"}

async def moderate_user_service(
    db: AsyncSession, 
    user_id: int, 
    action: str, 
    reason: Optional[str] = None,
    admin_username: str = "system"
):
    """
    Handles Ban/Unban logic for users.
    Args:
        action: 'ban' or 'unban'
    """
    # 1. Check User
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    is_banned = (action == "ban")
    
    # 2. Update Status
    success = await set_user_ban_state(user_id, is_banned, db)
    
    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to {action} user.")

    await db.commit()

    # 3. Audit Log
    log_action(f"{action}_user", actor=admin_username, metadata={"target_user_id": user_id, "reason": reason})

    return {"status": "success", "user_id": user_id, "is_banned": is_banned}