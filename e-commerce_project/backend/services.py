# services.py
# Production-level Business Logic Layer
# - User Auth & Recovery
# - Cloudinary Content Management
# - Atomic Order Fulfillment (Wallet + Gateways)
# - Payment Gateway Integration

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
from sqlalchemy import update, delete, and_, case

# IMPORT MODELS
from .models_schemas import (
    User,
    Admin,
    Product,
    ProductCode,
    Order,
    OrderItem,
    Transaction,
    Banner,
    Notification,
    OrderStatus,
    PaymentMethod,
    OTPPurpose,
    MultiProductOrderCreate
)

# IMPORT UTILS & CORE
from .utils import (
    generate_otp,
    send_email_otp,
    send_email_async,
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

from .db import get_unused_code, mark_code_as_used

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
    Registers a new user. Handles 'User Exists' states gracefully.
    """
    # Check if user already exists
    result = await db.execute(select(User).where(User.email == email))
    existing_user = result.scalar_one_or_none()

    if existing_user:
        if not existing_user.is_verified:
            # Frontend catches this specific 400 to show the "Verify Now" modal
            raise HTTPException(
                status_code=400, 
                detail="User exists but is unverified. Please verify your email."
            )
        raise HTTPException(status_code=400, detail="User with this email already exists.")

    # Create new user
    hashed_pw = hash_password(password)
    otp_code = generate_otp()
    
    new_user = User(
        email=email,
        password_hash=hashed_pw,
        country=country,
        email_otp=otp_code,
        otp_expiry=datetime.utcnow() + timedelta(minutes=10),
        is_verified=False,
        balance_usd=0.0
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Send OTP Email
    try:
        await send_email_otp(email, otp_code, OTPPurpose.EMAIL_VERIFY)
    except Exception as e:
        logger.error(f"Failed to send welcome email to {email}: {e}")
    
    return new_user

async def resend_otp_service(db: AsyncSession, email: str):
    """
    FIX: Resolves the registration 'deadlock'.
    Allows an unverified user to request a new OTP if the previous one expired or was lost.
    """
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    if user.is_verified:
        raise HTTPException(status_code=400, detail="Account is already verified. Please log in.")

    # Generate new OTP
    new_otp = generate_otp()
    
    # Update User Record
    user.email_otp = new_otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    
    await db.commit()

    # Send Email
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
        raise HTTPException(status_code=400, detail="Verification code has expired. Please request a new one.")

    # Mark Verified and Clear Security Fields
    user.is_verified = True
    user.email_otp = None
    user.otp_expiry = None
    
    await db.commit()
    return {"message": "Email verified successfully"}

# =========================================================
# 2. ADMIN & CONTENT SERVICES (Cloudinary Ready)
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
    price_usd: float, 
    description: str, 
    image_url: str,
    stock_quantity: int = 0,
    discount_percent: int = 0,
    is_featured: bool = False,
    is_trending: bool = False
):
    """
    Creates a product using the URL returned from Cloudinary.
    """
    new_product = Product(
        name=name,
        platform=platform, # Dynamic string
        price_usd=price_usd,
        stock_quantity=stock_quantity,
        in_stock=(stock_quantity > 0),
        discount_percent=discount_percent,
        description=description,
        image_url=image_url, # Permanent Cloudinary URL
        is_featured=is_featured,
        is_trending=is_trending
    )
    db.add(new_product)
    await db.commit()
    await db.refresh(new_product)
    return new_product

async def create_banner_service(db: AsyncSession, title: Optional[str], image_url: str):
    """Creates a banner using the URL returned from Cloudinary."""
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
    # Placeholder implementation
    return f"{frontend_url}/checkout/mock-provider?ref={order.order_reference}&provider=bybit"

# =========================================================
# 4. DIGITAL FULFILLMENT SERVICE (ATOMIC)
# =========================================================

async def fulfill_digital_order(db: AsyncSession, order_id: int):
    """
    Delivers digital goods. Uses concurrency safe checks.
    """
    logger.info(f"Starting fulfillment for Order ID: {order_id}")
    
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
    
    if not order or order.status == OrderStatus.COMPLETED:
        return

    delivered_items = []
    
    try:
        for item in order.items:
            product = item.product
            qty_needed = item.quantity
            codes_found = []

            for _ in range(qty_needed):
                code_val = await get_unused_code(product.id, db)
                if code_val:
                    await mark_code_as_used(code_val, db)
                    # Link to order
                    await db.execute(
                        update(ProductCode)
                        .where(ProductCode.code_value == code_val)
                        .values(order_id=order.id)
                    )
                    codes_found.append(code_val)
                else:
                    logger.critical(f"OUT OF STOCK: Product {product.id} in Order {order.order_reference}")
            
            # Decrement Stock
            await db.execute(
                update(Product)
                .where(Product.id == product.id)
                .values(
                    stock_quantity=Product.stock_quantity - qty_needed,
                    in_stock=case((Product.stock_quantity - qty_needed <= 0, False), else_=True) 
                )
            )

            if codes_found:
                delivered_items.append({"product_name": product.name, "codes": codes_found})

        order.status = OrderStatus.COMPLETED
        await db.commit()
        
        if delivered_items:
            await _send_delivery_email(order.user.email, order.order_reference, delivered_items)

        logger.info(f"Order {order.order_reference} fulfilled successfully.")

    except Exception as e:
        await db.rollback()
        logger.error(f"Fulfillment failed for order {order_id}: {e}")
        raise

async def _send_delivery_email(email: str, order_ref: str, items: List[dict]):
    """Sends HTML email with keys."""
    items_html = ""
    for item in items:
        codes_block = "<br>".join([f"<code style='background:#eee; padding:2px 5px;'>{c}</code>" for c in item['codes']])
        items_html += f"""
        <div style="border: 1px solid #ddd; padding: 10px; margin-bottom: 10px; border-radius: 5px;">
            <h3 style="margin: 0 0 10px;">{item['product_name']}</h3>
            <div style="background: #f9f9f9; padding: 10px; font-family: monospace; font-size: 16px;">
                {codes_block}
            </div>
        </div>
        """

    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2c3e50;">Here is your order!</h2>
        <p>Thank you for your purchase (Order #{order_ref}).</p>
        <p>Below are your activation codes/keys:</p>
        {items_html}
    </div>
    """
    await send_email_async(email, f"Order #{order_ref} - Your Digital Keys", html_content)

# =========================================================
# 5. ORDER CREATION SERVICES (Checkout & Deposits)
# =========================================================

async def create_order_service(db: AsyncSession, user_id: int, order_data: MultiProductOrderCreate) -> str:
    """
    Orchestrates order creation. 
    Handles:
    1. Stock Checks
    2. Wallet Payment Deduction (Instant)
    3. Crypto Payment Link Generation (Async)
    """
    if not order_data.items:
        raise HTTPException(status_code=400, detail="Cart is empty")

    requested_ids = {item.product_id for item in order_data.items}
    requested_quantities = {item.product_id: item.quantity for item in order_data.items}

    result = await db.execute(
        select(Product).where(and_(Product.id.in_(requested_ids), Product.is_deleted == False))
    )
    products_db = result.scalars().all()
    
    if len(products_db) != len(requested_ids):
        raise HTTPException(status_code=404, detail="One or more products not found.")

    total_amount_usd = 0.0
    order_items_objects = []

    # 1. Calculate Total & Prepare Items
    for product in products_db:
        qty = requested_quantities[product.id]
        if not product.in_stock or product.stock_quantity < qty:
            raise HTTPException(status_code=400, detail=f"Insufficient stock for '{product.name}'")
        
        unit_price = product.final_price
        total_amount_usd += unit_price * qty
        
        order_items_objects.append(
            OrderItem(product_id=product.id, quantity=qty, unit_price_at_purchase=unit_price)
        )

    # 2. Check Wallet Balance if paying with Wallet
    user_res = await db.execute(select(User).where(User.id == user_id))
    user = user_res.scalar_one_or_none()

    if order_data.payment_method == PaymentMethod.WALLET:
        if user.balance_usd < total_amount_usd:
            raise HTTPException(status_code=400, detail="Insufficient wallet balance.")

    # 3. Create Order Record
    order_ref = generate_otp(length=10)
    new_order = Order(
        user_id=user_id,
        order_reference=order_ref,
        total_amount_usd=round(total_amount_usd, 2),
        status=OrderStatus.PENDING,
        payment_method=order_data.payment_method,
        customer_ip="0.0.0.0",
        is_deposit=False
    )
    db.add(new_order)
    await db.flush()

    for item in order_items_objects:
        item.order_id = new_order.id
        db.add(item)

    # 4. Handle Payment
    try:
        # A) Wallet: Deduct & Fulfill Instantly
        if order_data.payment_method == PaymentMethod.WALLET:
            user.balance_usd -= total_amount_usd
            new_order.status = OrderStatus.PAID
            new_order.payment_reference = f"WALLET-{order_ref}"
            
            # Record Transaction
            db.add(Transaction(
                user_id=user.id, order_id=new_order.id, amount_usd=total_amount_usd,
                status="confirmed", provider="Wallet", tx_hash=f"INT-{order_ref}"
            ))
            await db.commit()
            
            # Trigger Fulfillment
            await fulfill_digital_order(db, new_order.id)
            
            # Return success URL
            frontend_url = settings.FRONTEND_URL or "http://localhost:3000"
            return f"{frontend_url}/checkout/success?ref={order_ref}"

        # B) Gateways: Generate Link
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
        is_deposit=True  # Important Flag
    )
    db.add(new_order)
    await db.commit()
    await db.refresh(new_order)

    # Generate Link
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
    Central handler for successful payments.
    - If Deposit: Funds Wallet.
    - If Purchase: Sends Keys.
    """
    stmt = select(Order).where(Order.order_reference == order_ref).options(selectinload(Order.user))
    result = await db.execute(stmt)
    order = result.scalar_one_or_none()

    # Idempotency Check
    if not order or order.status in [OrderStatus.PAID, OrderStatus.COMPLETED]:
        return

    # Mark Paid
    order.status = OrderStatus.PAID
    order.payment_reference = str(tx_hash)

    # Record Transaction Log
    db.add(Transaction(
        user_id=order.user_id, order_id=order.id, amount_usd=order.total_amount_usd,
        status="confirmed", provider=provider, tx_hash=str(tx_hash)
    ))

    # --- BRANCHING LOGIC ---
    if order.is_deposit:
        # Fund Wallet
        order.user.balance_usd += order.total_amount_usd
        logger.info(f"Wallet Funded: {order.user.email} +${order.total_amount_usd}")
        await db.commit()
    else:
        # Fulfill Product
        await db.commit() 
        await fulfill_digital_order(db, order.id)