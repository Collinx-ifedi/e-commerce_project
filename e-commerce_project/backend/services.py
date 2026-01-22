# services.py
# Production-level Business Logic Layer
# - User Auth & Recovery
# - Cloudinary Content Management
# - Atomic Order Fulfillment (Wallet + Gateways)
# - Payment Gateway Integration
# - Manual Delivery & Top-up Workflow

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
    MultiProductOrderCreate,
    ProductCategory  # Imported for category logic
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
# 4. DIGITAL FULFILLMENT SERVICE (MANUAL LOGIC)
# =========================================================

async def get_product_available_codes(db: AsyncSession, product_id: int) -> List[Dict[str, Any]]:
    """
    Service used by Admin 'Code Picker' to see unused codes.
    """
    stmt = (
        select(ProductCode)
        .where(ProductCode.product_id == product_id)
        .where(ProductCode.is_used == False)
        .order_by(ProductCode.id)
        .limit(100) # Limit to prevent UI overload
    )
    result = await db.execute(stmt)
    codes = result.scalars().all()
    
    return [{"id": c.id, "code": c.code_value} for c in codes]

# --- NEW: Admin Manual Action Handler ---
async def process_admin_order_action(
    db: AsyncSession, 
    order_id: int, 
    action: str, 
    manual_content: Optional[str] = None,
    code_ids: Optional[List[int]] = None
):
    """
    Handles the Admin's decision to 'Complete' or 'Reject' an order.
    Now supports selecting specific code_ids from the database.
    """
    # Fetch Order with Items and Product Info
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

    # --- REJECT LOGIC ---
    if action == "reject":
        order.status = OrderStatus.REJECTED
        await db.commit()
        # Notify user (optional, but good practice)
        logger.info(f"Order {order.order_reference} rejected by admin.")
        return {"status": "rejected", "detail": "Order marked as rejected."}

    # --- COMPLETE LOGIC ---
    if action == "complete":
        
        assigned_codes_data = []
        is_direct_topup = False

        # 1. Identify Order Type
        # Check if we have Direct Topups mixed with Gift Cards (usually separated, but handle logic safely)
        for item in order.items:
            if item.product.product_category == ProductCategory.DIRECT_TOPUP:
                is_direct_topup = True
            
        # 2. Handle Code Assignment (Gift Cards / Games)
        if code_ids and len(code_ids) > 0:
            # Fetch selected codes
            stmt_codes = select(ProductCode).where(ProductCode.id.in_(code_ids))
            codes_res = await db.execute(stmt_codes)
            selected_codes = codes_res.scalars().all()
            
            if len(selected_codes) != len(code_ids):
                raise HTTPException(status_code=400, detail="Some selected codes do not exist.")

            for code in selected_codes:
                if code.is_used:
                    raise HTTPException(status_code=400, detail=f"Code {code.code_value} is already used.")
                
                # Mark as Used
                code.is_used = True
                code.used_at = datetime.utcnow()
                code.order_id = order.id
                assigned_codes_data.append(code.code_value)
                
                # Note: Stock deduction typically happens at 'Payment/Processing' stage in `create_order` or webhook.
                # If your system relies on exact 'count of unused codes', the deduction is implicit.
                # If we rely on the `Product.stock_quantity` integer, ensure it was decremented during payment.

        # 3. Validation: If no codes selected and not a Direct Topup, ensure we have manual content
        if not assigned_codes_data and not is_direct_topup:
             if not manual_content:
                raise HTTPException(
                    status_code=400, 
                    detail="No codes selected and no manual text provided."
                )

        # 4. Finalize Status
        order.status = OrderStatus.COMPLETED
        order.fulfillment_note = manual_content or "Delivered via Admin Selection"
        order.updated_at = datetime.utcnow()
        
        # 5. Construct Email
        email_body_html = ""
        
        # Case A: Codes assigned (Gift Cards)
        if assigned_codes_data:
            codes_html = ""
            for c in assigned_codes_data:
                codes_html += f'<div style="background:#f4f4f4;padding:10px;margin:5px 0;font-family:monospace;font-size:16px;">{c}</div>'
            
            email_body_html = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; color: #333;">
                <h2>Your Order is Complete!</h2>
                <p>Order Reference: <strong>{order.order_reference}</strong></p>
                <p>Here are your digital keys:</p>
                {codes_html}
                <p>Thank you for shopping with us!</p>
            </div>
            """
        
        # Case B: Direct Topup (Manual Text)
        elif is_direct_topup and manual_content:
             email_body_html = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; color: #333;">
                <h2>Top-up Successful!</h2>
                <p>Order Reference: <strong>{order.order_reference}</strong></p>
                <div style="background-color: #e6fffa; padding: 15px; border-left: 4px solid #059669; margin: 20px 0;">
                    <strong>Admin Note:</strong><br/>
                    <pre style="font-family: sans-serif; white-space: pre-wrap;">{manual_content}</pre>
                </div>
                <p>The resources have been added to your account ID: <strong>{order.order_metadata.get('player_id', 'N/A')}</strong></p>
            </div>
            """

        # Case C: Fallback Manual Content
        elif manual_content:
             email_body_html = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; color: #333;">
                <h2>Order Update</h2>
                <p>Order Reference: <strong>{order.order_reference}</strong></p>
                <p>{manual_content}</p>
            </div>
            """

        # 6. Send Email & Commit
        if email_body_html:
            await send_email_async(order.user.email, f"Order #{order.order_reference} Completed", email_body_html)
            logger.info(f"Fulfillment email sent for Order {order.order_reference}")

        await db.commit()
        return {"status": "completed", "detail": "Order completed successfully.", "codes_count": len(assigned_codes_data)}

    raise HTTPException(status_code=400, detail="Invalid action")

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
    4. Player ID Capture for Metadata
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

    # 3. Create Order Record with Metadata (Player ID)
    order_ref = generate_otp(length=10)
    
    # NEW: Capture Metadata
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
        order_metadata=metadata # Save Player ID here
    )
    db.add(new_order)
    await db.flush()

    for item in order_items_objects:
        item.order_id = new_order.id
        db.add(item)

    # 4. Handle Payment
    try:
        # A) Wallet: Deduct & Mark IN_PROGRESS (Manual Delivery)
        if order_data.payment_method == PaymentMethod.WALLET:
            user.balance_usd -= total_amount_usd
            
            # Set to IN_PROGRESS so Admin knows to fulfill it
            new_order.status = OrderStatus.IN_PROGRESS 
            new_order.payment_reference = f"WALLET-{order_ref}"
            
            # Record Transaction
            db.add(Transaction(
                user_id=user.id, order_id=new_order.id, amount_usd=total_amount_usd,
                status="confirmed", provider="Wallet", tx_hash=f"INT-{order_ref}"
            ))
            
            # Decrement Stock Immediately (since user paid)
            for item in order_items_objects:
                await db.execute(
                    update(Product)
                    .where(Product.id == item.product_id)
                    .values(stock_quantity=Product.stock_quantity - item.quantity)
                )

            await db.commit()
            
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
        is_deposit=True,
        order_metadata={} # No metadata needed for deposits
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
    - If Purchase: Updates Status to IN_PROGRESS (Stops Auto-Delivery).
    """
    stmt = (
        select(Order)
        .where(Order.order_reference == order_ref)
        .options(selectinload(Order.user), selectinload(Order.items).selectinload(OrderItem.product))
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
        # Fund Wallet (Deposits are still automatic)
        order.status = OrderStatus.COMPLETED
        order.payment_reference = str(tx_hash)
        order.user.balance_usd += order.total_amount_usd
        logger.info(f"Wallet Funded: {order.user.email} +${order.total_amount_usd}")
        await db.commit()
    else:
        # Product Purchase -> Set to IN_PROGRESS for Manual Admin Action
        order.status = OrderStatus.IN_PROGRESS
        order.payment_reference = str(tx_hash)
        
        # Decrement Stock now that payment is confirmed
        for item in order.items:
            await db.execute(
                update(Product)
                .where(Product.id == item.product_id)
                .values(stock_quantity=Product.stock_quantity - item.quantity)
            )
            
        await db.commit()
        logger.info(f"Order {order.order_reference} paid. Status set to IN_PROGRESS for manual fulfillment.")