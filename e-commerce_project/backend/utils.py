# utils.py
# Production-level utility functions
# - Async Email sending (Brevo) with Retries
# - Cryptographically secure OTPs
# - Structured JSON Logging (Enhanced for Order Metadata)
# - Efficient CSV/TXT parsing for bulk uploads
# - Currency & Formatting helpers

import os
import csv
import logging
import secrets
import json
import httpx
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Union

from dotenv import load_dotenv

# Enum is imported to keep type hints clean
from models_schemas import OTPPurpose

# ======================================================
# CONFIGURATION & VALIDATION
# ======================================================

load_dotenv()

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")

# Fail fast if critical env vars are missing
if not BREVO_API_KEY or not SENDER_EMAIL:
    logging.critical("CRITICAL: BREVO_API_KEY or SENDER_EMAIL is missing. Email services will fail.")

# ======================================================
# STRUCTURED LOGGING
# ======================================================

class JSONFormatter(logging.Formatter):
    """
    Formatter to output logs in JSON format for production monitoring systems (ELK, Datadog, etc.)
    Updated to explicitly capture business-critical metadata like player_id and order_reference.
    """
    def format(self, record):
        log_obj = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }
        if hasattr(record, 'request_id'):
            log_obj['request_id'] = record.request_id
        
        # Merge structured metadata if present
        if hasattr(record, 'meta') and isinstance(record.meta, dict):
            log_obj.update(record.meta)
            
        return json.dumps(log_obj)

# Setup Logger
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger = logging.getLogger("ecommerce_core")
logger.setLevel(logging.INFO)
logger.addHandler(handler)
logger.propagate = False

def log_action(
    action: str, 
    actor: str = "system", 
    ip_address: Optional[str] = None, 
    metadata: Optional[dict] = None,
    order_reference: Optional[str] = None,
    player_id: Optional[str] = None
):
    """
    Centralized auditing helper.
    Automatically merges specific business keys (player_id, order_reference) into the metadata
    for easier indexing in log aggregation tools.
    """
    meta = metadata or {}
    
    # Explicitly hoist critical fields into the metadata dict
    if order_reference:
        meta['order_reference'] = order_reference
    if player_id:
        meta['player_id'] = player_id

    log_data = {
        "event": "audit_log",
        "action": action,
        "actor": actor,
        "ip": ip_address,
        "meta": meta
    }
    logger.info(json.dumps(log_data))

# ======================================================
# ASYNC EMAIL SERVICE (BREVO)
# ======================================================

async def send_email_async(
    recipient_email: str, 
    subject: str, 
    html_content: str, 
    retries: int = 3
) -> bool:
    """
    Asynchronously send an email using Brevo API with automatic retries.
    Used for OTPs, Order Confirmations, and Product Code Delivery.
    """
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "api-key": BREVO_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    payload = {
        "sender": {"email": SENDER_EMAIL},
        "to": [{"email": recipient_email}],
        "subject": subject,
        "htmlContent": html_content
    }

    async with httpx.AsyncClient() as client:
        for attempt in range(retries):
            try:
                response = await client.post(url, json=payload, headers=headers, timeout=10.0)
                response.raise_for_status()
                logger.info(f"Email sent successfully to {recipient_email} [Subject: {subject}]")
                return True
            except httpx.HTTPStatusError as e:
                logger.error(f"Email failed (Attempt {attempt+1}/{retries}): {e.response.text}")
                if e.response.status_code in [400, 401]: # Don't retry auth/bad request errors
                    break
            except Exception as e:
                logger.error(f"Network error sending email (Attempt {attempt+1}/{retries}): {str(e)}")
                await asyncio.sleep(1) # Simple backoff
            
    return False

# ======================================================
# FULFILLMENT & NOTIFICATION TEMPLATES
# ======================================================

async def send_fulfillment_email(
    user_email: str, 
    product_name: str, 
    order_reference: str,
    codes: Optional[List[str]] = None,
    manual_text: Optional[str] = None,
    player_id: Optional[str] = None
) -> bool:
    """
    Unified fulfillment email handler.
    Dynamically constructs the email body based on the delivery type:
    1. Codes: Standard digital key delivery.
    2. Player ID (Direct Topup): Confirmation of direct account credit.
    3. Manual Text: Admin messages/instructions.
    """
    subject = f"Order Complete: {product_name} (#{order_reference})"
    
    # -- 1. Build Content Sections --
    
    content_html = ""

    # Section A: Digital Codes
    if codes and len(codes) > 0:
        codes_block = ""
        for code in codes:
            codes_block += f"""
            <div style="background-color: #f0f0f0; border: 1px dashed #ccc; padding: 15px; margin: 10px 0; text-align: center; font-family: monospace; font-size: 18px; letter-spacing: 2px;">
                {code}
            </div>
            """
        content_html += f"""
        <h3>Your Activation Keys</h3>
        <p>Please redeem these keys immediately:</p>
        {codes_block}
        <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;" />
        """

    # Section B: Direct Top-up Confirmation
    if player_id:
        content_html += f"""
        <h3>Direct Top-up Successful</h3>
        <div style="background-color: #e6fffa; padding: 15px; border-left: 4px solid #059669; margin: 10px 0;">
            <p style="margin: 0; color: #064e3b;"><strong>Target Account ID:</strong> {player_id}</p>
            <p style="margin: 5px 0 0 0; font-size: 14px;">The resources have been credited directly to this account.</p>
        </div>
        """

    # Section C: Manual Admin Note / Instructions
    if manual_text:
        content_html += f"""
        <h3>Order Details & Instructions</h3>
        <div style="background-color: #fffbeb; padding: 15px; border-left: 4px solid #d97706; margin: 10px 0;">
            <pre style="font-family: Arial, sans-serif; white-space: pre-wrap; margin: 0; color: #333;">{manual_text}</pre>
        </div>
        """

    # -- 2. Wrap in Master Template --

    html_wrapper = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333; line-height: 1.6;">
        <h2 style="border-bottom: 2px solid #333; padding-bottom: 10px;">Your Order is Ready</h2>
        <p>Thank you for purchasing <strong>{product_name}</strong>.</p>
        <p style="color: #666; font-size: 14px;">Order Reference: <strong>{order_reference}</strong></p>
        
        {content_html}
        
        <p style="font-size: 12px; color: #777; margin-top: 30px; border-top: 1px solid #eee; padding-top: 10px;">
            If you have trouble with your order, please reply to this email or contact support with your Order ID.
        </p>
    </div>
    """
    
    return await send_email_async(user_email, subject, html_wrapper)

async def send_product_code_email(user_email: str, product_name: str, codes: List[str]) -> bool:
    """
    Legacy wrapper for backward compatibility.
    Redirects to the new unified fulfillment handler using a dummy order ref if not available.
    """
    return await send_fulfillment_email(
        user_email=user_email,
        product_name=product_name,
        order_reference="INSTANT-DELIVERY",
        codes=codes
    )

# ======================================================
# FILE PARSING (BULK UPLOAD HELPERS)
# ======================================================

def parse_codes_from_file(file_path: str) -> List[str]:
    """
    Parses a local file (CSV or TXT) to extract product codes.
    Thread-Safety: This function is synchronous and CPU-bound.
    It is designed to be executed via `asyncio.to_thread` in the caller
    to prevent blocking the main asyncio event loop.
    
    Returns:
        List of unique, stripped strings.
    """
    codes = set() # Use set to dedup within the file immediately
    ext = os.path.splitext(file_path)[1].lower()
    
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return []

    try:
        with open(file_path, mode='r', encoding='utf-8-sig') as f:
            if ext == '.csv':
                reader = csv.reader(f)
                for row in reader:
                    # Assume code is in the first column
                    if row and row[0].strip():
                        codes.add(row[0].strip())
            else: 
                # Assume .txt or other line-based format
                for line in f:
                    clean_line = line.strip()
                    if clean_line:
                        codes.add(clean_line)
        
        result_list = list(codes)
        logger.info(f"Parsed {len(result_list)} unique codes from {file_path}")
        return result_list

    except Exception as e:
        logger.error(f"File parsing error for {file_path}: {e}")
        return []

# ======================================================
# OTP & SECURITY
# ======================================================

def generate_otp(length: int = 6) -> str:
    """Generate a cryptographically secure numeric OTP."""
    return ''.join(secrets.choice("0123456789") for _ in range(length))

async def send_email_otp(recipient_email: str, otp_code: str, purpose: Union[OTPPurpose, str]):
    """
    Orchestrates constructing the email content and sending it.
    """
    # Handle Enum or String input for purpose
    purpose_val = purpose.value if hasattr(purpose, 'value') else str(purpose)
    
    subject_map = {
        "email_verify": "Verify Your Email Address",
        "password_reset": "Password Reset Request",
        "2fa": "Your 2FA Login Code"
    }
    
    subject = subject_map.get(purpose_val, "Your Verification Code")
    
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">{subject}</h2>
        <p>Use the following One-Time Password (OTP) to complete your action:</p>
        <div style="background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; font-weight: bold;">
            {otp_code}
        </div>
        <p>This code expires in 10 minutes.</p>
        <p style="color: #888; font-size: 12px;">If you did not request this, please ignore this email.</p>
    </div>
    """
    
    await send_email_async(recipient_email, subject, html_content)

async def save_otp_to_db(db, email: str, otp: str, purpose: Any, expires_minutes: int = 10):
    """
    Import OTPRecord locally to avoid circular imports if models import utils.
    """
    from models_schemas import OTPRecord
    
    expires_at = datetime.utcnow() + timedelta(minutes=expires_minutes)
    otp_record = OTPRecord(
        email=email,
        otp_hash=otp, # Ideally hash this in high-security envs
        purpose=purpose,
        expires_at=expires_at,
        used=False
    )
    db.add(otp_record)
    # Note: Commit is handled by the caller
    return otp_record

# ======================================================
# DATA EXPORT & FORMATTING
# ======================================================

def export_to_csv(filename: str, data: List[Dict[str, Any]]) -> Optional[str]:
    """
    Exports a list of dictionaries to a CSV file.
    """
    if not data:
        logger.warning("Export requested but no data provided.")
        return None

    os.makedirs("exports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = f"exports/{filename}_{timestamp}.csv"

    try:
        fieldnames = data[0].keys()
        with open(filepath, "w", newline="", encoding="utf-8-sig") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
            
        logger.info(f"Data exported successfully to {filepath}")
        return filepath
    except IOError as e:
        logger.error(f"File I/O error during CSV export: {e}")
        return None

# ======================================================
# MISC HELPERS
# ======================================================

def generate_random_token(length: int = 32) -> str:
    """Generate a secure random URL-safe token."""
    return secrets.token_urlsafe(length)

def format_currency(amount: float, currency: str = "USD") -> str:
    """
    Standardize currency display.
    """
    return f"{currency} {amount:,.2f}"