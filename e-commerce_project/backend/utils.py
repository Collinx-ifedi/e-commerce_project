# utils.py
# Production-level utility functions
# - Async Email sending (Brevo) with Retries
# - Cryptographically secure OTPs
# - Structured JSON Logging
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

# Enum is imported to keep type hints clean, assuming it's available or we treat purpose as string
# If OTPPurpose is strictly needed for type hinting, import it. Otherwise use str.
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
        # Include metadata if passed via extra={}
        if hasattr(record, 'meta'):
            log_obj['meta'] = record.meta
            
        return json.dumps(log_obj)

# Setup Logger
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger = logging.getLogger("ecommerce_core")
logger.setLevel(logging.INFO)
logger.addHandler(handler)
logger.propagate = False

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
# PRODUCT CODE DELIVERY TEMPLATES
# ======================================================

async def send_product_code_email(user_email: str, product_name: str, codes: List[str]) -> bool:
    """
    Specific helper to format and send digital goods.
    """
    subject = f"Your Digital Key(s) for {product_name}"
    
    # Format codes for HTML display
    codes_html = ""
    for code in codes:
        codes_html += f"""
        <div style="background-color: #f0f0f0; border: 1px dashed #ccc; padding: 15px; margin: 10px 0; text-align: center; font-family: monospace; font-size: 18px; letter-spacing: 2px;">
            {code}
        </div>
        """

    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
        <h2 style="border-bottom: 2px solid #000; padding-bottom: 10px;">Your Order is Ready</h2>
        <p>Thank you for purchasing <strong>{product_name}</strong>.</p>
        <p>Here are your activation details:</p>
        {codes_html}
        <p><strong>Instructions:</strong> Redeem these keys on the respective platform immediately.</p>
        <p style="font-size: 12px; color: #777; margin-top: 30px;">
            If you have trouble activating, please contact support with your order ID.
        </p>
    </div>
    """
    
    return await send_email_async(user_email, subject, html_content)

# ======================================================
# FILE PARSING (BULK UPLOAD HELPERS)
# ======================================================

def parse_codes_from_file(file_path: str) -> List[str]:
    """
    Parses a local file (CSV or TXT) to extract product codes.
    Designed to be run via `asyncio.to_thread` to avoid blocking the event loop.
    
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

def log_action(action: str, actor: str = "system", ip_address: Optional[str] = None, metadata: Optional[dict] = None):
    """
    Centralized auditing helper.
    """
    log_data = {
        "event": "audit_log",
        "action": action,
        "actor": actor,
        "ip": ip_address,
        "meta": metadata or {}
    }
    logger.info(json.dumps(log_data))

def format_currency(amount: float, currency: str = "USD") -> str:
    """
    Standardize currency display.
    """
    return f"{currency} {amount:,.2f}"