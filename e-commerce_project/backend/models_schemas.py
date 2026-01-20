# models_schemas.py
# Production-level Database Models & Pydantic Schemas
# Updated: Robust Form Handling, Dynamic Platforms, Optional Images, Pydantic V2

from datetime import datetime
from enum import Enum
from typing import Optional, List, Any, Union

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Enum as SQLEnum,
    Text,
    Index,
    JSON,
    UniqueConstraint
)
from sqlalchemy.orm import declarative_base, relationship
from pydantic import (
    BaseModel, 
    EmailStr, 
    Field, 
    ConfigDict, 
    field_validator, 
    model_validator
)

# ======================================================
# DATABASE BASE & MIXINS
# ======================================================

Base = declarative_base()

class TimestampMixin:
    """Standardizes creation and update timestamps across all models."""
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

class SoftDeleteMixin:
    """Allows 'soft deleting' records (hiding them) instead of permanent removal."""
    is_deleted = Column(Boolean, default=False, index=True)
    deleted_at = Column(DateTime, nullable=True)

# ======================================================
# ENUMS
# ======================================================

class OrderStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    PAID = "paid"
    SHIPPED = "shipped"     # Kept for compatibility, though mostly digital
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"
    FAILED = "failed"

class PaymentMethod(str, Enum):
    """Supported Payment Gateways."""
    NOWPAYMENTS = "nowpayments"
    BINANCE = "binance"
    BYBIT = "bybit"

class AdminRole(str, Enum):
    SUPERADMIN = "superadmin"
    ADMIN = "admin"
    SUPPORT = "support"
    MANAGER = "manager"

class AddressType(str, Enum):
    BILLING = "billing"
    SHIPPING = "shipping"

class OTPPurpose(str, Enum):
    EMAIL_VERIFY = "email_verify"
    PASSWORD_RESET = "password_reset"
    TWO_FACTOR = "2fa"

# ======================================================
# AUTH & USER MODELS
# ======================================================

class Admin(Base, TimestampMixin):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True) 
    password_hash = Column(Text, nullable=False)
    role = Column(SQLEnum(AdminRole), default=AdminRole.ADMIN, nullable=False)
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime, nullable=True)

    logs = relationship("ActivityLog", back_populates="admin")

class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    
    # Profile Info
    full_name = Column(String(150))
    phone = Column(String(50))
    country = Column(String(100))
    avatar_url = Column(String(500), nullable=True)
    
    # Status
    is_verified = Column(Boolean, default=False)
    is_banned = Column(Boolean, default=False)
    
    # Security
    email_otp = Column(String(10), nullable=True)
    otp_expiry = Column(DateTime, nullable=True)
    two_factor_enabled = Column(Boolean, default=False)

    # Wallet
    balance_usd = Column(Float, default=0.0)

    # Relationships
    orders = relationship("Order", back_populates="user", cascade="all, delete-orphan")
    transactions = relationship("Transaction", back_populates="user", cascade="all, delete-orphan")
    support_messages = relationship("SupportMessage", back_populates="user")
    addresses = relationship("Address", back_populates="user", cascade="all, delete-orphan")
    reviews = relationship("ProductReview", back_populates="user")
    wishlist = relationship("Wishlist", back_populates="user", cascade="all, delete-orphan")

class Address(Base, TimestampMixin):
    __tablename__ = "addresses"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    type = Column(SQLEnum(AddressType), default=AddressType.SHIPPING)
    
    street_line1 = Column(String(255), nullable=False)
    street_line2 = Column(String(255))
    city = Column(String(100), nullable=False)
    state = Column(String(100))
    zip_code = Column(String(20))
    country = Column(String(100), nullable=False)
    
    user = relationship("User", back_populates="addresses")

class OTPRecord(Base):
    """Separate table for tracking all OTPs (Audit Trail)"""
    __tablename__ = "otp_records"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), index=True, nullable=False)
    otp_hash = Column(String(255), nullable=False)
    purpose = Column(SQLEnum(OTPPurpose))
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# ======================================================
# CATALOG MODELS
# ======================================================

class Category(Base, TimestampMixin):
    __tablename__ = "categories"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    slug = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(Text)
    parent_id = Column(Integer, ForeignKey("categories.id"), nullable=True)
    
    # Relationships
    products = relationship("Product", back_populates="category")
    children = relationship("Category", back_populates="parent")
    parent = relationship("Category", back_populates="children", remote_side=[id])


class Product(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)
    
    name = Column(String(255), nullable=False, index=True)
    slug = Column(String(255), nullable=True, unique=True, index=True)
    
    # 2. DYNAMIC PLATFORM FIELD
    # Changed from strict Enum to String to allow admin flexibility
    platform = Column(String(100), nullable=False) 
    
    description = Column(Text)
    short_description = Column(String(500))
    
    image_url = Column(Text, nullable=True) # Nullable for draft states
    gallery_images = Column(JSON, default=list)
    
    price_usd = Column(Float, nullable=False)
    discount_percent = Column(Integer, default=0)
    
    in_stock = Column(Boolean, default=True)
    stock_quantity = Column(Integer, default=999) # Denormalized counter
    
    is_featured = Column(Boolean, default=False)
    is_trending = Column(Boolean, default=False)
    
    # Relationships
    category = relationship("Category", back_populates="products")
    order_items = relationship("OrderItem", back_populates="product")
    reviews = relationship("ProductReview", back_populates="product", cascade="all, delete-orphan")
    codes = relationship("ProductCode", back_populates="product", cascade="all, delete-orphan")

    def final_price(self) -> float:
        """Calculates price after discount."""
        if self.discount_percent and self.discount_percent > 0:
            return round(self.price_usd * (1 - self.discount_percent / 100), 2)
        return self.price_usd

class ProductCode(Base, TimestampMixin):
    """Stores individual digital keys/codes for products."""
    __tablename__ = "product_codes"

    id = Column(Integer, primary_key=True, index=True)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=True)
    
    code_value = Column(String(500), nullable=False, unique=True)
    is_used = Column(Boolean, default=False, index=True)
    used_at = Column(DateTime, nullable=True)
    
    batch_id = Column(String(50), index=True, nullable=True)
    source = Column(String(100), nullable=True)
    version_id = Column(Integer, default=1, nullable=False)

    product = relationship("Product", back_populates="codes")
    order = relationship("Order", back_populates="delivered_codes")

    __table_args__ = (
        Index("idx_product_available_codes", "product_id", "is_used"),
    )

class ProductReview(Base, TimestampMixin):
    __tablename__ = "product_reviews"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    rating = Column(Integer, nullable=False)
    comment = Column(Text)
    is_verified_purchase = Column(Boolean, default=False)

    user = relationship("User", back_populates="reviews")
    product = relationship("Product", back_populates="reviews")

class Wishlist(Base, TimestampMixin):
    __tablename__ = "wishlists"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    
    user = relationship("User", back_populates="wishlist")
    product = relationship("Product")

# ======================================================
# ORDER & TRANSACTION MODELS
# ======================================================

class Order(Base, TimestampMixin):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    order_reference = Column(String(50), unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    total_amount_usd = Column(Float, nullable=False)
    status = Column(SQLEnum(OrderStatus), default=OrderStatus.PENDING, index=True)
    payment_method = Column(SQLEnum(PaymentMethod), default=PaymentMethod.NOWPAYMENTS)
    payment_reference = Column(String(255), index=True)
    customer_ip = Column(String(50))

    user = relationship("User", back_populates="orders")
    items = relationship("OrderItem", back_populates="order", cascade="all, delete-orphan")
    transactions = relationship("Transaction", back_populates="order")
    delivered_codes = relationship("ProductCode", back_populates="order")

class OrderItem(Base):
    __tablename__ = "order_items"

    id = Column(Integer, primary_key=True)
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    quantity = Column(Integer, default=1, nullable=False)
    unit_price_at_purchase = Column(Float, nullable=False)
    
    order = relationship("Order", back_populates="items")
    product = relationship("Product", back_populates="order_items")

class Transaction(Base, TimestampMixin):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    order_id = Column(Integer, ForeignKey("orders.id"))
    amount_usd = Column(Float, nullable=False)
    currency = Column(String(10), default="USD")
    tx_hash = Column(String(255))
    status = Column(String(50), default="confirmed")
    provider = Column(String(50), default="NowPayments") 

    user = relationship("User", back_populates="transactions")
    order = relationship("Order", back_populates="transactions")

# ======================================================
# MARKETING & CMS MODELS
# ======================================================

class Banner(Base, TimestampMixin):
    __tablename__ = "banners"

    id = Column(Integer, primary_key=True)
    image_url = Column(Text, nullable=False)
    title = Column(String(255))
    subtitle = Column(String(255)) # Nullable allowed
    target_url = Column(Text) # Nullable allowed
    btn_text = Column(String(50), default="Shop Now")
    
    is_active = Column(Boolean, default=True)
    display_order = Column(Integer, default=0)
    
    start_date = Column(DateTime)
    end_date = Column(DateTime)

    __table_args__ = (
        Index("idx_banner_active", "is_active", "display_order"),
    )

class Notification(Base, TimestampMixin):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    title = Column(String(255))
    message = Column(Text)
    is_read = Column(Boolean, default=False)
    type = Column(String(50), default="info") 

class SupportMessage(Base, TimestampMixin):
    __tablename__ = "support_messages"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    ticket_id = Column(String(50), index=True)
    message = Column(Text, nullable=False)
    is_admin_reply = Column(Boolean, default=False)
    
    user = relationship("User", back_populates="support_messages")

class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True)
    admin_id = Column(Integer, ForeignKey("admins.id"))
    action = Column(Text, nullable=False)
    target = Column(String(255)) 
    ip_address = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)

    admin = relationship("Admin", back_populates="logs")

# ======================================================
# PYDANTIC SCHEMAS (V2 MIGRATION)
# ======================================================

class ORMBase(BaseModel):
    id: int
    created_at: datetime
    
    # 4. PYDANTIC V2 COMPATIBILITY
    model_config = ConfigDict(from_attributes=True)

# --- Auth Schemas ---

class UserCreateSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    country: str
    full_name: Optional[str] = None

class AdminLoginSchema(BaseModel):
    username: str
    password: str

class UserResponse(ORMBase):
    email: EmailStr
    full_name: Optional[str]
    country: Optional[str]
    balance_usd: float
    is_verified: bool
    avatar_url: Optional[str]

# --- Product Code Schemas ---

class ProductCodeBase(BaseModel):
    code_value: str
    batch_id: Optional[str] = None
    source: Optional[str] = None

class ProductCodeCreate(ProductCodeBase):
    pass

class ProductCodeResponse(ORMBase):
    is_used: bool
    used_at: Optional[datetime]
    order_id: Optional[int]
    
    model_config = ConfigDict(from_attributes=True)

# --- Product Schemas ---

# 1. PRICE & STOCK TYPE FLEXIBILITY
# We define a flexible base that allows inputs (which might come as strings from FormData)
# to be coerced into the correct types automatically by Pydantic V2.

class ProductBaseSchema(BaseModel):
    name: str
    platform: str
    category_id: Optional[int] = None
    description: Optional[str] = None
    short_description: Optional[str] = None
    
    # Using Union[float, str] allows explicit coercion logic if needed, 
    # but Pydantic V2 default validation is smart enough to parse "49.99" to 49.99.
    price_usd: float = Field(..., gt=0)
    discount_percent: int = Field(0, ge=0, le=100)
    stock_quantity: int = Field(..., ge=0)
    
    is_featured: bool = False
    is_trending: bool = False

    # Validator to ensure empty strings in form data become None or are handled
    @field_validator('price_usd', mode='before')
    @classmethod
    def parse_price(cls, v: Any) -> float:
        if isinstance(v, str):
            return float(v.strip())
        return v

    @field_validator('stock_quantity', 'discount_percent', mode='before')
    @classmethod
    def parse_int_fields(cls, v: Any) -> int:
        if isinstance(v, str):
            return int(v.strip()) if v.strip() else 0
        return v

class ProductCreateSchema(ProductBaseSchema):
    """Schema for creating a product. Image URL is required."""
    image_url: str 

class ProductUpdateSchema(ProductBaseSchema):
    """
    3. OPTIONAL IMAGE FOR UPDATES
    Schema for updating a product. Fields are optional to allow partial updates.
    """
    name: Optional[str] = None
    platform: Optional[str] = None
    price_usd: Optional[float] = None
    stock_quantity: Optional[int] = None
    
    # Image URL is optional here to prevent errors if no new file is uploaded
    image_url: Optional[str] = None 

class ProductSchema(ORMBase):
    """Output Schema"""
    name: str
    slug: Optional[str]
    platform: str
    image_url: Optional[str] # Nullable in DB
    price_usd: float
    discount_percent: int
    final_price: float = 0.0 
    in_stock: bool
    stock_quantity: int
    is_featured: bool
    is_trending: bool
    
    model_config = ConfigDict(from_attributes=True)

# --- Cart & Order Schemas ---

class CartItemSchema(BaseModel):
    product_id: int
    quantity: int = Field(1, ge=1)

class MultiProductOrderCreate(BaseModel):
    items: List[CartItemSchema]
    payment_method: PaymentMethod = PaymentMethod.NOWPAYMENTS

class OrderItemResponse(BaseModel):
    product_id: int
    product_name: str 
    quantity: int
    unit_price_at_purchase: float
    
    model_config = ConfigDict(from_attributes=True)

class DeliveredCodeSchema(BaseModel):
    product_id: int
    code_value: str
    
    model_config = ConfigDict(from_attributes=True)

class OrderResponse(ORMBase):
    order_reference: Optional[str]
    total_amount_usd: float
    status: OrderStatus
    payment_method: PaymentMethod
    items: List[OrderItemResponse] = [] 
    delivered_codes: List[DeliveredCodeSchema] = []

    model_config = ConfigDict(from_attributes=True)

# --- CMS Schemas ---

class BannerCreateSchema(BaseModel):
    """Schema for creating a banner."""
    image_url: str
    title: Optional[str] = None
    subtitle: Optional[str] = None
    target_url: Optional[str] = None
    btn_text: str = "Shop Now"
    is_active: bool = True

class BannerUpdateSchema(BannerCreateSchema):
    """Schema for updating a banner."""
    image_url: Optional[str] = None

class BannerSchema(ORMBase):
    """
    5. BANNER SCHEMA UPDATES
    Allows nullable subtitle/target_url and proper image handling.
    """
    image_url: str
    title: Optional[str]
    subtitle: Optional[str]
    target_url: Optional[str]
    btn_text: str
    is_active: bool
    
    model_config = ConfigDict(from_attributes=True)