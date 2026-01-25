# models_schemas.py
# Production-level Database Models & Pydantic Schemas
# Updated: Multi-Denomination Support & Multi-Item Orders
# Updated: Admin->User Inbox Messaging & Moderation Support
# FIX: InboxMessageCreate user_id made optional for URL-based routing

from datetime import datetime
from enum import Enum
from typing import Optional, List, Any, Dict

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

class ProductCategory(str, Enum):
    """
    Delivery Logic Categories.
    Determines if an order requires email delivery or manual top-up.
    """
    GIFT_CARDS = "gift_cards"      # Manual Email Delivery
    GAMES = "games"                # Manual Email Delivery
    DIRECT_TOPUP = "direct_topup"  # No Email (Player ID required)
    OTHERS = "others"              # Manual Email Delivery

class OrderStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    PAID = "paid"
    IN_PROGRESS = "in_progress" # Paid, waiting for Admin manual action
    SHIPPED = "shipped"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"       # Admin declined (e.g., bad Player ID)
    REFUNDED = "refunded"
    FAILED = "failed"

class PaymentMethod(str, Enum):
    """Supported Payment Gateways."""
    NOWPAYMENTS = "nowpayments"
    BINANCE = "binance"
    BYBIT = "bybit"
    WALLET = "wallet"  # Internal Wallet Payment

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
    blog_posts = relationship("BlogPost", back_populates="author")

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
    is_banned = Column(Boolean, default=False) # Moderation Field
    
    # Security
    email_otp = Column(String(10), nullable=True)
    otp_expiry = Column(DateTime, nullable=True)
    two_factor_enabled = Column(Boolean, default=False)

    # Wallet
    balance_usd = Column(Float, default=0.0, nullable=False)

    # Relationships
    orders = relationship("Order", back_populates="user", cascade="all, delete-orphan")
    transactions = relationship("Transaction", back_populates="user", cascade="all, delete-orphan")
    support_messages = relationship("SupportMessage", back_populates="user")
    inbox_messages = relationship("InboxMessage", back_populates="user", cascade="all, delete-orphan") # New Inbox Relationship
    addresses = relationship("Address", back_populates="user", cascade="all, delete-orphan")
    reviews = relationship("ProductReview", back_populates="user")
    wishlist = relationship("Wishlist", back_populates="user", cascade="all, delete-orphan")
    
    blog_comments = relationship("BlogComment", back_populates="user", cascade="all, delete-orphan")
    blog_reactions = relationship("BlogReaction", back_populates="user", cascade="all, delete-orphan")

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
    """
    Legacy Table for hierarchical organization.
    """
    __tablename__ = "categories"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    slug = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(Text)
    parent_id = Column(Integer, ForeignKey("categories.id"), nullable=True)
    
    products = relationship("Product", back_populates="category")
    children = relationship("Category", back_populates="parent")
    parent = relationship("Category", back_populates="children", remote_side=[id])


class Product(Base, TimestampMixin, SoftDeleteMixin):
    """
    Represents the 'Game' or 'Service' (e.g., PUBG Mobile, iTunes).
    Does NOT hold price or stock anymore.
    """
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)
    
    # Core Logic
    product_category = Column(SQLEnum(ProductCategory), default=ProductCategory.OTHERS, nullable=False, index=True)
    requires_player_id = Column(Boolean, default=False)
    
    name = Column(String(255), nullable=False, index=True)
    slug = Column(String(255), nullable=True, unique=True, index=True)
    platform = Column(String(100), nullable=False) 
    
    description = Column(Text)
    short_description = Column(String(500))
    
    image_url = Column(Text, nullable=True)
    gallery_images = Column(JSON, default=list)
    
    # Marketing
    is_featured = Column(Boolean, default=False)
    is_trending = Column(Boolean, default=False)
    
    # Relationships
    category = relationship("Category", back_populates="products")
    reviews = relationship("ProductReview", back_populates="product", cascade="all, delete-orphan")
    
    # ONE Product has MANY Denominations (Variants)
    denominations = relationship("Denomination", back_populates="product", cascade="all, delete-orphan")


class Denomination(Base, TimestampMixin, SoftDeleteMixin):
    """
    Represents a specific variant of a Product (e.g., "60 UC", "100 USD Card").
    Holds the Price and Stock logic.
    """
    __tablename__ = "denominations"

    id = Column(Integer, primary_key=True, index=True)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    
    label = Column(String(100), nullable=False) # e.g. "60 UC", "Premium Pass"
    
    price_usd = Column(Float, nullable=False)
    discount_percent = Column(Integer, default=0)
    
    in_stock = Column(Boolean, default=True)
    stock_quantity = Column(Integer, default=0) # Derived from codes count or manual
    
    # Relationships
    product = relationship("Product", back_populates="denominations")
    codes = relationship("ProductCode", back_populates="denomination", cascade="all, delete-orphan")
    order_items = relationship("OrderItem", back_populates="denomination")

    @property
    def final_price(self) -> float:
        if self.discount_percent and self.discount_percent > 0:
            return round(self.price_usd * (1 - self.discount_percent / 100), 2)
        return self.price_usd


class ProductCode(Base, TimestampMixin):
    """
    Stores individual digital keys/codes.
    Now linked to a specific Denomination (Variant), not the parent Product.
    """
    __tablename__ = "product_codes"

    id = Column(Integer, primary_key=True, index=True)
    denomination_id = Column(Integer, ForeignKey("denominations.id"), nullable=False)
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=True)
    
    code_value = Column(String(500), nullable=False, unique=True)
    is_used = Column(Boolean, default=False, index=True)
    used_at = Column(DateTime, nullable=True)
    
    batch_id = Column(String(50), index=True, nullable=True)
    source = Column(String(100), nullable=True)
    version_id = Column(Integer, default=1, nullable=False)

    denomination = relationship("Denomination", back_populates="codes")
    order = relationship("Order", back_populates="delivered_codes")

    __table_args__ = (
        Index("idx_denom_available_codes", "denomination_id", "is_used"),
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
    
    is_deposit = Column(Boolean, default=False, index=True)
    fulfillment_note = Column(Text, nullable=True) # Admin manual note
    
    # Metadata for capturing Player ID / User ID for Direct Topup
    order_metadata = Column(JSON, nullable=True, default={})

    user = relationship("User", back_populates="orders")
    items = relationship("OrderItem", back_populates="order", cascade="all, delete-orphan")
    transactions = relationship("Transaction", back_populates="order")
    delivered_codes = relationship("ProductCode", back_populates="order")

class OrderItem(Base):
    """
    Links an Order to specific Denominations (Variants).
    """
    __tablename__ = "order_items"

    id = Column(Integer, primary_key=True)
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=False)
    denomination_id = Column(Integer, ForeignKey("denominations.id"), nullable=False)
    
    quantity = Column(Integer, default=1, nullable=False)
    unit_price_at_purchase = Column(Float, nullable=False) # Snapshot of price
    
    # Metadata Snapshot (In case Denomination/Product is deleted later)
    product_name_snapshot = Column(String(255), nullable=True)
    variant_label_snapshot = Column(String(100), nullable=True)

    order = relationship("Order", back_populates="items")
    denomination = relationship("Denomination", back_populates="order_items")

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
# MARKETING, BLOG & CMS MODELS
# ======================================================

class Banner(Base, TimestampMixin):
    __tablename__ = "banners"

    id = Column(Integer, primary_key=True)
    image_url = Column(Text, nullable=False)
    title = Column(String(255))
    subtitle = Column(String(255))
    target_url = Column(Text)
    btn_text = Column(String(50), default="Shop Now")
    
    is_active = Column(Boolean, default=True)
    display_order = Column(Integer, default=0)
    
    start_date = Column(DateTime)
    end_date = Column(DateTime)

    __table_args__ = (
        Index("idx_banner_active", "is_active", "display_order"),
    )

class BlogPost(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "blog_posts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, index=True)
    content = Column(Text, nullable=False)
    image_url = Column(String(500), nullable=True)
    is_published = Column(Boolean, default=True)
    author_id = Column(Integer, ForeignKey("admins.id"), nullable=False)

    author = relationship("Admin", back_populates="blog_posts")
    comments = relationship("BlogComment", back_populates="post", cascade="all, delete-orphan")
    reactions = relationship("BlogReaction", back_populates="post", cascade="all, delete-orphan")

class BlogComment(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "blog_comments"

    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, ForeignKey("blog_posts.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)

    post = relationship("BlogPost", back_populates="comments")
    user = relationship("User", back_populates="blog_comments")

class BlogReaction(Base, TimestampMixin):
    __tablename__ = "blog_reactions"
    
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, ForeignKey("blog_posts.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    reaction_type = Column(String(20), default="like") 

    post = relationship("BlogPost", back_populates="reactions")
    user = relationship("User", back_populates="blog_reactions")

    __table_args__ = (UniqueConstraint('post_id', 'user_id', name='_user_post_reaction_uc'),)

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

class InboxMessage(Base, TimestampMixin):
    """
    One-way persistent messages from System/Admin to User.
    Displayed in User Inbox.
    """
    __tablename__ = "inbox_messages"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    sender = Column(String(50), default="system") # e.g. "admin", "system"
    subject = Column(String(255), nullable=True)
    body = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False)

    user = relationship("User", back_populates="inbox_messages")

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
    is_banned: bool
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

# --- Denomination Schemas (New) ---

class DenominationBase(BaseModel):
    label: str
    price_usd: float = Field(..., gt=0)
    discount_percent: int = Field(0, ge=0, le=100)
    stock_quantity: int = Field(0, ge=0)
    in_stock: bool = True

    @field_validator('price_usd', mode='before')
    @classmethod
    def parse_price(cls, v: Any) -> float:
        if isinstance(v, str):
            return float(v.strip())
        return v

class DenominationCreate(DenominationBase):
    pass

class DenominationResponse(ORMBase):
    label: str
    price_usd: float
    discount_percent: int
    final_price: float
    stock_quantity: int
    in_stock: bool
    
    model_config = ConfigDict(from_attributes=True)

# --- Product Schemas (Updated) ---

class ProductBaseSchema(BaseModel):
    name: str
    platform: str
    product_category: ProductCategory = Field(default=ProductCategory.OTHERS)
    requires_player_id: bool = False
    
    category_id: Optional[int] = None
    description: Optional[str] = None
    short_description: Optional[str] = None
    
    is_featured: bool = False
    is_trending: bool = False

class ProductCreateSchema(ProductBaseSchema):
    image_url: str 
    # Optional: Initial denominations can be passed here if logic allows,
    # but typically handled separately or via nested list.
    
class ProductUpdateSchema(ProductBaseSchema):
    name: Optional[str] = None
    platform: Optional[str] = None
    product_category: Optional[ProductCategory] = None
    requires_player_id: Optional[bool] = None
    image_url: Optional[str] = None 

class ProductSchema(ORMBase):
    """
    Response schema for Product.
    Includes list of available denominations.
    """
    name: str
    slug: Optional[str]
    platform: str
    product_category: ProductCategory
    requires_player_id: bool
    image_url: Optional[str]
    is_featured: bool
    is_trending: bool
    
    denominations: List[DenominationResponse] = []
    
    model_config = ConfigDict(from_attributes=True)

# --- Cart & Order Schemas (Updated) ---

class CartItemSchema(BaseModel):
    denomination_id: int # Changed from product_id
    quantity: int = Field(1, ge=1)

class MultiProductOrderCreate(BaseModel):
    items: List[CartItemSchema]
    payment_method: PaymentMethod = PaymentMethod.NOWPAYMENTS
    player_id: Optional[str] = None

class OrderItemResponse(BaseModel):
    denomination_id: int
    product_name_snapshot: Optional[str]
    variant_label_snapshot: Optional[str]
    quantity: int
    unit_price_at_purchase: float
    
    model_config = ConfigDict(from_attributes=True)

class DeliveredCodeSchema(BaseModel):
    denomination_id: int
    code_value: str
    
    model_config = ConfigDict(from_attributes=True)

class OrderResponse(ORMBase):
    order_reference: Optional[str]
    total_amount_usd: float
    status: OrderStatus
    payment_method: PaymentMethod
    is_deposit: bool
    order_metadata: Optional[Dict[str, Any]] = None
    items: List[OrderItemResponse] = [] 
    delivered_codes: List[DeliveredCodeSchema] = []

    model_config = ConfigDict(from_attributes=True)

# --- CMS Schemas ---

class BannerCreateSchema(BaseModel):
    image_url: str
    title: Optional[str] = None
    subtitle: Optional[str] = None
    target_url: Optional[str] = None
    btn_text: str = "Shop Now"
    is_active: bool = True

class BannerUpdateSchema(BannerCreateSchema):
    image_url: Optional[str] = None

class BannerSchema(ORMBase):
    image_url: str
    title: Optional[str]
    subtitle: Optional[str]
    target_url: Optional[str]
    btn_text: str
    is_active: bool
    
    model_config = ConfigDict(from_attributes=True)

# --- BLOG & SOCIAL SCHEMAS ---

class BlogCreate(BaseModel):
    title: Optional[str] = Field(default="Untitled Post", min_length=0, max_length=255)
    content: Optional[str] = Field(default="No content provided", min_length=0)
    image_url: Optional[str] = None
    is_published: bool = True

class BlogResponse(ORMBase):
    title: str
    slug: str
    content: str
    image_url: Optional[str]
    is_published: bool
    author_username: Optional[str] = None

    @model_validator(mode='before')
    @classmethod
    def get_author_name(cls, data: Any):
        if hasattr(data, 'author') and data.author:
            data.author_username = data.author.username
        return data

    model_config = ConfigDict(from_attributes=True)

class CommentCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=1000)

class CommentResponse(ORMBase):
    content: str
    username: Optional[str] = None

    @model_validator(mode='before')
    @classmethod
    def get_user_info(cls, data: Any):
        if hasattr(data, 'user') and data.user:
            data.username = data.user.full_name or "Anonymous"
        return data

    model_config = ConfigDict(from_attributes=True)

class BlogDetailResponse(BlogResponse):
    comments: List[CommentResponse] = []
    likes_count: int = 0
    has_liked: bool = False
    
    model_config = ConfigDict(from_attributes=True)

# --- ADMIN MESSAGING & INBOX SCHEMAS ---

class InboxMessageCreate(BaseModel):
    """Schema for Admin creating a message."""
    user_id: Optional[int] = None # Updated: Made Optional to handle URL-based ID passing
    subject: Optional[str] = "Notification"
    body: str

class InboxMessageResponse(ORMBase):
    """Schema for User Inbox."""
    subject: Optional[str]
    body: str
    sender: str
    is_read: bool
    
    # ID and Created_At are inherited from ORMBase
    model_config = ConfigDict(from_attributes=True)