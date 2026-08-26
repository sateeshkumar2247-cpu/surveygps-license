from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from database import Base
import datetime
import uuid

def gen_id(): return str(uuid.uuid4())[:8].upper()

class Customer(Base):
    __tablename__ = "customers"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    phone = Column(String)
    email = Column(String)
    notes = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    licenses = relationship("License", back_populates="customer")

class License(Base):
    __tablename__ = "licenses"
    id = Column(String, primary_key=True, default=gen_id)  # e.g. ABC123
    customer_id = Column(String, ForeignKey("customers.id"))
    plan = Column(String, default="standard")
    max_devices = Column(Integer, default=1)
    expires_at = Column(DateTime, nullable=True)  # None = lifetime
    is_revoked = Column(Boolean, default=False)
    is_suspended = Column(Boolean, default=False)
    min_app_version = Column(Integer, default=1)
    grace_days = Column(Integer, default=7)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_verified_at = Column(DateTime, nullable=True)

    customer = relationship("Customer", back_populates="licenses")
    devices = relationship("Device", back_populates="license", cascade="all, delete-orphan")

class Device(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    license_id = Column(String, ForeignKey("licenses.id"))
    installation_id = Column(String, nullable=False)  # SHA256(pubkey)
    device_name = Column(String)
    public_key = Column(Text)  # base64
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.datetime.utcnow)

    license = relationship("License", back_populates="devices")

class AppConfig(Base):
    __tablename__ = "app_config"
    id = Column(Integer, primary_key=True)
    latest_version_code = Column(Integer, default=1)
    latest_version_name = Column(String, default="1.0")
    min_supported_version = Column(Integer, default=1)
    apk_url = Column(String, default="")
    apk_sha256 = Column(String, default="")
    maintenance_mode = Column(Boolean, default=False)
