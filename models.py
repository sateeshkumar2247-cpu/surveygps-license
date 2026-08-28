from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Boolean, UniqueConstraint
from sqlalchemy.orm import relationship
from database import Base
import datetime

class License(Base):
    __tablename__ = "licenses"
    licenseId = Column(String, primary_key=True)  # SIV-XXXX-XXXX
    customerId = Column(String, nullable=False)
    product = Column(String, nullable=False, default="Sivanta GPS & GIS")
    maxVillages = Column(Integer, nullable=False, default=20)
    maxDevices = Column(Integer, nullable=False, default=1)
    issuedAt = Column(Integer, nullable=False)  # epoch seconds UTC
    expiresAt = Column(Integer, nullable=False)
    status = Column(String, nullable=False, default="active")
    is_revoked = Column(Boolean, nullable=False, default=False)
    is_suspended = Column(Boolean, nullable=False, default=False)
    graceDays = Column(Integer, nullable=False, default=7)
    createdAt = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)

class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint('installationId', name='uq_devices_installationId'),)
    id = Column(String, primary_key=True)
    licenseId = Column(String, ForeignKey("licenses.licenseId"), nullable=False)
    installationId = Column(String, nullable=False, unique=True)
    deviceName = Column(String, nullable=True)
    publicKey = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="active")
    firstSeenAt = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    createdAt = Column(DateTime, nullable=True, default=datetime.datetime.utcnow)
    lastSeenAt = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)

    license = relationship("License", backref="devices")
