import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# Permanent fix: use Render persistent disk if available, otherwise local file
# On Render, /opt/render exists; use disk mount for SQLite persistence across deploys
_default_sqlite = "sqlite:////opt/render/project/src/data/sivanta_license.db" if Path("/opt/render").exists() else "sqlite:///./sivanta_license.db"
# Ensure disk directory exists
if _default_sqlite.startswith("sqlite") and "/opt/render/project/src/data" in _default_sqlite:
    try: Path("/opt/render/project/src/data").mkdir(parents=True, exist_ok=True)
    except Exception: pass

DATABASE_URL = os.getenv("DATABASE_URL", _default_sqlite)
# Render gives postgres:// but SQLAlchemy needs postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
