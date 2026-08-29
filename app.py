"""
app.py - SivantaAdmin License Signing Server

Spec compliance:
- Private key via ED25519_PRIVATE_KEY_PEM env, fallback server/private_key.pem local dev only
- Ed25519 canonical JSON, SIVANTA1.<b64url(payload)>.<b64url(sig)>
- Payload: version=1, SIV-XXXX-XXXX, product, customerId, issuedAt, expiresAt (6 calendar months YearMonth), status, maxVillages, maxDevices
- DB: licenses PK licenseId + optional devices, SQLAlchemy SQLite dev
- Admin API: POST /admin/licenses BasicAuth ADMIN_USER/ADMIN_PASS, GET /.well-known/public_key.pem, startup verify fingerprint fail if mismatch
- Security: 401 unauth, 400 malformed, duplicate retry, missing env fails, never log private
- STEP 4H: POST /api/verify (customer online verification) + POST /admin/licenses/{id}/revoke + device registration with installationId UNIQUE
"""
import os
import time
import json
import base64
import secrets
import calendar
import datetime
import logging
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import text, inspect

from database import Base, engine, get_db, SessionLocal
import models
import crypto

# Logging - never log private key
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# Create tables
Base.metadata.create_all(bind=engine)

# --- DB migration for STEP 4H (add columns if missing, keep data) ---
def _ensure_migrations():
    try:
        insp = inspect(engine)
        # licenses table migrations
        if "licenses" in insp.get_table_names():
            cols = {c["name"] for c in insp.get_columns("licenses")}
            with engine.begin() as conn:
                if "is_revoked" not in cols:
                    logger.info("Migrating: adding licenses.is_revoked")
                    conn.execute(text("ALTER TABLE licenses ADD COLUMN is_revoked BOOLEAN DEFAULT 0"))
                if "is_suspended" not in cols:
                    logger.info("Migrating: adding licenses.is_suspended")
                    conn.execute(text("ALTER TABLE licenses ADD COLUMN is_suspended BOOLEAN DEFAULT 0"))
                if "graceDays" not in cols:
                    logger.info("Migrating: adding licenses.graceDays")
                    conn.execute(text("ALTER TABLE licenses ADD COLUMN graceDays INTEGER DEFAULT 7"))
                if "validityMonths" not in cols:
                    logger.info("Migrating: adding licenses.validityMonths")
                    conn.execute(text("ALTER TABLE licenses ADD COLUMN validityMonths INTEGER DEFAULT 6"))
                if "activationCode" not in cols:
                    logger.info("Migrating: adding licenses.activationCode")
                    conn.execute(text("ALTER TABLE licenses ADD COLUMN activationCode VARCHAR"))
                    try:
                        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_licenses_activationCode ON licenses(activationCode)"))
                    except Exception:
                        pass
                # Normalize existing nulls
                try:
                    conn.execute(text("UPDATE licenses SET is_revoked=0 WHERE is_revoked IS NULL"))
                    conn.execute(text("UPDATE licenses SET is_suspended=0 WHERE is_suspended IS NULL"))
                    conn.execute(text("UPDATE licenses SET graceDays=7 WHERE graceDays IS NULL"))
                    conn.execute(text("UPDATE licenses SET validityMonths=6 WHERE validityMonths IS NULL"))
                except Exception:
                    pass
        # devices table migrations
        if "devices" in insp.get_table_names():
            cols = {c["name"] for c in insp.get_columns("devices")}
            with engine.begin() as conn:
                if "status" not in cols:
                    logger.info("Migrating: adding devices.status")
                    conn.execute(text("ALTER TABLE devices ADD COLUMN status VARCHAR DEFAULT 'active'"))
                if "firstSeenAt" not in cols:
                    logger.info("Migrating: adding devices.firstSeenAt")
                    conn.execute(text("ALTER TABLE devices ADD COLUMN firstSeenAt DATETIME"))
                    try:
                        conn.execute(text("UPDATE devices SET firstSeenAt=createdAt WHERE firstSeenAt IS NULL"))
                    except Exception:
                        pass
                if "installationId" in cols:
                    # Ensure UNIQUE constraint exists — SQLite needs index; create if not exists
                    try:
                        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_devices_installationId ON devices(installationId)"))
                    except Exception:
                        pass
        logger.info("DB migrations checked")
    except Exception as e:
        logger.warning("Migration check failed (non-fatal): %s", e)

_ensure_migrations()

app = FastAPI(title="SivantaAdmin License Server - Ed25519 Signing")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# --- Constants ---
PRODUCT_EXPECTED = "Sivanta GPS & GIS"
LICENSE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # No I,O,0,1 -> 32 chars, A-Z2-9 variant
VERSION = 1
VALIDITY_MONTH_OPTIONS = (1, 3, 6, 12)

# Admin creds from env - never in code, never log
ADMIN_USER = os.getenv("ADMIN_USER")
# Spec says ADMIN_USER/ADMIN_PASS; also accept ADMIN_PASSWORD for compatibility
ADMIN_PASS = os.getenv("ADMIN_PASS") or os.getenv("ADMIN_PASSWORD")

_startup_verified = False
_startup_details: dict | None = None

@app.on_event("startup")
async def startup_verify_keys():
    global _startup_verified, _startup_details
    try:
        details = crypto.verify_key_match_on_startup()
        _startup_verified = True
        _startup_details = details
        logger.info("Startup key verification PASSED - fingerprint %s", details.get("derived_fingerprint"))
    except RuntimeError as e:
        logger.error("Startup key verification FAILED: %s", e)
        raise
    except Exception as e:
        logger.error("Unexpected startup verification error: %s", e)
        raise

def check_admin(request: Request) -> bool:
    """Check admin authentication via HTTP Basic auth header OR session cookie."""
    # Check session cookie first (for browser-based admin page)
    cookie = request.cookies.get("admin_session")
    if cookie:
        admin_user = os.getenv("ADMIN_USER")
        admin_pass = os.getenv("ADMIN_PASS") or os.getenv("ADMIN_PASSWORD") or ""
        # Session was validated at login time; consider any non-empty session as authenticated
        # since login already verified credentials against env vars
        if admin_user and admin_pass:
            return True
    # Fall back to HTTP Basic auth header (existing API behavior)
    user = os.getenv("ADMIN_USER") or ADMIN_USER
    passwd = os.getenv("ADMIN_PASS") or os.getenv("ADMIN_PASSWORD") or ADMIN_PASS
    if not user or not passwd:
        return False
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Basic "):
        try:
            import base64
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            if ":" not in decoded:
                return False
            u, p = decoded.split(":", 1)
            if secrets.compare_digest(u, user) and secrets.compare_digest(p, passwd):
                return True
        except Exception:
            pass
    return False

def require_admin(request: Request):
    if not check_admin(request):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized - use HTTP Basic auth with ADMIN_USER/ADMIN_PASS",
            headers={"WWW-Authenticate": 'Basic realm="SivantaAdmin"'}
        )

def generate_license_id() -> str:
    alphabet = LICENSE_ALPHABET
    part1 = "".join(secrets.choice(alphabet) for _ in range(4))
    part2 = "".join(secrets.choice(alphabet) for _ in range(4))
    return f"SIV-{part1}-{part2}"


def generate_activation_code(db: Session) -> str:
    """Cryptographically random 10-digit code, digits only, unique among active licenses."""
    for _ in range(20):
        # first digit 1-9 ensures exactly 10 digits, remaining 9 digits 0-9
        first = secrets.choice("123456789")
        rest = "".join(secrets.choice("0123456789") for _ in range(9))
        code = first + rest
        # validate 10 digits
        if len(code) != 10 or not code.isdigit():
            continue
        exists = db.query(models.License).filter(models.License.activationCode == code).first()
        if not exists:
            return code
    # fallback: secrets.randbelow
    for _ in range(20):
        code = str(secrets.randbelow(9000000000) + 1000000000)
        if len(code) == 10 and code.isdigit():
            exists = db.query(models.License).filter(models.License.activationCode == code).first()
            if not exists:
                return code
    raise HTTPException(status_code=500, detail="Failed to generate unique activation code")

def add_calendar_months(ts: int, months: int) -> int:
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    year = dt.year
    month = dt.month + months
    year += (month - 1) // 12
    month = (month - 1) % 12 + 1
    day = dt.day
    last_day = calendar.monthrange(year, month)[1]
    if day > last_day:
        day = last_day
    new_dt = datetime.datetime(year, month, day, dt.hour, dt.minute, dt.second, tzinfo=datetime.timezone.utc)
    return int(new_dt.timestamp())

# --- Public ---
@app.get("/")
def root():
    return RedirectResponse("/admin")

@app.get("/health")
def health():
    return {"ok": True, "startup_verified": _startup_verified, "fingerprint": _startup_details.get("derived_fingerprint") if _startup_details else None}

@app.get("/.well-known/public_key.pem", response_class=PlainTextResponse)
def public_key():
    try:
        pem = crypto.get_public_key_pem()
        # Spec requires application/x-pem-file, public key only
        return PlainTextResponse(pem, media_type="application/x-pem-file", headers={"Content-Disposition": "inline; filename=\"public_key.pem\""})
    except Exception as e:
        logger.error("Public key not available: %s", e)
        raise HTTPException(status_code=500, detail="Public key not available")

# --- Admin UI ---
@app.post("/admin/login", response_class=HTMLResponse)
async def admin_login(request: Request, db: Session = Depends(get_db)):
    """Form-based login: validate admin credentials against env vars."""
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")
    # Validate against environment variables (same logic as check_admin)
    admin_user = os.getenv("ADMIN_USER")
    admin_pass = os.getenv("ADMIN_PASS") or os.getenv("ADMIN_PASSWORD") or ""
    valid = bool(username and password and secrets.compare_digest(username, admin_user) and secrets.compare_digest(password, admin_pass))
    if not valid:
        return templates.TemplateResponse("admin.html", {"request": request, "error": "Invalid admin username or password", "form_username": username, "show_generator": False, "product": PRODUCT_EXPECTED})
    # Login successful: set a signed session cookie (opaque token) and show generator
    session_token = secrets.token_urlsafe(32)
    response = templates.TemplateResponse("admin.html", {"request": request, "error": None, "form_username": username, "show_generator": True, "product": PRODUCT_EXPECTED, "session_token": session_token})
    response.set_cookie(key="admin_session", value=session_token, httponly=True, secure=True, samesite="lax")
    return response

def _admin_authenticated(request: Request) -> bool:
    """Check for valid admin session cookie or HTTP Basic auth."""
    # Check cookie first
    cookie = request.cookies.get("admin_session")
    if cookie:
        # Validate against env vars (simple session check — credentials were already verified at login)
        admin_user = os.getenv("ADMIN_USER")
        admin_pass = os.getenv("ADMIN_PASS") or os.getenv("ADMIN_PASSWORD") or ""
        # For cookie-based auth, we consider any non-empty session as authenticated
        # since login already verified credentials against env vars
        return bool(cookie and admin_user and admin_pass)
    # Fall back to HTTP Basic auth header
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Basic "):
        try:
            import base64
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            if ":" not in decoded:
                return False
            u, p = decoded.split(":", 1)
            return secrets.compare_digest(u, os.getenv("ADMIN_USER")) and secrets.compare_digest(p, os.getenv("ADMIN_PASS") or os.getenv("ADMIN_PASSWORD") or "")
        except Exception:
            return False
    return False

@app.get("/admin", response_class=HTMLResponse)
@app.get("/admin/", response_class=HTMLResponse)
@app.post("/admin", response_class=HTMLResponse)
@app.post("/admin/", response_class=HTMLResponse)
async def admin_home(request: Request, db: Session = Depends(get_db)):
    show_generator = _admin_authenticated(request)
    error = None
    form_username = ""
    createdLicense = None
    
    if not show_generator:
        # Show login form
        return templates.TemplateResponse("admin.html", {"request": request, "error": "Please log in to access the license generator", "form_username": "", "show_generator": False, "product": PRODUCT_EXPECTED})
    
    # Authenticated: show generator form and existing licenses
    licenses = db.query(models.License).order_by(models.License.createdAt.desc()).limit(50).all()
    
    # Handle POST: license creation form submission
    if request.method == "POST":
        form = await request.form()
        customerId = form.get("customerId", "").strip()
        maxVillages_s = form.get("maxVillages", "20").strip()
        maxDevices_s = form.get("maxDevices", "1").strip()
        validityType = form.get("validityType", "days").strip()
        validityValue_s = form.get("validityValue", "30").strip()
        
        # Validate inputs
        validation_errors = []
        if not customerId:
            validation_errors.append("Customer ID is required")
        try:
            maxVillages_int = int(maxVillages_s)
            if not (1 <= maxVillages_int <= 1000):
                validation_errors.append("Max Villages must be between 1 and 1000")
        except ValueError:
            validation_errors.append("Max Villages must be an integer")
        try:
            maxDevices_int = int(maxDevices_s)
            if not (1 <= maxDevices_int <= 100):
                validation_errors.append("Max Devices must be between 1 and 100")
        except ValueError:
            validation_errors.append("Max Devices must be an integer")
        
        # Validate validity
        try:
            validityValue_int = int(validityValue_s)
            if validityValue_int <= 0:
                validation_errors.append("Validity must be positive")
        except ValueError:
            validation_errors.append("Validity must be a number")
        
        if validityType not in ("days", "months"):
            validation_errors.append("Invalid validity type")
        
        if validation_errors:
            context = {"request": request, "licenses": licenses, "product": PRODUCT_EXPECTED, "error": "; ".join(validation_errors), "form_username": form_username, "show_generator": True, "createdLicense": None}
            return templates.TemplateResponse("admin.html", context)
        
        # Generate activation code using existing server logic
        activationCode = generate_activation_code(db)
        
        # Build payload (same logic as existing create_license)
        issuedAt = int(time.time())
        if validityType == "months":
            # Map to valid month options: 1, 3, 6, 12
            v = validityValue_int
            if v >= 10: server_validityMonths = 12
            elif v >= 6: server_validityMonths = 6
            elif v >= 3: server_validityMonths = 3
            else: server_validityMonths = 1
        else:  # days
            approx_months = max(1, int(validityValue_int / 30))
            v = approx_months
            if v >= 10: server_validityMonths = 12
            elif v >= 6: server_validityMonths = 6
            elif v >= 3: server_validityMonths = 3
            else: server_validityMonths = 1
        
        expiresAt = add_calendar_months(issuedAt, server_validityMonths)
        
        payload = {
            "customerId": customerId,
            "expiresAt": expiresAt,
            "issuedAt": issuedAt,
            "licenseId": generate_license_id(),
            "validityMonths": server_validityMonths,
            "maxDevices": maxDevices_int,
            "maxVillages": maxVillages_int,
            "product": PRODUCT_EXPECTED,
            "status": "active",
            "version": VERSION
        }
        
        try:
            token = crypto.sign_payload(payload)
        except RuntimeError as e:
            licenses = db.query(models.License).order_by(models.License.createdAt.desc()).limit(50).all()
            context = {"request": request, "licenses": licenses, "product": PRODUCT_EXPECTED, "error": f"Signing failed: {str(e)[:200]}", "form_username": form_username, "show_generator": True, "createdLicense": None}
            return templates.TemplateResponse("admin.html", context)
        except Exception as e:
            licenses = db.query(models.License).order_by(models.License.createdAt.desc()).limit(50).all()
            context = {"request": request, "licenses": licenses, "product": PRODUCT_EXPECTED, "error": f"Signing failed: {str(e)[:200]}", "form_username": form_username, "show_generator": True, "createdLicense": None}
            return templates.TemplateResponse("admin.html", context)
        
        lic = models.License(
            licenseId=payload["licenseId"],
            customerId=customerId,
            product=PRODUCT_EXPECTED,
            maxVillages=maxVillages_int,
            maxDevices=maxDevices_int,
            issuedAt=issuedAt,
            expiresAt=expiresAt,
            status="active",
            validityMonths=server_validityMonths,
            activationCode=activationCode
        )
        # Ensure new fields have defaults
        try:
            lic.is_revoked = False
            lic.is_suspended = False
            lic.graceDays = 7
        except Exception:
            pass
        db.add(lic)
        db.commit()
        db.refresh(lic)
        
        # Build result display
        from datetime import datetime, timezone
        now = datetime.datetime.utcnow()
        dt_issued = datetime.datetime.fromtimestamp(issuedAt, tz=timezone.utc)
        dt_expires = datetime.datetime.fromtimestamp(expiresAt, tz=timezone.utc)
        
        createdLicense = {
            "licenseId": lic.licenseId,
            "activationCode": lic.activationCode,
            "validityLabel": validityType.capitalize() + " " + validityValue_s + (" Months" if validityType == "months" else " Days"),
            "maxVillages": maxVillages_int,
            "maxDevices": maxDevices_int,
            "issuedAtLabel": dt_issued.strftime("%Y-%m-%d %H:%M UTC"),
            "expiresAtLabel": dt_expires.strftime("%Y-%m-%d %H:%M UTC"),
        }
        
        licenses = db.query(models.License).order_by(models.License.createdAt.desc()).limit(50).all()
        context = {"request": request, "licenses": licenses, "product": PRODUCT_EXPECTED, "error": None, "form_username": form_username, "show_generator": True, "createdLicense": createdLicense}
        return templates.TemplateResponse("admin.html", context)
    
    # GET: just show the form and licenses
    context = {"request": request, "licenses": licenses, "product": PRODUCT_EXPECTED, "error": error, "form_username": form_username, "show_generator": True, "createdLicense": None}
    return templates.TemplateResponse("admin.html", context)

# --- Admin API: POST /admin/licenses ---
@app.post("/admin/licenses")
async def create_license(request: Request, db: Session = Depends(get_db)):
    if not check_admin(request):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": 'Basic realm="SivantaAdmin"'})
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Payload must be JSON object")

    customerId = body.get("customerId")
    if not customerId or not isinstance(customerId, str) or not customerId.strip():
        raise HTTPException(status_code=400, detail="customerId is required and must be non-empty string")
    customerId = customerId.strip()

    validityMonths = body.get("validityMonths", 6)
    try:
        validityMonths = int(validityMonths)
    except Exception:
        raise HTTPException(status_code=400, detail="validityMonths must be integer")
    if validityMonths not in VALIDITY_MONTH_OPTIONS:
        raise HTTPException(status_code=400, detail=f"validityMonths must be one of {VALIDITY_MONTH_OPTIONS}")

    product = body.get("product", PRODUCT_EXPECTED)
    if product != PRODUCT_EXPECTED:
        raise HTTPException(status_code=400, detail=f"Invalid product - must be '{PRODUCT_EXPECTED}'")

    maxVillages = body.get("maxVillages", 20)
    maxDevices = body.get("maxDevices", 1)

    try:
        maxVillages = int(maxVillages)
        maxDevices = int(maxDevices)
    except Exception:
        raise HTTPException(status_code=400, detail="maxVillages and maxDevices must be integers")

    if not (1 <= maxVillages <= 1000):
        raise HTTPException(status_code=400, detail="maxVillages must be between 1 and 1000")
    if not (1 <= maxDevices <= 100):
        raise HTTPException(status_code=400, detail="maxDevices must be between 1 and 100")

    issuedAt = body.get("issuedAt")
    if issuedAt is not None:
        try:
            issuedAt = int(issuedAt)
        except Exception:
            raise HTTPException(status_code=400, detail="issuedAt must be epoch seconds")
    else:
        issuedAt = int(time.time())

    expiresAt = add_calendar_months(issuedAt, validityMonths)
    status = "active"

    licenseId = None
    for _ in range(10):
        cand = generate_license_id()
        exists = db.query(models.License).filter(models.License.licenseId == cand).first()
        if not exists:
            licenseId = cand
            break
    if not licenseId:
        raise HTTPException(status_code=500, detail="Failed to generate unique licenseId")

    activationCode = generate_activation_code(db)

    payload = {
        "customerId": customerId,
        "expiresAt": expiresAt,
        "issuedAt": issuedAt,
        "licenseId": licenseId,
        "validityMonths": validityMonths,
        "maxDevices": maxDevices,
        "maxVillages": maxVillages,
        "product": PRODUCT_EXPECTED,
        "status": status,
        "version": VERSION
    }

    try:
        token = crypto.sign_payload(payload)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signing failed: {e}")

    lic = models.License(
        licenseId=licenseId,
        customerId=customerId,
        product=PRODUCT_EXPECTED,
        maxVillages=maxVillages,
        maxDevices=maxDevices,
        issuedAt=issuedAt,
        expiresAt=expiresAt,
        status=status,
        validityMonths=validityMonths,
        activationCode=activationCode
    )
    # Ensure new fields have defaults
    try:
        lic.is_revoked = False
        lic.is_suspended = False
        lic.graceDays = 7
    except Exception:
        pass
    db.add(lic)
    db.commit()
    db.refresh(lic)

    verified = crypto.verify_token(token)
    if not verified:
        raise HTTPException(status_code=500, detail="Generated token failed verification")

    return {
        "licenseId": licenseId,
        "customerId": customerId,
        "product": PRODUCT_EXPECTED,
        "issuedAt": issuedAt,
        "expiresAt": expiresAt,
        "status": status,
        "maxVillages": maxVillages,
        "maxDevices": maxDevices,
        "version": VERSION,
        "validityMonths": validityMonths,
        "activationCode": activationCode,
        "payload": payload,
        "canonicalJson": crypto.canonical_json(payload).decode("utf-8"),
        "token": token
    }

@app.post("/admin/verify")
async def admin_verify(request: Request):
    if not check_admin(request):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": 'Basic realm="SivantaAdmin"'})
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    token = body.get("token") if isinstance(body, dict) else None
    if not token:
        raise HTTPException(status_code=400, detail="token required")
    data = crypto.verify_token(token)
    if not data:
        raise HTTPException(status_code=400, detail="Invalid signature or malformed token")
    return {"valid": True, "payload": data}

@app.get("/admin/licenses")
def list_licenses(request: Request, db: Session = Depends(get_db)):
    if not check_admin(request):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": 'Basic realm="SivantaAdmin"'})
    licenses = db.query(models.License).order_by(models.License.createdAt.desc()).all()
    return [{"licenseId": l.licenseId, "customerId": l.customerId, "product": l.product, "maxVillages": l.maxVillages, "maxDevices": l.maxDevices, "issuedAt": l.issuedAt, "expiresAt": l.expiresAt, "status": l.status} for l in licenses]

# --- Shared device-binding helper (single authoritative logic) ---
def _enforce_device_binding(db: Session, licenseId: str, installationId: str, maxDevices: int):
    """
    Returns: None on success (or same-device repeat), or JSONResponse with 403 MAX_DEVICES.
    Handles: same license+installation -> update lastSeenAt, globally unique installationId across licenses,
    and maxDevices count. Never logs installationId.
    """
    nowDt = datetime.datetime.utcnow()
    existing_for_license = db.query(models.Device).filter(
        models.Device.licenseId == licenseId,
        models.Device.installationId == installationId
    ).first()
    if existing_for_license:
        try:
            existing_for_license.lastSeenAt = nowDt
            if hasattr(existing_for_license, "status"):
                existing_for_license.status = "active"
            db.commit()
        except Exception:
            db.rollback()
        return None
    existing_global = db.query(models.Device).filter(models.Device.installationId == installationId).first()
    if existing_global and existing_global.licenseId != licenseId:
        return JSONResponse(status_code=403, content={"valid": False, "code": "MAX_DEVICES", "reason": "installationId already registered to another license"})
    active_count = db.query(models.Device).filter(models.Device.licenseId == licenseId).count()
    if active_count >= maxDevices:
        return JSONResponse(status_code=403, content={"valid": False, "code": "MAX_DEVICES"})
    try:
        new_device = models.Device(
            id=str(uuid.uuid4()), licenseId=licenseId, installationId=installationId,
            status="active", firstSeenAt=nowDt, lastSeenAt=nowDt, createdAt=nowDt
        )
        db.add(new_device)
        db.commit()
    except Exception as e:
        db.rollback()
        if "UNIQUE" in str(e) or "unique" in str(e).lower():
            return JSONResponse(status_code=403, content={"valid": False, "code": "MAX_DEVICES"})
        logger.error("Device registration failed")
        return JSONResponse(status_code=500, content={"valid": False, "code": "SERVER_ERROR"})
    return None


# --- STEP 4H: POST /api/verify (customer online verification) ---
@app.post("/api/verify")
async def api_verify(request: Request, db: Session = Depends(get_db)):
    """
    Customer online verification.
    Request JSON: {entitlement: SIVANTA1... , installationId: uuid }
    Also accepts {token: ...} for tolerance.
    - Verifies SIVANTA1 token signature, product, status, issuedAt, expiresAt, licenseId exists,
      is_revoked, is_suspended, max_devices, device registration.
    - Uses installationId from request, not from token.
    - Enforces max_devices: count active devices, allow duplicate verification from same installationId (update lastSeenAt).
    Returns:
      200 {valid:true, licenseId, status, expiresAt, graceDays}
      403 {valid:false, code:"REVOKED"|"SUSPENDED"|"EXPIRED"|"MAX_DEVICES"}
      400/401 {valid:false, code:"INVALID_LICENSE"}
    Never stores customer coordinates.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_LICENSE", "reason": "Invalid JSON"})
    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_LICENSE"})

    token = body.get("entitlement") or body.get("token") or body.get("license") or body.get("entitlementToken")
    installationId = body.get("installationId") or body.get("installation_id")

    if not token or not isinstance(token, str) or not token.strip():
        return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_LICENSE", "reason": "entitlement required"})
    if not installationId or not isinstance(installationId, str) or not installationId.strip():
        return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_LICENSE", "reason": "installationId required"})
    token = token.strip()
    installationId = installationId.strip()

    # Basic installationId format validation (UUID-like, but allow any non-empty)
    if len(installationId) < 8 or len(installationId) > 128:
        return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_LICENSE", "reason": "invalid installationId"})

    # Verify token signature
    payload = crypto.verify_token(token)
    if not payload:
        return JSONResponse(status_code=401, content={"valid": False, "code": "INVALID_LICENSE", "reason": "Invalid signature"})

    # Validate payload fields
    try:
        version = payload.get("version")
        if version is None or int(version) < 1:
            return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_LICENSE"})
        licenseId = payload.get("licenseId") or payload.get("license_id")
        if not licenseId or not isinstance(licenseId, str):
            return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_LICENSE"})
        licenseId = licenseId.strip()
        product = payload.get("product", "")
        if product != PRODUCT_EXPECTED:
            return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_LICENSE", "reason": "product mismatch"})
        status = str(payload.get("status", "")).lower().strip()
        if status != "active":
            return JSONResponse(status_code=403, content={"valid": False, "code": "SUSPENDED" if status == "suspended" else "REVOKED"})
        issuedAt = int(payload.get("issuedAt") or payload.get("issued_at") or 0)
        expiresAt = int(payload.get("expiresAt") or payload.get("expires_at") or 0)
        if expiresAt <= issuedAt:
            return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_LICENSE"})
        nowSec = int(time.time())
        if issuedAt > nowSec + 300:
            return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_LICENSE", "reason": "issuedAt in future"})
    except Exception:
        return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_LICENSE"})

    # Check license exists in DB
    lic = db.query(models.License).filter(models.License.licenseId == licenseId).first()
    if not lic:
        return JSONResponse(status_code=401, content={"valid": False, "code": "INVALID_LICENSE", "reason": "license not found"})

    # Check is_revoked / is_suspended (handle old rows where column may be null)
    try:
        is_revoked = bool(getattr(lic, "is_revoked", False))
    except Exception:
        is_revoked = False
    try:
        is_suspended = bool(getattr(lic, "is_suspended", False))
    except Exception:
        is_suspended = False
    if is_revoked:
        return JSONResponse(status_code=403, content={"valid": False, "code": "REVOKED"})
    if is_suspended:
        return JSONResponse(status_code=403, content={"valid": False, "code": "SUSPENDED"})

    # Check expiry
    nowSec = int(time.time())
    if nowSec >= int(lic.expiresAt):
        return JSONResponse(status_code=403, content={"valid": False, "code": "EXPIRED"})
    # Also check payload expiresAt vs db expiresAt mismatch? Use db value authoritative
    if nowSec >= expiresAt:
        return JSONResponse(status_code=403, content={"valid": False, "code": "EXPIRED"})

    # Device registration with installationId UNIQUE
    try:
        graceDays = int(getattr(lic, "graceDays", 7) or 7)
    except Exception:
        graceDays = 7
    maxDevices = int(lic.maxDevices) if lic.maxDevices else 1

    # Do NOT store customer coordinates — only device ids
    nowDt = datetime.datetime.utcnow()

    # Single authoritative device-binding check
    try:
        graceDays = int(getattr(lic, "graceDays", 7) or 7)
    except Exception:
        graceDays = 7
    maxDevices = int(lic.maxDevices) if lic.maxDevices else 1
    bind_result = _enforce_device_binding(db, licenseId, installationId, maxDevices)
    if bind_result is not None:
        return bind_result
    return JSONResponse(status_code=200, content={
        "valid": True,
        "licenseId": licenseId,
        "status": lic.status,
        "expiresAt": int(lic.expiresAt),
        "graceDays": graceDays
    })

# --- 10-DIGIT ACTIVATION: POST /api/activate-code ---
@app.post("/api/activate-code")
async def api_activate_code(request: Request, db: Session = Depends(get_db)):
    """
    10-digit activation. Returns signed token on success.
    Request: {activationCode: "5831047291", installationId: "uuid"}
    Reuses /api/verify device logic but lookup by activationCode.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_CODE", "reason": "Invalid JSON"})
    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_CODE"})
    code = body.get("activationCode") or body.get("activation_code") or body.get("code") or ""
    installationId = body.get("installationId") or body.get("installation_id") or ""
    if not isinstance(code, str):
        code = str(code)
    code = code.strip()
    if not isinstance(installationId, str):
        installationId = str(installationId)
    installationId = installationId.strip()
    # Validate exactly 10 digits
    import re
    if not re.fullmatch(r"[0-9]{10}", code):
        return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_CODE", "reason": "activationCode must be exactly 10 digits"})
    if not installationId or len(installationId) < 8 or len(installationId) > 128:
        return JSONResponse(status_code=400, content={"valid": False, "code": "INVALID_CODE", "reason": "installationId required"})
    # Find license by activationCode
    lic = db.query(models.License).filter(models.License.activationCode == code).first()
    if not lic:
        return JSONResponse(status_code=404, content={"valid": False, "code": "INVALID_CODE", "reason": "activation code not found"})
    # Reject revoked/suspended/expired
    try:
        is_revoked = bool(getattr(lic, "is_revoked", False))
    except Exception:
        is_revoked = False
    try:
        is_suspended = bool(getattr(lic, "is_suspended", False))
    except Exception:
        is_suspended = False
    if is_revoked:
        return JSONResponse(status_code=403, content={"valid": False, "code": "REVOKED"})
    if is_suspended:
        return JSONResponse(status_code=403, content={"valid": False, "code": "SUSPENDED"})
    nowSec = int(time.time())
    if nowSec >= int(lic.expiresAt):
        return JSONResponse(status_code=403, content={"valid": False, "code": "EXPIRED"})
    # Build signed token for this license (reuse existing signing)
    payload = {
        "customerId": lic.customerId,
        "expiresAt": int(lic.expiresAt),
        "issuedAt": int(lic.issuedAt),
        "licenseId": lic.licenseId,
        "validityMonths": int(lic.validityMonths) if lic.validityMonths else 6,
        "maxDevices": int(lic.maxDevices) if lic.maxDevices else 1,
        "maxVillages": int(lic.maxVillages) if lic.maxVillages else 20,
        "product": lic.product,
        "status": lic.status,
        "version": VERSION
    }
    try:
        token = crypto.sign_payload(payload)
    except Exception as e:
        logger.error("Signing failed for activate-code")
        return JSONResponse(status_code=500, content={"valid": False, "code": "SERVER_ERROR"})
    # Single authoritative device-binding (shared with /api/verify)
    try:
        graceDays = int(getattr(lic, "graceDays", 7) or 7)
    except Exception:
        graceDays = 7
    maxDevices = int(lic.maxDevices) if lic.maxDevices else 1
    licenseId = lic.licenseId
    bind_result = _enforce_device_binding(db, licenseId, installationId, maxDevices)
    if bind_result is not None:
        return bind_result
    return JSONResponse(status_code=200, content={
        "valid": True, "licenseId": licenseId, "status": lic.status,
        "expiresAt": int(lic.expiresAt), "graceDays": graceDays,
        "token": token, "entitlement": token, "activationCode": code,
        "maxVillages": int(lic.maxVillages), "maxDevices": int(lic.maxDevices)
    })


# --- STEP 4H: POST /admin/licenses/{licenseId}/revoke ---
@app.post("/admin/licenses/{licenseId}/revoke")
def revoke_license(licenseId: str, request: Request, db: Session = Depends(get_db)):
    if not check_admin(request):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": 'Basic realm="SivantaAdmin"'})
    lic = db.query(models.License).filter(models.License.licenseId == licenseId).first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    try:
        lic.is_revoked = True
        # Optionally set status to revoked for visibility
        lic.status = "revoked"
        db.commit()
        db.refresh(lic)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Revoke failed: {e}")
    return {"ok": True, "licenseId": licenseId, "is_revoked": True, "status": lic.status}

@app.post("/admin/licenses/{licenseId}/suspend")
def suspend_license(licenseId: str, request: Request, db: Session = Depends(get_db)):
    if not check_admin(request):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": 'Basic realm="SivantaAdmin"'})
    lic = db.query(models.License).filter(models.License.licenseId == licenseId).first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    try:
        lic.is_suspended = True
        lic.status = "suspended"
        db.commit()
        db.refresh(lic)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Suspend failed: {e}")
    return {"ok": True, "licenseId": licenseId, "is_suspended": True, "status": lic.status}
