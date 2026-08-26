from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import func
import datetime
import hashlib
import os

from database import Base, engine, get_db, SessionLocal
import models
import crypto

Base.metadata.create_all(bind=engine)

# seed default admin config if missing
def seed():
    db = SessionLocal()
    if not db.query(models.AppConfig).first():
        db.add(models.AppConfig())
        db.commit()
    # default admin password from env or generated
    db.close()
seed()

app = FastAPI(title="SurveyGPS License Server")
templates = Jinja2Templates(directory="templates")

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")  # CHANGE IN PRODUCTION

def check_admin(request: Request):
    auth = request.headers.get("Authorization", "")
    # also support cookie / basic
    if request.cookies.get("admin") == "1":
        return True
    # Basic auth
    import base64
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode()
            u, p = decoded.split(":", 1)
            if u == ADMIN_USER and p == ADMIN_PASS:
                return True
        except: pass
    return False

# --- Public API ---

@app.get("/health")
def health(): return {"ok": True}

@app.get("/config")
def get_config(db: Session = Depends(get_db)):
    cfg = db.query(models.AppConfig).first()
    return {"latest_version_code": cfg.latest_version_code, "min_supported_version": cfg.min_supported_version,
            "maintenance_mode": cfg.maintenance_mode, "apk_url": cfg.apk_url}

@app.get("/.well-known/public_key.pem")
def public_key(): return crypto.get_public_key_pem()

@app.post("/api/activate")
def activate(license_key: str = Form(...), installation_id: str = Form(...),
             device_name: str = Form(""), app_version: int = Form(1), public_key: str = Form(""),
             db: Session = Depends(get_db)):
    lic = db.query(models.License).filter(models.License.id == license_key).first()
    if not lic: raise HTTPException(400, "Invalid license")
    if lic.is_revoked: raise HTTPException(403, "License revoked")
    if lic.is_suspended: raise HTTPException(403, "License suspended")
    if lic.expires_at and lic.expires_at < datetime.datetime.utcnow():
        raise HTTPException(403, "License expired")
    if lic.min_app_version > app_version:
        raise HTTPException(426, f"Update required. Minimum version: {lic.min_app_version}")
    # device limit
    active = [d for d in lic.devices if not d.is_revoked]
    # allow re-activation of same installation
    existing = next((d for d in active if d.installation_id == installation_id), None)
    if not existing and len(active) >= lic.max_devices:
        raise HTTPException(403, "Device limit reached")
    if not existing:
        dev = models.Device(license_id=lic.id, installation_id=installation_id,
                            device_name=device_name[:60], public_key=public_key[:2000])
        db.add(dev); db.commit(); db.refresh(dev)
        device_id = dev.id
    else:
        existing.last_seen_at = datetime.datetime.utcnow()
        db.commit()
        device_id = existing.id
    lic.last_verified_at = datetime.datetime.utcnow()
    db.commit()
    payload = {
        "license_id": lic.id,
        "device_id": device_id,
        "installation_id": installation_id,
        "issued_at": int(datetime.datetime.utcnow().timestamp()),
        "expires_at": int((datetime.datetime.utcnow() + datetime.timedelta(days=lic.grace_days)).timestamp()),
        "grace_days": lic.grace_days,
        "plan": lic.plan,
        "min_version": lic.min_app_version,
    }
    token = crypto.sign_entitlement(payload)
    return {"entitlement": token, "payload": payload}

@app.post("/api/verify")
def verify(entitlement: str = Form(...), installation_id: str = Form(...), db: Session = Depends(get_db)):
    payload = crypto.verify_entitlement(entitlement)
    if not payload: raise HTTPException(401, "Invalid entitlement signature")
    if payload["expires_at"] < int(datetime.datetime.utcnow().timestamp()):
        raise HTTPException(401, "Entitlement expired — re-activate")
    if payload["installation_id"] != installation_id:
        raise HTTPException(401, "Device mismatch")
    lic = db.query(models.License).filter(models.License.id == payload["license_id"]).first()
    if not lic or lic.is_revoked or lic.is_suspended:
        raise HTTPException(403, "License revoked")
    dev = db.query(models.Device).filter(models.Device.id == payload["device_id"]).first()
    if not dev or dev.is_revoked:
        raise HTTPException(403, "Device revoked")
    payload["expires_at"] = int((datetime.datetime.utcnow() + datetime.timedelta(days=lic.grace_days)).timestamp())
    new_token = crypto.sign_entitlement(payload)
    return {"entitlement": new_token, "payload": payload}

# --- Admin (very small, HTTP Basic protected) ---
@app.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request, db: Session = Depends(get_db)):
    if not check_admin(request):
        return HTMLResponse('<h3>401 Unauthorized</h3>Use HTTP Basic auth with ADMIN_USER/ADMIN_PASS', status_code=401,
                            headers={"WWW-Authenticate": "Basic"})
    lic_count = db.query(func.count(models.License.id)).scalar()
    cust_count = db.query(func.count(models.Customer.id)).scalar()
    dev_count = db.query(func.count(models.Device.id)).scalar()
    return templates.TemplateResponse("admin.html", {"request": request, "lic_count": lic_count, "cust_count": cust_count, "dev_count": dev_count,
                                                     "licenses": db.query(models.License).all()[:50],
                                                     "customers": db.query(models.Customer).all()[:50]})

@app.post("/admin/license/create")
def admin_create_license(customer_name: str = Form(...), max_devices: int = Form(1), days: int = Form(365),
                         db: Session = Depends(get_db)):
    cust = models.Customer(name=customer_name)
    db.add(cust); db.commit(); db.refresh(cust)
    lic = models.License(customer_id=cust.id, max_devices=max_devices,
                         expires_at=datetime.datetime.utcnow() + datetime.timedelta(days=days) if days else None)
    db.add(lic); db.commit()
    return RedirectResponse("/admin", status_code=303)
