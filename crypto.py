"""
crypto.py - Ed25519 signing for Sivanta license server.

Spec:
- Private key MUST load from env var ED25519_PRIVATE_KEY_PEM (PEM string),
  fallback to server/private_key.pem for local dev only.
- Never log private key, never return it, never commit it.
- Signing: Ed25519, canonical JSON sorted keys, compact separators, UTF-8,
  final token SIVANTA1.<base64url(payload)>.<base64url(signature)>
- Startup verification: derive public from private, compare to server/public_key.pem,
  also optionally compare to SurveyGPS customer APK public key, log fingerprint,
  fail if mismatch (do not rotate automatically).
"""
import os
import base64
import json
import hashlib
import logging
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

logger = logging.getLogger(__name__)

# Paths - never log these contents
PRIVATE_KEY_PATH = Path(__file__).parent / "private_key.pem"
PUBLIC_KEY_PATH = Path(__file__).parent / "public_key.pem"
# Allow override via env for flexibility, but default to local files
CUSTOMER_PUBLIC_KEY_PATH = Path(__file__).parent.parent.parent / "SurveyGPS" / "app" / "src" / "main" / "assets" / "public_key.pem"

def _get_env_private_pem() -> bytes | None:
    """Load PEM bytes from ED25519_PRIVATE_KEY_PEM env var if present."""
    pem_str = os.getenv("ED25519_PRIVATE_KEY_PEM")
    if not pem_str:
        return None
    # Handle escaped newlines from Render / env injection (literal \n)
    pem_str = pem_str.strip()
    if "\\n" in pem_str and "-----BEGIN" in pem_str:
        pem_str = pem_str.replace("\\n", "\n")
    # Also handle case where env has quotes
    if pem_str.startswith("'") and pem_str.endswith("'"):
        pem_str = pem_str[1:-1]
    if pem_str.startswith('"') and pem_str.endswith('"'):
        pem_str = pem_str[1:-1]
    return pem_str.encode("utf-8")

def _load_private_key():
    pem_data = _get_env_private_pem()
    source = "ED25519_PRIVATE_KEY_PEM env var"
    if pem_data is None:
        if PRIVATE_KEY_PATH.exists():
            with open(PRIVATE_KEY_PATH, "rb") as f:
                pem_data = f.read()
            source = f"fallback file {PRIVATE_KEY_PATH}"
            logger.info("Loaded private key from local fallback file for dev only")
        else:
            # Fail safely - do not generate fake key
            raise RuntimeError(
                "ED25519_PRIVATE_KEY_PEM missing and no private_key.pem found. "
                "Set ED25519_PRIVATE_KEY_PEM env var in production. Refusing to generate fake key."
            )
    else:
        logger.info("Loaded private key from ED25519_PRIVATE_KEY_PEM env var")

    try:
        priv = serialization.load_pem_private_key(pem_data, password=None)
        if not isinstance(priv, ed25519.Ed25519PrivateKey):
            raise ValueError("Private key is not Ed25519")
        # Never log pem_data
        logger.debug("Private key loaded successfully from %s (type Ed25519)", source)
        return priv
    except Exception as e:
        # Never log private key material
        raise RuntimeError(f"Failed to load Ed25519 private key: {e}") from e

def _load_public_key_from_file(path: Path):
    if not path.exists():
        return None
    with open(path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
        return pub
    return None

# Lazy singletons - do not init at import to allow env to be set in tests
_priv = None
_pub = None

def get_private_key():
    global _priv
    if _priv is None:
        _priv = _load_private_key()
    return _priv

def get_public_key():
    """Return public key derived from private key (primary) or file fallback."""
    global _pub
    if _pub is not None:
        return _pub
    # Try derive from private first (authoritative)
    try:
        priv = get_private_key()
        _pub = priv.public_key()
        return _pub
    except Exception:
        pass
    # Fallback to public_key.pem file
    if PUBLIC_KEY_PATH.exists():
        with open(PUBLIC_KEY_PATH, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
            _pub = pub
            return _pub
    raise RuntimeError("Public key not available (no private to derive, no public_key.pem)")

def get_public_key_pem() -> str:
    """Return PEM string for public key (derived from private if possible)."""
    # Prefer derived from private to guarantee match; fallback to file
    try:
        pub = get_public_key()
        pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        return pem
    except Exception:
        if PUBLIC_KEY_PATH.exists():
            return PUBLIC_KEY_PATH.read_text(encoding="utf-8")
        raise RuntimeError("Public key not available")

def get_public_key_fingerprint(pub=None) -> str:
    """SHA256 fingerprint of DER SubjectPublicKeyInfo (hex, no colons)."""
    if pub is None:
        pub = get_public_key()
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()

def verify_key_match_on_startup() -> dict:
    """
    Verify public/private match on startup.
    - Derives public from private
    - Compares to server/public_key.pem if exists
    - Optionally compares to SurveyGPS customer APK public key
    - Logs fingerprint
    - Fails (raises) if server public_key.pem exists and mismatches
    Returns dict with verification result for summary.
    """
    result = {
        "derived_fingerprint": None,
        "server_pub_match": None,
        "server_pub_path": str(PUBLIC_KEY_PATH),
        "customer_pub_match": None,
        "customer_pub_path": str(CUSTOMER_PUBLIC_KEY_PATH),
        "checks_passed": False,
    }
    try:
        priv = get_private_key()
    except RuntimeError as e:
        logger.error("Startup key check failed: private key not available: %s", e)
        raise

    derived_pub = priv.public_key()
    derived_pem = derived_pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8").strip()
    derived_fp = get_public_key_fingerprint(derived_pub)
    result["derived_fingerprint"] = derived_fp
    logger.info("Ed25519 public key fingerprint (SHA256 DER): %s", derived_fp)

    # Check server public_key.pem
    if PUBLIC_KEY_PATH.exists():
        server_pem = PUBLIC_KEY_PATH.read_text(encoding="utf-8").strip()
        server_pub = serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
        server_fp = get_public_key_fingerprint(server_pub)
        match = (server_pem == derived_pem) and (server_fp == derived_fp)
        result["server_pub_match"] = match
        result["server_fingerprint"] = server_fp
        if match:
            logger.info("Startup check: server public_key.pem matches derived public key (fingerprint %s)", derived_fp)
        else:
            logger.error(
                "Startup check FAILED: server public_key.pem does NOT match derived public key! "
                "derived fp=%s server fp=%s . Refusing to auto-rotate. Manual intervention required.",
                derived_fp, server_fp
            )
            raise RuntimeError(
                f"Public/private key mismatch: server/public_key.pem fingerprint {server_fp} "
                f"does not match derived from private key {derived_fp}. "
                "Do not rotate automatically. Fix private key or public_key.pem to match."
            )
    else:
        logger.warning("Startup check: server/public_key.pem not found - will serve derived public key. Create file from derived PEM if needed.")
        result["server_pub_match"] = None

    # Check customer APK public key (report only, never overwrite)
    if CUSTOMER_PUBLIC_KEY_PATH.exists():
        try:
            customer_pem = CUSTOMER_PUBLIC_KEY_PATH.read_text(encoding="utf-8").strip()
            customer_pub = serialization.load_pem_public_key(CUSTOMER_PUBLIC_KEY_PATH.read_bytes())
            customer_fp = get_public_key_fingerprint(customer_pub)
            match = (customer_pem == derived_pem) and (customer_fp == derived_fp)
            result["customer_pub_match"] = match
            result["customer_fingerprint"] = customer_fp
            if match:
                logger.info("Startup check: SurveyGPS customer public_key.pem MATCHES derived key (fingerprint %s)", derived_fp)
            else:
                logger.error(
                    "Startup check REPORT: SurveyGPS/app/src/main/assets/public_key.pem does NOT match server private key! "
                    "derived fp=%s customer fp=%s. NOT overwriting customer key - manual alignment required.",
                    derived_fp, customer_fp
                )
                # Do not raise for customer mismatch - just report per spec point 8
                # But include in result so caller can report
            # Per spec: If mismatch, report but do not overwrite customer public key.
        except Exception as e:
            logger.warning("Could not check customer public key at %s: %s", CUSTOMER_PUBLIC_KEY_PATH, e)
            result["customer_pub_match"] = None
    else:
        logger.info("Customer public key not found at %s - skipping cross-check", CUSTOMER_PUBLIC_KEY_PATH)
        result["customer_pub_match"] = None

    result["checks_passed"] = True
    return result

def canonical_json(payload: dict) -> bytes:
    """Sorted keys, compact separators, UTF-8, ensure_ascii False per spec."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def b64url_decode(s: str) -> bytes:
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sign_payload(payload: dict) -> str:
    """Sign canonical payload, return SIVANTA1.<payload>.<sig>"""
    data = canonical_json(payload)
    priv = get_private_key()
    sig = priv.sign(data)
    return f"SIVANTA1.{b64url_encode(data)}.{b64url_encode(sig)}"

def verify_token(token: str) -> dict | None:
    try:
        parts = token.strip().split(".")
        if len(parts) != 3 or parts[0] != "SIVANTA1":
            return None
        b64_data, b64_sig = parts[1], parts[2]
        if not b64_data or not b64_sig:
            return None
        data = b64url_decode(b64_data)
        sig = b64url_decode(b64_sig)
        pub = get_public_key()
        pub.verify(sig, data)
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None
