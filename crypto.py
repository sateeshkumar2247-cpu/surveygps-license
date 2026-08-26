import os
import base64
import json
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "./private_key.pem")
PUBLIC_KEY_PATH  = os.getenv("PUBLIC_KEY_PATH",  "./public_key.pem")

def load_or_create_keys():
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "rb") as f: priv = serialization.load_pem_private_key(f.read(), None)
        with open(PUBLIC_KEY_PATH, "rb") as f: pub  = serialization.load_pem_public_key(f.read())
        return priv, pub
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"[keys] Generated new Ed25519 keypair")
    return priv, pub

_priv, _pub = load_or_create_keys()

def sign_entitlement(payload: dict) -> str:
    """payload -> base64(payload).base64(signature)"""
    data = json.dumps(payload, sort_keys=True, separators=(",",":")).encode()
    sig = _priv.sign(data)
    return base64.urlsafe_b64encode(data).decode().rstrip("=") + "." + base64.urlsafe_b64encode(sig).decode().rstrip("=")

def verify_entitlement(token: str) -> dict | None:
    try:
        b64_data, b64_sig = token.split(".")
        # pad base64
        b64_data += "=" * (-len(b64_data) % 4)
        b64_sig  += "=" * (-len(b64_sig) % 4)
        data = base64.urlsafe_b64decode(b64_data)
        sig  = base64.urlsafe_b64decode(b64_sig)
        _pub.verify(sig, data)
        return json.loads(data)
    except Exception:
        return None

def get_public_key_pem() -> str:
    return open(PUBLIC_KEY_PATH).read()
