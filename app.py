import os
import json
import time
import base64
import hmac
import hashlib
import logging
import io
import random
import secrets
from pathlib import Path
from urllib.parse import urlencode

from flask import Flask, request, abort, jsonify
import boto3
from botocore.client import Config
import requests
from PIL import Image, ImageOps, ImageEnhance


# =========================================================
# App + logging
# =========================================================
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("cult-generator")


# =========================================================
# Environment variables
# =========================================================

# Shopify webhook verification (HMAC header verification)
SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_WEBHOOK_SECRET", "").strip()

# Shop domain (used for /install auth URL and Admin API host)
SHOPIFY_SHOP = os.getenv("SHOPIFY_SHOP", "").strip()  # e.g. cultofcustoms.myshopify.com

# Optional strict shop lock (webhooks only)
STRICT_SHOP_LOCK = os.getenv("STRICT_SHOP_LOCK", "0").strip() == "1"

# OAuth (used once to mint an Admin API access token)
SHOPIFY_API_KEY = os.getenv("SHOPIFY_API_KEY", "").strip()          # Client ID
SHOPIFY_API_SECRET = os.getenv("SHOPIFY_API_SECRET", "").strip()    # Client Secret (often starts shpss_)
SHOPIFY_SCOPES = os.getenv("SHOPIFY_SCOPES", "read_orders,write_orders").strip()
SHOPIFY_REDIRECT_URI = os.getenv("SHOPIFY_REDIRECT_URI", "").strip()  # e.g. https://<service>/auth/callback

# Shopify API version used for Admin API calls
SHOPIFY_API_VERSION = os.getenv("SHOPIFY_API_VERSION", "2024-07").strip()

# Where we store OAuth access token (in R2)
SHOPIFY_TOKEN_R2_KEY = os.getenv(
    "SHOPIFY_TOKEN_R2_KEY",
    "secrets/shopify_admin_token.json"
).strip()

# Cloudflare R2 (S3 compatible)
R2_ENDPOINT_URL = os.getenv("R2_ENDPOINT_URL", "").strip()
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "").strip()
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "").strip()
R2_BUCKET = os.getenv("R2_BUCKET", "").strip()

# Public base URL for downloads
R2_PUBLIC_BASE_URL = os.getenv("R2_PUBLIC_BASE_URL", "").strip()


# =========================================================
# Shopify webhook verification
# =========================================================
def verify_shopify_webhook(raw_body: bytes, hmac_header: str) -> bool:
    """
    Shopify sends X-Shopify-Hmac-Sha256 which is:
    base64( HMAC_SHA256(secret, raw_body) )
    """
    if not SHOPIFY_WEBHOOK_SECRET:
        return False

    digest = hmac.new(
        SHOPIFY_WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).digest()

    computed = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(computed, hmac_header or "")


def maybe_enforce_shop_lock():
    """
    Optional hard lock to a single shop domain (webhooks only).
    Only applied after verifying webhook HMAC.
    """
    if not (STRICT_SHOP_LOCK and SHOPIFY_SHOP):
        return

    shop_from_header = (request.headers.get("X-Shopify-Shop-Domain") or "").strip()
    if shop_from_header and shop_from_header != SHOPIFY_SHOP:
        abort(401, "Webhook shop mismatch")


# =========================================================
# R2 client + helpers
# =========================================================
_r2_client = None


def make_r2_client():
    global _r2_client
    if _r2_client is not None:
        return _r2_client

    missing = [k for k, v in {
        "R2_ENDPOINT_URL": R2_ENDPOINT_URL,
        "R2_ACCESS_KEY_ID": R2_ACCESS_KEY_ID,
        "R2_SECRET_ACCESS_KEY": R2_SECRET_ACCESS_KEY,
        "R2_BUCKET": R2_BUCKET,
    }.items() if not v]

    if missing:
        raise RuntimeError(f"Missing R2 env vars: {', '.join(missing)}")

    if "<" in R2_ENDPOINT_URL or ">" in R2_ENDPOINT_URL:
        raise RuntimeError(f"R2_ENDPOINT_URL contains placeholders: {R2_ENDPOINT_URL}")

    _r2_client = boto3.client(
        "s3",
        endpoint_url=R2_ENDPOINT_URL,
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        region_name="auto",
        config=Config(signature_version="s3v4"),
    )
    return _r2_client


def upload_png_to_r2(png_bytes: bytes, object_key: str) -> str:
    s3 = make_r2_client()

    s3.put_object(
        Bucket=R2_BUCKET,
        Key=object_key,
        Body=png_bytes,
        ContentType="image/png",
        ACL="public-read",
        CacheControl="public, max-age=31536000, immutable",
    )

    if R2_PUBLIC_BASE_URL:
        return f"{R2_PUBLIC_BASE_URL.rstrip('/')}/{object_key.lstrip('/')}"
    return f"{R2_ENDPOINT_URL.rstrip('/')}/{R2_BUCKET}/{object_key.lstrip('/')}"


def r2_object_exists(object_key: str) -> bool:
    s3 = make_r2_client()
    try:
        s3.head_object(Bucket=R2_BUCKET, Key=object_key)
        return True
    except Exception:
        return False


def mark_unique_hash_used(hash_hex: str) -> bool:
    key = f"unique/{hash_hex}.txt"
    if r2_object_exists(key):
        return False

    s3 = make_r2_client()
    s3.put_object(Bucket=R2_BUCKET, Key=key, Body=b"1", ContentType="text/plain")
    return True


# =========================================================
# OAuth helpers (robust raw-query HMAC verification)
# =========================================================
def _shopify_oauth_hmac_is_valid_raw(query_string: bytes) -> bool:
    """
    Verify Shopify OAuth callback HMAC using the RAW query string to avoid
    any decoding/normalisation differences (e.g. '+' vs '%20').

    Algorithm:
      - Take query string as sent by Shopify
      - Remove 'hmac' and 'signature' parameters
      - Sort remaining parameters by key (lexicographically)
      - Join as 'key=value' pairs with '&'
      - Compare hex HMAC-SHA256(secret, message) to received hmac
    """
    if not SHOPIFY_API_SECRET:
        return False

    qs = query_string.decode("utf-8", errors="strict")
    if not qs:
        return False

    parts = qs.split("&")
    received_hmac = None
    kv_pairs = []

    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""

        if k == "hmac":
            received_hmac = v
            continue
        if k in ("signature",):
            continue

        kv_pairs.append((k, v))

    if not received_hmac:
        return False

    kv_pairs.sort(key=lambda x: x[0])
    message = "&".join([f"{k}={v}" for k, v in kv_pairs])

    digest = hmac.new(
        SHOPIFY_API_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(digest, received_hmac)


def _save_shopify_token_to_r2(token_payload: dict) -> None:
    s3 = make_r2_client()
    s3.put_object(
        Bucket=R2_BUCKET,
        Key=SHOPIFY_TOKEN_R2_KEY,
        Body=json.dumps(token_payload).encode("utf-8"),
        ContentType="application/json",
        CacheControl="no-store",
    )


def load_shopify_admin_token() -> str:
    tok = os.getenv("SHOPIFY_ADMIN_TOKEN", "").strip()
    if tok:
        return tok

    s3 = make_r2_client()
    try:
        obj = s3.get_object(Bucket=R2_BUCKET, Key=SHOPIFY_TOKEN_R2_KEY)
        data = obj["Body"].read().decode("utf-8")
        payload = json.loads(data)
        return (payload.get("access_token") or "").strip()
    except Exception:
        return ""


# =========================================================
# OAuth routes (run once)
# =========================================================
@app.get("/install")
def shopify_install():
    if not (SHOPIFY_API_KEY and SHOPIFY_REDIRECT_URI and SHOPIFY_SHOP):
        abort(500, "Missing SHOPIFY_API_KEY / SHOPIFY_REDIRECT_URI / SHOPIFY_SHOP")

    state = secrets.token_urlsafe(24)

    params = {
        "client_id": SHOPIFY_API_KEY,
        "scope": SHOPIFY_SCOPES,
        "redirect_uri": SHOPIFY_REDIRECT_URI,
        "state": state,
    }

    auth_url = f"https://{SHOPIFY_SHOP}/admin/oauth/authorize?{urlencode(params)}"

    resp = jsonify({"ok": True, "redirect_to": auth_url})
    resp.set_cookie(
        "shopify_oauth_state",
        state,
        max_age=600,
        secure=True,
        httponly=True,
        samesite="Lax",
    )
    return resp, 200


@app.get("/auth/callback")
def shopify_auth_callback():
    """
    OPTION A: no shop-match enforcement.
    We still enforce: state cookie + raw-query HMAC.
    """
    code = request.args.get("code", "")
    shop = request.args.get("shop", "")
    state = request.args.get("state", "")

    if not code or not shop or not state:
        abort(400, "Missing code/shop/state")

    expected_state = request.cookies.get("shopify_oauth_state", "")
    if not expected_state or not hmac.compare_digest(expected_state, state):
        abort(401, "Invalid OAuth state")

    # RAW query-string verification (fixes your current error)
    if not _shopify_oauth_hmac_is_valid_raw(request.query_string):
        abort(401, "Invalid OAuth HMAC")

    token_url = f"https://{shop}/admin/oauth/access_token"
    payload = {
        "client_id": SHOPIFY_API_KEY,
        "client_secret": SHOPIFY_API_SECRET,
        "code": code,
    }

    r = requests.post(token_url, json=payload, timeout=15)
    if r.status_code >= 300:
        abort(500, f"Token exchange failed: {r.status_code} {r.text}")

    token_payload = r.json()
    access_token = (token_payload.get("access_token") or "").strip()
    if not access_token:
        abort(500, "No access_token returned")

    _save_shopify_token_to_r2({
        "shop": shop,
        "access_token": access_token,
        "scopes": SHOPIFY_SCOPES,
        "saved_at": int(time.time()),
    })

    resp = jsonify({"ok": True, "message": "OAuth complete. Token saved to R2.", "shop": shop})
    resp.set_cookie("shopify_oauth_state", "", expires=0)
    return resp, 200


# =========================================================
# Shopify Admin API helper
# =========================================================
def add_crest_url_to_order(order_id: str, crest_url: str) -> None:
    token = load_shopify_admin_token()
    if not token:
        raise RuntimeError("No Shopify Admin token available. Run /install then approve OAuth first.")

    if not SHOPIFY_SHOP:
        raise RuntimeError("Missing SHOPIFY_SHOP")

    url = f"https://{SHOPIFY_SHOP}/admin/api/{SHOPIFY_API_VERSION}/orders/{order_id}.json"
    headers = {
        "X-Shopify-Access-Token": token,
        "Content-Type": "application/json",
    }

    payload = {
        "order": {
            "id": int(order_id),
            "note_attributes": [
                {"name": "Crest Download", "value": crest_url}
            ]
        }
    }

    r = requests.put(url, headers=headers, data=json.dumps(payload), timeout=15)
    if r.status_code >= 300:
        raise RuntimeError(f"Shopify update failed: {r.status_code} {r.text}")


# =========================================================
# Asset loading
# =========================================================
ASSETS_DIR = Path(__file__).parent / "assets"
SHIELDS_DIR = ASSETS_DIR / "shields"
SIGILS_DIR = ASSETS_DIR / "sigils"

_SHIELD_FILES = sorted(p for p in SHIELDS_DIR.glob("*.png") if p.is_file())
_SIGIL_FILES = sorted(p for p in SIGILS_DIR.glob("*.png") if p.is_file())


# =========================================================
# Image helpers (alpha tinting)
# =========================================================
def tint_from_alpha(img: Image.Image, rgb: tuple[int, int, int]) -> Image.Image:
    img = img.convert("RGBA")
    _, _, _, a = img.split()
    coloured = Image.new("RGBA", img.size, rgb + (255,))
    coloured.putalpha(a)
    return coloured


def composite_sigil_on_shield(shield: Image.Image, sigil: Image.Image, rng: random.Random) -> Image.Image:
    if rng.random() < 0.20:
        sigil = ImageOps.mirror(sigil)

    angle = rng.uniform(-3.0, 3.0)
    sigil = sigil.rotate(angle, resample=Image.Resampling.BICUBIC, expand=True)

    bw, bh = shield.size
    ow, oh = sigil.size

    target_w = int(bw * rng.uniform(0.66, 0.72))
    target_h = int(target_w * (oh / ow))
    sigil = sigil.resize((target_w, target_h), Image.Resampling.LANCZOS)

    x = (bw - target_w) // 2 + int(bw * rng.uniform(-0.01, 0.01))
    y = (bh - target_h) // 2 + int(bh * rng.uniform(-0.005, 0.02))

    out = shield.copy()
    out.alpha_composite(sigil, (x, y))
    return out


# =========================================================
# Crest generator (guaranteed unique)
# =========================================================
def generate_crest_png_bytes() -> bytes:
    if not _SHIELD_FILES:
        raise RuntimeError("No shield PNGs found in assets/shields")
    if not _SIGIL_FILES:
        raise RuntimeError("No sigil PNGs found in assets/sigils")

    rng = random.Random()
    palettes = [
        {"shield": (205, 170, 80), "sigil": (15, 15, 15)},
        {"shield": (30, 30, 30), "sigil": (235, 235, 235)},
    ]

    for _ in range(40):
        shield_path = rng.choice(_SHIELD_FILES)
        sigil_path = rng.choice(_SIGIL_FILES)
        palette = rng.choice(palettes)

        shield = tint_from_alpha(Image.open(shield_path), palette["shield"])
        sigil = tint_from_alpha(Image.open(sigil_path), palette["sigil"])

        crest = composite_sigil_on_shield(shield, sigil, rng)
        crest = ImageEnhance.Contrast(crest).enhance(rng.uniform(0.99, 1.05))

        buf = io.BytesIO()
        crest.save(buf, format="PNG", optimize=True)
        png_bytes = buf.getvalue()

        hash_hex = hashlib.sha256(png_bytes).hexdigest()
        if mark_unique_hash_used(hash_hex):
            return png_bytes

    raise RuntimeError("Unable to generate unique crest after multiple attempts")


# =========================================================
# Routes
# =========================================================
@app.get("/")
def home():
    return "Cult generator live", 200


@app.post("/webhook/order-paid")
def webhook_order_paid():
    raw = request.get_data(cache=False, as_text=False)
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not verify_shopify_webhook(raw, hmac_header):
        abort(401, "Invalid webhook signature")

    maybe_enforce_shop_lock()

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        abort(400, "Invalid JSON")

    order_id = payload.get("id") or payload.get("order_id")
    if not order_id:
        log.warning("Webhook received but no order id found in payload")
        return jsonify({"ok": True, "note": "No order id in payload"}), 200

    try:
        png_bytes = generate_crest_png_bytes()
        object_key = f"crests/order_{order_id}.png"
        crest_url = upload_png_to_r2(png_bytes, object_key)

        add_crest_url_to_order(str(order_id), crest_url)

        log.info("Crest generated and attached to order %s", order_id)
        return jsonify({"ok": True, "order_id": order_id, "crest_url": crest_url}), 200

    except Exception as e:
        log.exception("Webhook processing failed for order %s: %s", str(order_id), str(e))
        return jsonify({"ok": True, "note": "Webhook verified; processing failed (logged)"}), 200


# =========================================================
# Local dev
# =========================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
