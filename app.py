import os
import json
import time
import base64
import hmac
import hashlib
import logging
import io
import random
from pathlib import Path

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

# Shopify webhook verification
SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_WEBHOOK_SECRET", "")
SHOPIFY_SHOP = os.getenv("SHOPIFY_SHOP", "").strip()

# Shopify Admin API (for writing download link to order)
SHOPIFY_ADMIN_TOKEN = os.getenv("SHOPIFY_ADMIN_TOKEN", "").strip()
SHOPIFY_API_VERSION = os.getenv("SHOPIFY_API_VERSION", "2024-07").strip()

# Optional strict shop lock
STRICT_SHOP_LOCK = os.getenv("STRICT_SHOP_LOCK", "0").strip() == "1"

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
# Shopify Admin API helper
# =========================================================
def add_crest_url_to_order(order_id: str, crest_url: str) -> None:
    if not (SHOPIFY_SHOP and SHOPIFY_ADMIN_TOKEN):
        raise RuntimeError("Missing Shopify Admin API configuration")

    url = f"https://{SHOPIFY_SHOP}/admin/api/{SHOPIFY_API_VERSION}/orders/{order_id}.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
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

    raise RuntimeError("Unable to generate unique crest")


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

    payload = json.loads(raw.decode("utf-8"))
    order_id = payload.get("id")

    try:
        png_bytes = generate_crest_png_bytes()
        object_key = f"crests/order_{order_id}.png"
        crest_url = upload_png_to_r2(png_bytes, object_key)

        add_crest_url_to_order(str(order_id), crest_url)

        log.info("Crest generated for order %s", order_id)
        return jsonify({"ok": True}), 200

    except Exception as e:
        log.exception("Processing failed: %s", str(e))
        return jsonify({"ok": True, "error": "Logged"}), 200


# =========================================================
# Local dev
# =========================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
