import os
import json
import time
import base64
import hmac
import hashlib
import logging
from typing import Optional

from flask import Flask, request, abort, jsonify
import boto3
from botocore.client import Config


# ----------------------------
# App + logging
# ----------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("cult-generator")


# ----------------------------
# Env vars
# ----------------------------
# Shopify
SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_WEBHOOK_SECRET", "")
# Optional: if you want to hard-lock to one shop, set SHOPIFY_SHOP to e.g. cultofcustoms.myshopify.com
SHOPIFY_SHOP = os.getenv("SHOPIFY_SHOP", "").strip()
# Optional: strict shop lock (off by default because header isn't always reliable)
STRICT_SHOP_LOCK = os.getenv("STRICT_SHOP_LOCK", "0").strip() == "1"

# R2 (S3-compatible)
R2_ENDPOINT_URL = os.getenv("R2_ENDPOINT_URL", "").strip()  # e.g. https://<accountid>.r2.cloudflarestorage.com
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "").strip()
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "").strip()
R2_BUCKET = os.getenv("R2_BUCKET", "").strip()

# Public URL base (optional). If you want public links returned, set:
# e.g. https://pub-<something>.r2.dev  OR your custom domain.
R2_PUBLIC_BASE_URL = os.getenv("R2_PUBLIC_BASE_URL", "").strip()


# ----------------------------
# Shopify webhook verification
# ----------------------------
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
    Optional hard lock to a single shop domain.
    This is OFF by default because the header isn't always present/consistent.
    """
    if not (STRICT_SHOP_LOCK and SHOPIFY_SHOP):
        return

    shop_from_header = (request.headers.get("X-Shopify-Shop-Domain") or "").strip()
    # Flask header lookup is already case-insensitive; no need for lowercased key.

    if shop_from_header and shop_from_header != SHOPIFY_SHOP:
        abort(401, f"Webhook shop mismatch: {shop_from_header}")


# ----------------------------
# R2 helpers
# ----------------------------
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
        raise RuntimeError(f"Missing R2 config env vars: {', '.join(missing)}")

    # Defensive: catch the exact problem you hit earlier
    if "<" in R2_ENDPOINT_URL or ">" in R2_ENDPOINT_URL:
        raise RuntimeError(f"R2_ENDPOINT_URL still contains placeholders: {R2_ENDPOINT_URL}")

    _r2_client = boto3.client(
        "s3",
        endpoint_url=R2_ENDPOINT_URL,
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        region_name="auto",
        config=Config(signature_version="s3v4"),
    )
    log.info("R2 client created. endpoint_url=%s bucket=%s", R2_ENDPOINT_URL, R2_BUCKET)
    return _r2_client


def upload_png_to_r2(png_bytes: bytes, object_key: str) -> str:
    s3 = make_r2_client()

    s3.put_object(
        Bucket=R2_BUCKET,
        Key=object_key,
        Body=png_bytes,
        ContentType="image/png",
        ACL="public-read",  # OK if bucket public access enabled. If not, remove.
        CacheControl="public, max-age=31536000, immutable",
    )

    if R2_PUBLIC_BASE_URL:
        return f"{R2_PUBLIC_BASE_URL.rstrip('/')}/{object_key.lstrip('/')}"
    # Fallback: S3-style URL (may not be publicly reachable depending on setup)
    return f"{R2_ENDPOINT_URL.rstrip('/')}/{R2_BUCKET}/{object_key.lstrip('/')}"


# ----------------------------
# Your crest generator (stub)
# Replace this with your real logic
# ----------------------------
def generate_crest_png_bytes(order_payload: dict) -> bytes:
    """
    Replace this with your actual image generator.
    Must return PNG bytes.
    """
    # If you already have code for this elsewhere in your file, paste it in here.
    # For now this is a placeholder to prevent crashes.
    raise NotImplementedError("Wire in your real crest generator here.")


# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def home():
    return "Cult generator is live 🎉", 200


@app.post("/webhook/order-paid")
def webhook_order_paid():
    # 1) Read raw body first
    raw = request.get_data(cache=False, as_text=False)
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    # 2) Verify signature
    if not verify_shopify_webhook(raw, hmac_header):
        # Shopify will retry on non-200, but 401 is correct for “nope”
        abort(401, "Invalid webhook signature")

    # 3) Optional shop lock (only after HMAC)
    maybe_enforce_shop_lock()

    # 4) Parse JSON
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        abort(400, "Invalid JSON")

    # 5) Process webhook — IMPORTANT:
    # Shopify retries if you fail. If generation/upload can be flaky,
    # you can return 200 quickly and do background processing elsewhere.
    # For now we do it inline.
    try:
        # --- CREATE YOUR OBJECT KEY ---
        # Use order id + timestamp to avoid collisions
        order_id = payload.get("id") or payload.get("order_id") or "unknown"
        object_key = f"crests/crest_{order_id}_{int(time.time())}.png"

        # --- GENERATE PNG ---
        png_bytes = generate_crest_png_bytes(payload)

        # --- UPLOAD TO R2 ---
        crest_url = upload_png_to_r2(png_bytes, object_key)

        log.info("Order paid webhook processed. order_id=%s url=%s", order_id, crest_url)
        return jsonify({"ok": True, "crest_url": crest_url}), 200

    except NotImplementedError as e:
        # Verified webhook, but your generator stub isn’t wired in.
        # Return 200 so Shopify stops retrying while you fix generator wiring.
        log.exception("Generator not wired: %s", str(e))
        return jsonify({"ok": True, "note": "Webhook verified; generator not wired yet"}), 200

    except Exception as e:
        # If you want Shopify to retry on errors, return 500.
        # If you want to avoid retry storms, return 200 and log the failure.
        log.exception("Webhook processing failed: %s", str(e))
        return jsonify({"ok": True, "note": "Webhook verified; processing failed (logged)"}), 200


if __name__ == "__main__":
    # Local dev
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
