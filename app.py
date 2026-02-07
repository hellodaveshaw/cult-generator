import base64
import hashlib
import hmac
import io
import json
import os
import re
import time
from typing import Any, Dict, Optional

import boto3
import requests
from botocore.config import Config
from flask import Flask, abort, jsonify, redirect, request
from PIL import Image, ImageDraw

app = Flask(__name__)

# ----------------------------
# Env vars (Render)
# ----------------------------
SHOPIFY_SHOP = os.getenv("SHOPIFY_SHOP", "").strip()  # e.g. "cultofcustoms.myshopify.com"
SHOPIFY_CLIENT_ID = os.getenv("SHOPIFY_CLIENT_ID", "").strip()
SHOPIFY_CLIENT_SECRET = os.getenv("SHOPIFY_CLIENT_SECRET", "").strip()
SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_WEBHOOK_SECRET", "").strip()
SHOPIFY_API_VERSION = os.getenv("SHOPIFY_API_VERSION", "2024-10").strip()

R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "").strip()
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "").strip()
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID", "").strip()
R2_BUCKET = os.getenv("R2_BUCKET", "").strip()
R2_PUBLIC_BASE_URL = os.getenv("R2_PUBLIC_BASE_URL", "").strip().rstrip("/")


# ----------------------------
# Helpers
# ----------------------------
def _require_env() -> None:
    missing = []
    for k in [
        "SHOPIFY_SHOP",
        "SHOPIFY_CLIENT_ID",
        "SHOPIFY_CLIENT_SECRET",
        "SHOPIFY_WEBHOOK_SECRET",
        "SHOPIFY_API_VERSION",
        "R2_ACCESS_KEY_ID",
        "R2_SECRET_ACCESS_KEY",
        "R2_ACCOUNT_ID",
        "R2_BUCKET",
        "R2_PUBLIC_BASE_URL",
    ]:
        if not os.getenv(k):
            missing.append(k)
    if missing:
        raise RuntimeError(f"Missing env vars: {', '.join(missing)}")


def verify_shopify_webhook(raw_body: bytes, hmac_header: str) -> bool:
    """
    Shopify sends X-Shopify-Hmac-Sha256 = base64(HMAC_SHA256(secret, raw_body))
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


# ---- Shopify token via client credentials (cached) ----
_token_cache = {"access_token": None, "expires_at": 0}


def get_shopify_access_token() -> str:
    _require_env()

    now = int(time.time())
    if _token_cache["access_token"] and now < _token_cache["expires_at"] - 60:
        return _token_cache["access_token"]

    url = f"https://{SHOPIFY_SHOP}/admin/oauth/access_token"
    resp = requests.post(
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "client_credentials",
            "client_id": SHOPIFY_CLIENT_ID,
            "client_secret": SHOPIFY_CLIENT_SECRET,
        },
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json()

    _token_cache["access_token"] = data["access_token"]
    _token_cache["expires_at"] = now + int(data.get("expires_in", 86399))
    return _token_cache["access_token"]


def shopify_graphql(query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    token = get_shopify_access_token()
    url = f"https://{SHOPIFY_SHOP}/admin/api/{SHOPIFY_API_VERSION}/graphql.json"

    r = requests.post(
        url,
        json={"query": query, "variables": variables or {}},
        headers={
            "X-Shopify-Access-Token": token,
            "Content-Type": "application/json",
        },
        timeout=30,
    )

    # refresh once if 401
    if r.status_code == 401:
        _token_cache["access_token"] = None
        token = get_shopify_access_token()
        r = requests.post(
            url,
            json={"query": query, "variables": variables or {}},
            headers={
                "X-Shopify-Access-Token": token,
                "Content-Type": "application/json",
            },
            timeout=30,
        )

    r.raise_for_status()
    data = r.json()
    if "errors" in data and data["errors"]:
        raise RuntimeError(f"Shopify GraphQL errors: {data['errors']}")
    return data


# ---- R2 helpers ----
def make_r2_client():
    _require_env()
    endpoint_url = f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
    return boto3.client(
        "s3",
        region_name="auto",
        endpoint_url=endpoint_url,
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        config=Config(signature_version="s3v4"),
    )


def upload_png_to_r2(png_bytes: bytes, object_key: str) -> str:
    s3 = make_r2_client()
    s3.put_object(
        Bucket=R2_BUCKET,
        Key=object_key,
        Body=png_bytes,
        ContentType="image/png",
        CacheControl="public, max-age=31536000, immutable",
    )
    return f"{R2_PUBLIC_BASE_URL}/{object_key}"


# ---- Order extraction ----
def extract_order_id(payload: Dict[str, Any]) -> str:
    if "id" in payload:
        return str(payload["id"])
    gid = payload.get("admin_graphql_api_id", "")
    m = re.search(r"(\d+)$", gid)
    if m:
        return m.group(1)
    raise ValueError("Could not extract order id from webhook payload")


def extract_order_gid(payload: Dict[str, Any]) -> Optional[str]:
    gid = payload.get("admin_graphql_api_id")
    if isinstance(gid, str) and gid.startswith("gid://shopify/Order/"):
        return gid
    return None


# ---- Crest generator ----
def generate_crest_png(order_id: str) -> bytes:
    size = 1024
    img = Image.new("RGBA", (size, size), (0, 0, 0, 255))
    draw = ImageDraw.Draw(img)

    cx, cy = size // 2, size // 2
    w, h = 220, 260
    shield = [
        (cx - w, cy - h),
        (cx + w, cy - h),
        (cx + w, cy - 20),
        (cx, cy + h),
        (cx - w, cy - 20),
    ]
    draw.polygon(shield, outline=(255, 255, 255, 255), width=12)

    inner = [
        (cx - 70, cy - 40),
        (cx + 70, cy - 40),
        (cx + 40, cy + 10),
        (cx, cy + 90),
        (cx - 40, cy + 10),
    ]
    draw.polygon(inner, fill=(255, 215, 0, 255))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def write_order_metafield(order_gid: str, crest_url: str) -> None:
    mutation = """
    mutation SetCrestUrl($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields: $metafields) {
        metafields { id namespace key value }
        userErrors { field message }
      }
    }
    """
    variables = {
        "metafields": [
            {
                "ownerId": order_gid,
                "namespace": "cult",
                "key": "crest_url",
                "type": "single_line_text_field",
                "value": crest_url,
            }
        ]
    }

    data = shopify_graphql(mutation, variables)
    errs = data.get("data", {}).get("metafieldsSet", {}).get("userErrors", [])
    if errs:
        raise RuntimeError(f"metafieldsSet userErrors: {errs}")


# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def home():
    return jsonify({"ok": True, "service": "cult-generator", "version": "v3-client-credentials"})


@app.get("/health")
def health():
    try:
        _require_env()
        # also prove we can mint a token (doesn't leak it)
        _ = get_shopify_access_token()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.post("/webhook/order-paid")
def webhook_order_paid():
    raw = request.get_data(cache=False, as_text=False)
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not verify_shopify_webhook(raw, hmac_header):
        abort(401, "Invalid webhook signature")

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        abort(400, "Invalid JSON")

    order_id = extract_order_id(payload)
    order_gid = extract_order_gid(payload)

    png_bytes = generate_crest_png(order_id)

    object_key = f"crest_{order_id}.png"
    crest_url = upload_png_to_r2(png_bytes, object_key)

    if order_gid:
        write_order_metafield(order_gid, crest_url)

    return jsonify({"ok": True, "order_id": order_id, "crest_url": crest_url})


@app.get("/crest/<order_id>.png")
def crest_redirect(order_id: str):
    url = f"{R2_PUBLIC_BASE_URL}/crest_{order_id}.png"
    return redirect(url, code=302)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
