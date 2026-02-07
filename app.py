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

# ============================================================
# ENV VARS (Render)
# ============================================================
SHOPIFY_SHOP = os.getenv("SHOPIFY_SHOP", "").strip()  # e.g. "cultofcustoms.myshopify.com" (fallback)
SHOPIFY_CLIENT_ID = os.getenv("SHOPIFY_CLIENT_ID", "").strip()
SHOPIFY_CLIENT_SECRET = os.getenv("SHOPIFY_CLIENT_SECRET", "").strip()
SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_WEBHOOK_SECRET", "").strip()
SHOPIFY_API_VERSION = os.getenv("SHOPIFY_API_VERSION", "2026-01").strip()

R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "").strip()
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "").strip()
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID", "").strip()
R2_BUCKET = os.getenv("R2_BUCKET", "").strip()
R2_PUBLIC_BASE_URL = os.getenv("R2_PUBLIC_BASE_URL", "").strip().rstrip("/")  # e.g. "https://pub-xxxx.r2.dev"


# ============================================================
# ENV CHECKS
# ============================================================
def _require_env() -> None:
    missing = []
    for k in [
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

    # SHOPIFY_SHOP is optional (we prefer header shop domain), but allow fallback
    if not os.getenv("SHOPIFY_SHOP"):
        # don't fail hard; we'll derive from webhook header
        pass

    if missing:
        raise RuntimeError(f"Missing env vars: {', '.join(missing)}")


# ============================================================
# SHOPIFY WEBHOOK SIGNATURE
# ============================================================
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


# ============================================================
# SHOPIFY AUTH: CLIENT CREDENTIALS TOKEN (CACHED)
# ============================================================
_token_cache_by_shop: Dict[str, Dict[str, Any]] = {}


def get_shopify_access_token(shop: str) -> str:
    """
    Gets an access token via client credentials grant, cached in-memory per shop.
    """
    if not shop:
        raise RuntimeError("Missing shop domain for token request")

    now = int(time.time())
    cache = _token_cache_by_shop.setdefault(shop, {"access_token": None, "expires_at": 0})

    if cache["access_token"] and now < int(cache["expires_at"]) - 60:
        return cache["access_token"]

    url = f"https://{shop}/admin/oauth/access_token"
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

    cache["access_token"] = data["access_token"]
    cache["expires_at"] = now + int(data.get("expires_in", 86399))
    return cache["access_token"]


def shopify_graphql(shop: str, api_version: str, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    POST GraphQL to Shopify Admin API using the cached client-credentials token.
    Retries once on 401 by clearing the cache.
    """
    token = get_shopify_access_token(shop)
    url = f"https://{shop}/admin/api/{api_version}/graphql.json"
    payload = {"query": query, "variables": variables or {}}
    headers = {"Content-Type": "application/json", "X-Shopify-Access-Token": token}

    r = requests.post(url, headers=headers, json=payload, timeout=30)

    if r.status_code == 401:
        # token invalid/expired; retry once
        _token_cache_by_shop[shop]["access_token"] = None
        token = get_shopify_access_token(shop)
        headers["X-Shopify-Access-Token"] = token
        r = requests.post(url, headers=headers, json=payload, timeout=30)

    r.raise_for_status()
    data = r.json()

    if "errors" in data and data["errors"]:
        raise RuntimeError(f"Shopify GraphQL errors: {data['errors']}")

    return data


# ============================================================
# NEW: RESOLVE ORDER GID FROM NUMERIC ID
# ============================================================
def get_order_gid_from_numeric_id(shop: str, order_id: str) -> str:
    """
    Webhooks often provide only numeric order id. Metafields need ownerId (GID).
    We query orders with 'id:{order_id}' to get the GraphQL GID.
    """
    query = """
    query GetOrder($query: String!) {
      orders(first: 1, query: $query) {
        edges {
          node {
            id
            name
          }
        }
      }
    }
    """
    variables = {"query": f"id:{order_id}"}

    data = shopify_graphql(shop, SHOPIFY_API_VERSION, query, variables)
    edges = data.get("data", {}).get("orders", {}).get("edges", [])

    if not edges:
        raise RuntimeError(f"Order {order_id} not found in shop {shop}")

    return edges[0]["node"]["id"]


# ============================================================
# R2 (S3-COMPAT)
# ============================================================
def make_r2_client():
    if not (R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY and R2_ACCOUNT_ID):
        raise RuntimeError("Missing R2 credentials")

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


# ============================================================
# ORDER ID HELPERS
# ============================================================
def extract_order_id(payload: Dict[str, Any]) -> str:
    """
    Prefer numeric 'id' if present. Else try to parse digits from admin_graphql_api_id.
    """
    if "id" in payload:
        return str(payload["id"])

    gid = payload.get("admin_graphql_api_id", "")
    m = re.search(r"(\d+)$", gid)
    if m:
        return m.group(1)

    raise ValueError("Could not extract order id from webhook payload")


# ============================================================
# CREST PNG GENERATOR (PLACEHOLDER)
# ============================================================
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


# ============================================================
# WRITE METAFIELD
# ============================================================
def write_order_metafield(shop: str, order_gid: str, crest_url: str) -> None:
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

    data = shopify_graphql(shop, SHOPIFY_API_VERSION, mutation, variables)
    errs = data.get("data", {}).get("metafieldsSet", {}).get("userErrors", [])
    if errs:
        raise RuntimeError(f"metafieldsSet userErrors: {errs}")


# ============================================================
# ROUTES
# ============================================================
@app.get("/")
def home():
    return jsonify({"ok": True, "service": "cult-generator", "version": "v2-r2-metafield-gid-resolve"})


@app.get("/health")
def health():
    try:
        _require_env()
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

    # Prefer shop domain from webhook header; fallback to env
    shop = (request.headers.get("X-Shopify-Shop-Domain", "") or SHOPIFY_SHOP).strip()
    if not shop:
        abort(400, "Missing X-Shopify-Shop-Domain and SHOPIFY_SHOP env var")

    order_id = extract_order_id(payload)

    print("Webhook from shop:", shop)
    print("Numeric order id:", order_id)

    # 1) Generate PNG
    png_bytes = generate_crest_png(order_id)

    # 2) Upload to R2
    object_key = f"crest_{order_id}.png"
    crest_url = upload_png_to_r2(png_bytes, object_key)

    # 3) Resolve real Order GID, then write metafield
    order_gid = get_order_gid_from_numeric_id(shop, order_id)
    print("Resolved order GID:", order_gid)

    write_order_metafield(shop, order_gid, crest_url)

    print(f"SUCCESS: crest written to order {order_id}")
    print(f"Uploaded to R2: {crest_url}")

    return jsonify({"ok": True, "shop": shop, "order_id": order_id, "order_gid": order_gid, "crest_url": crest_url})


@app.get("/crest/<order_id>.png")
def crest_redirect(order_id: str):
    url = f"{R2_PUBLIC_BASE_URL}/crest_{order_id}.png"
    return redirect(url, code=302)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
