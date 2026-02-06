import os
import random
import base64
import hmac
import hashlib
from datetime import datetime

import requests
from flask import Flask, request, jsonify, send_from_directory
from PIL import Image, ImageOps

app = Flask(__name__)

# ----------------------------
# Paths
# ----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ASSETS_DIR = os.path.join(BASE_DIR, "assets")
SHIELD_DIR = os.path.join(ASSETS_DIR, "shields")
SIGIL_DIR = os.path.join(ASSETS_DIR, "sigils")

STATIC_DIR = os.path.join(BASE_DIR, "static")
GENERATED_DIR = os.path.join(STATIC_DIR, "generated")
os.makedirs(GENERATED_DIR, exist_ok=True)

# ----------------------------
# Shopify env config
# ----------------------------
SHOPIFY_STORE_DOMAIN = os.environ.get("SHOPIFY_STORE_DOMAIN", "").strip()  # e.g. "cultofcustoms.myshopify.com"
SHOPIFY_ADMIN_TOKEN = os.environ.get("SHOPIFY_ADMIN_TOKEN", "").strip()    # Admin API access token (custom app)
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2024-10").strip()
SHOPIFY_WEBHOOK_SECRET = os.environ.get("SHOPIFY_WEBHOOK_SECRET", "").strip()  # signing secret shown under Webhooks page

# ----------------------------
# Helpers
# ----------------------------
ALLOWED_EXTS = {".png", ".jpg", ".jpeg", ".webp"}


def list_image_files(folder_path: str) -> list[str]:
    """Return image filenames only, ignoring .gitkeep and hidden files."""
    if not os.path.isdir(folder_path):
        return []
    out = []
    for name in os.listdir(folder_path):
        if name.startswith("."):
            continue
        ext = os.path.splitext(name.lower())[1]
        if ext in ALLOWED_EXTS:
            out.append(name)
    return sorted(out)


def open_rgba(path: str) -> Image.Image:
    return Image.open(path).convert("RGBA")


def safe_host_url() -> str:
    """Ensures trailing slash."""
    url = request.host_url
    if not url.endswith("/"):
        url += "/"
    return url


def generate_crest(order_id: str) -> tuple[str, str]:
    """
    Creates a crest PNG and saves it in static/generated.
    Returns (absolute_file_path, filename).
    """
    shields = list_image_files(SHIELD_DIR)
    sigils = list_image_files(SIGIL_DIR)

    if not shields:
        raise RuntimeError(f"No shield images found in {SHIELD_DIR}")
    if not sigils:
        raise RuntimeError(f"No sigil images found in {SIGIL_DIR}")

    shield_file = random.choice(shields)
    sigil_file = random.choice(sigils)

    shield = open_rgba(os.path.join(SHIELD_DIR, shield_file))
    sigil = open_rgba(os.path.join(SIGIL_DIR, sigil_file))

    # 50/50 mirror (no rotation)
    if random.random() < 0.5:
        sigil = ImageOps.mirror(sigil)

    # Brand-ish palette (RGBA)
    palette = [
        (0, 0, 0, 255),          # black
        (255, 255, 0, 255),      # yellow
        (70, 170, 255, 255),     # light blue
        (40, 70, 160, 255),      # dark blue
        (245, 90, 40, 255),      # orange/red
        (120, 120, 120, 255),    # grey
        (255, 255, 255, 255),    # white
    ]

    sigil_colour = random.choice(palette)
    bg_colour = random.choice([c for c in palette if c != sigil_colour])

    # Recolour sigil via alpha mask
    alpha = sigil.split()[-1]
    coloured_sigil = Image.new("RGBA", sigil.size, sigil_colour)
    coloured_sigil.putalpha(alpha)

    # Optional coloured field behind shield
    background = Image.new("RGBA", shield.size, bg_colour)

    # Compose: background -> shield -> sigil
    canvas = Image.alpha_composite(background, shield)

    # Fit sigil inside shield
    max_w = int(shield.size[0] * 0.62)
    max_h = int(shield.size[1] * 0.62)
    coloured_sigil.thumbnail((max_w, max_h), Image.Resampling.LANCZOS)

    x = (canvas.size[0] - coloured_sigil.size[0]) // 2
    y = (canvas.size[1] - coloured_sigil.size[1]) // 2
    canvas.paste(coloured_sigil, (x, y), coloured_sigil)

    filename = f"crest_{order_id}.png"
    output_path = os.path.join(GENERATED_DIR, filename)
    canvas.save(output_path, "PNG")

    return output_path, filename


def verify_shopify_webhook(raw_body: bytes, hmac_header: str, secret: str) -> bool:
    """
    Shopify sends HMAC in header 'X-Shopify-Hmac-Sha256' which is base64(HMAC_SHA256(secret, raw_body))
    """
    if not secret:
        return False
    if not hmac_header:
        return False

    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).digest()
    computed = base64.b64encode(digest).decode("utf-8")

    # constant-time compare
    return hmac.compare_digest(computed, hmac_header.strip())


def shopify_request(method: str, path: str, json_body: dict | None = None) -> requests.Response:
    """
    Minimal Admin REST call helper.
    path example: "/admin/api/2024-10/orders/123.json"
    """
    if not SHOPIFY_STORE_DOMAIN or not SHOPIFY_ADMIN_TOKEN:
        raise RuntimeError("Missing SHOPIFY_STORE_DOMAIN or SHOPIFY_ADMIN_TOKEN")

    url = f"https://{SHOPIFY_STORE_DOMAIN}{path}"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    return requests.request(method=method, url=url, headers=headers, json=json_body, timeout=20)


def try_add_crest_link_to_order(order_id: str, preview_url: str, download_url: str) -> None:
    """
    Optional nicety: write links onto the Shopify order as a note.
    If it fails, we don't break the webhook (webhooks should be fast + resilient).
    """
    if not SHOPIFY_STORE_DOMAIN or not SHOPIFY_ADMIN_TOKEN:
        # Not configured, just skip.
        return

    note = (
        "Cult Crest generated:\n"
        f"- Preview: {preview_url}\n"
        f"- Download: {download_url}\n"
        f"- File: crest_{order_id}.png\n"
    )

    path = f"/admin/api/{SHOPIFY_API_VERSION}/orders/{order_id}.json"
    payload = {"order": {"id": int(order_id), "note": note}}

    try:
        resp = shopify_request("PUT", path, json_body=payload)
        if resp.status_code >= 400:
            # Log but don't explode the webhook
            app.logger.warning("Shopify order update failed: %s %s", resp.status_code, resp.text[:500])
    except Exception as e:
        app.logger.warning("Shopify order update exception: %s", str(e))


# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def home():
    # Render health checks hit this; returning 200 avoids noisy logs
    return "OK", 200


@app.get("/routes")
def routes():
    return (
        "/\n"
        "/routes\n"
        "/new-order\n"
        "/webhook/order-paid\n"
        "/preview/<filename>\n"
        "/download/<filename>\n"
        "/static/\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.post("/new-order")
def new_order():
    """
    Manual test endpoint (your curl command).
    """
    data = request.get_json(silent=True) or {}
    order_id = str(data.get("id") or "").strip()
    if not order_id:
        return jsonify({"status": "error", "message": "Missing id"}), 400

    try:
        _, filename = generate_crest(order_id)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    base = safe_host_url()
    preview_url = f"{base}preview/{filename}"
    download_url = f"{base}download/{filename}"

    return jsonify(
        {
            "status": "generated",
            "file": filename,
            "preview_url": preview_url,
            "download_url": download_url,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
    )


@app.post("/webhook/order-paid")
def webhook_order_paid():
    """
    Shopify "Order payment" / "Orders paid" webhook target.
    Must return 200 quickly. Verifies HMAC signature.
    """
    raw = request.get_data(cache=False, as_text=False)
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not verify_shopify_webhook(raw, hmac_header, SHOPIFY_WEBHOOK_SECRET):
        return jsonify({"status": "unauthorized"}), 401

    payload = request.get_json(silent=True) or {}

    # Shopify order payload usually includes: id (numeric), name, order_number, etc.
    order_id = str(payload.get("id") or "").strip()
    if not order_id:
        # still 200 so Shopify doesn't keep retrying forever for a payload we can't use
        return jsonify({"status": "ignored", "reason": "missing order id"}), 200

    try:
        _, filename = generate_crest(order_id)
        base = safe_host_url()
        preview_url = f"{base}preview/{filename}"
        download_url = f"{base}download/{filename}"

        # Optional: write links back to the order note (requires Admin token + store domain)
        try_add_crest_link_to_order(order_id, preview_url, download_url)

        app.logger.info("Generated crest for order %s -> %s", order_id, filename)
        return jsonify({"status": "generated", "order_id": order_id, "file": filename}), 200

    except Exception as e:
        # Return 200 so Shopify doesn't hammer retries, but log the failure
        app.logger.exception("Crest generation failed for order %s: %s", order_id, str(e))
        return jsonify({"status": "error", "order_id": order_id, "message": str(e)}), 200


@app.get("/preview/<path:filename>")
def preview(filename):
    # Inline display
    return send_from_directory(GENERATED_DIR, filename, as_attachment=False)


@app.get("/download/<path:filename>")
def download(filename):
    # Forces download
    return send_from_directory(GENERATED_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    # Local dev only; Render runs gunicorn
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
