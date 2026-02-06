import os
import random
import hmac
import hashlib
import base64
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

# Generated output is served from /static/generated/...
STATIC_DIR = os.path.join(BASE_DIR, "static")
GENERATED_DIR = os.path.join(STATIC_DIR, "generated")

os.makedirs(GENERATED_DIR, exist_ok=True)

# ----------------------------
# Config (from Render env vars)
# ----------------------------
SHOPIFY_STORE_DOMAIN = os.environ.get("SHOPIFY_STORE_DOMAIN", "").strip()  # e.g. cultofcustoms.myshopify.com
SHOPIFY_ADMIN_TOKEN = os.environ.get("SHOPIFY_ADMIN_TOKEN", "").strip()    # Admin API access token
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2024-10").strip()
SHOPIFY_WEBHOOK_SECRET = os.environ.get("SHOPIFY_WEBHOOK_SECRET", "").strip()  # webhook signing secret

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
    """
    Ensures trailing slash.
    """
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

    # 50/50 mirror
    if random.random() < 0.5:
        sigil = ImageOps.mirror(sigil)

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

    # recolour sigil via alpha mask
    alpha = sigil.split()[-1]
    coloured_sigil = Image.new("RGBA", sigil.size, sigil_colour)
    coloured_sigil.putalpha(alpha)

    # background field
    background = Image.new("RGBA", shield.size, bg_colour)

    # compose
    canvas = Image.alpha_composite(background, shield)

    # scale sigil into shield
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


# ----------------------------
# Shopify helpers
# ----------------------------
def verify_shopify_webhook(req) -> bool:
    """
    Verifies X-Shopify-Hmac-Sha256 signature using SHOPIFY_WEBHOOK_SECRET.
    """
    if not SHOPIFY_WEBHOOK_SECRET:
        # If you haven't set it, fail closed.
        return False

    hmac_header = req.headers.get("X-Shopify-Hmac-Sha256", "")
    raw_body = req.get_data()  # bytes

    digest = hmac.new(
        SHOPIFY_WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).digest()

    computed = base64.b64encode(digest).decode("utf-8")

    # constant-time compare
    return hmac.compare_digest(computed, hmac_header)


def add_download_link_to_order(order_id: str, download_url: str) -> tuple[bool, str]:
    """
    Writes the crest download link into the Shopify order NOTE.

    Returns (ok, message).
    """
    if not SHOPIFY_STORE_DOMAIN or not SHOPIFY_ADMIN_TOKEN:
        return False, "Missing SHOPIFY_STORE_DOMAIN or SHOPIFY_ADMIN_TOKEN env vars"

    url = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/orders/{order_id}.json"

    note_text = (
        "Cult Crest Generator\n"
        "Download your crest:\n"
        f"{download_url}\n"
    )

    payload = {
        "order": {
            "id": int(order_id),
            "note": note_text
        }
    }

    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
        "Content-Type": "application/json",
    }

    r = requests.put(url, json=payload, headers=headers, timeout=20)

    if 200 <= r.status_code < 300:
        return True, "Order updated"
    return False, f"Shopify update failed: {r.status_code} {r.text}"


# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def home():
    return (
        "Cult Generator is running. Try GET /routes or POST /new-order",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


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


# Manual/test endpoint (your curl tests)
@app.post("/new-order")
def new_order():
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


# Shopify webhook endpoint (Order paid)
@app.post("/webhook/order-paid")
def webhook_order_paid():
    # 1) Verify webhook signature (security)
    if not verify_shopify_webhook(request):
        return jsonify({"status": "error", "message": "Invalid webhook signature"}), 401

    # 2) Parse payload
    data = request.get_json(silent=True) or {}
    order_id = str(data.get("id") or "").strip()
    if not order_id:
        return jsonify({"status": "error", "message": "Missing order id in webhook"}), 400

    # 3) Generate crest
    try:
        _, filename = generate_crest(order_id)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Generate failed: {e}"}), 500

    # 4) Build links
    base = safe_host_url()
    preview_url = f"{base}preview/{filename}"
    download_url = f"{base}download/{filename}"

    # 5) Write link onto Shopify order note
    ok, msg = add_download_link_to_order(order_id, download_url)
    if not ok:
        # IMPORTANT: return 200 anyway so Shopify doesn't keep retrying forever,
        # but include the failure in the response for your logs.
        return jsonify(
            {
                "status": "generated_but_not_written_to_shopify",
                "file": filename,
                "preview_url": preview_url,
                "download_url": download_url,
                "shopify_update": msg,
            }
        ), 200

    return jsonify(
        {
            "status": "generated_and_written_to_shopify",
            "file": filename,
            "preview_url": preview_url,
            "download_url": download_url,
            "shopify_update": msg,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
    ), 200


@app.get("/preview/<path:filename>")
def preview(filename):
    return send_from_directory(GENERATED_DIR, filename, as_attachment=False)


@app.get("/download/<path:filename>")
def download(filename):
    return send_from_directory(GENERATED_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    # Local dev only; Render runs gunicorn
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
