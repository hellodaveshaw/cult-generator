import os
import random
import hmac
import base64
import hashlib
from datetime import datetime

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
# Config (Shopify)
# ----------------------------
# Put your Shopify App "Client secret" (aka API secret key) in Render as an env var:
#   SHOPIFY_WEBHOOK_SECRET=xxxxx
SHOPIFY_WEBHOOK_SECRET = os.environ.get("SHOPIFY_WEBHOOK_SECRET", "").strip()

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
    Render/Cloudflare sometimes proxies headers; host_url is usually correct.
    Ensures trailing slash.
    """
    url = request.host_url
    if not url.endswith("/"):
        url += "/"
    return url


def verify_shopify_hmac(raw_body: bytes, hmac_header: str, secret: str) -> bool:
    """
    Verifies X-Shopify-Hmac-Sha256 against the raw request body.
    Shopify sends base64(hmac_sha256(secret, body)).
    """
    if not secret:
        # If you haven't set the secret yet, fail closed (safer).
        return False
    if not hmac_header:
        return False

    digest = hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).digest()

    computed = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(computed, hmac_header)


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

    # --- Mirror rule (no rotation): 50/50 mirror
    if random.random() < 0.5:
        sigil = ImageOps.mirror(sigil)

    # --- Colour palette (replace with your exact brand swatches if you want)
    palette = [
        (0, 0, 0, 255),          # black
        (255, 255, 0, 255),      # yellow
        (70, 170, 255, 255),     # light blue
        (40, 70, 160, 255),      # dark blue
        (245, 90, 40, 255),      # orange/red
        (120, 120, 120, 255),    # grey
        (255, 255, 255, 255),    # white (useful for inverse)
    ]

    sigil_colour = random.choice(palette)
    bg_colour = random.choice([c for c in palette if c != sigil_colour])

    # --- Recolour sigil by tinting its alpha mask
    alpha = sigil.split()[-1]
    coloured_sigil = Image.new("RGBA", sigil.size, sigil_colour)
    coloured_sigil.putalpha(alpha)

    # --- Optional: add a coloured field behind shield
    background = Image.new("RGBA", shield.size, bg_colour)

    # Compose: background -> shield -> sigil centered
    canvas = Image.alpha_composite(background, shield)

    # Fit sigil nicely inside shield
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
    # Quick sanity check endpoint
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
    Manual/test endpoint (your curl).
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
    Shopify Webhook endpoint.
    In Shopify Admin/Webhooks or your app webhook config, set URL to:
      https://cult-generator.onrender.com/webhook/order-paid
    """
    raw = request.get_data(cache=False)  # raw bytes for HMAC validation
    shopify_hmac = request.headers.get("X-Shopify-Hmac-Sha256", "")

    # Verify webhook authenticity (strongly recommended)
    if not verify_shopify_hmac(raw, shopify_hmac, SHOPIFY_WEBHOOK_SECRET):
        return jsonify({"status": "error", "message": "Invalid webhook signature"}), 401

    payload = request.get_json(silent=True) or {}
    order_id = str(payload.get("id") or "").strip()
    if not order_id:
        return jsonify({"status": "error", "message": "Missing order id in webhook"}), 400

    try:
        _, filename = generate_crest(order_id)
    except Exception as e:
        # Return 500 so Shopify may retry (useful if assets temporarily missing)
        return jsonify({"status": "error", "message": str(e)}), 500

    base = safe_host_url()
    preview_url = f"{base}preview/{filename}"
    download_url = f"{base}download/{filename}"

    # IMPORTANT: Shopify just needs a 200 OK to stop retrying.
    # You can extend this later to write the URL back onto the order via Admin API.
    return jsonify(
        {
            "status": "generated",
            "order_id": order_id,
            "file": filename,
            "preview_url": preview_url,
            "download_url": download_url,
        }
    ), 200


@app.get("/preview/<path:filename>")
def preview(filename):
    # Inline display (browser shows image)
    return send_from_directory(GENERATED_DIR, filename, as_attachment=False)


@app.get("/download/<path:filename>")
def download(filename):
    # Forces download
    return send_from_directory(GENERATED_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    # Local dev only; Render runs gunicorn
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
