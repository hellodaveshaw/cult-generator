# app.py
# Cult Generator - Flask + Pillow
# Routes:
#   GET  /                     -> simple health check
#   GET  /routes               -> list routes
#   POST /new-order            -> manual/test generator (no Shopify)
#   POST /shopify/order-paid   -> Shopify webhook (Order paid) -> generate + write link into order note
#   GET  /preview/<filename>   -> view generated PNG
#   GET  /download/<filename>  -> download generated PNG

import os
import random
import hmac
import hashlib
import base64

import requests
from flask import Flask, request, jsonify, send_from_directory
from PIL import Image

app = Flask(__name__)

# -----------------------------
# Paths
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SHIELD_FOLDER = os.path.join(BASE_DIR, "assets", "shields")
SIGIL_FOLDER = os.path.join(BASE_DIR, "assets", "sigils")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "output")
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# -----------------------------
# Shopify config (Render Env Vars)
# -----------------------------
SHOPIFY_SHARED_SECRET = os.environ.get("SHOPIFY_SHARED_SECRET", "")
SHOPIFY_ADMIN_TOKEN = os.environ.get("SHOPIFY_ADMIN_TOKEN", "")
SHOPIFY_STORE_DOMAIN = os.environ.get("SHOPIFY_STORE_DOMAIN", "")  # e.g. "cultofcustoms.myshopify.com"
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2024-10")


# -----------------------------
# Helpers
# -----------------------------
def load_random_png(folder: str) -> Image.Image:
    """
    Pick a random .png from a folder and open it as RGBA.
    Ignores non-png files like .gitkeep.
    """
    files = [f for f in os.listdir(folder) if f.lower().endswith(".png")]
    if not files:
        raise Exception(f"No PNG files found in {folder}")
    path = os.path.join(folder, random.choice(files))
    return Image.open(path).convert("RGBA")


def generate_crest(order_id: str) -> str:
    """
    Composites a random sigil onto a random shield and saves it to OUTPUT_FOLDER.
    Returns the output filename (not full path).
    """
    shield = load_random_png(SHIELD_FOLDER)
    sigil = load_random_png(SIGIL_FOLDER)

    # Resize sigil to 60% of shield size (tweak later)
    sigil = sigil.resize((int(shield.width * 0.6), int(shield.height * 0.6)))

    # Center placement
    x = (shield.width - sigil.width) // 2
    y = (shield.height - sigil.height) // 2

    # Paste using sigil alpha as mask
    shield.paste(sigil, (x, y), sigil)

    filename = f"crest_{order_id}.png"
    output_path = os.path.join(OUTPUT_FOLDER, filename)
    shield.save(output_path)

    return filename


def verify_shopify_hmac(raw_body: bytes, hmac_header: str) -> bool:
    """
    Verify Shopify webhook HMAC.
    Shopify sends base64(hmac_sha256(secret, raw_body)).
    """
    if not SHOPIFY_SHARED_SECRET or not hmac_header:
        return False

    digest = hmac.new(
        SHOPIFY_SHARED_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).digest()

    calculated = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(calculated, hmac_header)


def shopify_api_request(method: str, path: str, json_data=None):
    """
    Make an authenticated call to Shopify Admin API using the Admin API access token.
    """
    if not (SHOPIFY_ADMIN_TOKEN and SHOPIFY_STORE_DOMAIN):
        raise Exception("Missing SHOPIFY_ADMIN_TOKEN or SHOPIFY_STORE_DOMAIN env vars.")

    url = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/{path.lstrip('/')}"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
        "Content-Type": "application/json",
    }

    r = requests.request(method, url, headers=headers, json=json_data, timeout=20)
    if r.status_code >= 400:
        raise Exception(f"Shopify API error {r.status_code}: {r.text}")

    return r.json() if r.text else {}


# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def home():
    return "Cult Generator is alive."


@app.route("/routes")
def routes():
    return "<pre>" + "\n".join(sorted([str(r) for r in app.url_map.iter_rules()])) + "</pre>"


@app.route("/new-order", methods=["POST"])
def new_order():
    """
    Manual/test endpoint (not Shopify).
    POST JSON: {"id": 123}
    Returns JSON with preview + download URLs.
    """
    data = request.get_json(silent=True) or {}
    order_id = str(data.get("id") or random.randint(100000, 999999))

    filename = generate_crest(order_id)

    base_url = request.host_url.rstrip("/")
    return jsonify({
        "status": "generated",
        "file": filename,
        "preview_url": f"{base_url}/preview/{filename}",
        "download_url": f"{base_url}/download/{filename}",
    })


@app.route("/shopify/order-paid", methods=["POST"])
def shopify_order_paid():
    """
    Shopify webhook: Order paid
    - Verify HMAC
    - Generate crest using Shopify order id
    - Add preview/download links to the order note
    """
    raw = request.get_data()  # bytes
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not verify_shopify_hmac(raw, hmac_header):
        return jsonify({"status": "forbidden"}), 403

    payload = request.get_json(silent=True) or {}

    order_id = payload.get("id")
    if not order_id:
        return jsonify({"status": "bad_request", "error": "Missing order id"}), 400

    filename = generate_crest(str(order_id))

    base_url = request.host_url.rstrip("/")
    preview_url = f"{base_url}/preview/{filename}"
    download_url = f"{base_url}/download/{filename}"

    existing_note = payload.get("note") or ""
    addition = (
        "\n\n— Cult of Customs —\n"
        "Your one-of-a-kind Cult Crest is ready:\n"
        f"Preview: {preview_url}\n"
        f"Download: {download_url}\n"
    )
    new_note = (existing_note + addition).strip()

    # Update order note via Shopify Admin API
    shopify_api_request(
        "PUT",
        f"orders/{order_id}.json",
        {"order": {"id": order_id, "note": new_note}},
    )

    return jsonify({
        "status": "ok",
        "order_id": order_id,
        "file": filename,
        "preview_url": preview_url,
        "download_url": download_url,
    })


@app.route("/preview/<path:filename>", methods=["GET"])
def preview(filename):
    """Show the generated PNG in the browser."""
    return send_from_directory(OUTPUT_FOLDER, filename, as_attachment=False)


@app.route("/download/<path:filename>", methods=["GET"])
def download(filename):
    """Force download of the generated PNG."""
    return send_from_directory(OUTPUT_FOLDER, filename, as_attachment=True)


if __name__ == "__main__":
    # Local dev only. Render uses: gunicorn app:app
    app.run(host="0.0.0.0", port=5000)




