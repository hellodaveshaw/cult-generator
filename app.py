import os
import hmac
import base64
import hashlib
import random
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory, abort
from PIL import Image, ImageOps

app = Flask(__name__)

# ============================================================
# ENV VARS (from Render)
# ============================================================
SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_WEBHOOK_SECRET")

# ============================================================
# Paths
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ASSETS_DIR = os.path.join(BASE_DIR, "assets")
SHIELD_DIR = os.path.join(ASSETS_DIR, "shields")
SIGIL_DIR = os.path.join(ASSETS_DIR, "sigils")

STATIC_DIR = os.path.join(BASE_DIR, "static")
GENERATED_DIR = os.path.join(STATIC_DIR, "generated")

os.makedirs(GENERATED_DIR, exist_ok=True)

ALLOWED_EXTS = {".png", ".jpg", ".jpeg", ".webp"}

# ============================================================
# Shopify Webhook Verification
# ============================================================
def verify_shopify_webhook(data, hmac_header):
    digest = hmac.new(
        SHOPIFY_WEBHOOK_SECRET.encode("utf-8"),
        data,
        hashlib.sha256
    ).digest()

    computed_hmac = base64.b64encode(digest)

    return hmac.compare_digest(computed_hmac, hmac_header.encode("utf-8"))

# ============================================================
# Image Helpers
# ============================================================
def list_image_files(folder_path):
    return [f for f in os.listdir(folder_path)
            if os.path.splitext(f.lower())[1] in ALLOWED_EXTS]

def open_rgba(path):
    return Image.open(path).convert("RGBA")

# ============================================================
# Crest Generator
# ============================================================
def generate_crest(order_id):
    shields = list_image_files(SHIELD_DIR)
    sigils = list_image_files(SIGIL_DIR)

    shield = open_rgba(os.path.join(SHIELD_DIR, random.choice(shields)))
    sigil = open_rgba(os.path.join(SIGIL_DIR, random.choice(sigils)))

    if random.random() < 0.5:
        sigil = ImageOps.mirror(sigil)

    palette = [
        (0,0,0,255),(255,255,0,255),(70,170,255,255),
        (40,70,160,255),(245,90,40,255),(120,120,120,255),(255,255,255,255)
    ]

    sigil_colour = random.choice(palette)
    bg_colour = random.choice([c for c in palette if c != sigil_colour])

    alpha = sigil.split()[-1]
    coloured_sigil = Image.new("RGBA", sigil.size, sigil_colour)
    coloured_sigil.putalpha(alpha)

    background = Image.new("RGBA", shield.size, bg_colour)
    canvas = Image.alpha_composite(background, shield)

    coloured_sigil.thumbnail((int(shield.size[0]*0.6), int(shield.size[1]*0.6)))
    x = (canvas.size[0]-coloured_sigil.size[0])//2
    y = (canvas.size[1]-coloured_sigil.size[1])//2

    canvas.paste(coloured_sigil,(x,y),coloured_sigil)

    filename = f"crest_{order_id}.png"
    path = os.path.join(GENERATED_DIR, filename)
    canvas.save(path)

    return filename

# ============================================================
# SHOPIFY WEBHOOK ROUTE (THE IMPORTANT BIT)
# ============================================================
@app.post("/webhook/order-paid")
def order_paid():

    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256")
    data = request.get_data()

    if not verify_shopify_webhook(data, hmac_header):
        abort(401)

    order = request.json
    order_id = order["id"]

    print("Order paid received:", order_id)

    filename = generate_crest(order_id)

    print("Generated:", filename)

    return jsonify({"status": "success"}), 200

# ============================================================
# FILE SERVING
# ============================================================
@app.get("/preview/<filename>")
def preview(filename):
    return send_from_directory(GENERATED_DIR, filename)

@app.get("/download/<filename>")
def download(filename):
    return send_from_directory(GENERATED_DIR, filename, as_attachment=True)

@app.get("/")
def home():
    return "Cult Generator running"

# ============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",10000)))
