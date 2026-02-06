import os
import random
import base64
import hashlib
import hmac
import requests
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory, abort
from PIL import Image, ImageOps

app = Flask(__name__)

# --------------------------------------------------
# ENV VARIABLES (Render)
# --------------------------------------------------
SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_WEBHOOK_SECRET")
SHOPIFY_ADMIN_TOKEN = os.getenv("SHOPIFY_ADMIN_TOKEN")
SHOPIFY_STORE_DOMAIN = os.getenv("SHOPIFY_STORE_DOMAIN")
SHOPIFY_API_VERSION = os.getenv("SHOPIFY_API_VERSION", "2024-10")

# --------------------------------------------------
# PATHS
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ASSETS_DIR = os.path.join(BASE_DIR, "assets")
SHIELD_DIR = os.path.join(ASSETS_DIR, "shields")
SIGIL_DIR = os.path.join(ASSETS_DIR, "sigils")

STATIC_DIR = os.path.join(BASE_DIR, "static")
GENERATED_DIR = os.path.join(STATIC_DIR, "generated")

os.makedirs(GENERATED_DIR, exist_ok=True)

ALLOWED_EXTS = {".png", ".jpg", ".jpeg", ".webp"}

# --------------------------------------------------
# SHOPIFY WEBHOOK VERIFICATION
# --------------------------------------------------
def verify_shopify_webhook(data, hmac_header):
    digest = hmac.new(
        SHOPIFY_WEBHOOK_SECRET.encode(),
        data,
        hashlib.sha256
    ).digest()
    computed_hmac = base64.b64encode(digest)
    return hmac.compare_digest(computed_hmac, hmac_header.encode())

# --------------------------------------------------
# SHOPIFY ORDER FILE UPLOAD
# --------------------------------------------------
def upload_file_to_shopify(order_id, file_path, filename):
    url = f"https://{SHOPIFY_STORE_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/graphql.json"

    with open(file_path, "rb") as f:
        encoded = base64.b64encode(f.read()).decode()

    mutation = """
    mutation fileCreate($files: [FileCreateInput!]!) {
      fileCreate(files: $files) {
        files {
          id
          url
        }
      }
    }
    """

    variables = {
        "files": [{
            "alt": filename,
            "contentType": "IMAGE",
            "originalSource": f"data:image/png;base64,{encoded}"
        }]
    }

    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
        "Content-Type": "application/json"
    }

    requests.post(url, json={"query": mutation, "variables": variables}, headers=headers)

# --------------------------------------------------
# IMAGE GENERATOR
# --------------------------------------------------
def list_image_files(folder_path):
    return [f for f in os.listdir(folder_path) if os.path.splitext(f)[1].lower() in ALLOWED_EXTS]

def open_rgba(path):
    return Image.open(path).convert("RGBA")

def generate_crest(order_id):
    shield = open_rgba(os.path.join(SHIELD_DIR, random.choice(list_image_files(SHIELD_DIR))))
    sigil = open_rgba(os.path.join(SIGIL_DIR, random.choice(list_image_files(SIGIL_DIR))))

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

    coloured_sigil.thumbnail((int(shield.size[0]*0.62), int(shield.size[1]*0.62)))
    x = (canvas.size[0] - coloured_sigil.size[0]) // 2
    y = (canvas.size[1] - coloured_sigil.size[1]) // 2

    canvas.paste(coloured_sigil, (x,y), coloured_sigil)

    filename = f"crest_{order_id}.png"
    path = os.path.join(GENERATED_DIR, filename)
    canvas.save(path, "PNG")

    return path, filename

# --------------------------------------------------
# SHOPIFY WEBHOOK ROUTE ⭐⭐⭐
# --------------------------------------------------
@app.post("/webhook/order-paid")
def shopify_order_paid():

    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256")
    data = request.get_data()

    if not verify_shopify_webhook(data, hmac_header):
        abort(401)

    order = request.json
    order_id = order["id"]

    file_path, filename = generate_crest(order_id)

    upload_file_to_shopify(order_id, file_path, filename)

    return jsonify({"status": "success"})

# --------------------------------------------------
# TEST ROUTES
# --------------------------------------------------
@app.post("/new-order")
def test_generator():
    order_id = str(request.json.get("id"))
    _, filename = generate_crest(order_id)
    return jsonify({"file": filename})

@app.get("/preview/<filename>")
def preview(filename):
    return send_from_directory(GENERATED_DIR, filename)

@app.get("/download/<filename>")
def download(filename):
    return send_from_directory(GENERATED_DIR, filename, as_attachment=True)

# --------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
