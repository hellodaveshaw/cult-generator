# app.py
# Cult Generator - working Flask app with:
# - /new-order (POST) generates crest PNG
# - /preview/<filename> (GET) shows PNG in browser
# - /download/<filename> (GET) forces download
# - /routes (GET) lists all routes (debug)

from flask import Flask, request, jsonify, send_from_directory
from PIL import Image
import os
import random

app = Flask(__name__)

# --- Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SHIELD_FOLDER = os.path.join(BASE_DIR, "assets", "shields")
SIGIL_FOLDER = os.path.join(BASE_DIR, "assets", "sigils")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "output")

os.makedirs(OUTPUT_FOLDER, exist_ok=True)


# --- Helpers ---
def load_random_png(folder: str) -> Image.Image:
    """Pick a random .png from a folder and open it as RGBA."""
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


# --- Routes ---
@app.route("/")
def home():
    return "Cult Generator is alive."


@app.route("/routes")
def routes():
    return "<pre>" + "\n".join(sorted([str(r) for r in app.url_map.iter_rules()])) + "</pre>"


@app.route("/new-order", methods=["POST"])
def new_order():
    """
    POST JSON: {"id": 123}
    Returns JSON with preview + download URLs.
    """
    data = request.get_json(silent=True) or {}
    order_id = str(data.get("id") or random.randint(100000, 999999))

    filename = generate_crest(order_id)

    # Full URLs (absolute) are nicer for Shopify later
    base_url = request.host_url.rstrip("/")

    return jsonify({
        "status": "generated",
        "file": filename,
        "preview_url": f"{base_url}/preview/{filename}",
        "download_url": f"{base_url}/download/{filename}",
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
    # Local dev only. Render uses gunicorn.
    app.run(host="0.0.0.0", port=5000)



