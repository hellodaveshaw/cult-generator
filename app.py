from flask import Flask, request, jsonify
from PIL import Image
import os
import random

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SHIELD_FOLDER = os.path.join(BASE_DIR, "assets/shields")
SIGIL_FOLDER  = os.path.join(BASE_DIR, "assets/sigils")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "output")

os.makedirs(OUTPUT_FOLDER, exist_ok=True)


# DEBUG ROUTE (leave this forever)
@app.route("/routes")
def routes():
    return "<pre>" + "\n".join(sorted([str(r) for r in app.url_map.iter_rules()])) + "</pre>"


# HOME ROUTE (so visiting the site shows something)
@app.route("/")
def home():
    return "Cult Generator is alive."


# MAIN WEBHOOK ROUTE
@app.route("/new-order", methods=["POST"])
def new_order():
    data = request.get_json(silent=True) or {}
    order_id = str(data.get("id", random.randint(1000,9999)))

    file_path = generate_crest(order_id)

    return jsonify({
        "status": "generated",
        "file": file_path
    })


def load_random_image(folder):
    files = [f for f in os.listdir(folder) if f.lower().endswith(".png")]
    if not files:
        raise Exception(f"No PNG files found in {folder}")
    return Image.open(os.path.join(folder, random.choice(files))).convert("RGBA")


def generate_crest(order_id):
    shield = load_random_image(SHIELD_FOLDER)
    sigil  = load_random_image(SIGIL_FOLDER)

    sigil = sigil.resize((int(shield.width * 0.6), int(shield.height * 0.6)))
    x = (shield.width - sigil.width) // 2
    y = (shield.height - sigil.height) // 2

    shield.paste(sigil, (x, y), sigil)

    filename = f"crest_{order_id}.png"
    output_path = os.path.join(OUTPUT_FOLDER, filename)
    shield.save(output_path)

    return filename


