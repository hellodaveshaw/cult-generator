from flask import Flask, request, jsonify
from PIL import Image
import os
import random

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
SHIELD_FOLDER = os.path.join(ASSETS_DIR, "shields")
SIGIL_FOLDER = os.path.join(ASSETS_DIR, "sigils")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "output")

os.makedirs(OUTPUT_FOLDER, exist_ok=True)


def generate_crest(order_id):
    shield_files = [f for f in os.listdir(SHIELD_FOLDER) if f.endswith(".png")]
    sigil_files = [f for f in os.listdir(SIGIL_FOLDER) if f.endswith(".png")]

    shield_file = random.choice(shield_files)
    sigil_file = random.choice(sigil_files)

    shield = Image.open(os.path.join(SHIELD_FOLDER, shield_file)).convert("RGBA")
    sigil = Image.open(os.path.join(SIGIL_FOLDER, sigil_file)).convert("RGBA")

    sigil = sigil.resize(shield.size)
    combined = Image.alpha_composite(shield, sigil)

    filename = f"crest_{order_id}.png"
    output

