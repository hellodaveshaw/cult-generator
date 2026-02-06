import os
import random
import hashlib
from flask import Flask, request, jsonify
from PIL import Image, ImageOps
import requests

app = Flask(__name__)

# ---- SETTINGS ----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SHIELD_FOLDER = os.path.join(BASE_DIR, "assets", "shields")
SIGIL_FOLDER = os.path.join(BASE_DIR, "assets", "sigils")

COLOURS = [
    (0,0,0),        # black
    (255,230,0),    # yellow
    (60,160,220),   # light blue
    (50,80,150),    # dark blue
    (240,90,30),    # orange
    (130,130,130)   # grey
]

# ---- HELPER FUNCTIONS ----

def seeded_choice(seed, items):
    random.seed(seed)
    return random.choice(items)

def recolour_image(img, colour):
    img = img.convert("RGBA")
    pixels = img.load()

    for y in range(img.height):
        for x in range(img.width):
            if pixels[x,y][3] > 0:  # if pixel not transparent
                pixels[x,y] = (*colour, 255)
    return img

def generate_crest(order_id):
    # deterministic seed
    seed = int(hashlib.sha256(order_id.encode()).hexdigest(), 16)

    shields = os.listdir(SHIELD_FOLDER)
    sigils = os.listdir(SIGIL_FOLDER)

    random.seed(seed)
    shield_file = random.choice(shields)
    sigil_file = random.choice(sigils)

    # pick two different colours
    colour1, colour2 = random.sample(COLOURS, 2)

    mirror = random.choice([True, False])

    # load images
    shield = Image.open(f"{SHIELD_FOLDER}/{shield_file}").convert("RGBA")
    sigil = Image.open(f"{SIGIL_FOLDER}/{sigil_file}").convert("RGBA")

    # recolour
    shield = recolour_image(shield, colour1)
    sigil = recolour_image(sigil, colour2)

    # mirror rule
    if mirror:
        sigil = ImageOps.mirror(sigil)

    # scale sigil smaller
    sigil = sigil.resize((int(shield.width*0.6), int(shield.height*0.6)))

    # center sigil on shield
    x = (shield.width - sigil.width)//2
    y = (shield.height - sigil.height)//2
    shield.paste(sigil, (x,y), sigil)

    # save result
    filename = f"crest_{order_id}.png"
    output_path = f"/tmp/{filename}"
    shield.save(output_path)

    return output_path, filename

# ---- WEBHOOK ----

@app.route("/")
def home():
    return "Cult Generator running"

@app.route("/new-order", methods=["POST"])
def new_order():
    data = request.json
    order_id = str(data["id"])

    file_path, filename = generate_crest(order_id)

    # For now we just confirm generation
    return jsonify({
        "status": "generated",
        "file": filename
    })
