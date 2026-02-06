import os
import random
import hashlib
from flask import Flask, request, jsonify
from PIL import Image, ImageOps

app = Flask(__name__)

# ---------- PATH SETUP ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SHIELD_FOLDER = os.path.join(BASE_DIR, "assets", "shields")
SIGIL_FOLDER = os.path.join(BASE_DIR, "assets", "sigils")

# ---------- COLOUR PALETTE ----------
COLOURS = [
    (0,0,0),        # black
    (255,230,0),    # yellow
    (60,160,220),   # light blue
    (50,80,150),    # dark blue
    (240,90,30),    # orange
    (130,130,130)   # grey
]

# ---------- HELPERS ----------

def list_images(folder):
    exts = (".png", ".jpg", ".jpeg")
    return [f for f in os.listdir(folder) if f.lower().endswith(exts)]

def recolour_image(img, colour):
    img = img.convert("RGBA")
    pixels = img.load()

    for y in range(img.height):
        for x in range(img.width):
            if pixels[x,y][3] > 0:
                pixels[x,y] = (*colour, 255)
    return img

# ---------- GENERATOR ----------

def generate_crest(order_id):

    shields = list_images(SHIELD_FOLDER)
    sigils = list_images(SIGIL_FOLDER)

    if not shields:
        raise Exception("No PNG shields found in assets/shields")
    if not sigils:
        raise Exception("No PNG sigils found in assets/sigils")

    # deterministic seed from order ID
    seed = int(hashlib.sha256(order_id.encode()).hexdigest(), 16)
    random.seed(seed)

    shield_file = random.choice(shields)
    sigil_file = random.choice(sigils)

    colour1, colour2 = random.sample(COLOURS, 2)
    mirror = random.choice([True, False])

    shield = Image.open(os.path.join(SHIELD_FOLDER, shield_file)).convert("RGBA")
    sigil = Image.open(os.path.join(SIGIL_FOLDER, sigil_file)).convert("RGBA")

    shield = recolour_image(shield, colour1)
    sigil = recolour_image(sigil, colour2)

    if mirror:
        sigil = ImageOps.mirror(sigil)

    sigil = sigil.resize((int(shield.width*0.6), int(shield.height*0.6)))

    x = (shield.width - sigil.width)//2
    y = (shield.height - sigil.height)//2
    shield.paste(sigil, (x,y), sigil)

    filename = f"crest_{order_id}.png"
    output_path = f"/tmp/{filename}"
    shield.save(output_path)

    return output_path, filename

# ---------- ROUTES ----------

@app.route("/")
