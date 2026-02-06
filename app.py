import os
import random
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

    # --- Colour palette (RGB is fine because you're doing digital downloads)
    # You can replace these with your exact brand swatches
    palette = [
        (0, 0, 0, 255),          # black
        (255, 255, 0, 255),      # yellow
        (70, 170, 255, 255),     # light blue
        (40, 70, 160, 255),      # dark blue
        (245, 90, 40, 255),      # orange/red
        (120, 120, 120, 255),    # grey
        (255, 255, 255, 255),    # white (useful for inverse)
    ]

    # Pick two different colours for overlay logic
    sigil_colour = random.choice(palette)
    bg_colour = random.choice([c for c in palette if c != sigil_colour])

    # --- Recolour sigil by tinting its alpha mask
    # Keeps crisp shapes. Assumes sigil art is solid/mono shapes.
    alpha = sigil.split()[-1]
    coloured_sigil = Image.new("RGBA", sigil.size, sigil_colour)
    coloured_sigil.putalpha(alpha)

    # --- Optional: add a coloured field behind shield (evokes “heraldry”)
    # If your shield already includes a border, this reads nicely.
    background = Image.new("RGBA", shield.size, bg_colour)

    # Compose: background -> shield -> sigil centered
    canvas = Image.alpha_composite(background, shield)

    # Fit sigil nicely inside shield (tweak this once you see your real assets)
    # Scale sigil to ~60% of shield width/height, preserving aspect.
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
        "/\n/routes\n/new-order\n/preview/<filename>\n/download/<filename>\n/static/\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


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

