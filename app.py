from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/")
def home():
    return "Cult Generator is alive"

@app.route("/new-order", methods=["POST"])
def new_order():
    data = request.json
    print("Received order:", data)
    return jsonify({"status": "ok"})
