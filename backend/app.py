"""
app.py – Flask REST API for PacketTrust.

Endpoints
---------
POST /api/upload           – upload a PCAP file
GET  /api/completeness     – completeness analysis
POST /api/simulate-loss    – simulate packet loss
GET  /api/triage           – threat triage
POST /api/experiment       – multi-trial reliability experiment
GET  /api/report           – printable HTML report
"""

from __future__ import annotations

import os

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

import completeness
import loss_sim
import triage
import reliability

# ---------------------------------------------------------------------------
# app setup
# ---------------------------------------------------------------------------

app = Flask(__name__, template_folder="templates")
CORS(app)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXT = {"pcap", "pcapng", "cap"}


def _allowed(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def _resolve(filename: str) -> str:
    path = os.path.join(UPLOAD_DIR, secure_filename(filename))
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {filename}")
    return path


# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------

@app.route("/api/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    f = request.files["file"]
    if f.filename == "" or not _allowed(f.filename):
        return jsonify({"error": "Invalid file type. Allowed: pcap, pcapng, cap"}), 400
    name = secure_filename(f.filename)
    dest = os.path.join(UPLOAD_DIR, name)
    f.save(dest)
    size = os.path.getsize(dest)

    # quick packet count
    from scapy.all import rdpcap
    pkts = rdpcap(dest)
    return jsonify({"filename": name, "size_bytes": size, "packet_count": len(pkts)})


@app.route("/api/completeness")
def completeness_endpoint():
    filename = request.args.get("file")
    if not filename:
        return jsonify({"error": "?file= parameter required"}), 400
    try:
        path = _resolve(filename)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify(completeness.analyse(path))


@app.route("/api/simulate-loss", methods=["POST"])
def simulate_loss():
    data = request.get_json(force=True)
    filename = data.get("file")
    loss_pct = data.get("loss_pct", 20)
    mode = data.get("mode", "random")
    if not filename:
        return jsonify({"error": "'file' is required"}), 400
    try:
        path = _resolve(filename)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    result = loss_sim.simulate(path, loss_pct, mode=mode, output_dir=UPLOAD_DIR)
    return jsonify(result)


@app.route("/api/triage")
def triage_endpoint():
    filename = request.args.get("file")
    if not filename:
        return jsonify({"error": "?file= parameter required"}), 400
    try:
        path = _resolve(filename)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify(triage.analyse(path))


@app.route("/api/experiment", methods=["POST"])
def experiment():
    data = request.get_json(force=True)
    filename = data.get("file")
    loss_levels = data.get("loss_levels", [0, 10, 20, 30, 50])
    trials = data.get("trials", 20)
    if not filename:
        return jsonify({"error": "'file' is required"}), 400
    try:
        path = _resolve(filename)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    result = reliability.run_experiment(
        path, loss_levels=loss_levels, trials=trials, output_dir=UPLOAD_DIR,
    )
    return jsonify(result)


@app.route("/api/report")
def report():
    filename = request.args.get("file")
    if not filename:
        return jsonify({"error": "?file= parameter required"}), 400
    try:
        path = _resolve(filename)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404

    comp = completeness.analyse(path)
    tri = triage.analyse(path)

    return render_template(
        "report.html",
        comp=comp,
        tri=tri,
        filename=filename,
    )


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5000)
