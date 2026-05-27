"""
server.py  -  WeakCryptoDetector local web server
Run:  python server.py
"""

from flask import Flask, Response, jsonify, send_file, request
import subprocess, threading, os, json, queue, time, shutil

app = Flask(__name__)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DETECTOR    = os.path.join(BASE_DIR, "WeakCryptoDetector.exe")
TARGET      = os.path.join(BASE_DIR, "test_target", "test_target.exe")
REPORT_FILE = os.path.join(BASE_DIR, "weak_crypto_report.txt")
UPLOAD_DIR  = os.path.join(BASE_DIR, "uploaded_targets")

os.makedirs(UPLOAD_DIR, exist_ok=True)

output_queue = queue.Queue()
running      = False
current_target = None

# ── serve UI ──────────────────────────────────────────────────────────────
@app.route("/")
def index():
    with open(os.path.join(BASE_DIR, "index.html"), encoding="utf-8") as f:
        return f.read()

# ── upload a custom exe ───────────────────────────────────────────────────
@app.route("/upload", methods=["POST"])
def upload():
    global current_target
    if "exe" not in request.files:
        return jsonify({"status":"error","msg":"No file"}), 400
    f = request.files["exe"]
    if not f.filename.lower().endswith(".exe"):
        return jsonify({"status":"error","msg":"Only .exe files allowed"}), 400
    save_path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(save_path)
    current_target = save_path
    return jsonify({"status":"ok","filename": f.filename, "path": save_path})

# ── set target to default test_target ────────────────────────────────────
@app.route("/use_default")
def use_default():
    global current_target
    current_target = None
    return jsonify({"status":"ok"})

# ── run detector ──────────────────────────────────────────────────────────
def run_detector(target_path):
    global running
    running = True
    output_queue.put(json.dumps({"type":"start","target": os.path.basename(target_path)}))

    if not os.path.exists(DETECTOR):
        output_queue.put(json.dumps({"type":"error","msg":f"Detector not found: {DETECTOR}"}))
        running = False
        return
    if not os.path.exists(target_path):
        output_queue.put(json.dumps({"type":"error","msg":f"Target not found: {target_path}"}))
        running = False
        return

    try:
        proc = subprocess.Popen(
            [DETECTOR, target_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=BASE_DIR
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                output_queue.put(json.dumps({"type":"line","msg":line}))
        proc.wait()
        output_queue.put(json.dumps({"type":"done","code":proc.returncode}))
    except Exception as e:
        output_queue.put(json.dumps({"type":"error","msg":str(e)}))
    finally:
        running = False

@app.route("/run")
def run():
    global running, current_target
    if running:
        return jsonify({"status":"already_running"})
    target = current_target if current_target else TARGET
    t = threading.Thread(target=run_detector, args=(target,), daemon=True)
    t.start()
    return jsonify({"status":"started", "target": os.path.basename(target)})

# ── SSE stream ────────────────────────────────────────────────────────────
@app.route("/stream")
def stream():
    def generate():
        while True:
            try:
                msg = output_queue.get(timeout=30)
                yield f"data: {msg}\n\n"
                data = json.loads(msg)
                if data.get("type") == "done":
                    break
            except queue.Empty:
                yield "data: {\"type\":\"ping\"}\n\n"
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── report ────────────────────────────────────────────────────────────────
@app.route("/report")
def report():
    if os.path.exists(REPORT_FILE):
        return send_file(REPORT_FILE, mimetype="text/plain",
                         as_attachment=True,
                         download_name="weak_crypto_report.txt")
    return "Report not found", 404

@app.route("/report_text")
def report_text():
    if os.path.exists(REPORT_FILE):
        with open(REPORT_FILE, encoding="utf-8", errors="replace") as f:
            return f.read(), 200, {"Content-Type":"text/plain"}
    return "", 404

# ── status ────────────────────────────────────────────────────────────────
@app.route("/status")
def status():
    target = current_target if current_target else TARGET
    return jsonify({
        "running": running,
        "report_exists": os.path.exists(REPORT_FILE),
        "current_target": os.path.basename(target)
    })

if __name__ == "__main__":
    import webbrowser
    print("=" * 55)
    print("  WeakCryptoDetector  -  Web UI")
    print("  http://localhost:5000")
    print("=" * 55)
    threading.Timer(1.2, lambda: webbrowser.open("http://localhost:5000")).start()
    app.run(host="127.0.0.1", port=5000, debug=False)
