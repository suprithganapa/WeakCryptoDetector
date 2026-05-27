"""
server.py  -  WeakCryptoDetector local web server
Run:  python server.py
Then open:  http://localhost:5000
"""

from flask import Flask, render_template_string, Response, jsonify, send_file
import subprocess, threading, os, json, queue, time

app = Flask(__name__)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DETECTOR    = os.path.join(BASE_DIR, "WeakCryptoDetector.exe")
TARGET      = os.path.join(BASE_DIR, "test_target", "test_target.exe")
REPORT_FILE = os.path.join(BASE_DIR, "weak_crypto_report.txt")

output_queue = queue.Queue()
running      = False

# ── serve UI ──────────────────────────────────────────────────────────────
@app.route("/")
def index():
    with open(os.path.join(BASE_DIR, "index.html"), encoding="utf-8") as f:
        return f.read()

# ── run detector ──────────────────────────────────────────────────────────
def run_detector():
    global running
    running = True
    output_queue.put(json.dumps({"type":"start"}))

    if not os.path.exists(DETECTOR):
        output_queue.put(json.dumps({"type":"error","msg":f"Detector not found: {DETECTOR}"}))
        running = False
        return
    if not os.path.exists(TARGET):
        output_queue.put(json.dumps({"type":"error","msg":f"Target not found: {TARGET}"}))
        running = False
        return

    try:
        proc = subprocess.Popen(
            [DETECTOR, TARGET],
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
    global running
    if running:
        return jsonify({"status":"already_running"})
    t = threading.Thread(target=run_detector, daemon=True)
    t.start()
    return jsonify({"status":"started"})

# ── SSE stream of output lines ────────────────────────────────────────────
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

# ── serve report file ─────────────────────────────────────────────────────
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
    return jsonify({"running": running,
                    "report_exists": os.path.exists(REPORT_FILE)})

if __name__ == "__main__":
    import webbrowser
    print("=" * 55)
    print("  WeakCryptoDetector  -  Web UI")
    print("  http://localhost:5000")
    print("=" * 55)
    threading.Timer(1.2, lambda: webbrowser.open("http://localhost:5000")).start()
    app.run(host="127.0.0.1", port=5000, debug=False)
