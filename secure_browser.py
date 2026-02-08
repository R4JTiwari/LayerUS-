from flask import Flask, request, render_template_string
from scanner import scan_url
from playwright.sync_api import sync_playwright
from datetime import datetime

app = Flask(__name__)

BLOCK_THRESHOLD = 60

# -----------------------------
# GLOBAL LOG STORAGE (in-memory)
# -----------------------------
history_logs = []   # stores all visited URLs + risk
threat_logs = []    # stores blocked threats

# -----------------------------
# UI Templates (Modern UI)
# -----------------------------

HOME_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LayerUS - Secure Browser</title>

    <style>
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: radial-gradient(circle at top, #0b1220, #05070d);
            color: white;
            padding: 20px;
            overflow-x: hidden;
        }

        /* GRID BACKGROUND */
        .grid-bg {
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(to right, rgba(255,255,255,0.06) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(255,255,255,0.06) 1px, transparent 1px);
            background-size: 28px 28px;
            mask-image: radial-gradient(circle at top, black 60%, transparent 100%);
            opacity: 0.25;
            z-index: 0;
        }

        /* SCANLINE EFFECT */
        .scanlines {
            pointer-events: none;
            position: fixed;
            inset: 0;
            background: linear-gradient(rgba(0,0,0,0) 50%, rgba(0,0,0,0.25) 50%);
            background-size: 100% 2px;
            opacity: 0.18;
            z-index: 1;
        }

        .container {
            position: relative;
            z-index: 5;
            max-width: 1200px;
            margin: auto;
        }

        /* HEADER */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 18px 25px;
            border-radius: 18px;
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.12);
            backdrop-filter: blur(12px);
            box-shadow: 0px 0px 25px rgba(0,230,118,0.15);
        }

        .header h1 {
            margin: 0;
            font-size: 30px;
            font-weight: 900;
            letter-spacing: 1px;
            text-shadow: 0 0 12px rgba(0,230,118,0.6);
        }

        .header p {
            margin: 6px 0 0;
            font-size: 13px;
            opacity: 0.75;
        }

        .live {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            font-family: monospace;
            opacity: 0.8;
        }

        .dot {
            width: 10px;
            height: 10px;
            background: #00e676;
            border-radius: 50%;
            box-shadow: 0 0 15px rgba(0,230,118,0.8);
            animation: pulse 1.2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(1); opacity: 0.8; }
            50% { transform: scale(1.4); opacity: 1; }
            100% { transform: scale(1); opacity: 0.8; }
        }

        /* BOX STYLE */
        .box {
            margin-top: 18px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 18px;
            padding: 20px;
            backdrop-filter: blur(10px);
            box-shadow: 0px 0px 20px rgba(0,0,0,0.4);
        }

        /* URL SCANNER */
        .scanner {
            display: flex;
            gap: 10px;
            margin-top: 12px;
        }

        input {
            flex: 1;
            padding: 14px;
            border-radius: 50px;
            border: 1px solid rgba(255,255,255,0.18);
            outline: none;
            background: rgba(0,0,0,0.4);
            color: white;
            font-size: 15px;
        }

        input:focus {
            border: 1px solid #00e676;
            box-shadow: 0 0 15px rgba(0,230,118,0.4);
        }

        button {
            padding: 14px 22px;
            border-radius: 50px;
            border: none;
            cursor: pointer;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            background: linear-gradient(90deg, #00e676, #00c853);
            color: black;
            transition: 0.25s;
        }

        button:hover {
            transform: scale(1.06);
            box-shadow: 0 0 20px rgba(0,230,118,0.6);
        }

        /* DASHBOARD CARDS */
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        .card {
            padding: 18px;
            border-radius: 16px;
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.12);
            transition: 0.25s;
        }

        .card:hover {
            transform: translateY(-4px);
            border: 1px solid rgba(0,230,118,0.45);
            box-shadow: 0 0 18px rgba(0,230,118,0.2);
        }

        .card h3 {
            margin: 0;
            font-size: 13px;
            opacity: 0.7;
        }

        .card p {
            margin: 10px 0 0;
            font-size: 28px;
            font-weight: 900;
        }

        /* TABLE */
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 14px;
        }

        th {
            text-align: left;
            padding: 12px;
            font-size: 12px;
            opacity: 0.7;
            text-transform: uppercase;
            border-bottom: 1px solid rgba(255,255,255,0.15);
        }

        td {
            padding: 12px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
        }

        tr:hover {
            background: rgba(255,255,255,0.06);
        }

        /* STATUS BADGES */
        .badge {
            padding: 6px 12px;
            border-radius: 30px;
            font-size: 12px;
            font-weight: 700;
            display: inline-block;
        }

        .safe { background: rgba(0,255,0,0.15); color: #00ff6a; border: 1px solid rgba(0,255,0,0.3); }
        .warn { background: rgba(255,165,0,0.15); color: orange; border: 1px solid rgba(255,165,0,0.3); }
        .block { background: rgba(255,0,0,0.15); color: red; border: 1px solid rgba(255,0,0,0.3); }

        /* RISK BAR */
        .riskbar {
            width: 100%;
            height: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            margin-top: 6px;
            overflow: hidden;
        }

        .riskfill {
            height: 100%;
            border-radius: 10px;
        }

        /* THREAT CARD */
        .threat-card {
            padding: 15px;
            border-radius: 14px;
            margin-bottom: 12px;
            background: rgba(255,0,0,0.06);
            border: 1px solid rgba(255,0,0,0.15);
            transition: 0.25s;
        }

        .threat-card:hover {
            border: 1px solid rgba(255,0,0,0.5);
            box-shadow: 0 0 18px rgba(255,0,0,0.25);
        }

        .threat-card h4 {
            margin: 0;
            color: #ff4d4d;
        }

        .footer {
            text-align: center;
            margin-top: 30px;
            opacity: 0.5;
            font-size: 12px;
        }

    </style>
</head>

<body>
    <div class="grid-bg"></div>
    <div class="scanlines"></div>

    <div class="container">

        <div class="header">
            <div>
                <h1>🛡️ LayerUS</h1>
                <p>AI Browser Security Firewall | Prompt Injection + Phishing Detection</p>
            </div>
            <div class="live">
                <div class="dot"></div>
                LIVE
            </div>
        </div>

        <div class="box">
            <h2>🌐 Scan & Visit Website</h2>
            <form class="scanner" method="POST" action="/visit">
                <input type="text" name="url" placeholder="Enter URL (example: https://example.com)" required>
                <button type="submit">Scan</button>
            </form>
        </div>

        <div class="box">
            <h2>📊 Risk Dashboard</h2>
            <div class="dashboard">
                <div class="card">
                    <h3>Total Visits</h3>
                    <p>{{total_visits}}</p>
                </div>
                <div class="card">
                    <h3>Safe Sites</h3>
                    <p style="color:#00ff6a;">{{safe_count}}</p>
                </div>
                <div class="card">
                    <h3>Warnings</h3>
                    <p style="color:orange;">{{warn_count}}</p>
                </div>
                <div class="card">
                    <h3>Blocked Threats</h3>
                    <p style="color:red;">{{blocked_count}}</p>
                </div>
            </div>
        </div>

        <div class="box">
            <h2>🕒 URL History Logs</h2>
            <table>
                <tr>
                    <th>Time</th>
                    <th>URL</th>
                    <th>Risk</th>
                    <th>Status</th>
                </tr>

                {% for log in history %}
                <tr>
                    <td style="font-family:monospace; opacity:0.8;">{{log.time}}</td>
                    <td>{{log.url}}</td>
                    <td>
                        {{log.risk}}/100
                        <div class="riskbar">
                            <div class="riskfill"
                                style="width: {{log.risk}}%;
                                background: {% if log.risk < 30 %}#00ff6a{% elif log.risk < 60 %}orange{% else %}red{% endif %};">
                            </div>
                        </div>
                    </td>
                    <td>
                        <span class="badge {{log.status_class}}">
                            {{log.status}}
                        </span>
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <div class="box">
            <h2>🚨 Live Threat Report Panel</h2>

            {% if threats|length == 0 %}
                <p style="opacity:0.7;">No threats detected yet.</p>
            {% else %}
                {% for t in threats %}
                <div class="threat-card">
                    <h4>🚫 BLOCKED Threat</h4>
                    <p><b>Time:</b> {{t.time}}</p>
                    <p><b>URL:</b> {{t.url}}</p>
                    <p><b>Risk:</b> <span style="color:red; font-weight:900;">{{t.risk}}</span></p>
                    <p><b>Reasons:</b> {{t.reasons}}</p>
                </div>
                {% endfor %}
            {% endif %}
        </div>

        <div class="footer">
            LayerUS v1.0 | by CodeWizards 🚀
        </div>

    </div>
</body>
</html>
"""

BLOCK_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LayerUS - Blocked</title>
    <style>
        body {
            margin: 0;
            font-family: Arial;
            background: radial-gradient(circle at top, #1a0000, #000);
            color: white;
            padding: 40px;
        }

        .box {
            border: 2px solid red;
            padding: 25px;
            border-radius: 15px;
            background: rgba(255, 0, 0, 0.08);
            box-shadow: 0px 0px 25px rgba(255,0,0,0.5);
        }

        h1 {
            color: red;
            text-shadow: 0 0 10px rgba(255,0,0,0.7);
        }

        ul {
            padding-left: 20px;
        }

        a {
            display: inline-block;
            margin-top: 20px;
            color: cyan;
            text-decoration: none;
            font-weight: bold;
        }

        a:hover {
            text-decoration: underline;
        }
    </style>
</head>

<body>
    <div class="box">
        <h1>🚫 BLOCKED by LayerUS Firewall</h1>
        <p><b>URL:</b> {{url}}</p>
        <p><b>Risk Score:</b> {{risk}}</p>

        <h3>Reasons:</h3>
        <ul>
            {% for r in reasons %}
            <li>{{r}}</li>
            {% endfor %}
        </ul>

        <a href="/">⬅ Back to Dashboard</a>
    </div>
</body>
</html>
"""

# -----------------------------
# Helper function for status
# -----------------------------
def classify_risk(risk):
    if risk < 30:
        return "SAFE", "safe"
    elif risk < 60:
        return "WARNING", "warn"
    else:
        return "BLOCKED", "block"

# -----------------------------
# ROUTES
# -----------------------------
@app.route("/")
def home():
    safe_count = sum(1 for h in history_logs if h["status"] == "SAFE")
    warn_count = sum(1 for h in history_logs if h["status"] == "WARNING")
    blocked_count = sum(1 for h in history_logs if h["status"] == "BLOCKED")

    return render_template_string(
        HOME_PAGE,
        history=history_logs[::-1],   # newest first
        threats=threat_logs[::-1],    # newest first
        total_visits=len(history_logs),
        safe_count=safe_count,
        warn_count=warn_count,
        blocked_count=blocked_count
    )

@app.route("/visit", methods=["POST"])
def visit():
    url = request.form["url"]
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Scan URL
    result = scan_url(url)
    risk = result["risk_score"]
    reasons = result["reasons"]

    status, status_class = classify_risk(risk)

    # Add to history logs
    history_logs.append({
        "time": timestamp,
        "url": url,
        "risk": risk,
        "status": status,
        "status_class": status_class
    })

    # Block if malicious
    if risk >= BLOCK_THRESHOLD:
        threat_logs.append({
            "time": timestamp,
            "url": url,
            "risk": risk,
            "reasons": ", ".join(reasons)
        })
        return render_template_string(BLOCK_PAGE, url=url, risk=risk, reasons=reasons)

    # If safe -> load and show webpage
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url, wait_until="networkidle", timeout=60000)
        html = page.content()
        browser.close()

    return html

# -----------------------------
# RUN APP
# -----------------------------
if __name__ == "__main__":
    app.run(port=5000, debug=True)
