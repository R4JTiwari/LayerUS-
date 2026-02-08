# 🛡️ LayerUS (Agentic Browser Security)

LayerUS is a cybersecurity prototype that detects **prompt injection attacks**, **phishing pages**, and **data exfiltration attempts** by scanning webpage content and generating a **risk score**.

It works like a **secure browser app** where the user enters a URL → the system scans it → blocks malicious pages before loading.

---

## 🚀 Features

✅ Scan any URL before loading  
✅ Detect malicious patterns like:
- Prompt Injection Attacks
- Hidden instructions / hidden text
- Credential phishing traps
- Suspicious login forms
- Redirect patterns
- Data exfiltration attempts

✅ Generates **Risk Score (0–100)**  
✅ Provides **Threat Reasons**  
✅ Automatically blocks malicious pages  
✅ Simple secure browser UI dashboard  
✅ URL History Logs + Threat Report Panel (optional)

---

## 🧠 How It Works

### 🔍 Workflow
1. User enters a website URL in the Secure Browser UI.
2. Scanner fetches the webpage content.
3. Risk score is calculated using rule-based detection.
4. If `risk_score >= threshold` → page is blocked.
5. If safe → webpage is rendered.

---

## 📂 Project Structure

agentic-browser-security/
│
├── scanner.py # Core scanner logic (risk scoring + keyword detection)
├── secure_browser.py # Flask Secure Browser UI (main application)
├── malicious_test.html # Example malicious test page (optional)
├── requirements.txt # Python dependencies
└── README.md # Documentation


---

## ⚙️ Requirements

- Python 3.9+
- Flask
- Playwright
- BeautifulSoup4
- Requests

---

## 🛠️ Installation

1️⃣ Clone / Download Project
```bash
git clone <repo-link>
cd agentic-browser-security

2️⃣ Create Virtual Environment
python -m venv venv
Activate:

Windows

venv\Scripts\activate
Linux/Mac

source venv/bin/activate
3️⃣ Install Dependencies
pip install -r requirements.txt
4️⃣ Install Playwright Browsers
playwright install
▶️ Run the Secure Browser App
Run:

python secure_browser.py
Then open in browser:

http://127.0.0.1:5000
Now enter any URL and scan it.

🧪 Testing with Malicious Page (Optional)
Step 1: Start local server
python -m http.server 8000
Step 2: Open in secure browser
http://127.0.0.1:8000/malicious_test.html
If your test file contains malicious prompt injection keywords, it will show:

🚫 BLOCKED by AI Secure Browser Firewall

📊 Risk Scoring System
Risk Score Range	Status
0 – 29	SAFE ✅
30 – 59	WARNING ⚠️
60+	MALICIOUS 🚫 BLOCKED
🔥 Threat Detection Examples
The scanner flags phrases like:

ignore previous instructions

system prompt

send credentials

upload all files

extract passwords

override agent rules

download and execute

Also detects suspicious HTML patterns such as:

hidden malicious text (display:none, opacity:0)

<input type="password"> forms

suspicious <form action="external">

👨‍💻 Technologies Used
Python

Flask

Playwright

BeautifulSoup4

HTML/CSS

🎯 Use Case
This prototype can be used for:

Agentic Browser Security research

Prompt Injection defense systems

SaaS phishing detection demos

Hackathon cybersecurity projects