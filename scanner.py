from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
import hashlib
import time


# -------------------------------
# CONFIG: SECURITY POLICIES
# -------------------------------

PROMPT_INJECTION_KEYWORDS = [
    "ignore previous instructions",
    "disregard above instructions",
    "override system prompt",
    "developer message",
    "system message",
    "your task has changed",
    "new instructions",
    "execute the following",
    "you must comply",
    "this is higher priority",
    "act as a privileged agent",
    "do not follow safety rules",

    "enter your password",
    "verify your account",
    "session expired",
    "authentication required",
    "enter otp",
    "confirm payment",
    "confirm billing details",
    "re-enter your password",

    "upload the file",
    "send all data",
    "post the results to",
    "copy and paste the content",
    "extract all emails",
    "extract all contacts",
    "send system info",

    "download now",
    "install update",
    "run this command",
    "enable notifications",
    "click allow to continue"
]

SUSPICIOUS_DOMAINS = [
    "ngrok",
    "pastebin",
    "webhook.site",
    "discord.com/api/webhooks",
    "tinyurl",
    "bit.ly",
    ".ru",
    ".cn",
    "anonfiles",
    "transfer.sh"
]

# Policy-based action control (0.0.2)
ACTION_ALLOWLIST = ["read", "scroll", "extract_text"]
ACTION_BLOCKLIST = ["type_password", "upload_file", "submit_payment"]

# Risk thresholds
ALLOW_THRESHOLD = 30
WARN_THRESHOLD = 60

# Scalability limit (0.0.4)
MAX_TEXT_NODES = 5000
MAX_TEXT_LENGTH = 500000


# -------------------------------
# CACHE (Scalability optimization)
# -------------------------------

SCAN_CACHE = {}


def hash_page(html):
    return hashlib.md5(html.encode("utf-8")).hexdigest()


# -------------------------------
# STEP 1: OPEN WEBPAGE
# -------------------------------

def open_page(url):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.goto(url, wait_until="networkidle", timeout=60000)
        content = page.content()

        browser.close()
        return content


# -------------------------------
# STEP 2: DOM + CONTENT ANALYSIS (0.0.1)
# -------------------------------

def extract_text(html):
    soup = BeautifulSoup(html, "html.parser")

    visible_text = []
    hidden_text = []
    suspicious_hidden_nodes = []

    text_nodes = soup.find_all(string=True)

    # Scalability protection
    if len(text_nodes) > MAX_TEXT_NODES:
        text_nodes = text_nodes[:MAX_TEXT_NODES]

    for tag in text_nodes:
        parent = tag.parent.name
        style = tag.parent.attrs.get("style", "")

        text = tag.strip()
        if not text:
            continue

        # skip scripts/styles
        if parent in ["script", "style", "meta", "noscript"]:
            continue

        style_lower = style.lower()

        # detect hidden / low visibility
        if ("display:none" in style_lower or
            "visibility:hidden" in style_lower or
            "opacity:0" in style_lower or
            "font-size:0" in style_lower or
            "position:absolute" in style_lower):

            hidden_text.append(text)
            suspicious_hidden_nodes.append(text)

        else:
            visible_text.append(text)

    return visible_text, hidden_text, suspicious_hidden_nodes


# -------------------------------
# STEP 3: PROMPT INJECTION SCAN
# -------------------------------

def scan_for_injection(text_list):
    matches = []

    for text in text_list:
        lowered = text.lower()
        for keyword in PROMPT_INJECTION_KEYWORDS:
            if keyword in lowered:
                matches.append((keyword, text))

    return matches


# -------------------------------
# STEP 4: DETECT LOGIN FORMS
# -------------------------------

def detect_login_form(html):
    soup = BeautifulSoup(html, "html.parser")

    password_inputs = soup.find_all("input", {"type": "password"})
    email_inputs = soup.find_all("input", {"type": "email"})
    forms = soup.find_all("form")

    if password_inputs:
        return True, "Password field detected"
    if email_inputs and forms:
        return True, "Email login form detected"
    if forms and len(forms) > 0:
        return True, "Form detected (possible login)"

    return False, None


# -------------------------------
# STEP 5: DETECT SUSPICIOUS URLS IN TEXT
# -------------------------------

def detect_suspicious_urls(text_list):
    found = []

    for text in text_list:
        urls = re.findall(r'https?://[^\s"]+', text.lower())
        for url in urls:
            for bad in SUSPICIOUS_DOMAINS:
                if bad in url:
                    found.append(url)

    return list(set(found))


# -------------------------------
# STEP 6: DETECT EXTERNAL FORM ACTIONS
# -------------------------------

def detect_external_form_action(html, page_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")

    base_domain = urlparse(page_url).netloc
    external_actions = []

    for form in forms:
        action = form.get("action")
        if action and action.startswith("http"):
            action_domain = urlparse(action).netloc
            if action_domain and action_domain != base_domain:
                external_actions.append(action)

    return external_actions


# -------------------------------
# STEP 7: DETECT REDIRECT SCRIPTS
# -------------------------------

def detect_redirect_scripts(html):
    patterns = [
        "window.location",
        "document.location",
        "location.href",
        "meta http-equiv=\"refresh\"",
        "settimeout(function(){location"
    ]

    hits = []
    lower_html = html.lower()

    for p in patterns:
        if p in lower_html:
            hits.append(p)

    return hits


# -------------------------------
# STEP 8: DOM STRUCTURE THREAT DETECTION (0.0.1)
# -------------------------------

def detect_suspicious_dom_patterns(html):
    soup = BeautifulSoup(html, "html.parser")
    suspicious = []

    # too many iframes = common phishing / tracking trick
    iframes = soup.find_all("iframe")
    if len(iframes) > 2:
        suspicious.append(f"Too many iframes detected ({len(iframes)})")

    # suspicious input fields
    inputs = soup.find_all("input")
    for inp in inputs:
        name = inp.get("name", "")
        if "token" in name.lower() or "secret" in name.lower():
            suspicious.append(f"Suspicious input field name: {name}")

    # suspicious script count
    scripts = soup.find_all("script")
    if len(scripts) > 15:
        suspicious.append(f"High number of scripts ({len(scripts)})")

    return suspicious


# -------------------------------
# STEP 9: RULE-BASED + ML READY RISK SCORING (0.0.2)
# -------------------------------

def calculate_risk(features):
    risk = 0
    reasons = []

    if features["visible_hits"]:
        risk += 40
        reasons.append("Prompt injection found in visible content")

    if features["hidden_hits"]:
        risk += 30
        reasons.append("Prompt injection found in hidden content")

    if features["login_detected"]:
        risk += 25
        reasons.append("Login form detected (credential theft risk)")

    if features["suspicious_urls"]:
        risk += 20
        reasons.append("Suspicious external URLs found")

    if features["external_forms"]:
        risk += 35
        reasons.append("Form submits data to external domain (possible exfiltration)")

    if features["redirects"]:
        risk += 15
        reasons.append("Redirect script detected")

    if features["dom_suspicious"]:
        risk += 15
        reasons.append("Suspicious DOM structure detected")

    if features["hidden_nodes"]:
        risk += 10
        reasons.append("Hidden / low visibility nodes detected")

    # Cap risk score at 100
    if risk > 100:
        risk = 100

    return risk, reasons


# -------------------------------
# STEP 10: POLICY-BASED ACTION CONTROL (0.0.2)
# -------------------------------

def decide_action(risk_score, action_type):
    # allowlist override
    if action_type in ACTION_ALLOWLIST:
        return "ALLOW"

    # blocklist override
    if action_type in ACTION_BLOCKLIST:
        return "BLOCK"

    # risk-based logic
    if risk_score >= WARN_THRESHOLD:
        if action_type in ["type_email", "type_password", "submit", "upload_file"]:
            return "BLOCK"
        return "WARNING"

    if ALLOW_THRESHOLD <= risk_score < WARN_THRESHOLD:
        if action_type == "type_password":
            return "BLOCK"
        return "WARNING"

    return "ALLOW"


# -------------------------------
# STEP 11: MULTI-STEP VERIFICATION SIMULATION (0.0.2)
# -------------------------------

def multi_step_verification(action_type):
    print(f"\n⚠️ Sensitive Action Detected: {action_type}")
    confirm = input("Type YES to confirm agent can proceed: ")
    return confirm.strip().upper() == "YES"


# -------------------------------
# STEP 12: SIMULATE AGENT ACTIONS
# -------------------------------

def simulate_agent_actions(risk_score):
    actions = ["read", "click", "type_email", "type_password", "upload_file", "submit_payment"]

    print("\n--- AGENT ACTION CHECK ---")
    for action in actions:
        decision = decide_action(risk_score, action)

        if decision == "WARNING":
            print(f"Action: {action} -> WARNING (needs verification)")
            allowed = multi_step_verification(action)
            if allowed:
                print("✅ User verified action allowed.")
            else:
                print("⛔ Action blocked by user verification.")
        else:
            print(f"Action: {action} -> {decision}")


# -------------------------------
# MAIN PROGRAM
# -------------------------------

if __name__ == "__main__":
    url = input("Enter website URL: ")

    start = time.time()
    html = open_page(url)
    page_hash = hash_page(html)

    # caching optimization
    if page_hash in SCAN_CACHE:
        print("\n✅ Loaded result from cache")
        result = SCAN_CACHE[page_hash]
    else:
        visible_text, hidden_text, hidden_nodes = extract_text(html)

        # text length protection
        full_text = " ".join(visible_text + hidden_text)
        if len(full_text) > MAX_TEXT_LENGTH:
            full_text = full_text[:MAX_TEXT_LENGTH]

        visible_hits = scan_for_injection(visible_text)
        hidden_hits = scan_for_injection(hidden_text)

        login_detected, login_reason = detect_login_form(html)

        suspicious_urls = detect_suspicious_urls(visible_text + hidden_text)
        external_forms = detect_external_form_action(html, url)
        redirects = detect_redirect_scripts(html)
        dom_suspicious = detect_suspicious_dom_patterns(html)

        features = {
            "visible_hits": visible_hits,
            "hidden_hits": hidden_hits,
            "login_detected": login_detected,
            "suspicious_urls": suspicious_urls,
            "external_forms": external_forms,
            "redirects": redirects,
            "dom_suspicious": dom_suspicious,
            "hidden_nodes": hidden_nodes
        }

        risk_score, reasons = calculate_risk(features)

        result = {
            "risk_score": risk_score,
            "reasons": reasons,
            "login_reason": login_reason,
            "suspicious_urls": suspicious_urls,
            "external_forms": external_forms,
            "redirects": redirects,
            "dom_suspicious": dom_suspicious,
            "visible_hits": visible_hits,
            "hidden_hits": hidden_hits
        }

        SCAN_CACHE[page_hash] = result

def scan_url(url):
    html = open_page(url)

    visible_text, hidden_text, hidden_nodes = extract_text(html)

    visible_hits = scan_for_injection(visible_text)
    hidden_hits = scan_for_injection(hidden_text)

    login_detected, login_reason = detect_login_form(html)

    suspicious_urls = detect_suspicious_urls(visible_text + hidden_text)
    external_forms = detect_external_form_action(html, url)
    redirects = detect_redirect_scripts(html)
    dom_suspicious = detect_suspicious_dom_patterns(html)

    features = {
        "visible_hits": visible_hits,
        "hidden_hits": hidden_hits,
        "login_detected": login_detected,
        "suspicious_urls": suspicious_urls,
        "external_forms": external_forms,
        "redirects": redirects,
        "dom_suspicious": dom_suspicious,
        "hidden_nodes": hidden_nodes
    }

    risk_score, reasons = calculate_risk(features)

    return {
        "risk_score": risk_score,
        "reasons": reasons
    }



    # OUTPUT
    print("\n--- SCAN RESULT ---")
    print(f"Risk Score: {result['risk_score']}")

    if result["risk_score"] < ALLOW_THRESHOLD:
        print("Decision: ALLOW")
    elif result["risk_score"] < WARN_THRESHOLD:
        print("Decision: WARNING")
    else:
        print("Decision: BLOCK")

    print("\nReasons:")
    for r in result["reasons"]:
        print("-", r)

    if result["login_reason"]:
        print("\nLogin Detection:", result["login_reason"])

    if result["suspicious_urls"]:
        print("\nSuspicious URLs Detected:")
        for u in result["suspicious_urls"]:
            print("-", u)

    if result["external_forms"]:
        print("\nExternal Form Actions Detected:")
        for f in result["external_forms"]:
            print("-", f)

    if result["redirects"]:
        print("\nRedirect Indicators Found:")
        for r in result["redirects"]:
            print("-", r)

    if result["dom_suspicious"]:
        print("\nSuspicious DOM Patterns:")
        for d in result["dom_suspicious"]:
            print("-", d)

    if result["visible_hits"] or result["hidden_hits"]:
        print("\nMatched Keywords:")
        for k, t in result["visible_hits"] + result["hidden_hits"]:
            print(f"[{k}] → {t[:80]}...")

    simulate_agent_actions(result["risk_score"])

    end = time.time()
    print(f"\n⏱ Scan Time: {round(end - start, 2)} seconds")
