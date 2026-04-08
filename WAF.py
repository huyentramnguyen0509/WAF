from flask import Flask, request, Response
import requests
import joblib
import urllib.parse
import html
import re
import numpy as np
from math import log2
from collections import Counter
from sklearn.base import BaseEstimator, TransformerMixin
from colorama import Fore, Style, init
import datetime
from sklearn.preprocessing import StandardScaler

init(autoreset=True)

# ==============================
# FEATURE CLASS
# ==============================

def calculate_entropy(text):
    if not text:
        return 0
    counter = Counter(text)
    length = len(text)
    return -sum((count/length) * log2(count/length) for count in counter.values())


class StatisticalFeatures(BaseEstimator, TransformerMixin):

    def fit(self, x, y=None):
        return self

    def transform(self, posts):

        features = []

        for text in posts:

            length = len(text)
            entropy = calculate_entropy(text)
            chunk_ent = chunk_entropy(text)

            special_chars = len(re.findall(r'[^a-zA-Z0-9\s]', text))
            digit_count = len(re.findall(r'\d', text))

            sqli_signs = text.count("'") + text.count("--") + text.count(";") + text.count("/*")
            xss_signs = text.count("<") + text.count(">") + text.count("script") + text.count("alert")
            path_signs = text.count("../") + text.count("etc/passwd")

            features.append([
                length,
                entropy,
                chunk_ent,
                special_chars / (length + 1),
                digit_count / (length + 1),
                sqli_signs,
                xss_signs,
                path_signs
            ])

        return np.array(features)

class AdvancedSecurityFeatures(BaseEstimator, TransformerMixin):

    def fit(self, x, y=None):
        return self

    def transform(self, posts):
        features = []

        sql_keywords = [
            "select","union","insert","update","delete","drop",
            "where","or","and","sleep","benchmark",
            "from","not","like","in","exists"
        ]

        xss_keywords = [
            "<script>","<img","<iframe","javascript:",
            "alert","onerror","onload","eval"
        ]

        cmd_keywords = [
            "cmd","exec","system","bash","sh",
            "powershell","/bin/bash","/etc/passwd"
        ]

        # compile OUTSIDE loop
        sql_pattern = re.compile(r'\b(' + '|'.join(map(re.escape, sql_keywords)) + r')\b', re.IGNORECASE)
        xss_pattern = re.compile('|'.join(map(re.escape, xss_keywords)), re.IGNORECASE)
        cmd_pattern = re.compile('|'.join(map(re.escape, cmd_keywords)), re.IGNORECASE)

        for text in posts:

            length = len(text) + 1

            # ===== SQL =====
            sql_count = len(sql_pattern.findall(text))
            sql_ratio = sql_count / length

            # ===== XSS =====
            xss_count = len(xss_pattern.findall(text))
            xss_ratio = xss_count / length

            # ===== CMD =====
            cmd_count = len(cmd_pattern.findall(text))
            cmd_ratio = cmd_count / length

            # ===== Logic =====
            logic_true = int(bool(re.search(r'1\s*=\s*1|true', text, re.IGNORECASE)))
            logic_false = int(bool(re.search(r'1\s*=\s*0|false', text, re.IGNORECASE)))

            # ===== Obfuscation =====
            encoded = len(re.findall(r'%[0-9a-fA-F]{2}', text))
            hex_obfuscation = len(re.findall(r'\\x[0-9a-fA-F]{2}', text))
            unicode_obfuscation = len(re.findall(r'\\u[0-9a-fA-F]{4}', text))
            base64_like = len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text))
            mixed_case = int(bool(re.search(r'[a-z][A-Z]|[A-Z][a-z]', text)))

            features.append([
                sql_count,
                sql_ratio,
                xss_count,
                xss_ratio,
                cmd_count,
                cmd_ratio,
                logic_true,
                logic_false,
                encoded,
                hex_obfuscation,
                unicode_obfuscation,
                base64_like,
                mixed_case
            ])

        return np.array(features)

class HeaderAnomalyFeatures(BaseEstimator, TransformerMixin):

    def fit(self, x, y=None):
        return self

    def transform(self, posts):
        features = []

        for text in posts:

            user_agent_missing = int("user-agent" not in text)
            referer_missing = int("referer" not in text)

            suspicious_agents = int(any(bot in text for bot in [
                "sqlmap","nikto","crawler","bot","scan"
            ]))

            long_token = int(len(max(text.split(), key=len, default="")) > 50)

            many_params = int(text.count("=") > 5)

            unusual_method = int(any(m in text for m in [
                "put","delete","trace","connect"
            ]))

            features.append([
                user_agent_missing,
                referer_missing,
                suspicious_agents,
                long_token,
                many_params,
                unusual_method
            ])

        return np.array(features)

model = joblib.load("final_model.pkl")

app = Flask(__name__)

DVWA_URL = "http://127.0.0.1"

def deep_decode(text):

    if not isinstance(text, str) or text == "":
        return "empty"

    try:

        for _ in range(2):
            text = urllib.parse.unquote(text)
            text = html.unescape(text)

        text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)

        return text.lower()

    except:
        return str(text).lower()

def chunk_entropy(text, size=10):
    if not text:
        return 0
    return max([
        calculate_entropy(text[i:i+size])
        for i in range(0, len(text), size)
    ])

def preprocess_request(req):

    path = req.path
    query = req.query_string.decode()

    body = req.get_data(as_text=True)

    headers = " ".join([f"{k}:{v}" for k,v in req.headers.items()])

    text = path + " " + query + " " + body + " " + headers

    text = deep_decode(text)

    return text

def is_static_file(path):

    static_ext = (
        ".css",
        ".js",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico"
    )

    return path.endswith(static_ext)

def log_attack(payload):

    with open("waf_logs.txt", "a") as f:

        f.write("\n====================\n")
        f.write("TIME: " + str(datetime.datetime.now()) + "\n")
        f.write("IP: " + request.remote_addr + "\n")
        f.write("REQUEST: " + payload + "\n")

def block_page():

    page = f"""
<html>
<head>
<title>403 Forbidden</title>

<style>

body{{
background:#0f172a;
font-family:Arial;
color:white;
text-align:center;
padding-top:120px;
}}

.box{{
background:#1e293b;
width:600px;
margin:auto;
padding:40px;
border-radius:10px;
box-shadow:0 0 25px rgba(0,0,0,0.4);
}}

h1{{
color:#ef4444;
font-size:50px;
}}

h2{{
color:#facc15;
}}

p{{
font-size:18px;
}}

.info{{
margin-top:25px;
color:#94a3b8;
}}

</style>

</head>

<body>

<div class="box">

<h1>403 Forbidden</h1>

<h2>AI Web Application Firewall</h2>

<p>
Your request has been blocked because
the system detected <b>malicious traffic</b>.
</p>

<p>
Possible attack detected:
SQL Injection / XSS / Path Traversal
</p>

<div class="info">

Client IP: {request.remote_addr} <br>
Request Path: {request.path}

</div>

</div>

</body>
</html>
"""

    return page

def forward_to_dvwa():

    url = DVWA_URL + request.full_path

    resp = requests.request(
        method=request.method,
        url=url,
        headers={key: value for key, value in request.headers if key != "Host"},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False
    )

    excluded = ["content-encoding", "content-length", "transfer-encoding", "connection"]

    headers = [
        (name, value)
        for (name, value) in resp.raw.headers.items()
        if name.lower() not in excluded
    ]

    return Response(resp.content, resp.status_code, headers)


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])

def waf_proxy(path):

    print(Fore.YELLOW + "\n[REQUEST]")
    print(Fore.CYAN + request.full_path)

    if is_static_file(request.path):

        print(Fore.GREEN + "[STATIC] Allowed")

        return forward_to_dvwa()

    text = preprocess_request(request)

    print(Fore.MAGENTA + "[MODEL INPUT]", text)

    payload = request.query_string.decode().lower()

    if payload.strip() in ["id=1", "id=1&submit=submit"]:
        print(Fore.GREEN + "NORMAL DVWA REQUEST - ALLOWED (RULE)")
        return forward_to_dvwa()

    prob = model.predict_proba([text])[0][1]

    print(Fore.YELLOW + f"[PROB] Attack probability: {prob:.4f}")

    THRESHOLD = 0.45

    if prob > THRESHOLD:
        print(Fore.RED + "[BLOCKED] Attack detected")

        log_attack(text)

        return Response(block_page(), status=403, mimetype="text/html")

    print(Fore.GREEN + "[ALLOWED] Normal request")

    return forward_to_dvwa()


if __name__ == "__main__":

    print(Fore.CYAN + """
=====================================
        AI Web Application Firewall
=====================================
Proxy Port : 8080
Backend    : DVWA (127.0.0.1)
Model      : Random Forest
=====================================
""")

    app.run(
        host="0.0.0.0",
        port=8080
    )