# -*- coding: utf-8 -*-
import os
import sys
import json
import urllib.request
import urllib.error

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_file = os.path.join(repo_root, ".env")
if os.path.isfile(env_file):
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v

api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
base_url = "https://generativelanguage.googleapis.com/v1beta"

test_models = [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-flash-latest",
    "gemini-flash-lite-latest",
    "gemini-2.5-pro",
    "gemini-3-flash-preview",
    "gemini-3.1-flash-lite"
]

payload = json.dumps({
    "contents": [{"parts": [{"text": "Return JSON: {\"status\": \"ok\"}"}]}],
    "generationConfig": {"temperature": 0.1, "maxOutputTokens": 50}
}).encode("utf-8")

for m in test_models:
    url = f"{base_url}/models/{m}:generateContent"
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            print(f"[OK] Model '{m}' SUCCESS (HTTP {resp.status}): {text.strip()[:60]}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"[FAIL] Model '{m}' HTTPError {e.code}: {e.reason} -> {body[:100]}")
    except Exception as e:
        print(f"[FAIL] Model '{m}' Exception: {e}")
