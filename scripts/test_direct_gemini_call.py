# -*- coding: utf-8 -*-
import os
import sys
import json
import urllib.request
import urllib.error

# Load .env
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
print(f"Key present: {'yes' if api_key else 'no'}, length: {len(api_key) if api_key else 0}")

if not api_key:
    print("ERROR: No API key found in .env or os.environ")
    sys.exit(1)

base_url = "https://generativelanguage.googleapis.com/v1beta"

# 1. Test List Models
print("\n--- 1. Testing GET /v1beta/models ---")
try:
    req = urllib.request.Request(
        f"{base_url}/models",
        headers={
            "Accept": "application/json",
            "x-goog-api-key": api_key
        },
        method="GET"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        print(f"List Models HTTP Status: {resp.status}")
        data = json.loads(resp.read().decode("utf-8"))
        models = [m.get("name", "") for m in data.get("models", [])]
        print(f"Total models available: {len(models)}")
        # Print models supporting generateContent
        supported = [
            m.get("name", "").replace("models/", "")
            for m in data.get("models", [])
            if "generateContent" in m.get("supportedGenerationMethods", [])
        ]
        print(f"Models supporting generateContent ({len(supported)}):")
        for sm in supported[:15]:
            print(f"  - {sm}")
except urllib.error.HTTPError as e:
    err_body = e.read().decode("utf-8", errors="replace")
    print(f"HTTPError {e.code}: {e.reason}\nBody: {err_body}")
except Exception as e:
    print(f"Exception listing models: {e}")

# 2. Test generateContent using web/gemini_client.py
sys.path.insert(0, repo_root)
from web.gemini_client import GeminiClient

client = GeminiClient()
print(f"\n--- 2. Client config ---")
cfg = client.get_config()
print(f"model_name: {cfg.get('model_name')}")
print(f"model_fast: {cfg.get('model_fast')}")
print(f"model_advanced: {cfg.get('model_advanced')}")

print("\n--- 3. Testing client.check_health() ---")
h_ok, h_msg, h_details = client.check_health(force_refresh=True)
print(f"Health ok: {h_ok}")
print(f"Health message: {h_msg}")
print(f"Health details: {json.dumps(h_details, indent=2)}")

print("\n--- 4. Testing client.chat() ---")
res = client.chat(
    messages=[{"role": "user", "content": "Return valid JSON only: {\"status\": \"ok\", \"hello\": \"vital\"}"}],
    tier="fast",
    timeout=20.0
)
print(f"Chat success: {res.get('success')}")
print(f"Chat model used: {res.get('model')}")
print(f"Chat content: {res.get('content')}")
if not res.get("success"):
    print(f"Chat error: {res.get('error')}")
