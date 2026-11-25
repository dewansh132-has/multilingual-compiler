# -*- coding: utf-8 -*-
import os, sys, json, urllib.request, urllib.error

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_file = os.path.join(repo_root, ".env")
if os.path.isfile(env_file):
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip().strip("'\"")

api_key = os.environ.get("GEMINI_API_KEY")
base_url = "https://generativelanguage.googleapis.com/v1beta"

# Get all models that support generateContent
req = urllib.request.Request(f"{base_url}/models", headers={"x-goog-api-key": api_key})
with urllib.request.urlopen(req) as r:
    data = json.loads(r.read())
candidates = [m['name'].replace('models/', '') for m in data['models'] if 'generateContent' in m.get('supportedGenerationMethods', [])]

payload = json.dumps({
    "contents": [{"parts": [{"text": "Say OK"}]}],
    "generationConfig": {"maxOutputTokens": 10}
}).encode("utf-8")

for m in candidates:
    if any(x in m for x in ['image', 'tts', 'audio', 'robotics', 'clip', 'transcribe']): continue
    url = f"{base_url}/models/{m}:generateContent"
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json", "x-goog-api-key": api_key}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            txt = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()
            print(f"[SUCCESS 200] {m}: {txt}")
    except urllib.error.HTTPError as e:
        print(f"[{e.code}] {m}")
    except Exception as e:
        print(f"[ERR] {m}: {e}")
