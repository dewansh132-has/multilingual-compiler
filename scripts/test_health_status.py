# -*- coding: utf-8 -*-
import os
import sys
import json

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

env_file = os.path.join(repo_root, ".env")
with open(env_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip().strip("'\"")

from web.gemini_client import ai_client

ok, msg, details = ai_client.check_health(force_refresh=True)
print(f"Health ok: {ok}")
print(f"Health msg: {msg}")
print(f"Target model: {details.get('target_model')}")
print(f"Resolved model: {details.get('resolved_model')}")
print(f"Latency: {details.get('latency_ms')}ms")
