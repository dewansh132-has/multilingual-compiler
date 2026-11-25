# -*- coding: utf-8 -*-
import os
import sys

print("Current working directory:", os.getcwd())
env_path = os.path.join(os.getcwd(), ".env")
print(".env file exists:", os.path.isfile(env_path))

k_env = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
print(f"In current os.environ: present: {'yes' if k_env else 'no'}, length {len(k_env) if k_env else 0}")

if os.path.isfile(env_path):
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if "KEY" in k or "GEMINI" in k:
                    print(f"In .env file: {k} present: yes, length {len(v)}")
                os.environ[k] = v

k_after = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
print(f"After loading .env: present: {'yes' if k_after else 'no'}, length {len(k_after) if k_after else 0}")
