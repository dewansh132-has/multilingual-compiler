# -*- coding: utf-8 -*-
"""
app.py — Main Entry Point for the VITAL Multilingual Web IDE

Usage:
    python app.py

Then open your browser to:
    http://localhost:8000
"""

import os
import sys
import webbrowser

# Ensure UTF-8 console output on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Load environment variables from .env before importing server
def _load_env():
    env_file = os.path.join(PROJECT_ROOT, '.env')
    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv(env_file)
    except ImportError:
        if os.path.isfile(env_file):
            try:
                with open(env_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#') or '=' not in line:
                            continue
                        k, v = line.split('=', 1)
                        k = k.strip()
                        v = v.strip()
                        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                            v = v[1:-1]
                        if k and k not in os.environ:
                            os.environ[k] = v
            except Exception:
                pass

_load_env()

from web.server import app

def main():
    port = int(os.environ.get('PORT', 8000))
    host = os.environ.get('HOST', '127.0.0.1')
    has_key = bool(os.environ.get('GEMINI_API_KEY') or os.environ.get('GOOGLE_API_KEY'))
    ai_status = "AI: Gemini (key configured)" if has_key else "AI: Gemini (no key; running deterministic fixes only)"
    
    print("=" * 65)
    print("  🌐 VITAL MULTILINGUAL PROGRAMMING LANGUAGE COMPILER — WEB IDE")
    print("=" * 65)
    print(f"  • IDE Interface:     http://{host}:{port}")
    print(f"  • API Endpoint:      http://{host}:{port}/api/run")
    print(f"  • Supported Scripts: English, Hindi, Telugu, Bengali, Marathi, Nepali")
    print(f"  • Compiler Engine:   Existing VITAL Pipeline (src/main.py)")
    print(f"  • Desktop GUI:       src/gui.py remains available")
    print(f"  • {ai_status}")
    print("=" * 65)
    print("  Press Ctrl+C to stop the server.\n")

    # Start Flask dev server
    app.run(host=host, port=port, debug=False, threaded=True)

if __name__ == '__main__':
    main()
