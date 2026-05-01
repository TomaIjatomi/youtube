"""
server.py — Single command to run the full Episode 2 demo

Starts:
  1. Local HTTP server on port 8765 serving malicious_page.html
  2. The Gradio agent UI on port 7860

Usage:
  python server.py

Then open http://localhost:7860 in your browser.
"""

import os
import sys
import threading
import subprocess
import http.server
import socketserver
from pathlib import Path

PAGE_PORT = 8765
DEMO_DIR  = Path(__file__).parent


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    """Serve files from the demo directory. Only log malicious page requests."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DEMO_DIR), **kwargs)

    def log_message(self, format, *args):
        if args and "malicious_page" in str(args[0]):
            print(f"  🌐 Agent fetched: {self.path}")


def start_page_server():
    with socketserver.TCPServer(("", PAGE_PORT), QuietHandler) as httpd:
        httpd.serve_forever()


def check_env():
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        env_file = DEMO_DIR / ".env"
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line.startswith("GEMINI_API_KEY="):
                    key = line.split("=", 1)[1].strip().strip('"').strip("'")
                    os.environ["GEMINI_API_KEY"] = key
                    break

    if not key:
        print("\n  ❌  GEMINI_API_KEY not found.")
        print("      Create a .env file in this directory:")
        print("      GEMINI_API_KEY=your_key_here\n")
        sys.exit(1)

    print(f"  ✓ API key found ({key[:8]}...)")
    return key


if __name__ == "__main__":
    print("\n" + "=" * 56)
    print("  Agent Defence Demo — Episode 2")
    print("  You Saw My Agent Get Hacked — Here's How I Fixed It")
    print("=" * 56 + "\n")

    check_env()

    # Start page server in background thread
    t = threading.Thread(target=start_page_server, daemon=True)
    t.start()
    print(f"  ✓ Page server: http://localhost:{PAGE_PORT}")
    print(f"    Malicious page: http://localhost:{PAGE_PORT}/malicious_page.html\n")
    print(f"  Starting agent UI at http://localhost:7860 ...")
    print("  (This will open automatically)\n")

    # Run agent.py — blocks until Ctrl+C
    subprocess.run([sys.executable, str(DEMO_DIR / "agent.py")], check=True)
