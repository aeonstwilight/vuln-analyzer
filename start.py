#!/usr/bin/env python3
"""
Single-command launcher for VulnAnalyzer.
Builds the React frontend on first run, then starts the FastAPI server.

Usage:
    python start.py              # default port 8000
    python start.py --port 9000  # custom port
    python start.py --rebuild    # force frontend rebuild
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
DIST = FRONTEND / "dist"


def run(cmd, cwd=None, check=True):
    # shell=True required on Windows so .cmd wrappers (npm, node) are found
    result = subprocess.run(cmd, cwd=str(cwd or ROOT), check=check,
                            shell=(sys.platform == "win32"))
    return result.returncode


def check_node():
    r = subprocess.run(["node", "--version"], capture_output=True)
    if r.returncode != 0:
        print("ERROR: Node.js is not installed or not on PATH.")
        print("Download it from https://nodejs.org and re-run this script.")
        sys.exit(1)


def build_frontend(force=False):
    if DIST.exists() and not force:
        return
    check_node()
    print("Building frontend" + (" (forced rebuild)" if force else " (first run)") + "...")
    run(["npm", "install"], cwd=FRONTEND)
    run(["npm", "run", "build"], cwd=FRONTEND)
    print("Frontend built successfully.\n")


def ensure_backend_deps():
    try:
        import fastapi, uvicorn, pandas, reportlab, aiofiles  # noqa
    except ImportError:
        print("Installing backend dependencies...")
        run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=BACKEND)
        print("Dependencies installed.\n")


def main():
    parser = argparse.ArgumentParser(description="VulnAnalyzer launcher")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--rebuild", action="store_true", help="Force frontend rebuild")
    args = parser.parse_args()

    build_frontend(force=args.rebuild)
    ensure_backend_deps()

    url = f"http://localhost:{args.port}"
    print(f"Starting VulnAnalyzer at {url}")
    print("Press Ctrl+C to stop.\n")

    os.chdir(BACKEND)
    subprocess.run([
        sys.executable, "-m", "uvicorn", "main:app",
        "--host", "0.0.0.0",
        "--port", str(args.port),
    ])


if __name__ == "__main__":
    main()
