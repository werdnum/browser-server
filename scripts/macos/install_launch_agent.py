#!/usr/bin/env python3
"""Install, reload, or remove the macOS Aqua LaunchAgents for browser-server.

Writes two per-user LaunchAgents under ``~/Library/LaunchAgents``:
- ``dev.andrewgarrett.browser-server`` (KeepAlive uvicorn service in Aqua session)
- ``dev.andrewgarrett.browser-server-updater`` (every 5 minutes git updater with best-effort active-session deferral)
"""

from __future__ import annotations

import argparse
import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

SERVICE_LABEL = "dev.andrewgarrett.browser-server"
UPDATER_LABEL = "dev.andrewgarrett.browser-server-updater"
CHROME_MACOS_APP = Path("/Applications/Google Chrome.app")

ENV_TEMPLATE = """# browser-server macOS LaunchAgent configuration (mode 0600)
# Required: shared bearer token matching Kubernetes Secret/browser-server (key: service-token)
BROWSER_HANDOFF_SERVICE_TOKEN=REPLACE_WITH_SERVICE_TOKEN

# Optional: place the browser-server Keychute client token in ~/.config/browser-server/keychute.token
# (mode 0600), or set BROWSER_KEYCHUTE_TOKEN_FILE explicitly.
# BROWSER_KEYCHUTE_TOKEN_FILE=/Users/admin/.config/browser-server/keychute.token

# Defaults applied by run_service.sh when unset:
# BROWSER_HEADED=1
# BROWSER_CONTEXT_PERSISTENT=1
# BROWSER_CHROMIUM_CHANNEL=chrome
# BROWSER_REMOTE_MODE=auto
# BROWSER_TIMEZONE=Australia/Sydney
# BROWSER_HANDOFF_PUBLIC_URL=https://browser.andrewgarrett.dev
# UVICORN_HOST=0.0.0.0
# UVICORN_PORT=8000
"""


def build_service_plist(repo_root: Path, log_dir: Path) -> bytes:
    payload = {
        "Label": SERVICE_LABEL,
        "ProgramArguments": ["/bin/bash", str(repo_root / "scripts" / "macos" / "run_service.sh")],
        "WorkingDirectory": str(repo_root),
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 5,
        "LimitLoadToSessionType": "Aqua",
        "StandardOutPath": str(log_dir / "service.log"),
        "StandardErrorPath": str(log_dir / "service.log"),
    }
    return plistlib.dumps(payload)


def build_updater_plist(repo_root: Path, log_dir: Path, interval_seconds: int = 300) -> bytes:
    payload = {
        "Label": UPDATER_LABEL,
        "ProgramArguments": ["/bin/bash", str(repo_root / "scripts" / "macos" / "self_update.sh")],
        "WorkingDirectory": str(repo_root),
        "RunAtLoad": True,
        "StartInterval": interval_seconds,
        "LimitLoadToSessionType": "Aqua",
        "StandardOutPath": str(log_dir / "updater.log"),
        "StandardErrorPath": str(log_dir / "updater.log"),
    }
    return plistlib.dumps(payload)


def _ensure_venv_and_chrome(repo_root: Path) -> None:
    uv = shutil.which("uv")
    venv_python = repo_root / ".venv" / "bin" / "python"
    if uv and (repo_root / "uv.lock").exists():
        subprocess.run([uv, "sync", "--frozen", "--no-dev"], cwd=repo_root, check=True)
    else:
        if not venv_python.exists():
            subprocess.run([sys.executable, "-m", "venv", str(repo_root / ".venv")], cwd=repo_root, check=True)
        subprocess.run([str(venv_python), "-m", "pip", "install", "-e", str(repo_root)], cwd=repo_root, check=True)

    if sys.platform == "darwin" and not CHROME_MACOS_APP.exists():
        patchright_bin = repo_root / ".venv" / "bin" / "patchright"
        if patchright_bin.exists():
            print("Google Chrome.app not found; installing Chrome via patchright...")
            subprocess.run([str(patchright_bin), "install", "chrome"], cwd=repo_root, check=True)


def _ensure_env_file(env_file: Path) -> bool:
    """Ensure config directory and env file exist; return True if service token is configured."""
    env_file.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(env_file.parent, 0o700)
    if not env_file.exists():
        env_file.write_text(ENV_TEMPLATE, encoding="utf-8")
        os.chmod(env_file, 0o600)
        return False
    os.chmod(env_file, 0o600)
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        cleaned = value.strip().strip('"').strip("'")
        if key.strip() == "BROWSER_HANDOFF_SERVICE_TOKEN" and cleaned and cleaned != "REPLACE_WITH_SERVICE_TOKEN":
            return True
    return False


def _launchctl_reload(plist_path: Path) -> None:
    domain = f"gui/{os.getuid()}"
    subprocess.run(["launchctl", "bootout", domain, str(plist_path)], check=False, capture_output=True)
    subprocess.run(["launchctl", "bootstrap", domain, str(plist_path)], check=True)


def _launchctl_unload(plist_path: Path) -> None:
    domain = f"gui/{os.getuid()}"
    subprocess.run(["launchctl", "bootout", domain, str(plist_path)], check=False, capture_output=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install or remove browser-server macOS LaunchAgents.")
    parser.add_argument("--uninstall", action="store_true", help="Boot out and remove installed LaunchAgent plists.")
    parser.add_argument("--no-load", action="store_true", help="Write plists and .venv without calling launchctl.")
    parser.add_argument(
        "--update-interval",
        type=int,
        default=300,
        help="Polling interval in seconds for the self-updater LaunchAgent (default: 300).",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[2]
    home = Path.home()
    agents_dir = home / "Library" / "LaunchAgents"
    log_dir = home / "Library" / "Logs" / "browser-server"
    env_file = Path(os.environ.get("BROWSER_SERVER_ENV_FILE", str(home / ".config" / "browser-server" / "env")))

    service_plist = agents_dir / f"{SERVICE_LABEL}.plist"
    updater_plist = agents_dir / f"{UPDATER_LABEL}.plist"

    if args.uninstall:
        if sys.platform == "darwin":
            _launchctl_unload(updater_plist)
            _launchctl_unload(service_plist)
        updater_plist.unlink(missing_ok=True)
        service_plist.unlink(missing_ok=True)
        print(f"Removed {service_plist} and {updater_plist}")
        return 0

    _ensure_venv_and_chrome(repo_root)
    token_ready = _ensure_env_file(env_file)

    agents_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    service_plist.write_bytes(build_service_plist(repo_root, log_dir))
    updater_plist.write_bytes(build_updater_plist(repo_root, log_dir, interval_seconds=args.update_interval))

    print(f"Wrote {service_plist}")
    print(f"Wrote {updater_plist}")
    print(f"Logs: {log_dir}")

    if args.no_load or sys.platform != "darwin":
        return 0

    if not token_ready:
        print(f"\nAction needed before loading: set BROWSER_HANDOFF_SERVICE_TOKEN in {env_file} (mode 0600),")
        print("then run `make install-macos-agent` again to bootstrap both LaunchAgents.")
        return 0

    _launchctl_reload(service_plist)
    _launchctl_reload(updater_plist)
    print(f"Loaded {SERVICE_LABEL} and {UPDATER_LABEL} in gui/{os.getuid()}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
