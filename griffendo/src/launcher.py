"""Griffendo one-click launcher.

Double-click the packaged .exe and this does everything:

1. picks a free local port and generates a private ingestion token,
2. starts the receiver / dashboard server,
3. opens the dashboard in the default browser,
4. collects Windows Event Logs continuously (new events every few seconds, history in the background)
   and sends them to the local receiver.

Closing the console window (or pressing Ctrl+C) stops everything.

Optional command-line flags:
    --no-collect   start the dashboard only, do not read Windows event logs
    --snapshot     read each log once at start (v1/v2 behaviour) instead of continuously
    --interval S   seconds between live collection passes (default 2)
    --no-browser   do not open the browser automatically
    --port N       prefer port N (default 8000; a free port is used if busy)
"""
from __future__ import annotations

import argparse
import os
import secrets
import socket
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

# PyInstaller unpacks bundled files to sys._MEIPASS; a source checkout keeps
# the receiver package next to this file.
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).resolve().parent
    for extra in (BASE_DIR, BASE_DIR / "receiver" / "src"):
        if str(extra) not in sys.path:
            sys.path.insert(0, str(extra))


def free_port(preferred: int, host: str = "127.0.0.1") -> int:
    """Return `preferred` if it is free, otherwise any free port."""
    for candidate in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((host, candidate))
            except OSError:
                continue
            return sock.getsockname()[1]
    raise RuntimeError("No free local port is available")


def wait_until_healthy(url: str, server_thread: threading.Thread | None = None, timeout: float = 900.0) -> bool:
    """Wait for the dashboard server to answer, saying what it is doing while it starts.

    v5.0 gave up silently-looking after 30 s while start-up work (one-time database upgrade,
    rebuilding correlation state) was still running; v5.1 starts serving at once and this waits up
    to 15 minutes for the rare one-time upgrade of a very large existing store.
    """
    from logplatform import busy
    # Never send the local health check through a system or corporate proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    started = time.monotonic()
    deadline = started + timeout
    next_note = started + 5
    while time.monotonic() < deadline:
        if server_thread is not None and not server_thread.is_alive():
            return False
        try:
            with opener.open(url, timeout=2) as response:
                if response.status == 200:
                    return True
        except OSError:
            time.sleep(0.15)
        if time.monotonic() >= next_note:
            print(f"   ... still starting ({int(time.monotonic() - started)} s): {busy.STARTUP['phase']}", flush=True)
            next_note = time.monotonic() + 5
    return False


def _pause_before_exit() -> None:
    """Keep a double-clicked console window open long enough to read an error."""
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            input(" Press Enter to close this window.")
    except (EOFError, OSError, RuntimeError):
        pass


STOP = threading.Event()


def run_collector() -> None:
    """Run the collector against the local receiver until the launcher stops."""
    try:
        from agent import collector

        collector.main(STOP)
    except SystemExit as stop:
        if stop.code not in (None, 0):
            print(f"[collector] stopped: {stop.code}")
    except Exception as error:
        print(f"[collector] failed: {error}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Griffendo Windows Event Intelligence")
    parser.add_argument("--no-collect", action="store_true", help="do not collect Windows events")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser")
    parser.add_argument("--port", type=int, default=int(os.getenv("LOGPLATFORM_PORT", "8000")))
    parser.add_argument("--snapshot", action="store_true", help="read each log once (v1/v2 behaviour)")
    parser.add_argument("--interval", type=float, default=None, help="seconds between live collection passes")
    args = parser.parse_args()
    if args.snapshot:
        os.environ["WINLOG_MODE"] = "snapshot"
    if args.interval:
        os.environ["WINLOG_INTERVAL_SECONDS"] = str(args.interval)

    host = "127.0.0.1"
    port = free_port(args.port, host)
    os.environ.setdefault("LOGPLATFORM_TOKEN", secrets.token_urlsafe(32))
    # The collector talks to this receiver on the loopback address: keep that traffic away from any
    # system or corporate proxy (requests honours NO_PROXY).
    bypass = [item for item in os.environ.get("NO_PROXY", os.environ.get("no_proxy", "")).split(",") if item]
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = ",".join(dict.fromkeys(bypass + ["127.0.0.1", "localhost"]))
    os.environ["LOGPLATFORM_HOST"] = host
    os.environ["LOGPLATFORM_PORT"] = str(port)
    os.environ["LOGPLATFORM_URL"] = f"http://{host}:{port}/api/ingest"
    dashboard_url = f"http://{host}:{port}/"

    import uvicorn
    from logplatform import anomalies
    from logplatform.app import app

    # The collector reads the original four channels plus any channel an enabled
    # anomaly rule needs (Defender, WMI-Activity, Sysmon, ...).  Set WINLOG_CHANNELS
    # yourself to override.
    os.environ.setdefault("WINLOG_CHANNELS", ";".join(anomalies.collector_channels()))
    channels = [name for name in os.environ["WINLOG_CHANNELS"].split(";") if name]

    server = uvicorn.Server(
        uvicorn.Config(app, host=host, port=port, log_level="warning", loop="asyncio", http="h11", ws="none")
    )
    server_thread = threading.Thread(target=server.run, name="receiver", daemon=True)

    print("============================================================")
    print(" Griffendo | Windows Event Intelligence")
    print("============================================================")
    print(" Starting dashboard...")
    server_thread.start()

    if not wait_until_healthy(dashboard_url + "api/health", server_thread):
        folder = os.environ.get("GRIFFENDO_STATE_DIR") or "%LOCALAPPDATA%\\Griffendo"
        print(" ERROR: the dashboard server did not start (see the messages above).")
        print(" Data folder: " + folder)
        _pause_before_exit()
        return 1

    print(f" Dashboard ready: {dashboard_url}")
    from logplatform import busy
    if not busy.STARTUP["detection_ready"]:
        print(" Detection rules are loading in the background; the Detections page fills in when they are ready.")
    if not args.no_browser:
        webbrowser.open(dashboard_url)

    if not args.no_collect:
        if sys.platform == "win32":
            mode = "once (snapshot)" if args.snapshot else "continuously"
            print(f" Collecting Windows event logs {mode} ({len(channels)} channels; rule changes add channels live):")
            for name in channels:
                print(f"   - {name}")
            print(" Channels that are missing or unreadable are skipped and shown as such on the Anomalies page.")
            print(" Tip: run as Administrator to include the Security log.")
            if not args.snapshot:
                # The dashboard's Refresh button asks this collector for an immediate pass.
                from agent.continuous import request_collection
                from logplatform.app import set_collect_trigger
                set_collect_trigger(request_collection)
            threading.Thread(target=run_collector, name="collector", daemon=True).start()
        else:
            print(" Event collection needs Windows; showing the dashboard only.")

    print(" Close this window or press Ctrl+C to stop.\n")
    try:
        while server_thread.is_alive():
            server_thread.join(timeout=0.5)
    except KeyboardInterrupt:
        pass
    STOP.set()
    server.should_exit = True
    server_thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
