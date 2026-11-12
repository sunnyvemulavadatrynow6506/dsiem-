"""Who is waiting for the server right now, and what the server is doing at start-up.

The detection worker runs in the same process as the dashboard and the receiver.  Python runs
one thread at a time, so a busy worker slows every page and every ingest call.  The HTTP
middleware in app.py counts requests in flight here; the worker pauses between small batches
while any are waiting (collection and the dashboard first, detection catches up afterwards).

STARTUP records the start-up phase so the launcher can say what it is waiting for.
"""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager

_LOCK = threading.Lock()
_IN_FLIGHT = 0
_LAST_REQUEST = 0.0
STARTUP = {"phase": "starting", "since": time.monotonic(), "ready": False, "detection_ready": False}


def set_phase(phase: str, ready: bool | None = None, detection_ready: bool | None = None) -> None:
    STARTUP["phase"] = phase
    STARTUP["since"] = time.monotonic()
    if ready is not None:
        STARTUP["ready"] = ready
    if detection_ready is not None:
        STARTUP["detection_ready"] = detection_ready


def enter() -> None:
    global _IN_FLIGHT, _LAST_REQUEST
    with _LOCK:
        _IN_FLIGHT += 1
        _LAST_REQUEST = time.monotonic()


def leave() -> None:
    global _IN_FLIGHT, _LAST_REQUEST
    with _LOCK:
        _IN_FLIGHT = max(0, _IN_FLIGHT - 1)
        _LAST_REQUEST = time.monotonic()


def busy() -> bool:
    """True while a request is in flight or one finished in the last 300 ms (pages fire several calls
    in a row, and the collector sends its batches back to back while it reads history)."""
    return _IN_FLIGHT > 0 or time.monotonic() - _LAST_REQUEST < 0.3


def wait_until_idle(max_wait: float = 2.0, stop: threading.Event | None = None) -> float:
    """Sleep while requests are being served (at most max_wait seconds); return the time waited."""
    started = time.monotonic()
    while busy() and time.monotonic() - started < max_wait:
        if stop is not None and stop.is_set():
            break
        time.sleep(0.01)
    return time.monotonic() - started


@contextmanager
def waiting_for_engine():
    """A request that is itself waiting for the detection engine must not make the engine wait."""
    global _IN_FLIGHT
    with _LOCK:
        counted = _IN_FLIGHT > 0          # called outside a request (tests, tools): change nothing
        if counted:
            _IN_FLIGHT -= 1
    try:
        yield
    finally:
        if counted:
            with _LOCK:
                _IN_FLIGHT += 1
