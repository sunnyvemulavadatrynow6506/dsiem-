"""Readers for Windows Event Log channels.

Two interchangeable sources with the same small interface:

* NativeSource  - the Windows Event Log API (wevtapi.dll: EvtQuery / EvtNext /
                  EvtRender) through ctypes.  No extra process per read and no
                  extra binaries (ctypes ships with Python).
* PowerShellSource - Get-WinEvent, as used by Griffendo v1/v2; the fallback.

Interface (all reads are by EventRecordID, which Windows assigns in strictly
increasing order per channel):

    newest_record(channel)                      -> int | None (None = empty log)
    read_after(channel, cursor, limit)          -> (events oldest-first, newest_record)
    read_before(channel, upper, limit, lookback_ms) -> events newest-first, record_id <= upper
    log_info(channels)                          -> {channel: {...retention metadata...}}

Errors raise SourceError with kind 'unavailable' | 'access_denied' | 'error'.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Any

_RECORD = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")


class SourceError(RuntimeError):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


def classify(message: str) -> str:
    text = message.lower()
    if ("not an event log" in text or "no event log" in text or "could not be found" in text
            or "channel not found" in text or "15007" in text):
        return "unavailable"
    if "unauthorized" in text or "access is denied" in text or "access denied" in text:
        return "access_denied"
    return "error"


def record_id(xml: str) -> int | None:
    match = _RECORD.search(xml)
    return int(match.group(1)) if match else None


def _time_bound(lookback_ms: int) -> str:
    return f" and TimeCreated[timediff(@SystemTime) <= {int(lookback_ms)}]" if lookback_ms else ""


# --------------------------------------------------------------------------- native (wevtapi via ctypes)
class NativeSource:
    name = "native"
    _QUERY_CHANNEL_PATH = 0x1
    _QUERY_FORWARD = 0x100
    _QUERY_REVERSE = 0x200
    _RENDER_EVENT_XML = 1
    _INFINITE = 0xFFFFFFFF
    _NO_MORE_ITEMS = 259
    _INSUFFICIENT_BUFFER = 122
    _ERRORS = {2: "unavailable", 15007: "unavailable", 5: "access_denied"}

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        api = ctypes.WinDLL("wevtapi.dll", use_last_error=True)
        handle = wintypes.HANDLE
        self._handle = handle
        api.EvtQuery.argtypes = [handle, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        api.EvtQuery.restype = handle
        api.EvtNext.argtypes = [handle, wintypes.DWORD, ctypes.POINTER(handle), wintypes.DWORD, wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD)]
        api.EvtNext.restype = wintypes.BOOL
        api.EvtRender.argtypes = [handle, handle, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
        api.EvtRender.restype = wintypes.BOOL
        api.EvtClose.argtypes = [handle]
        api.EvtClose.restype = wintypes.BOOL
        self._api = api
        self._dword = wintypes.DWORD

    def _fail(self, channel: str, action: str) -> SourceError:
        code = self._ctypes.get_last_error()
        message = f"{channel}: {action} failed (Windows error {code}: {self._ctypes.FormatError(code).strip()})"
        return SourceError(self._ERRORS.get(code, classify(message)), message)

    def _render(self, event) -> str:
        used, count = self._dword(0), self._dword(0)
        byref = self._ctypes.byref
        if not self._api.EvtRender(None, event, self._RENDER_EVENT_XML, 0, None, byref(used), byref(count)):
            if self._ctypes.get_last_error() != self._INSUFFICIENT_BUFFER:
                raise self._fail("event", "EvtRender")
        buffer = self._ctypes.create_string_buffer(used.value)
        if not self._api.EvtRender(None, event, self._RENDER_EVENT_XML, used.value, buffer, byref(used), byref(count)):
            raise self._fail("event", "EvtRender")
        return self._ctypes.wstring_at(self._ctypes.addressof(buffer), used.value // 2).rstrip("\x00")

    def _query(self, channel: str, xpath: str, reverse: bool, limit: int) -> list[dict[str, Any]]:
        flags = self._QUERY_CHANNEL_PATH | (self._QUERY_REVERSE if reverse else self._QUERY_FORWARD)
        results = self._api.EvtQuery(None, channel, xpath, flags)
        if not results:
            raise self._fail(channel, "EvtQuery")
        events: list[dict[str, Any]] = []
        try:
            array = (self._handle * 64)()
            returned = self._dword(0)
            while len(events) < limit:
                wanted = min(64, limit - len(events))
                if not self._api.EvtNext(results, wanted, array, self._INFINITE, 0, self._ctypes.byref(returned)):
                    if self._ctypes.get_last_error() == self._NO_MORE_ITEMS:
                        break
                    raise self._fail(channel, "EvtNext")
                for index in range(returned.value):
                    handle = array[index]
                    try:
                        xml = self._render(handle)
                    finally:
                        self._api.EvtClose(handle)
                    events.append({"record_id": record_id(xml), "xml": xml})
                if returned.value < wanted:
                    break
        finally:
            self._api.EvtClose(results)
        return [event for event in events if event["record_id"] is not None]

    def newest_record(self, channel: str) -> int | None:
        events = self._query(channel, "*", True, 1)
        return events[0]["record_id"] if events else None

    def read_after(self, channel: str, cursor: int, limit: int) -> tuple[list[dict[str, Any]], int | None]:
        events = self._query(channel, f"*[System[EventRecordID > {int(cursor)}]]", False, limit)
        newest = events[-1]["record_id"] if len(events) < limit and events else self.newest_record(channel)
        return events, newest

    def read_before(self, channel: str, upper: int, limit: int, lookback_ms: int = 0) -> list[dict[str, Any]]:
        return self._query(channel, f"*[System[EventRecordID <= {int(upper)}{_time_bound(lookback_ms)}]]", True, limit)

    def log_info(self, channels: list[str]) -> dict[str, dict[str, Any]]:
        return powershell_log_info(channels)


# --------------------------------------------------------------------------- PowerShell (v1/v2 method)
_POWERSHELL = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command"]
_CATCH = ("if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') "
          "{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")


def _run_powershell(script: str, channel: str, timeout: int = 120) -> Any:
    try:
        result = subprocess.run([*_POWERSHELL, script], capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SourceError("error", f"{channel}: {error}") from error
    if result.returncode:
        message = f"{channel}: {result.stderr.strip() or f'PowerShell exited with {result.returncode}'}"
        raise SourceError(classify(message), message)
    output = result.stdout.strip()
    if not output:
        raise SourceError("error", f"{channel}: PowerShell returned no output")
    try:
        return json.loads(output)
    except ValueError as error:
        raise SourceError("error", f"{channel}: unreadable PowerShell output ({error})") from error


def _events(decoded: Any) -> list[dict[str, Any]]:
    items = decoded.get("events") or [] if isinstance(decoded, dict) else []
    items = items if isinstance(items, list) else [items]
    return [{"record_id": int(item["record_id"]), "xml": str(item["xml"])} for item in items if item and "xml" in item]


class PowerShellSource:
    name = "powershell"

    def newest_record(self, channel: str) -> int | None:
        script = f"""
$ErrorActionPreference = 'Stop'
$id = $null
try {{ $e = Get-WinEvent -LogName '{channel}' -MaxEvents 1; if ($e) {{ $id = [long]$e.RecordId }} }} catch {{ {_CATCH} }}
[PSCustomObject]@{{ newest = $id }} | ConvertTo-Json -Compress
"""
        value = _run_powershell(script, channel, 60).get("newest")
        return int(value) if value is not None else None

    def read_after(self, channel: str, cursor: int, limit: int) -> tuple[list[dict[str, Any]], int | None]:
        script = f"""
$ErrorActionPreference = 'Stop'
$newest = $null
try {{ $e = Get-WinEvent -LogName '{channel}' -MaxEvents 1; if ($e) {{ $newest = [long]$e.RecordId }} }} catch {{ {_CATCH} }}
$items = @()
try {{
    $items = @(Get-WinEvent -LogName '{channel}' -FilterXPath "*[System[EventRecordID > {int(cursor)}]]" -Oldest -MaxEvents {int(limit)} | ForEach-Object {{
        [PSCustomObject]@{{ record_id = [long]$_.RecordId; xml = $_.ToXml() }} }})
}} catch {{ {_CATCH} }}
[PSCustomObject]@{{ newest = $newest; events = $items }} | ConvertTo-Json -Compress -Depth 4
"""
        decoded = _run_powershell(script, channel)
        newest = decoded.get("newest") if isinstance(decoded, dict) else None
        return _events(decoded), int(newest) if newest is not None else None

    def read_before(self, channel: str, upper: int, limit: int, lookback_ms: int = 0) -> list[dict[str, Any]]:
        script = f"""
$ErrorActionPreference = 'Stop'
$items = @()
try {{
    $items = @(Get-WinEvent -LogName '{channel}' -FilterXPath "*[System[EventRecordID <= {int(upper)}{_time_bound(lookback_ms)}]]" -MaxEvents {int(limit)} | ForEach-Object {{
        [PSCustomObject]@{{ record_id = [long]$_.RecordId; xml = $_.ToXml() }} }})
}} catch {{ {_CATCH} }}
[PSCustomObject]@{{ events = $items }} | ConvertTo-Json -Compress -Depth 4
"""
        return _events(_run_powershell(script, channel))

    def log_info(self, channels: list[str]) -> dict[str, dict[str, Any]]:
        return powershell_log_info(channels)


def powershell_log_info(channels: list[str]) -> dict[str, dict[str, Any]]:
    """Retention metadata (enabled, mode, size, record count, oldest record) for coverage reporting."""
    names = ",".join(f"'{channel}'" for channel in channels)
    script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$out = @()
foreach ($name in @({names})) {{
    $l = Get-WinEvent -ListLog $name -ErrorAction SilentlyContinue
    if ($l) {{ $out += [PSCustomObject]@{{ channel = $name; enabled = [bool]$l.IsEnabled; mode = [string]$l.LogMode;
        max_bytes = [long]$l.MaximumSizeInBytes; file_bytes = [long]$l.FileSize; record_count = [long]$l.RecordCount;
        oldest_record = [long]$l.OldestRecordNumber; is_full = [bool]$l.IsLogFull }} }}
}}
@{{ logs = $out }} | ConvertTo-Json -Compress -Depth 4
"""
    try:
        decoded = _run_powershell(script, "log metadata", 120)
    except SourceError:
        return {}
    logs = decoded.get("logs") or [] if isinstance(decoded, dict) else []
    logs = logs if isinstance(logs, list) else [logs]
    return {item["channel"]: {key: item.get(key) for key in ("enabled", "mode", "max_bytes", "file_bytes", "record_count",
                                                              "oldest_record", "is_full")}
            for item in logs if isinstance(item, dict) and item.get("channel")}


def open_source(preferred: str = "auto"):
    """'native', 'powershell' or 'auto' (native when it works on this machine, else PowerShell)."""
    if preferred == "powershell" or sys.platform != "win32":
        return PowerShellSource(), None
    try:
        source = NativeSource()
        source.newest_record("System")   # self-test against a log every Windows host has
        return source, None
    except Exception as error:  # noqa: BLE001 - any failure means "use the proven fallback"
        if preferred == "native":
            raise
        return PowerShellSource(), f"Native Windows Event Log API unavailable ({error}); using PowerShell."
