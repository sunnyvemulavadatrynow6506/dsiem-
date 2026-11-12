"""Decision engine: alert, suppress or learn-only for every signal.

  alert       the default for deterministic rule and chain matches (whatever the behaviour model's stage)
  suppressed  an analyst approved this exact activity as known-good: same rule AND the same fingerprint
              (process path, parent path, command line, user, service/task/registry/file/address values
              that the evidence carries).  A materially different event has a different fingerprint and
              still alerts.  Suppressed signals are kept, counted separately and auditable.
  learn_only  behaviour-model signals while the host's baseline is in the Learn stage, and new-terms /
              first-seen signals when Griffendo does not yet hold enough history to call a value "new"
  shadow      behaviour-model signals during the Shadow stage: scored and recorded, never alerted
An immature behaviour model never suppresses a deterministic rule match.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .normalizer import get

FINGERPRINT_FIELDS = (
    "event.code", "winlog.channel", "event.provider", "process.executable", "process.parent.executable",
    "process.command_line", "user.name", "user.id", "service.name", "scheduled_task.name", "registry.path",
    "registry.data.strings", "file.path", "dll.path", "source.ip", "destination.ip", "destination.port",
    "dns.question.name", "group.name", "user.target.name", "powershell.file.script_block_text",
)


def fingerprint(rule_id: str, events: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    parts = []
    for ev in events:
        fields = {}
        for name in FINGERPRINT_FIELDS:
            value = get(ev, name)
            if value is not None:
                fields[name] = value if not isinstance(value, str) else value.strip()
        parts.append(fields)
    material = json.dumps([rule_id, sorted(parts, key=lambda item: json.dumps(item, sort_keys=True, default=str))],
                          sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32], {"rule_id": rule_id, "events": parts}


class Decider:
    def __init__(self, suppressions: list[dict[str, Any]] | None = None):
        self.load(suppressions or [])
        self.matches: dict[str, int] = {}

    def load(self, suppressions: list[dict[str, Any]]) -> None:
        self.by_key = {(item["rule_id"], item["fingerprint"]): item["id"] for item in suppressions
                       if not item.get("revoked_at")}

    def decide(self, signal: dict[str, Any], behaviour_stage: str) -> dict[str, Any]:
        if signal["source"] == "behavior":
            if behaviour_stage == "learn":
                signal["decision"] = "learn_only"
            elif behaviour_stage == "shadow":
                signal["decision"] = "shadow"
        if signal["decision"] in ("learn_only", "shadow"):
            return signal
        if self.by_key:
            key, _ = fingerprint(signal["rule_id"], signal["events"])
            suppression = self.by_key.get((signal["rule_id"], key))
            if suppression:
                signal["decision"] = "suppressed"
                signal["suppression_id"] = suppression
                self.matches[suppression] = self.matches.get(suppression, 0) + 1
        return signal

    def take_matches(self) -> dict[str, int]:
        counts, self.matches = self.matches, {}
        return counts
