"""Analyst feedback: investigation status, verdicts and narrowly-scoped suppressions.

Verdicts: true_positive, false_positive, benign (expected activity), needs_investigation.

  * Every verdict is stored with the detection (history kept) and never deletes evidence.
  * On a behaviour-model detection the verdict updates the model, narrowly: only the exact
    feature values in that detection (false positive / benign -> counted as known-good;
    true positive -> never learned as normal).  Repeated false positives raise the
    behaviour alert threshold a little; every change is written to the model audit log.
  * A false-positive verdict never whitelists anything by itself.  Suppression is a separate,
    explicit action that covers one rule AND one exact fingerprint (decision.fingerprint),
    can be revoked, and counts how often it matched.
"""
from __future__ import annotations

VERDICTS = {
    "true_positive": "True positive",
    "false_positive": "False positive",
    "benign": "Benign / expected activity",
    "needs_investigation": "Needs investigation",
}
STATUSES = ("New", "Investigating", "Resolved")
