"""Identity: which events belong to "the same thing" and so may correlate.

v5 joined signals on a single entity (logon -> user -> process GUID) inside a fixed
30-minute bucket.  That is too coarse in one direction (all activity of one user for
30 minutes is one detection, whatever it was) and too fine in the other (a failed
logon ten minutes later is a *new* detection because the bucket rolled over).

The v6 model keeps two distinct notions:

``entity_key``      the actor the activity belongs to: logon session -> user -> process
                    GUID -> host.  System accounts and system logon sessions are
                    excluded, exactly as in v5, because they would join unrelated work.

``correlation_key`` the *subject* of the activity, used to keep independent incidents
                    apart inside one entity, following DSIEM directives, where a backlog
                    is per (source/destination/entity) directive-chain, not per user:
                      * a logon carries an account and a source address -> (entity, account,
                        source address), so brute force from one address is one incident
                        while the same user logging in locally is another;
                      * a process-scoped event belongs to that process tree -> (entity, root
                        ancestor process), so two unrelated command lines run by the same
                        admin in the same half hour are not one detection;
                      * anything else falls back to the entity alone.

Both keys are always derived from *event content only* — never from arrival order — so a
historical replay reproduces identical identities.
"""
from __future__ import annotations

from typing import Any

from ..engine import normalizer


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


def entity_key(ev: dict[str, Any]) -> str | None:
    """The actor of the event: ``logon:<id>`` -> ``user:<name>`` -> ``process:<guid>`` -> ``host:<name>``."""
    ent = normalizer.entity(ev)
    for name in ("logon", "user", "process"):
        if ent.get(name):
            return f"{name}:{ent[name]}"
    host = _clean(ev.get("host.name"))
    return f"host:{host}" if host else None


# Event families whose activity is authentication-shaped: the account and the source
# address identify the incident (one brute-force source is one incident).
_AUTH_EVENT_CODES = {"4624", "4625", "4634", "4647", "4648", "4672", "4720", "4722", "4723", "4724", "4725",
                     "4726", "4728", "4732", "4738", "4740", "4756", "4767", "4776", "4778", "4779"}


def is_auth(ev: dict[str, Any]) -> bool:
    code = ev.get("event.code")
    if code is None:
        return False
    return str(code) in _AUTH_EVENT_CODES


def correlation_key(ev: dict[str, Any], entity: str | None, process_root: str | None) -> str:
    """The incident subject: narrower than the entity, never wider."""
    if entity is None:
        return "anonymous"
    if is_auth(ev):
        account = _clean(ev.get("user.name")) or _clean(ev.get("user.target.name")) or "unknown-account"
        source = _clean(ev.get("source.ip")) or _clean(ev.get("source.domain")) or "local"
        return f"{entity}|auth|{account}|{source}"
    if process_root:
        return f"{entity}|proc|{process_root}"
    return entity


def process_root(ev: dict[str, Any], ancestors: list[str] | None) -> str | None:
    """Oldest known ancestor of the event's process (the root of its process tree).

    ``ancestors`` comes from the process table and is ordered nearest-first, so the last
    entry is the root.  Falls back to the event's own process identity.
    """
    own = _clean(ev.get("process.entity_id"))
    if ancestors:
        root = _clean(ancestors[-1])
        if root:
            return root
    return own
