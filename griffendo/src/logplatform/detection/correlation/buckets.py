"""Time buckets: the ordering-independent slicing of event time used for episodes.

Two properties matter and are both tested:

  * **Purity** — ``bucket_index`` depends on the timestamp and the configured width only,
    never on the order events were processed, so replaying the stored events after a
    restart or re-evaluating a rule produces byte-identical episode ids.
  * **Continuity is not assumed** — a bucket boundary does not split an incident that is
    still live: :func:`belongs` lets the correlation engine keep writing to the previous
    bucket while nothing has closed it, and the *incident window* is reported on the
    episode (first/last evidence time), which is what analysts and the UI actually use.

Bucket width is ``GRIFFENDO_CORRELATION_BUCKET_MINUTES`` (default 30, the v5 value).
"""
from __future__ import annotations

from . import config
from .config import CorrelationConfig


class Bucketer:
    """Maps timestamps to bucket indexes and formats them for display."""

    def __init__(self, cfg: CorrelationConfig | None = None) -> None:
        self.cfg = cfg or config.current()
        self.width = max(1, self.cfg.bucket_minutes) * 60

    def index(self, t: float) -> int:
        return int(t // self.width)

    def start(self, index: int) -> float:
        return index * self.width

    def end(self, index: int) -> float:
        return (index + 1) * self.width

    def label(self, index: int) -> str:
        """Human-readable bucket range, in UTC (the UI applies the user's offset)."""
        from ...settings import iso
        from datetime import datetime, timezone
        start = datetime.fromtimestamp(self.start(index), tz=timezone.utc)
        end = datetime.fromtimestamp(self.end(index) - 1, tz=timezone.utc)
        if start.date() == end.date():
            return f"{start:%Y-%m-%d %H:%M}–{end:%H:%M} UTC"
        return f"{iso(start)} – {iso(end)}"

    def belongs(self, t: float, index: int) -> bool:
        """Whether ``t`` may still be written to bucket ``index`` (same or next bucket)."""
        return self.index(t) in (index, index + 1) or self.index(t) == index

    def neighbours(self, index: int, t: float) -> list[int]:
        """Candidate buckets for ``t``, nearest first: its own, then an open neighbour.

        Used when an incident started in one bucket and its continuation arrives just
        after the boundary: the continuation joins the open episode instead of opening a
        second one, which is what DSIEM backlogs do through their ``timeout``.
        """
        own = self.index(t)
        order = [own]
        for candidate in (own - 1, own + 1):
            if candidate >= 0 and candidate not in order:
                order.append(candidate)
        return order
