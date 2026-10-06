"""Bounded counted log ring for the OTLP ingest adapter (spec §4.2.1, phase 5).

Design constraints (from Architecture paragraph + round-1 review):

Ring backing store
  ``collections.deque`` WITHOUT ``maxlen`` plus an explicit eviction loop.
  ``deque(maxlen=N)`` silently evicts with NO counter increment — the M4
  mutation (swap to maxlen) proves the tests catch this.  The explicit
  ``while len >= capacity: popleft(); dropped += 1`` loop is the ONLY
  design that gives an honest ``dropped_oldest`` count.

Clock domain
  ``covered_window`` uses ``recv_ts`` (the receiver-side timestamp passed to
  ``append``) — never any timestamp embedded inside the record (sender clock).
  This is the M5 constraint: sender clocks can be skewed; receiver clock is
  the authoritative bound.

Lock discipline (M9b reviewer audit)
  The ``threading.Lock`` guards ONLY these operations:
    - ``append``: ``popleft`` + ``_buf.append`` + counter increments
    - ``snapshot``: ``list(self._buf)``
    - ``note_truncated``: ``self._truncated_records += n``
    - ``covered_window``/``stats``: read of ``_dropped_oldest``,
      ``_truncated_records``, ``len(self._buf)``, ``self._buf[0][0]``
  No ISO formatting, no datetime construction, no ``time.time()`` call,
  and no ``await`` occurs inside any critical section.

Empty ring behaviour
  An empty ring with zero drops returns ``(iso(start_ts), iso(now))``
  — NOT ``None``.  This is an honest answer: "the receiver started at
  start_ts and has seen nothing yet."

Covered-window honesty
  The lower bound (start) is ceil'd to the next whole second before
  rendering (``iso_z(math.ceil(lower_ts))``).  Flooring the start would
  claim up-to-1 s MORE coverage than actually observed — the dishonest
  direction.  Ceiling is conservative: it never overstates coverage.
  The upper bound (``now``) stays as-is (floor is fine for an open end).

  Task-5 MUST use ``iso_z`` (this module's public renderer) for
  requested_window rendering — ONE-renderer mandate.
"""
from __future__ import annotations

import collections
import math
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional


def iso_z(ts: "float | datetime") -> str:
    """Render a POSIX timestamp or tz-aware datetime as an ISO-8601 UTC string
    ending in Z.

    No fractional seconds — seconds precision is sufficient and keeps the
    format stable under injected clocks used by unit tests.

    Parameters
    ----------
    ts:
        A POSIX float (or int) **or** a tz-aware :class:`~datetime.datetime`.
        Naive datetimes are rejected with :exc:`ValueError` — they carry no
        timezone information and an implicit UTC assumption would be silent.

    Notes
    -----
    The lower bound of ``covered_window`` / ``stats`` is ceil'd at the call
    site (``iso_z(math.ceil(lower_ts))``); this function does NOT apply any
    rounding so callers control precision semantics.
    """
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            raise ValueError(
                "iso_z requires a tz-aware datetime; got a naive datetime "
                "(set tzinfo, or pass a float POSIX timestamp instead)"
            )
        return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class LogRing:
    """A bounded FIFO ring buffer with explicit drop counting.

    Parameters
    ----------
    capacity:
        Maximum number of ``(recv_ts, record)`` tuples retained.  Must be > 0.
    now_fn:
        Callable returning the current time as a POSIX float.  Defaults to
        ``time.time``.  Injectable for deterministic unit tests.
    start_ts:
        Ring creation timestamp as a POSIX float.  Defaults to
        ``now_fn()`` at construction time.  Injectable for deterministic
        unit tests.
    """

    def __init__(
        self,
        capacity: int,
        *,
        now_fn: Callable[[], float] = time.time,
        start_ts: Optional[float] = None,
    ) -> None:
        if capacity < 1:
            raise ValueError(
                f"LogRing capacity must be >= 1, got {capacity!r}"
            )
        self._capacity = capacity
        self._now_fn = now_fn
        self._start_ts: float = start_ts if start_ts is not None else now_fn()
        # NO maxlen — explicit eviction loop is required for honest counting.
        self._buf: collections.deque = collections.deque()
        self._lock = threading.Lock()
        self._dropped_oldest: int = 0
        self._truncated_records: int = 0

    @property
    def capacity(self) -> int:
        """Maximum number of records retained."""
        return self._capacity

    # ── write path ────────────────────────────────────────────────────────────

    def append(self, recv_ts: float, record: Any) -> None:
        """Append ``(recv_ts, record)`` to the ring, evicting the oldest
        entry when the buffer is at capacity.

        All mutations — popleft, append, counter increment — occur under
        the lock.  No formatting or parsing is done inside the critical
        section (M9b).
        """
        with self._lock:
            while len(self._buf) >= self._capacity:
                self._buf.popleft()
                self._dropped_oldest += 1
            self._buf.append((recv_ts, record))

    def note_dropped(self, n: int) -> None:
        """Count ``n`` records as dropped without buffering them.

        The receiver skips the older records of a batch larger than the ring
        (they would be evicted by the same batch anyway); counting them here
        keeps ``dropped_oldest`` identical to appending and evicting them.
        ``n <= 0`` is a no-op.
        """
        if n <= 0:
            return
        with self._lock:
            self._dropped_oldest += n

    def note_truncated(self, n: int) -> None:
        """Add ``n`` to the cumulative truncated-record counter.

        Called by the receiver handler after a successful parse when records
        were truncated during ingest (V4).  ``n <= 0`` is a no-op (guarded
        before acquiring the lock to avoid unnecessary lock contention and to
        prevent negative values from decrementing the honesty counter).
        """
        if n <= 0:
            return
        with self._lock:
            self._truncated_records += n

    # ── read path ─────────────────────────────────────────────────────────────

    def snapshot(self) -> list[tuple[float, Any]]:
        """Return a point-in-time copy of all buffered ``(recv_ts, record)``
        tuples, oldest first.

        The ``list()`` copy is taken under the lock; filtering and any other
        work is left to the caller (M9b: no parsing under the lock).
        """
        with self._lock:
            return list(self._buf)

    def covered_window(self) -> tuple[str, str]:
        """Return the (start, end) of the time interval this ring covers as
        ISO-8601 UTC strings.

        ``start`` is:
          - ``iso(ceil(start_ts))`` when no records have been evicted
            (``dropped == 0``), including when the ring is empty.
          - ``iso(ceil(oldest_retained_recv_ts))`` after any eviction.

        The lower bound is ceil'd to the next whole second so coverage is
        never overstated (flooring would claim up-to-1 s of extra coverage).

        ``end`` is always ``iso(now_fn())``.

        ISO rendering is done OUTSIDE the lock (M9b).
        """
        with self._lock:
            dropped = self._dropped_oldest
            oldest_ts: Optional[float] = self._buf[0][0] if self._buf else None

        now_ts = self._now_fn()
        now_str = iso_z(now_ts)
        lower_ts = self._start_ts if (dropped == 0 or oldest_ts is None) else oldest_ts
        # Ceil the LOWER bound only (never overstate coverage start), then clamp
        # to floor(now) so a sub-second-old ring can never render an inverted
        # window (start after end) — review re-round finding.
        start_str = iso_z(min(math.ceil(lower_ts), math.floor(now_ts)))
        return (start_str, now_str)

    def stats(self) -> dict:
        """Return a snapshot of ring statistics.

        Keys:
          ``buffered``         — number of records currently in the ring.
          ``dropped_oldest``   — cumulative count of records evicted to make room.
          ``truncated_records``— cumulative count of truncated-record notifications.
          ``covered_window``   — 2-tuple of ISO-Z strings (start, end).

        Counter values and the oldest recv_ts are read under the lock;
        ISO rendering of ``covered_window`` is done outside (M9b).
        """
        with self._lock:
            buffered = len(self._buf)
            dropped = self._dropped_oldest
            truncated = self._truncated_records
            oldest_ts: Optional[float] = self._buf[0][0] if self._buf else None

        now_ts = self._now_fn()
        now_str = iso_z(now_ts)
        lower_ts = self._start_ts if (dropped == 0 or oldest_ts is None) else oldest_ts
        # Ceil the LOWER bound only (never overstate coverage start), then clamp
        # to floor(now) so a sub-second-old ring can never render an inverted
        # window (start after end) — review re-round finding.
        start_str = iso_z(min(math.ceil(lower_ts), math.floor(now_ts)))

        return {
            "buffered": buffered,
            "dropped_oldest": dropped,
            "truncated_records": truncated,
            "covered_window": (start_str, now_str),
        }
