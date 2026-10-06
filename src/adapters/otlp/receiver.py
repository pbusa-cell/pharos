"""OTLP/HTTP receiver app (spec §4.2.1, phase 5 Task 3).

``build_receiver_app`` returns a Starlette ASGI callable (middleware-wrapped
when a token is supplied, bare otherwise) that accepts OTLP/JSON log exports
on ``POST /v1/logs``.

Security contracts (§4.7 + §4.2.1)
  * Body bounds: Content-Length precheck AND wire-byte cap AND cumulative
    decompressed cap AND unconsumed_tail/unused_data hard-stops (M3 a/b/c).
  * Catch-all error mapping: zlib.error, RecursionError, OverflowError,
    TypeError and ANY other exception → 400 with a fixed literal.  ``str(exc)``
    and payload content NEVER appear in a response body or log record (F3/M6b).
  * BearerASGIMiddleware constructed only when ``token`` is truthy (F13ii).
  * Zero outbound calls — this module is pure in-process logic (F13i / §4.7).
  * No uvicorn import — serving lives in main.py (D9 tripwire).

Handler precedence (round-2 V2 — load-bearing order)
  media-type check
  → _read_bounded in its OWN try:
        _TooLarge        → 413
        _UnsupportedEncoding → 415
        Exception        → 400 (fixed literal)
  → parse try (json.loads + parse_export_logs_request):
        Exception        → 400 (fixed literal)
  → ring.note_truncated(n) + ring.note_dropped(skipped)
    + ring.append(recv_ts, record) for each kept record
    (only the newest ring.capacity records of a batch are parsed into memory
    at once — C01)
  → 200 {}
"""
from __future__ import annotations

import json
import time
import zlib

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from adapters.otlp.parse import parse_newest_log_records
from adapters.otlp.rings import LogRing
from core.http_transport import BearerASGIMiddleware

# ── sentinel exceptions (private; caught in the handler only) ─────────────────

class _TooLarge(Exception):
    """Body exceeded wire or decompressed cap."""


class _UnsupportedEncoding(Exception):
    """Content-Encoding is not in the accepted set."""


# ── fixed error response literals (F3: never embed payload or exc) ────────────

_400_BODY = json.dumps({"code": 400, "message": "malformed OTLP/JSON request"}).encode()
_413_BODY = json.dumps({"code": 413, "message": "request body too large"}).encode()
_415_JSON_BODY = json.dumps(
    {"code": 415, "message": "unsupported media type; use encoding: json"}
).encode()
_415_ENC_BODY = json.dumps(
    {"code": 415, "message": "unsupported Content-Encoding; use compression: gzip|none"}
).encode()
_501_BODY = json.dumps(
    {"code": 501, "message": "not implemented; only /v1/logs accepted in v1 (§4.2.1 item 5b)"}
).encode()
_405_BODY = json.dumps({"code": 405, "message": "method not allowed"}).encode()


def _json_resp(status: int, body: bytes, *, allow: str | None = None) -> Response:
    h: dict[str, str] = {"content-type": "application/json"}
    if allow is not None:
        h["allow"] = allow
    return Response(content=body, status_code=status, headers=h)


# ── bounded body reader ───────────────────────────────────────────────────────

async def _read_bounded(request: Request, max_body_bytes: int) -> bytes:
    """Read and (optionally) decompress the request body within strict bounds.

    ROUND-1 F1 VERBATIM CONTRACT — five guards in order:

    1) Content-Length precheck: declared length > max → _TooLarge (413 pre-read).
    2) Content-Encoding allowlist: only "", "identity", "gzip" accepted;
       anything else (zstd, snappy, deflate …) → _UnsupportedEncoding (415).
       Tokens are .strip().lower() — case-insensitive (V3).
    3) Wire-byte cap: raw_total counted over chunks; raw_total > max →
       _TooLarge (F1b — trailing garbage is bounded on the wire side too).
    4) Gzip decompression:
         piece = dec.decompress(chunk, max_length=max - out_total + 1)
         out_total += len(piece)
         out_total > max  OR  dec.unconsumed_tail  → _TooLarge (F1a/c cumulative)
         dec.eof AND dec.unused_data               → _TooLarge (F1b trailing bytes)
    5) Identity: chunks accumulated into a buffer; eof + raw_total already bounded.

    Content-Length is parsed defensively: absent / non-decimal-digit / negative →
    treated as absent (never raise from it).

    Note on multi-member gzip: a body that is two or more concatenated gzip
    members (valid per RFC 1952) is rejected as 413 by design — the
    ``dec.eof and dec.unused_data`` check fires on the second member's bytes.
    OTLP senders emit single-member output, so this is an accepted trade-off
    (documented interop false-positive per spec §4.7).

    Returns the decoded body bytes.  All exceptions from zlib or int() are
    propagated as-is so the caller's except-Exception arm catches them; this
    module never widens its own catch to absorb them (the handler is the
    catch-all boundary).
    """
    # ── Guard 1: Content-Length precheck ─────────────────────────────────────
    cl_raw = request.headers.get("content-length", "")
    cl: int | None = None
    if cl_raw.strip().isdecimal():
        cl_int = int(cl_raw.strip())
        if cl_int >= 0:
            cl = cl_int
    if cl is not None and cl > max_body_bytes:
        raise _TooLarge("declared Content-Length exceeds limit")

    # ── Guard 2: Content-Encoding allowlist ──────────────────────────────────
    enc = request.headers.get("content-encoding", "").strip().lower()
    if enc not in ("", "identity", "gzip"):
        raise _UnsupportedEncoding("unsupported Content-Encoding")

    # ── Guards 3/4/5: streaming read with caps ────────────────────────────────
    raw_total: int = 0
    out_total: int = 0
    pieces: list[bytes] = []

    if enc == "gzip":
        dec = zlib.decompressobj(wbits=31)  # wbits=31 → gzip format

    async for chunk in request.stream():
        raw_total += len(chunk)
        if raw_total > max_body_bytes:
            raise _TooLarge("wire-byte cap exceeded")

        if enc == "gzip":
            # max_length bounds the output per chunk (F1a — cumulative gap plug)
            piece = dec.decompress(chunk, max_length=max_body_bytes - out_total + 1)
            out_total += len(piece)
            if out_total > max_body_bytes or dec.unconsumed_tail:
                raise _TooLarge("decompressed size cap exceeded")
            if dec.eof and dec.unused_data:
                raise _TooLarge("trailing bytes after gzip EOF")
            pieces.append(piece)
        else:
            pieces.append(chunk)

    return b"".join(pieces)


# ── handler builder ───────────────────────────────────────────────────────────

def build_receiver_app(ring: LogRing, opts: dict, token: str | None):
    """Build and return the OTLP/HTTP ASGI receiver app.

    Parameters
    ----------
    ring:
        The ``LogRing`` to append ingest records into.
    opts:
        Validated options dict (``max_body_bytes``, ``max_record_bytes``, …).
    token:
        Bearer token for auth.  ``None`` or absent → bare app (localhost-open).
        Truthy string → ``BearerASGIMiddleware`` wraps the app.
        NEVER pass an empty string — the middleware invariant forbids it (F13ii).

    Returns
    -------
    ASGI callable (middleware-wrapped or bare Starlette app).
    """
    max_body_bytes: int = opts["max_body_bytes"]
    max_record_bytes: int = opts["max_record_bytes"]

    async def _handle_logs(request: Request) -> Response:
        # ── method guard ─────────────────────────────────────────────────────
        if request.method != "POST":
            return _json_resp(405, _405_BODY, allow="POST")

        # ── media-type check (F6 — split on ';', strip, lower) ───────────────
        ct = request.headers.get("content-type", "")
        media_type = ct.split(";")[0].strip().lower()
        if media_type != "application/json":
            return _json_resp(415, _415_JSON_BODY)

        # ── bounded body read — OWN try block (V2 precedence is load-bearing) ─
        try:
            body_bytes = await _read_bounded(request, max_body_bytes)
        except _TooLarge:
            return _json_resp(413, _413_BODY)
        except _UnsupportedEncoding:
            return _json_resp(415, _415_ENC_BODY)
        except Exception:
            # zlib.error, OverflowError, etc. — NOT ValueError; must land here,
            # never become a 5xx (proven; V2 mutation narrows this to ValueError
            # and must fail).
            return _json_resp(400, _400_BODY)

        # ── parse + ingest — separate try block (F3 catch-all) ───────────────
        try:
            parsed = json.loads(body_bytes)
            records, truncated, skipped = parse_newest_log_records(
                parsed, max_record_bytes=max_record_bytes, max_records=ring.capacity
            )
            recv_ts = time.time()
            ring.note_truncated(truncated)
            ring.note_dropped(skipped)
            for record in records:
                ring.append(recv_ts, record)
        except Exception:
            # RecursionError, TypeError, OverflowError, ValueError — none may
            # escape as 5xx (F3).  Fixed literal only — no str(exc) or payload.
            return _json_resp(400, _400_BODY)

        return _json_resp(200, b"{}")

    async def _handle_not_implemented(request: Request) -> Response:
        """POST /v1/metrics and /v1/traces → 501 naming 5b."""
        if request.method != "POST":
            return _json_resp(405, _405_BODY, allow="POST")
        return _json_resp(501, _501_BODY)

    routes = [
        Route("/v1/logs", _handle_logs, methods=["GET", "POST", "PUT", "PATCH",
                                                  "DELETE", "HEAD", "OPTIONS"]),
        Route("/v1/metrics", _handle_not_implemented, methods=["GET", "POST",
                                                                "PUT", "PATCH",
                                                                "DELETE", "HEAD",
                                                                "OPTIONS"]),
        Route("/v1/traces", _handle_not_implemented, methods=["GET", "POST",
                                                               "PUT", "PATCH",
                                                               "DELETE", "HEAD",
                                                               "OPTIONS"]),
    ]
    app = Starlette(routes=routes)

    if token:
        # exempt_paths=frozenset() — no path is exempt on the ingest surface
        return BearerASGIMiddleware(app, token, exempt_paths=frozenset())
    return app
