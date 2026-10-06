"""OTLP/JSON log record parser (spec §4.2.1, phase 5 Task 2).

``parse_export_logs_request`` parses a decoded OTLP ExportLogsServiceRequest
JSON body into a list of canonical :class:`~core.signals.LogRecord` objects
and a truncated-record count.

Security (F3 / M6b)
  Exception messages NEVER embed payload content — all ``ValueError`` messages
  are static strings so that a malformed or attacker-controlled body cannot
  exfiltrate data via error paths.

Record budget (F5)
  Each record's estimated size is ``len(body) + sum(len(k)+len(str(v)) for
  k, v in attrs.items())``.  When this exceeds ``max_record_bytes``: the body
  takes first priority (truncated to fit), then attributes are kept in order
  until the remaining budget is exhausted (excess attributes dropped).
  Truncated records are counted; the caller MUST pass the count to
  ``ring.note_truncated()``.

  The ``entity`` attribute is budget-EXEMPT: it is derived before budget
  enforcement and re-attached afterward (capped at ``_ENTITY_MAX_CHARS``
  characters) so that truncated records remain fetchable by Entity selectors.
  The cap prevents a huge ``k8s.pod.name`` value from bypassing the budget
  through the exemption.

Timestamp clamping (F3)
  ``timeUnixNano`` accepts ``str`` or ``int``.  Values outside ``[0, 2**63)``
  and values that cannot be parsed as an integer yield ``timestamp=None``
  (undated).  The parser NEVER raises from a timestamp failure.

Entity precedence
  Resource attribute ``k8s.pod.name`` > ``service.name`` > ``"otlp"``
  (fallback).

Attribute count limit (C01)
  ``max_record_bytes`` counts characters, not objects, so thousands of short
  attributes fit any byte budget. At most ``MAX_ATTRIBUTES`` resource and
  ``MAX_ATTRIBUTES`` record-level attributes are kept per record (first ones,
  in order); a record that lost attributes counts as truncated. ``entity`` is
  derived from ALL resource attributes before the limit applies.

Newest-records mode (C01)
  ``parse_newest_log_records`` counts the records first, then only
  type-checks the older ones and builds just the newest ``max_records``, so a
  request never materialises more records than the ring can hold.

Shared resource attributes (C01)
  The size of each resource attribute is computed once per resource, and
  records share one read-only mapping of the resource attributes (records
  with their own attributes use a ChainMap over it), so per-record CPU and
  memory do not grow with the resource attribute count.

Exception surface
  ``parse_export_logs_request`` raises ``ValueError`` for structurally invalid
  bodies (non-dict, required fields not lists, required fields not dicts).
  Deeply-nested AnyValue inputs may additionally surface ``TypeError``,
  ``KeyError``, or (for pathological recursive inputs) ``RecursionError``.
  The RECEIVER's catch-all handler owns the 400-mapping for all of these;
  the parser itself NEVER widens its catch to absorb them.

Outbound calls
  ZERO — this module is pure in-process logic with no HTTP clients.
"""
from __future__ import annotations

import collections
import itertools
import types
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple

from adapters.otlp.rings import iso_z
from core.signals import LogRecord

# Exclusive upper bound for timeUnixNano (2**63 ns ≈ year 2262).
_NANO_MAX: int = 2**63

# Maximum characters stored in the budget-exempt ``entity`` attribute.
# Caps entity so a huge ``k8s.pod.name`` / ``service.name`` value cannot
# bypass ``max_record_bytes`` through the exemption.  The value is always
# present on every record (truncated or not) so Entity selectors never miss
# an over-budget record.
_ENTITY_MAX_CHARS: int = 512

# Attributes kept per resource and per log record (OpenTelemetry SDK default
# attribute count limit).
MAX_ATTRIBUTES: int = 128


def _parse_nano_to_iso(raw: Any) -> Optional[str]:
    """Convert a ``timeUnixNano`` value to an ISO-Z string.

    Accepts ``str`` or ``int`` (not ``bool``).  Returns ``None`` for:
      * non-str/non-int types
      * strings that don't parse as integers (``"abc"``, ``"-1"``)
      * values outside ``[0, 2**63)``

    NEVER raises — undated records are preferable to parse failures (F3).
    """
    try:
        if isinstance(raw, bool):
            # bool is a subclass of int in Python; treat as non-parseable.
            return None
        if isinstance(raw, int):
            nanos = raw
        elif isinstance(raw, str):
            # ValueError for "abc"; OverflowError for very long decimal strings.
            nanos = int(raw)
        else:
            return None
    except (ValueError, OverflowError):
        return None

    if not (0 <= nanos < _NANO_MAX):
        return None

    # Convert nanoseconds → seconds → ISO-Z via the ONE shared renderer.
    # Flooring happens inside iso_z (seconds precision).
    return iso_z(nanos / 1_000_000_000.0)


def _resolve_any_value(av: Any) -> Any:
    """Resolve an OTLP AnyValue dict to a Python scalar or collection.

    Supported one-of keys: ``stringValue``, ``intValue``, ``doubleValue``,
    ``boolValue``, ``bytesValue``, ``arrayValue``, ``kvlistValue``.
    Unknown or absent key → ``None``.  Non-dict input → ``str(av)``.
    """
    if not isinstance(av, dict):
        return str(av) if av is not None else None

    if "stringValue" in av:
        return av["stringValue"]
    if "intValue" in av:
        try:
            return int(av["intValue"])
        except (ValueError, TypeError):
            return str(av["intValue"])
    if "doubleValue" in av:
        try:
            return float(av["doubleValue"])
        except (ValueError, TypeError):
            return av["doubleValue"]
    if "boolValue" in av:
        return bool(av["boolValue"])
    if "bytesValue" in av:
        # Base64 string from JSON encoding — kept as-is (no decode).
        return av["bytesValue"]
    if "arrayValue" in av:
        inner = av["arrayValue"]
        values = inner.get("values", []) if isinstance(inner, dict) else []
        if not isinstance(values, list):
            values = []
        return [_resolve_any_value(v) for v in values]
    if "kvlistValue" in av:
        inner = av["kvlistValue"]
        pairs = inner.get("values", []) if isinstance(inner, dict) else []
        if not isinstance(pairs, list):
            pairs = []
        result: Dict[str, Any] = {}
        for p in pairs:
            if isinstance(p, dict) and "key" in p:
                result[p["key"]] = _resolve_any_value(p.get("value", {}))
        return result

    return None


def _parse_attrs(attr_list: Any) -> Dict[str, Any]:
    """Parse an OTLP key-value attribute list into a Python dict.

    Non-list input → empty dict (tolerant — malformed attribute lists must
    not prevent the containing record from being parsed).
    """
    if not isinstance(attr_list, list):
        return {}
    result: Dict[str, Any] = {}
    for item in attr_list:
        if isinstance(item, dict) and "key" in item:
            k = item["key"]
            v = _resolve_any_value(item.get("value", {}))
            result[k] = v
    return result


def _cap_attrs(attrs: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """Keep the first MAX_ATTRIBUTES attributes; return (attrs, dropped_any)."""
    if len(attrs) <= MAX_ATTRIBUTES:
        return attrs, False
    return dict(itertools.islice(attrs.items(), MAX_ATTRIBUTES)), True


def _extract_entity(resource_attrs: Dict[str, Any]) -> str:
    """Extract the entity name from resource attributes.

    Priority: ``k8s.pod.name`` > ``service.name`` > ``"otlp"`` (fallback).
    """
    pod = resource_attrs.get("k8s.pod.name")
    if pod is not None:
        return str(pod)
    svc = resource_attrs.get("service.name")
    if svc is not None:
        return str(svc)
    return "otlp"


def _attr_cost(key: str, value: Any) -> int:
    """Budget cost of one attribute: len(key) + len(str(value))."""
    return len(key) + len(str(value))


def _enforce_budget(
    body: str,
    attrs: Mapping[str, Any],
    max_bytes: int,
    costs: Mapping[str, int],
) -> Tuple[str, Dict[str, Any]]:
    """Trim a record's body and attributes to fit within ``max_bytes``.

    The body takes first priority: it is truncated to ``max_bytes`` if it
    alone exceeds the budget.  Remaining capacity is then allocated to
    attributes in iteration order; attributes that would exceed the remaining
    budget are dropped.

    Note: the ``entity`` attribute is budget-EXEMPT and is NOT passed to
    this function.  The caller re-attaches it (capped at
    ``_ENTITY_MAX_CHARS``) after the call so it always survives truncation.

    ``costs`` holds the precomputed ``_attr_cost`` of every attribute.

    Returns ``(trimmed_body, kept_attrs)``.
    """
    remaining = max_bytes

    # Body claims first slice of the budget.
    if len(body) > remaining:
        body = body[:remaining]
        remaining = 0
    else:
        remaining -= len(body)

    # Attributes fill what remains.
    kept: Dict[str, Any] = {}
    for k, v in attrs.items():
        attr_size = costs[k]
        if attr_size <= remaining:
            kept[k] = v
            remaining -= attr_size
        # else: over budget — silently drop this attribute.

    return body, kept


def parse_export_logs_request(
    body: dict,
    *,
    max_record_bytes: int,
) -> Tuple[List[LogRecord], int]:
    """Parse an OTLP ExportLogsServiceRequest JSON body into LogRecords.

    Parameters
    ----------
    body:
        Decoded JSON object (must be a ``dict``).
    max_record_bytes:
        Per-record size budget (bytes).  Records whose estimated size
        (``len(body_str) + sum(len(k)+len(str(v)) for attrs)``) exceeds this
        limit have their attributes trimmed and body truncated (F5).

    Returns
    -------
    ``(records, truncated_count)``
        ``records``         — list of :class:`~core.signals.LogRecord` objects.
        ``truncated_count`` — count of records whose content was trimmed.
        The caller MUST call ``ring.note_truncated(truncated_count)`` after
        a successful batch append (V4).

    Raises
    ------
    ValueError
        If ``body`` is not a dict, or if required list fields (``resourceLogs``,
        ``scopeLogs``, ``logRecords``) are not lists.
        Messages NEVER embed payload content (F3 / M6b).
    """
    records: List[LogRecord] = []
    truncated_count = 0
    for record, truncated in _iter_log_records(body, max_record_bytes, skip=0):
        records.append(record)
        truncated_count += truncated
    return records, truncated_count


def parse_newest_log_records(
    body: dict,
    *,
    max_record_bytes: int,
    max_records: int,
) -> Tuple[List[LogRecord], int, int]:
    """Like :func:`parse_export_logs_request`, but build only the newest records.

    The request is validated as a whole (same ValueErrors), but only the last
    ``max_records`` records in request order are built; older ones are only
    type-checked.

    Returns ``(records, truncated_count, skipped_count)``. ``truncated_count``
    covers the returned records; ``skipped_count`` is the number of older
    records not built — the caller counts them as dropped from the ring.
    """
    total = _count_log_records(body)
    skip = max(0, total - max_records)
    records: List[LogRecord] = []
    truncated_count = 0
    for record, truncated in _iter_log_records(body, max_record_bytes, skip=skip):
        records.append(record)
        truncated_count += truncated
    return records, truncated_count, skip


def _scope_record_lists(body: Any) -> Iterator[Tuple[dict, list]]:
    """Yield ``(resourceLogs entry, logRecords list)``; raise on bad structure."""
    if not isinstance(body, dict):
        raise ValueError(
            "OTLP request body must be a JSON object (dict)"
        )

    resource_logs_raw = body.get("resourceLogs", [])
    if not isinstance(resource_logs_raw, list):
        raise ValueError(
            "OTLP body: 'resourceLogs' must be an array"
        )

    for rl in resource_logs_raw:
        if not isinstance(rl, dict):
            raise ValueError(
                "OTLP body: each resourceLogs entry must be an object"
            )

        scope_logs_raw = rl.get("scopeLogs", [])
        if not isinstance(scope_logs_raw, list):
            raise ValueError(
                "OTLP body: 'scopeLogs' must be an array"
            )

        for sl in scope_logs_raw:
            if not isinstance(sl, dict):
                raise ValueError(
                    "OTLP body: each scopeLogs entry must be an object"
                )

            log_records_raw = sl.get("logRecords", [])
            if not isinstance(log_records_raw, list):
                raise ValueError(
                    "OTLP body: 'logRecords' must be an array"
                )
            yield rl, log_records_raw


def _count_log_records(body: Any) -> int:
    """Number of log records in the request (validates the structure)."""
    return sum(len(records) for _, records in _scope_record_lists(body))


class _ResourceView:
    """Per-resource state shared by all its records (computed once)."""

    def __init__(self, rl: dict) -> None:
        resource_raw = rl.get("resource", {})
        if not isinstance(resource_raw, dict):
            resource_raw = {}
        # _parse_attrs builds every attribute (bounded by the body size); the
        # count limit applies after, and entity comes from ALL of them.
        attrs = _parse_attrs(resource_raw.get("attributes", []))
        self.entity = _extract_entity(attrs)[:_ENTITY_MAX_CHARS]
        attrs, self.capped = _cap_attrs(attrs)
        self.attrs = types.MappingProxyType(attrs)
        self.costs = {k: _attr_cost(k, v) for k, v in attrs.items()}
        self.total_cost = sum(self.costs.values())
        # Records without own attributes that fit the budget share this mapping.
        self.shared = types.MappingProxyType({**attrs, "entity": self.entity})
        # Over-budget records without own attributes: kept attrs depend only on
        # the body length left after truncation.
        self._trimmed: Dict[int, Mapping[str, Any]] = {}

    def trimmed(self, body_str: str, max_record_bytes: int) -> Tuple[str, Mapping[str, Any]]:
        body_str, kept = _enforce_budget(body_str, self.attrs, max_record_bytes, self.costs)
        key = len(body_str)
        if key not in self._trimmed:
            self._trimmed[key] = types.MappingProxyType({**kept, "entity": self.entity})
        return body_str, self._trimmed[key]


def _iter_log_records(
    body: Any, max_record_bytes: int, *, skip: int
) -> Iterator[Tuple[LogRecord, bool]]:
    """Yield ``(record, was_truncated)`` in request order, after the first ``skip``.

    Skipped records are only type-checked, so validation errors are the same
    as for a full parse.
    """
    resource: Optional[_ResourceView] = None
    current_rl: Optional[dict] = None

    for rl, log_records_raw in _scope_record_lists(body):
        for lr in log_records_raw:
            if not isinstance(lr, dict):
                raise ValueError(
                    "OTLP body: each logRecords entry must be an object"
                )
            if skip > 0:
                skip -= 1
                continue
            if rl is not current_rl:
                resource, current_rl = _ResourceView(rl), rl

            # ── Timestamp (clamped — never raises) ────────────────────────
            timestamp = _parse_nano_to_iso(lr.get("timeUnixNano"))

            # ── Body text ─────────────────────────────────────────────────
            body_val = lr.get("body", {})
            if isinstance(body_val, dict):
                resolved = _resolve_any_value(body_val)
                body_str: str = str(resolved) if resolved is not None else ""
            else:
                body_str = str(body_val) if body_val is not None else ""

            # ── Severity text (optional) ───────────────────────────────────
            sev_raw = lr.get("severityText")
            severity: Optional[str] = str(sev_raw) if sev_raw is not None else None

            # ── Attributes: resource merged with record-level ──────────────
            # Resource attrs provide baseline; record-level attrs override.
            # ``entity`` is budget-exempt, derived from resource attrs only,
            # capped at _ENTITY_MAX_CHARS, and always set last (F5 note).
            own, own_capped = _cap_attrs(_parse_attrs(lr.get("attributes", [])))
            truncated = resource.capped or own_capped

            if not own:
                if len(body_str) + resource.total_cost <= max_record_bytes:
                    attributes: Mapping[str, Any] = resource.shared
                else:
                    body_str, attributes = resource.trimmed(body_str, max_record_bytes)
                    truncated = True
            else:
                own_costs = {k: _attr_cost(k, v) for k, v in own.items()}
                estimated = len(body_str) + resource.total_cost + sum(own_costs.values()) - sum(
                    resource.costs[k] for k in own if k in resource.costs
                )
                if estimated > max_record_bytes:
                    merged = {**resource.attrs, **own}
                    body_str, kept = _enforce_budget(
                        body_str, merged, max_record_bytes,
                        collections.ChainMap(own_costs, resource.costs),
                    )
                    kept["entity"] = resource.entity
                    attributes = types.MappingProxyType(kept)
                    truncated = True
                else:
                    own_layer = dict(own)
                    own_layer["entity"] = resource.entity
                    attributes = types.MappingProxyType(
                        collections.ChainMap(own_layer, resource.attrs)
                    )

            yield LogRecord(
                timestamp=timestamp,
                body=body_str,
                severity=severity,
                attributes=attributes,
            ), truncated
