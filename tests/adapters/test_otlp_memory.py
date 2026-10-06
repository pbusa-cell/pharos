"""
tests/adapters/test_otlp_memory.py

C01: one small OTLP request must not use memory far beyond its own size.

A resource with thousands of short attributes and many empty logRecords used
to copy every resource attribute into every record and build every record
before the ring kept only ring_capacity of them (7.6 KB gzip -> ~300 MB peak).

Contract:
  * at most MAX_ATTRIBUTES (128, the OpenTelemetry SDK default) resource and
    record-level attributes are kept per record, plus "entity"; a record that
    lost attributes counts as truncated;
  * entity still comes from k8s.pod.name / service.name even when they are
    beyond the attribute limit;
  * the receiver keeps only the newest ring_capacity records of a batch while
    parsing; the older ones count as dropped_oldest, exactly as if the ring had
    evicted them.
"""
import gzip
import json
import sys
import tracemalloc
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from starlette.testclient import TestClient  # noqa: E402

from adapters.otlp import parse  # noqa: E402
from adapters.otlp.receiver import build_receiver_app  # noqa: E402
from adapters.otlp.rings import LogRing  # noqa: E402

MAX_ATTRS = 128


def _attrs(n, prefix="a"):
    return [{"key": f"{prefix}{i}", "value": {"stringValue": ""}} for i in range(n)]


def _request(resource_attrs, records):
    return {"resourceLogs": [{
        "resource": {"attributes": resource_attrs},
        "scopeLogs": [{"logRecords": records}],
    }]}


def test_attribute_limit_is_otel_default():
    assert parse.MAX_ATTRIBUTES == MAX_ATTRS


def test_resource_attributes_capped_and_counted_as_truncated():
    records, truncated = parse.parse_export_logs_request(
        _request(_attrs(3000), [{}, {}]), max_record_bytes=65536
    )

    assert len(records) == 2
    for r in records:
        assert len(r.attributes) == MAX_ATTRS + 1  # + entity
        assert "a0" in r.attributes and f"a{MAX_ATTRS - 1}" in r.attributes
    assert truncated == 2


def test_record_attributes_capped():
    records, truncated = parse.parse_export_logs_request(
        _request(_attrs(10, "r"), [{"attributes": _attrs(3000, "x")}]), max_record_bytes=65536
    )

    (r,) = records
    assert len(r.attributes) == 10 + MAX_ATTRS + 1
    assert truncated == 1


def test_entity_found_beyond_attribute_limit():
    resource = _attrs(500) + [{"key": "k8s.pod.name", "value": {"stringValue": "web-0"}}]

    (r,), _ = parse.parse_export_logs_request(_request(resource, [{}]), max_record_bytes=65536)

    assert r.attributes["entity"] == "web-0"


def test_small_request_unchanged():
    records, truncated = parse.parse_export_logs_request(
        _request(_attrs(3), [{"body": {"stringValue": "hello"}}]), max_record_bytes=65536
    )

    (r,) = records
    assert r.body == "hello"
    assert set(r.attributes) == {"a0", "a1", "a2", "entity"}
    assert truncated == 0


def test_parse_newest_keeps_last_records_and_counts_skipped():
    recs = [{"body": {"stringValue": f"m{i}"}} for i in range(50)]

    records, truncated, skipped = parse.parse_newest_log_records(
        _request(_attrs(2), recs), max_record_bytes=65536, max_records=10
    )

    assert [r.body for r in records] == [f"m{i}" for i in range(40, 50)]
    assert skipped == 40
    assert truncated == 0


def _gzip_body(n_attrs, n_records):
    raw = json.dumps(_request(_attrs(n_attrs), [{} for _ in range(n_records)]), separators=(",", ":"))
    return gzip.compress(raw.encode())


def test_receiver_small_request_bounded_memory():
    ring = LogRing(capacity=10)
    app = build_receiver_app(ring, {"max_body_bytes": 1_000_000, "max_record_bytes": 65536}, None)
    client = TestClient(app)
    body = _gzip_body(3000, 3000)
    assert len(body) < 20_000

    tracemalloc.start()
    resp = client.post("/v1/logs", content=body,
                       headers={"content-type": "application/json", "content-encoding": "gzip"})
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert resp.status_code == 200
    assert peak < 40 * 2**20, f"peak {peak / 2**20:.0f} MB for a {len(body)} byte request"
    stats = ring.stats()
    assert stats["buffered"] == 10
    assert stats["dropped_oldest"] == 2990  # same honest count as before the fix
    assert all(len(rec.attributes) <= MAX_ATTRS + 1 for _, rec in ring.snapshot())


def test_receiver_drop_count_includes_existing_ring_contents():
    """Evicting earlier batches still counts, as before."""
    ring = LogRing(capacity=5)
    app = build_receiver_app(ring, {"max_body_bytes": 1_000_000, "max_record_bytes": 65536}, None)
    client = TestClient(app)
    headers = {"content-type": "application/json"}

    for _ in range(2):
        resp = client.post("/v1/logs", content=json.dumps(_request(_attrs(1), [{} for _ in range(8)])),
                           headers=headers)
        assert resp.status_code == 200

    stats = ring.stats()
    assert stats["buffered"] == 5
    assert stats["dropped_oldest"] == 16 - 5


# ── review follow-up: CPU per record, receiver newest path, atomic ingest ────


def _counting(monkeypatch, name):
    calls = []
    original = getattr(parse, name)

    def wrapper(*a, **kw):
        calls.append(1)
        return original(*a, **kw)

    monkeypatch.setattr(parse, name, wrapper)
    return calls


def test_resource_attribute_cost_computed_once_per_resource(monkeypatch):
    """Records must not recompute str() of every resource attribute (CPU DoS)."""
    costs = _counting(monkeypatch, "_attr_cost")

    records, _, _ = parse.parse_newest_log_records(
        _request(_attrs(MAX_ATTRS), [{} for _ in range(2000)]), max_record_bytes=65536, max_records=2000
    )

    assert len(records) == 2000
    assert len(costs) == MAX_ATTRS


def test_records_share_resource_attributes():
    records, _, _ = parse.parse_newest_log_records(
        _request(_attrs(MAX_ATTRS), [{}, {}, {"attributes": _attrs(1, "own")}]),
        max_record_bytes=65536, max_records=10,
    )

    a, b, c = (r.attributes for r in records)
    assert a is b, "records without own attributes must share one mapping"
    assert c["own0"] == "" and c["a5"] == "" and c["entity"] == "otlp"
    assert dict(c) == {**{f"a{i}": "" for i in range(MAX_ATTRS)}, "own0": "", "entity": "otlp"}
    with pytest.raises(TypeError):
        a["x"] = 1  # shared mapping is read-only


def test_newest_mode_builds_only_kept_records(monkeypatch):
    built = _counting(monkeypatch, "LogRecord")

    records, _, skipped = parse.parse_newest_log_records(
        _request(_attrs(MAX_ATTRS), [{} for _ in range(50_000)]), max_record_bytes=65536, max_records=10
    )

    assert len(records) == 10 and skipped == 49_990
    assert len(built) == 10


def test_newest_mode_still_validates_skipped_records():
    with pytest.raises(ValueError):
        parse.parse_newest_log_records(
            _request(_attrs(1), ["not-an-object"] + [{} for _ in range(20)]),
            max_record_bytes=65536, max_records=5,
        )


def test_receiver_uses_newest_path(monkeypatch):
    """Fails if the receiver parses every record of a large batch."""
    built = _counting(monkeypatch, "LogRecord")
    ring = LogRing(capacity=10)
    app = build_receiver_app(ring, {"max_body_bytes": 2_000_000, "max_record_bytes": 65536}, None)
    body = json.dumps(_request(_attrs(MAX_ATTRS), [{} for _ in range(50_000)]))

    resp = TestClient(app).post("/v1/logs", content=body, headers={"content-type": "application/json"})

    assert resp.status_code == 200
    assert len(built) == 10
    assert ring.stats()["dropped_oldest"] == 49_990


def test_ring_ingest_is_one_atomic_update():
    ring = LogRing(capacity=3)
    ring.ingest(1.0, ["a", "b"])

    ring.ingest(2.0, ["x", "y", "z"], skipped=4, truncated=2)

    stats = ring.stats()
    assert [r for _, r in ring.snapshot()] == ["x", "y", "z"]
    assert stats["dropped_oldest"] == 4 + 2
    assert stats["truncated_records"] == 2
