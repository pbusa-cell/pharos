"""Regression: kubernetes client 36.x + urllib3 2.x returns pod logs as the
Python REPR of bytes (live finding, 2026-07-24, itup prod cluster).

ApiClient.deserialize tries json.loads(response.data); pod logs are not JSON,
so the raw bytes fall through and str-deserialization produces "b'...'" with
literal \\n escapes — the whole log becomes ONE pseudo-line and every per-line
analysis silently degrades.  Test fakes return clean str, which is why the
suite never caught it.  normalize_pod_log_text() must undo all three shapes:
bytes-repr str, raw bytes, and (pass-through) clean text.
"""
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from helpers.utils import normalize_pod_log_text  # noqa: E402


REAL_TEXT = "2026-07-24T11:18:37Z line one\n2026-07-24T11:18:38Z line two\n"


def test_bytes_repr_string_is_decoded_to_real_lines():
    # Exactly what the broken client hands back: str(b"...") — quotes + escapes.
    mangled = str(REAL_TEXT.encode("utf-8"))
    assert mangled.startswith("b'")
    normalized = normalize_pod_log_text(mangled)
    assert normalized == REAL_TEXT
    assert normalized.count("\n") == 2


def test_bytes_repr_with_double_quote_delimiter():
    # str(bytes) uses b"..." when the content contains a single quote.
    text = "it's a log line\nsecond line\n"
    mangled = str(text.encode("utf-8"))
    assert mangled.startswith('b"')
    assert normalize_pod_log_text(mangled) == text


def test_raw_bytes_are_decoded():
    assert normalize_pod_log_text(REAL_TEXT.encode("utf-8")) == REAL_TEXT


def test_clean_text_passes_through_unchanged():
    assert normalize_pod_log_text(REAL_TEXT) is REAL_TEXT


def test_log_line_that_merely_starts_with_b_quote_is_untouched():
    # NOT a full bytes literal — literal_eval fails -> passthrough, no mangling.
    tricky = "b'not actually a bytes repr\nbecause of this raw newline"
    assert normalize_pod_log_text(tricky) is tricky


def test_invalid_utf8_bytes_decode_with_replacement():
    out = normalize_pod_log_text(b"ok \xff\xfe line\n")
    assert "ok" in out and out.endswith("line\n")


def test_invalid_utf8_inside_bytes_repr_str_decodes_with_replacement():
    # Pins errors="replace" on the literal-eval branch too (review minor).
    out = normalize_pod_log_text(str(b"ok \xff"))
    assert out.startswith("ok ") and "�" in out


def test_none_and_empty_are_safe():
    assert normalize_pod_log_text(None) is None
    assert normalize_pod_log_text("") == ""


@pytest.mark.asyncio
async def test_get_pod_logs_normalizes_mangled_client_output(monkeypatch):
    """End-to-end through the central fetch helper with a fake client that
    returns the bytes-repr shape."""
    from helpers import utils as utils_mod

    class FakePod:
        class spec:
            containers = [type("C", (), {"name": "app"})()]

    class FakeCore:
        def read_namespaced_pod(self, name, namespace, **kwargs):
            return FakePod()

        def read_namespaced_pod_log(self, **kwargs):
            return str(REAL_TEXT.encode("utf-8"))  # the broken-client shape

    result = await utils_mod.get_all_pod_logs(
        pod_name="p", namespace="ns", k8s_core_api=FakeCore(), tail_lines=10
    )
    assert result == {"app": REAL_TEXT}
