"""
tests/test_secret_redaction.py

Secret values must never reach tool output.

Covers get_kubernetes_resource("secret", ...) in every output format and the
per-item annotations returned by search_resources_by_labels.

Contract: key names, type and metadata stay visible; data/stringData values
are replaced by size markers; Secret annotation values outside an allowlist
are redacted; non-Secret resources are unchanged.
"""
import base64
import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from kubernetes import client

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"

FAKE_KUBECONFIG = """\
apiVersion: v1
kind: Config
clusters:
- cluster: {server: "https://127.0.0.1:1"}
  name: fake
contexts:
- context: {cluster: fake, user: fake}
  name: fake
current-context: fake
users:
- name: fake
  user: {token: "fake-token"}
"""

LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration"
TOKEN_SECRET_VALUE = "openshift.io/token-secret.value"
CERT_ISSUER = "cert-manager.io/issuer-name"
TLS_KEY = "-----BEGIN PRIVATE KEY-----\nTOPSECRETKEYMATERIAL\n-----END PRIVATE KEY-----\n"
TOKEN = "sha256~very-secret-token"


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


# Every substring that must never appear in tool output.
LEAK_MARKERS = [
    "TOPSECRETKEYMATERIAL",
    _b64(TLS_KEY),
    TOKEN,
    _b64(TOKEN),
    "plain-string-data-value",
    "dockercfg-sa-token-value",
    "custom-annotation-value",
]


def _fake_secret() -> client.V1Secret:
    applied = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "my-tls", "namespace": "team-a"},
        "data": {"tls.key": _b64(TLS_KEY), "token": _b64(TOKEN)},
    }
    return client.V1Secret(
        api_version="v1",
        kind="Secret",
        type="kubernetes.io/tls",
        metadata=client.V1ObjectMeta(
            name="my-tls",
            namespace="team-a",
            labels={"app": "web"},
            annotations={
                LAST_APPLIED: json.dumps(applied),
                TOKEN_SECRET_VALUE: "dockercfg-sa-token-value",
                "example.com/custom": "custom-annotation-value",
                CERT_ISSUER: "letsencrypt-prod",
            },
        ),
        data={"tls.key": _b64(TLS_KEY), "token": _b64(TOKEN)},
        string_data={"extra": "plain-string-data-value"},
    )


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """Import server-mcp.py once per module against a fake kubeconfig."""
    _orig_kubeconfig = os.environ.get("KUBECONFIG")
    _orig_kubearchive = os.environ.get("KUBEARCHIVE_ENABLED")
    _orig_telemetry = os.environ.get("LUMINO_DISABLE_TELEMETRY")

    kubeconfig = tmp_path_factory.mktemp("kube_secret") / "config"
    kubeconfig.write_text(FAKE_KUBECONFIG)
    os.environ["KUBECONFIG"] = str(kubeconfig)
    os.environ["KUBEARCHIVE_ENABLED"] = "false"
    os.environ.setdefault("LUMINO_DISABLE_TELEMETRY", "1")
    os.environ.pop("LUMINO_CONFIG", None)
    os.environ.pop("LUMINO_PROFILE", None)

    sys.path.insert(0, str(SRC))
    spec = importlib.util.spec_from_file_location(
        "server_mcp_secret", SRC / "server-mcp.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["server_mcp_secret"] = mod
    spec.loader.exec_module(mod)

    yield mod

    def _restore_env(key, original):
        if original is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = original

    _restore_env("KUBECONFIG", _orig_kubeconfig)
    _restore_env("KUBEARCHIVE_ENABLED", _orig_kubearchive)
    _restore_env("LUMINO_DISABLE_TELEMETRY", _orig_telemetry)
    sys.modules.pop("server_mcp_secret", None)
    try:
        sys.path.remove(str(SRC))
    except ValueError:
        pass


def _assert_no_leak(output: str):
    for marker in LEAK_MARKERS:
        assert marker not in output, f"secret value {marker[:20]!r}... leaked:\n{output}"


@pytest.mark.asyncio
@pytest.mark.parametrize("output_format", ["summary", "detailed", "yaml"])
async def test_get_kubernetes_resource_secret_values_redacted(server, monkeypatch, output_format):
    fake_core = MagicMock()
    fake_core.read_namespaced_secret.return_value = _fake_secret()
    monkeypatch.setattr(server, "k8s_core_api", fake_core)

    output = await server.get_kubernetes_resource(
        "secret", "my-tls", "team-a", output_format=output_format
    )

    assert "my-tls" in output
    _assert_no_leak(output)


@pytest.mark.asyncio
async def test_get_kubernetes_resource_secret_yaml_keeps_key_names_and_sizes(server, monkeypatch):
    fake_core = MagicMock()
    fake_core.read_namespaced_secret.return_value = _fake_secret()
    monkeypatch.setattr(server, "k8s_core_api", fake_core)

    output = await server.get_kubernetes_resource(
        "secret", "my-tls", "team-a", output_format="yaml"
    )

    assert "tls.key: <redacted, %d bytes>" % len(TLS_KEY) in output
    assert "token: <redacted, %d bytes>" % len(TOKEN) in output
    assert "kubernetes.io/tls" in output
    assert f"{CERT_ISSUER}: letsencrypt-prod" in output  # allowlisted annotation stays
    assert f"{LAST_APPLIED}: <redacted>" in output
    assert f"{TOKEN_SECRET_VALUE}: <redacted>" in output


@pytest.mark.asyncio
async def test_get_kubernetes_resource_configmap_not_redacted(server, monkeypatch):
    """Guard against over-redaction: ConfigMap data is not secret."""
    fake_core = MagicMock()
    fake_core.read_namespaced_config_map.return_value = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name="cm", namespace="team-a"),
        data={"log_level": "debug-visible-value"},
    )
    monkeypatch.setattr(server, "k8s_core_api", fake_core)

    output = await server.get_kubernetes_resource(
        "configmap", "cm", "team-a", output_format="yaml"
    )

    assert "debug-visible-value" in output


def test_redact_secret_does_not_mutate_input_dict():
    sys.path.insert(0, str(SRC))
    from helpers.utils import redact_secret

    original = _fake_secret().to_dict()
    snapshot = json.dumps(original, sort_keys=True, default=str)

    redacted = redact_secret(original)

    assert json.dumps(original, sort_keys=True, default=str) == snapshot
    _assert_no_leak(json.dumps(redacted, default=str))


@pytest.mark.parametrize("hint", ["secrets", "Secrets", "SECRETS"])
def test_extract_resource_info_redacts_secret_annotations(hint):
    """search_resources_by_labels(["secrets"]) returns annotations per item.

    List API items carry no kind, so the type hint (any case, since
    get_resource_api_info lowercases it) must trigger redaction on its own.
    """
    sys.path.insert(0, str(SRC))
    from helpers.utils import extract_resource_info

    list_item = _fake_secret().to_dict()
    list_item["kind"] = None
    list_item["api_version"] = None

    info = extract_resource_info(list_item, False, False, hint)

    annotations = info["metadata"]["annotations"]
    assert annotations[LAST_APPLIED] == "<redacted>"
    assert annotations[TOKEN_SECRET_VALUE] == "<redacted>"
    assert annotations[CERT_ISSUER] == "letsencrypt-prod"
    _assert_no_leak(json.dumps(info, default=str))


def test_extract_resource_info_keeps_last_applied_on_non_secret():
    sys.path.insert(0, str(SRC))
    from helpers.utils import extract_resource_info

    deployment = {
        "kind": "Deployment",
        "metadata": {"name": "web", "annotations": {LAST_APPLIED: '{"kind":"Deployment"}'}},
    }

    info = extract_resource_info(deployment, False, False, "deployments")

    assert info["metadata"]["annotations"][LAST_APPLIED] == '{"kind":"Deployment"}'
