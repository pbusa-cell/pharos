"""
tests/test_kubearchive_path_validation.py

KubeArchive URL path segments must be valid Kubernetes names.

Contract: a namespace that is not a DNS-1123 label, a path name that is not a
DNS-1123 subdomain, or a fallback resource type that is not plain lowercase
letters is rejected before any token lookup or HTTP call.
"""
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import helpers.kubearchive_integration as ka
from helpers.kubearchive_integration import KubeArchiveClient

ENDPOINT = "https://kubearchive.example:8081"

BAD_NAMESPACES = [
    "openshift-config/secrets?x=",
    "a/b",
    "..",
    "ns#frag",
    "ns%2Fsecrets",
    "Upper",
    "",
    "-leading-dash",
    "a" * 64,
    "team-a\n",
]

BAD_NAMES = [
    "x/../../secrets",
    "pr?x=",
    "pr#frag",
    "..",
    "pr%2F",
    "a" * 254,
    "pr-1\n",
]


def _client(monkeypatch):
    discovery = MagicMock()
    discovery.discover_endpoint = AsyncMock(return_value=ENDPOINT)
    c = KubeArchiveClient(endpoint_discovery=discovery, k8s_auth_token="tok")
    c._get_auth_token = AsyncMock(return_value="tok")

    def _no_http(*args, **kwargs):
        raise AssertionError("HTTP session opened for an invalid path segment")

    monkeypatch.setattr(ka.aiohttp, "ClientSession", _no_http)
    return c


@pytest.mark.asyncio
@pytest.mark.parametrize("namespace", BAD_NAMESPACES)
async def test_query_resources_rejects_bad_namespace(monkeypatch, namespace):
    c = _client(monkeypatch)

    result = await c.query_resources(resource_type="pod", namespace=namespace)

    assert result["status"] == "error"
    assert "namespace" in result["message"]
    c._get_auth_token.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", BAD_NAMES)
async def test_query_resources_rejects_bad_name(monkeypatch, name):
    c = _client(monkeypatch)

    result = await c.query_resources(resource_type="pipelinerun", namespace="team-a", name=name)

    assert result["status"] == "error"
    assert "name" in result["message"]
    c._get_auth_token.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("namespace,name", [("openshift-config/secrets?x=", "p"), ("team-a", "x/../../secrets")])
async def test_get_resource_logs_rejects_bad_segments(monkeypatch, namespace, name):
    c = _client(monkeypatch)

    result = await c.get_resource_logs(resource_type="pod", namespace=namespace, name=name)

    assert result["status"] == "error"
    c._get_auth_token.assert_not_called()


def test_valid_segments_build_expected_urls():
    c = KubeArchiveClient(endpoint_discovery=MagicMock())

    assert c._build_resource_url(ENDPOINT, "pipelinerun", "team-a", "my-pr.v1-abc12") == (
        f"{ENDPOINT}/apis/tekton.dev/v1/namespaces/team-a/pipelineruns/my-pr.v1-abc12"
    )
    assert c._build_resource_url(ENDPOINT, "pod", "team-a") == (
        f"{ENDPOINT}/api/v1/namespaces/team-a/pods"
    )
    assert c._build_log_url(ENDPOINT, "taskrun", "team-a", "tr-1") == (
        f"{ENDPOINT}/apis/tekton.dev/v1/namespaces/team-a/taskruns/tr-1/log"
    )


def test_max_length_segments_accepted():
    c = KubeArchiveClient(endpoint_discovery=MagicMock())
    namespace = "a" * 63
    name = ".".join(["b" * 63] * 4)[:253].rstrip(".")

    assert c._build_resource_url(ENDPOINT, "pod", namespace, name) == (
        f"{ENDPOINT}/api/v1/namespaces/{namespace}/pods/{name}"
    )


@pytest.mark.parametrize("resource_type", ["secrets/x?y=", "pod/../secret", "a b"])
def test_fallback_resource_type_rejected(resource_type):
    """Types outside the map fall back to api/v1/<type>s; that segment is checked too."""
    c = KubeArchiveClient(endpoint_discovery=MagicMock())

    with pytest.raises(ValueError):
        c._build_resource_url(ENDPOINT, resource_type, "team-a")
    with pytest.raises(ValueError):
        c._build_log_url(ENDPOINT, resource_type, "team-a", "x")


def test_wildcard_name_stays_out_of_path():
    """Wildcard names go to the name query parameter, so they stay allowed."""
    c = KubeArchiveClient(endpoint_discovery=MagicMock())

    assert c._build_resource_url(ENDPOINT, "pipelinerun", "team-a", "my-pipeline-*") == (
        f"{ENDPOINT}/apis/tekton.dev/v1/namespaces/team-a/pipelineruns"
    )
