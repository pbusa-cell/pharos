"""Which namespaces endpoint discovery may trust.

Discovery picks Prometheus/Thanos and KubeArchive endpoints by well-known
namespace names ("monitoring", "kubearchive", ...). On OpenShift any user can
self-provision a project with such a name when it does not exist yet, and then
own the route/service discovery would pick. KubeArchive requests carry the
caller's bearer token, so that is a token leak, not only wrong data.

Self-provisioned projects carry the openshift.io/requester annotation; names
under openshift-* and kube-* (and "default") cannot be self-provisioned.
"""
from __future__ import annotations

import logging

from core.readonly_client import ReadOnlyK8sClient

logger = logging.getLogger("lumino-mcp.namespace_trust")

REQUESTER_ANNOTATION = "openshift.io/requester"
_PLATFORM_PREFIXES = ("openshift-", "kube-")


def namespace_is_trusted(core_api, namespace: str) -> bool:
    """True when discovery may use endpoints found in namespace.

    openshift-*, kube-* and default are trusted without an API call. Any other
    namespace is trusted only when it can be read and has no
    openshift.io/requester annotation (i.e. it was not self-provisioned).
    """
    if namespace == "default" or namespace.startswith(_PLATFORM_PREFIXES):
        return True
    if core_api is None:
        logger.warning(f"Not trusting namespace {namespace!r} for discovery: cannot read it (no core API)")
        return False
    try:
        ns = ReadOnlyK8sClient.wrap(core_api).read_namespace(name=namespace)
    except Exception as e:
        if getattr(e, "status", None) == 404:
            logger.debug(f"Namespace {namespace!r} does not exist")
        else:
            logger.warning(f"Not trusting namespace {namespace!r} for discovery: cannot read it ({getattr(e, 'status', None) or type(e).__name__})")
        return False
    annotations = (getattr(ns.metadata, "annotations", None) or {}) if ns.metadata else {}
    if REQUESTER_ANNOTATION in annotations:
        logger.warning(
            f"Not trusting namespace {namespace!r} for discovery: it is a self-provisioned project "
            f"(requested by {annotations[REQUESTER_ANNOTATION]!r})"
        )
        return False
    return True
