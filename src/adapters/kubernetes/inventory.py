"""Kubernetes InventorySource implementation (spec SS4.2).  Thin fetch over
the read-only client returning canonical InventoryBatch.  Phase-3 reference
implementation; tool bodies do not route through this yet (2b is gate-only)."""
from __future__ import annotations

from typing import Tuple

try:
    from core.k8s_async import k8s_call
    from core.readonly_client import ReadOnlyK8sClient
    from core.signals import InventoryBatch, InventoryItem, Provenance
except ImportError:
    from src.core.k8s_async import k8s_call
    from src.core.readonly_client import ReadOnlyK8sClient
    from src.core.signals import InventoryBatch, InventoryItem, Provenance

_SUPPORTED_KINDS = ("pod",)


async def fetch_inventory(core_api, namespace: str,
                          kinds: Tuple[str, ...] = ("pod",)) -> InventoryBatch:
    ro = ReadOnlyK8sClient.wrap(core_api)
    items = []
    for kind in kinds:
        if kind == "pod":
            resp = await k8s_call(
                ro.list_namespaced_pod, namespace=namespace, watch=False)
            for p in resp.items:
                items.append(InventoryItem(
                    kind="pod",
                    name=p.metadata.name,
                    namespace=p.metadata.namespace,
                    labels=dict(p.metadata.labels or {}),
                ))
        else:
            raise ValueError(
                f"fetch_inventory: unsupported kind {kind!r}; "
                f"supported: {_SUPPORTED_KINDS}")
    return InventoryBatch(
        items=tuple(items),
        provenance=Provenance(
            adapter="kubernetes",
            query={"namespace": namespace, "kinds": list(kinds)}))
