"""Kubernetes EventSource implementation (spec SS4.2).  Thin fetch over the
read-only client returning canonical EventBatch.  Phase-3 reference
implementation; tool bodies do not route through this yet (2b is gate-only)."""
from __future__ import annotations

from typing import Optional

try:
    from core.k8s_async import k8s_call
    from core.readonly_client import ReadOnlyK8sClient
    from core.signals import EventBatch, EventRecord, Provenance
except ImportError:
    from src.core.k8s_async import k8s_call
    from src.core.readonly_client import ReadOnlyK8sClient
    from src.core.signals import EventBatch, EventRecord, Provenance


async def fetch_events(core_api, namespace: str, limit: int = 100,
                       time_period: Optional[str] = None) -> EventBatch:
    ro = ReadOnlyK8sClient.wrap(core_api)
    resp = await k8s_call(
        ro.list_namespaced_event, namespace=namespace, watch=False, limit=limit)
    records = tuple(
        EventRecord(
            timestamp=(ev.last_timestamp or ev.first_timestamp).isoformat()
            if (ev.last_timestamp or ev.first_timestamp) else None,
            type=ev.type or "",
            reason=ev.reason or "",
            message=ev.message or "",
            involved_kind=getattr(ev.involved_object, "kind", "") or "",
            involved_name=getattr(ev.involved_object, "name", "") or "",
            count=ev.count or 0,
        )
        for ev in resp.items
    )
    return EventBatch(
        records=records,
        provenance=Provenance(
            adapter="kubernetes",
            query={"namespace": namespace, "limit": limit,
                   "time_period": time_period}))
