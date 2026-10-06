"""Regression tests for cross-tenant lineage resolution (live-p02 finding, 2026-07-24).

Managed release PipelineRuns execute in the releng namespace (e.g.
rhtap-releng-tenant) while their Snapshot/Application/Component/Release
objects live in the ORIGIN tenant named by the
release.appstudio.openshift.io/namespace label.  follow_lifecycle_chain
must resolve against the origin namespace when that label is present and
fall back to the PLR's own namespace otherwise.

Also pins the stage-classification partition: managed/tenant/final release
PLRs must not be counted as the "build" stage.
"""
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from extensions.konflux import lineage  # noqa: E402


ORIGIN_NS = "origin-tenant"
RELENG_NS = "rhtap-releng-tenant"
SNAPSHOT_NAME = "my-app-20260724-103732-000"


class FakeCustomApi:
    """Snapshot exists ONLY in the origin tenant; records every namespace queried."""

    def __init__(self):
        self.get_calls = []
        self.list_calls = []

    def get_namespaced_custom_object(self, group, version, namespace, plural, name, **kwargs):
        self.get_calls.append((plural, namespace, name))
        if plural == "snapshots" and namespace == ORIGIN_NS and name == SNAPSHOT_NAME:
            return {
                "metadata": {"annotations": {}, "creationTimestamp": "2026-07-24T10:37:00Z"},
                "spec": {
                    "application": "my-app",
                    "components": [
                        {
                            "name": "my-comp",
                            "containerImage": "quay.io/example/my-comp@sha256:abc",
                            "source": {"git": {"url": "https://git.example/repo",
                                               "revision": "0a7b120542e4104015d4e8"}},
                        }
                    ],
                },
                "status": {"conditions": [
                    {"type": "AppStudioTestSucceeded", "status": "True", "reason": "Passed",
                     "message": "ok"},
                ]},
            }
        raise Exception(f"(404) snapshot {name} not found in {namespace}")

    def list_namespaced_custom_object(self, group, version, namespace, plural, **kwargs):
        self.list_calls.append((plural, namespace))
        return {"items": []}


def _managed_release_plr():
    return {
        "namespace": RELENG_NS,
        "pipeline_run_name": "managed-gzdvs",
        "labels": {
            "appstudio.openshift.io/snapshot": SNAPSHOT_NAME,
            "pipelines.appstudio.openshift.io/type": "managed",
            "release.appstudio.openshift.io/namespace": ORIGIN_NS,
        },
        "annotations": {},
        "status": "Failed",
    }


def _build_plr(namespace="tenant-a"):
    return {
        "namespace": namespace,
        "pipeline_run_name": "my-comp-on-push-abcde",
        "labels": {
            "appstudio.openshift.io/snapshot": SNAPSHOT_NAME,
            "pipelines.appstudio.openshift.io/type": "build",
        },
        "annotations": {},
        "status": "Succeeded",
    }


@pytest.mark.asyncio
async def test_lifecycle_resolves_snapshot_in_release_origin_namespace():
    fake = FakeCustomApi()
    lifecycle = await lineage.follow_lifecycle_chain(
        [_managed_release_plr()], fake, core_api=None, trace_depth="deep"
    )
    snap = lifecycle["snapshots"][0]
    assert snap["namespace"] == ORIGIN_NS
    assert "status" not in snap, f"snapshot unresolved: {snap.get('status')}"
    assert snap["application"] == "my-app"
    assert snap["component_count"] == 1
    # Releases for the snapshot must also be looked up in the origin tenant.
    release_list_namespaces = [ns for plural, ns in fake.list_calls if plural == "releases"]
    assert release_list_namespaces == [ORIGIN_NS]


@pytest.mark.asyncio
async def test_lifecycle_falls_back_to_plr_namespace_without_origin_label():
    fake = FakeCustomApi()
    lifecycle = await lineage.follow_lifecycle_chain(
        [_build_plr(namespace="tenant-a")], fake, core_api=None, trace_depth="shallow"
    )
    snap = lifecycle["snapshots"][0]
    # Snapshot only exists in origin-tenant, so tenant-a resolution fails —
    # what matters is that the lookup TARGETED the PLR's own namespace.
    assert snap["namespace"] == "tenant-a"
    assert ("snapshots", "tenant-a", SNAPSHOT_NAME) in fake.get_calls


def test_partition_release_plrs_separates_release_types_from_build():
    managed = _managed_release_plr()
    build = _build_plr()
    tenant_plr = dict(build, labels={**build["labels"],
                                     "pipelines.appstudio.openshift.io/type": "tenant"})
    final_plr = dict(build, labels={**build["labels"],
                                    "pipelines.appstudio.openshift.io/type": "final"})
    unlabeled = {"namespace": "tenant-a", "labels": {}, "status": "Running"}

    build_flow, release_flow = lineage.partition_release_plrs(
        [managed, build, tenant_plr, final_plr, unlabeled]
    )
    assert release_flow == [managed, tenant_plr, final_plr]
    assert build_flow == [build, unlabeled]


# ── overall-status derivation (review finding: the tools.py wiring must be
#    pinned; logic extracted into pure helpers so the matrix is testable) ──

def _plr(status):
    return {"status": status, "labels": {}}


def test_overall_status_release_plr_failure_is_release_failed():
    # THE live-p02 case: no build PLRs matched (pruned), one failed release PLR.
    assert lineage.derive_overall_status(
        build_flow=[], release_plr_flow=[_plr("Failed")], releases=[]
    ) == "release_failed"


def test_overall_status_running_release_plr_is_in_progress():
    # Review finding: a still-running release PLR with no resolvable Release CR
    # must NOT report succeeded.
    assert lineage.derive_overall_status(
        build_flow=[], release_plr_flow=[_plr("Running")], releases=[]
    ) == "in_progress"


def test_overall_status_build_failure_wins_over_release_failure():
    assert lineage.derive_overall_status(
        build_flow=[_plr("Failed")], release_plr_flow=[_plr("Failed")], releases=[]
    ) == "failed"


def test_overall_status_all_terminal_success():
    assert lineage.derive_overall_status(
        build_flow=[_plr("Succeeded")], release_plr_flow=[_plr("Completed")],
        releases=[{"status": "Succeeded"}],
    ) == "succeeded"


def test_overall_status_failed_release_object():
    assert lineage.derive_overall_status(
        build_flow=[_plr("Succeeded")], release_plr_flow=[], releases=[{"status": "Failed"}]
    ) == "release_failed"


def test_overall_status_empty_flow_is_not_found():
    assert lineage.derive_overall_status([], [], []) == "not_found"


def test_summarize_stages_managed_only_has_release_bucket_not_build():
    managed = dict(_plr("Failed"), labels={"pipelines.appstudio.openshift.io/type": "managed"})
    stages = lineage.summarize_stages(
        build_flow=[], release_plr_flow=[managed], lifecycle={}
    )
    assert "build" not in stages
    assert stages["release_pipelines"] == {"count": 1, "status": "failed"}


# ── Release-CR status derivation (live-p02 finding #2: Released=False with
#    reason=Progressing means IN-FLIGHT, not Failed — the old mapping labeled
#    every in-progress release "Failed") ──

def test_release_status_released_true_is_succeeded():
    assert lineage.derive_release_status(
        {"Released": {"status": "True", "reason": "Succeeded"}}
    ) == "Succeeded"


def test_release_status_false_progressing_is_progressing():
    assert lineage.derive_release_status(
        {"Released": {"status": "False", "reason": "Progressing"}}
    ) == "Progressing"


def test_release_status_false_failed_is_failed():
    assert lineage.derive_release_status(
        {"Released": {"status": "False", "reason": "Failed"}}
    ) == "Failed"


def test_release_status_missing_condition_is_in_progress():
    assert lineage.derive_release_status({}) == "InProgress"


def test_overall_status_progressing_release_is_in_progress_not_failed():
    # The live case: managed PLR Running + Release CR Released=False/Progressing.
    assert lineage.derive_overall_status(
        build_flow=[], release_plr_flow=[_plr("Running")],
        releases=[{"status": "Progressing"}],
    ) == "in_progress"


def test_summarize_stages_error_lifecycle_is_safe():
    stages = lineage.summarize_stages(
        build_flow=[_plr("Succeeded")], release_plr_flow=[],
        lifecycle={"error": "boom"},
    )
    assert stages == {"build": {"count": 1, "status": "succeeded"}}


def test_summarize_stages_running_build_is_in_progress():
    """F-15: a Running build stage must be "in_progress", not "failed".

    Root cause: the old binary ternary in summarize_stages had no middle branch —
    any build not in _TERMINAL_OK was unconditionally labelled "failed", which
    means a still-Running build was mis-classified as "failed", contradicting
    derive_overall_status (which correctly returns "in_progress").

    Fix: three-way ternary in summarize_stages for both build and release_pipelines.

    Mutation target (M-C2c): restoring the binary "else 'failed'" ternary makes
    this test RED (stage status == "failed", not "in_progress").
    """
    stages = lineage.summarize_stages(
        build_flow=[{"status": "Running"}],
        release_plr_flow=[],
        lifecycle={},
    )
    assert stages["build"]["status"] == "in_progress", (
        f"Running build should be in_progress, got {stages['build']['status']!r}"
    )
    # Consistency check: summarize_stages must agree with derive_overall_status.
    overall = lineage.derive_overall_status(
        build_flow=[{"status": "Running"}],
        release_plr_flow=[], releases=[]
    )
    assert overall == "in_progress"
