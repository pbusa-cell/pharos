# ============================================================================
# LOG ANALYSIS HELPER MODULE
# ============================================================================
#
# This module contains all log analysis related classes, functions, and utilities
# used by the MCP server for log processing and pattern detection.
# ============================================================================

import time
import json
import hashlib
import logging
import re
import pandas as pd
import numpy as np
from datetime import datetime, timedelta, timezone
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Tuple, Union
from collections import Counter, defaultdict

from kubernetes.client.rest import ApiException
from helpers.utils import get_all_pod_logs, calculate_context_tokens, normalize_pod_log_text, clean_etcd_logs
from core.k8s_async import LOG_TIMEOUT, k8s_call
from core.readonly_client import ReadOnlyCoreV1

logger = logging.getLogger("lumino-mcp")

# Sentinel replaced by server-mcp.py at import time with the real _DefaultClientView
# class (which late-binds server module globals and cannot live in this module).
# After server import, _estimate_pod_log_tokens' clients=None path resolves the
# module-level k8s_core_api via _DefaultClientView().core_api exactly as before.
_DefaultClientView = None

# ============================================================================
# LOG ANALYSIS STRATEGY CLASSES
# ============================================================================


class LogAnalysisStrategy(Enum):
    """Available log analysis strategies."""

    SMART_SUMMARY = "smart_summary"
    STREAMING = "streaming"
    HYBRID = "hybrid"
    AUTO = "auto"


@dataclass
class LogAnalysisContext:
    """Context information for strategy selection."""

    log_size_estimate: int
    pod_name: str
    namespace: str
    request_type: str  # "troubleshooting", "monitoring", "investigation"
    urgency: str  # "low", "medium", "high", "critical"
    time_sensitivity: bool
    follow_up_analysis: bool


# ============================================================================
# ANALYSIS CACHE CLASS
# ============================================================================


class AnalysisCache:
    """Simple in-memory cache for analysis results."""

    def __init__(self, max_size: int = 100):
        self.cache = {}
        self.max_size = max_size
        self.access_times = {}

    def _generate_key(self, namespace: str, pod_name: str, params: Dict[str, Any]) -> str:
        """Generate cache key from parameters."""
        key_data = f"{namespace}:{pod_name}:{str(sorted(params.items()))}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def get(
        self, namespace: str, pod_name: str, params: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Retrieve cached result if available and still valid."""
        key = self._generate_key(namespace, pod_name, params)

        if key in self.cache:
            result, timestamp = self.cache[key]
            # Cache valid for 10 minutes
            if time.time() - timestamp < 600:
                self.access_times[key] = time.time()
                return result
            else:
                # Expired, remove from cache
                del self.cache[key]
                if key in self.access_times:
                    del self.access_times[key]

        return None

    def set(
        self, namespace: str, pod_name: str, params: Dict[str, Any], result: Dict[str, Any]
    ) -> None:
        """Store result in cache."""
        key = self._generate_key(namespace, pod_name, params)

        # Evict oldest entries if cache is full
        if len(self.cache) >= self.max_size:
            oldest_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
            del self.cache[oldest_key]
            del self.access_times[oldest_key]

        self.cache[key] = (result, time.time())
        self.access_times[key] = time.time()


# ============================================================================
# STRATEGY SELECTOR CLASS
# ============================================================================


class StrategySelector:
    """Intelligent strategy selector based on context and requirements."""

    @staticmethod
    def select_strategy(
        context: LogAnalysisContext, available_strategies: List[LogAnalysisStrategy]
    ) -> LogAnalysisStrategy:
        """Select optimal strategy based on context."""

        # High urgency always uses streaming for real-time insights
        if context.urgency == "critical" and context.time_sensitivity:
            if LogAnalysisStrategy.STREAMING in available_strategies:
                return LogAnalysisStrategy.STREAMING

        # Large logs benefit from smart summarization
        if context.log_size_estimate > 50000:  # >50k lines
            if LogAnalysisStrategy.SMART_SUMMARY in available_strategies:
                return LogAnalysisStrategy.SMART_SUMMARY

        # Medium-sized logs for troubleshooting work well with streaming
        if context.request_type == "troubleshooting" and context.log_size_estimate > 10000:
            if LogAnalysisStrategy.STREAMING in available_strategies:
                return LogAnalysisStrategy.STREAMING

        # Investigation and monitoring typically use smart summary
        if context.request_type in ["investigation", "monitoring"]:
            if LogAnalysisStrategy.SMART_SUMMARY in available_strategies:
                return LogAnalysisStrategy.SMART_SUMMARY

        # Default to smart summary as it's most versatile
        return LogAnalysisStrategy.SMART_SUMMARY

    @staticmethod
    def estimate_log_size(namespace: str, pod_name: str) -> int:
        """Estimate log size for strategy selection."""
        try:
            # This would need to import the actual get_pod_logs function
            # For now, return a default estimate
            return 10000
        except Exception:
            return 10000  # Default safe estimate


# ============================================================================
# LOG STREAM PROCESSOR CLASS
# ============================================================================


class LogStreamProcessor:
    """Manages streaming log processing with pattern detection."""

    def __init__(
        self,
        chunk_size: int = 5000,
        analysis_mode: str = "errors_and_warnings",
        max_patterns_per_chunk: int = 100,
        max_content_length: int = 200,
    ):
        self.chunk_size = chunk_size
        self.analysis_mode = analysis_mode
        self.max_patterns_per_chunk = max_patterns_per_chunk
        self.max_content_length = max_content_length
        self.processed_lines = 0
        self.detected_patterns = []
        self.current_chunk = []

    def add_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Add a line to current chunk and return analysis if chunk is complete."""
        self.current_chunk.append(line)
        self.processed_lines += 1

        if len(self.current_chunk) >= self.chunk_size:
            return self._analyze_chunk()
        return None

    def _analyze_chunk(self) -> Dict[str, Any]:
        """Analyze current chunk and return results."""
        chunk_patterns = self._extract_patterns_from_chunk(self.current_chunk)

        result = {
            "chunk_id": len(self.detected_patterns) + 1,
            "lines_processed": len(self.current_chunk),
            "total_lines_processed": self.processed_lines,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "patterns": chunk_patterns,
            "new_issues": self._identify_new_issues(chunk_patterns),
            "chunk_summary": self._summarize_chunk(chunk_patterns),
        }

        self.detected_patterns.append(result)
        self.current_chunk = []  # Reset chunk
        return result

    def _extract_patterns_from_chunk(
        self, chunk_lines: List[str]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Extract patterns from a chunk of log lines with token-aware limits."""
        focus_areas = self._get_focus_areas_for_mode(self.analysis_mode)
        # Calculate max patterns per area based on total limit
        max_per_area = (
            max(10, self.max_patterns_per_chunk // len(focus_areas)) if focus_areas else 10
        )
        return extract_log_patterns(
            chunk_lines,
            focus_areas,
            max_patterns_per_area=max_per_area,
            max_content_length=self.max_content_length,
        )

    def _get_focus_areas_for_mode(self, mode: str) -> List[str]:
        """Get focus areas based on analysis mode."""
        mode_mappings = {
            "errors_only": ["errors"],
            "errors_and_warnings": ["errors", "warnings"],
            "full_analysis": ["errors", "warnings", "performance", "exceptions", "timeouts"],
            "custom_patterns": [
                "errors",
                "warnings",
                "performance",
                "exceptions",
                "timeouts",
                "memory_issues",
                "network_issues",
            ],
        }
        return mode_mappings.get(mode, ["errors", "warnings"])

    def _identify_new_issues(
        self, chunk_patterns: Dict[str, List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """Identify new issues not seen in previous chunks (limited to prevent token overflow)."""
        new_issues = []
        max_new_issues = 20  # Limit new issues per chunk to prevent token overflow

        for category, patterns in chunk_patterns.items():
            for pattern in patterns:
                if len(new_issues) >= max_new_issues:
                    break  # Stop if we've found enough new issues

                # Simple new issue detection (could be enhanced with ML)
                pattern_signature = pattern["content"][:100]  # First 100 chars as signature

                # Check if this pattern signature was seen before
                seen_before = any(
                    pattern_signature in str(prev_chunk.get("patterns", {}).get(category, []))
                    for prev_chunk in self.detected_patterns[-5:]  # Check last 5 chunks
                )

                if not seen_before:
                    new_issues.append(
                        {
                            "category": category,
                            "pattern": pattern,
                            "severity": self._assess_severity(category, pattern),
                        }
                    )

            if len(new_issues) >= max_new_issues:
                break

        return new_issues

    def _assess_severity(self, category: str, pattern: Dict[str, Any]) -> str:
        """Assess severity of an issue."""
        content = pattern["content"].lower()

        if category in ["exceptions", "memory_issues"] or any(
            word in content for word in ["fatal", "panic", "crash"]
        ):
            return "critical"
        elif category in ["errors", "timeouts"] or any(
            word in content for word in ["error", "failed", "timeout"]
        ):
            return "high"
        elif category in ["warnings", "performance"]:
            return "medium"
        else:
            return "low"

    def _summarize_chunk(self, chunk_patterns: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Generate summary for the current chunk."""
        total_issues = sum(len(patterns) for patterns in chunk_patterns.values())

        return {
            "total_issues": total_issues,
            "error_count": len(chunk_patterns.get("errors", [])),
            "warning_count": len(chunk_patterns.get("warnings", [])),
            "critical_issues": len(
                [
                    p
                    for patterns in chunk_patterns.values()
                    for p in patterns
                    if self._assess_severity("", p) == "critical"
                ]
            ),
            "dominant_category": max(chunk_patterns.keys(), key=lambda k: len(chunk_patterns[k]))
            if chunk_patterns
            else None,
        }

    def finalize(self) -> Optional[Dict[str, Any]]:
        """Process any remaining lines in the current chunk."""
        if self.current_chunk:
            return self._analyze_chunk()
        return None


# ============================================================================
# LOG PATTERN EXTRACTION FUNCTIONS
# ============================================================================


def _get_structured_log_level(line: str) -> Optional[str]:
    """Extract severity from structured JSON logs, returning None for non-JSON."""
    try:
        content = line.strip()
        # Strip leading timestamp if present
        timestamp_match = re.match(r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z?\s*", content)
        if timestamp_match:
            content = content[timestamp_match.end() :]
        if content.startswith("{"):
            parsed = json.loads(content)
            level = (parsed.get("level") or parsed.get("severity") or "").lower()
            if level in ("info", "debug", "warn", "warning", "error", "fatal", "panic"):
                return level
    except (json.JSONDecodeError, AttributeError, ValueError):
        pass
    return None


def extract_log_patterns(
    log_lines: List[str],
    focus_areas: List[str],
    max_patterns_per_area: int = 50,
    max_content_length: int = 200,
) -> Dict[str, List[Dict[str, Any]]]:
    """Extract patterns from log lines based on focus areas.

    Args:
        log_lines: List of log lines to analyze
        focus_areas: List of focus areas to extract patterns for
        max_patterns_per_area: Maximum number of patterns per area (default: 50)
        max_content_length: Maximum content length per pattern (default: 200 chars)
    """

    patterns = {area: [] for area in focus_areas}

    # Define pattern regex for different categories
    pattern_regex = {
        "errors": [
            r"(?i)error[:|\s](.{0,100})",
            r"(?i)exception[:|\s](.{0,100})",
            r"(?i)failed[:|\s](.{0,100})",
            r"(?i)failure[:|\s](.{0,100})",
        ],
        "warnings": [
            r"(?i)warning[:|\s](.{0,100})",
            r"(?i)warn[:|\s](.{0,100})",
            r"(?i)deprecated[:|\s](.{0,100})",
        ],
        "performance": [
            r"(?i)slow[:|\s](.{0,100})",
            r"(?i)timeout[:|\s](.{0,100})",
            r"(?i)latency[:|\s](.{0,100})",
            r"(?i)bottleneck[:|\s](.{0,100})",
        ],
        "exceptions": [
            r"(?i)panic[:|\s](.{0,100})",
            r"(?i)stacktrace[:|\s](.{0,100})",
            r"(?i)traceback[:|\s](.{0,100})",
        ],
        "timeouts": [
            r"(?i)timeout[:|\s](.{0,100})",
            r"(?i)timed out[:|\s](.{0,100})",
            r"(?i)deadline exceeded[:|\s](.{0,100})",
        ],
        "memory_issues": [
            r"(?i)out of memory[:|\s](.{0,100})",
            r"(?i)oom[:|\s](.{0,100})",
            r"(?i)memory leak[:|\s](.{0,100})",
        ],
        "network_issues": [
            r"(?i)connection refused[:|\s](.{0,100})",
            r"(?i)dns[:|\s](.{0,100})",
            r"(?i)network unreachable[:|\s](.{0,100})",
        ],
        "security": [
            r"(?i)tls[:|\s](.{0,100})",
            r"(?i)certificate[:|\s](.{0,100})",
            r"(?i)ssl[:|\s](.{0,100})",
            r"(?i)x509[:|\s](.{0,100})",
            r"(?i)permission[:|\s](.{0,100})",
            r"(?i)forbidden[:|\s](.{0,100})",
        ],
    }

    # Areas where structured JSON log level should gate pattern matching.
    # Include "performance" to prevent false positives from timeout/latency
    # values in pipeline parameters of info-level structured log lines.
    _error_sensitive_areas = {"errors", "warnings", "exceptions", "performance"}

    for line_num, line in enumerate(log_lines, 1):
        timestamp = extract_timestamp(line)
        structured_level = _get_structured_log_level(line)

        for area in focus_areas:
            # Skip if this area already has max patterns
            if len(patterns[area]) >= max_patterns_per_area:
                continue

            # For error/warning/exception areas, skip lines whose structured
            # JSON log level is info or debug — the keyword match is a false positive
            if structured_level in ("info", "debug") and area in _error_sensitive_areas:
                continue

            if area in pattern_regex:
                for regex in pattern_regex[area]:
                    # Skip if area is already full
                    if len(patterns[area]) >= max_patterns_per_area:
                        break

                    matches = re.findall(regex, line)
                    for match in matches:
                        if len(patterns[area]) >= max_patterns_per_area:
                            break
                        matched_text = match if isinstance(match, str) else str(match)

                        # Deduplicate: check if a similar pattern was already captured
                        # Use the matched_text as a signature (strip variable parts like IPs/ports)
                        dedup_sig = re.sub(r"\d+\.\d+\.\d+\.\d+:\d+", "<ip:port>", matched_text)
                        dedup_sig = re.sub(r"[0-9a-f]{8,}", "<id>", dedup_sig)
                        existing_sigs = [
                            re.sub(
                                r"\d+\.\d+\.\d+\.\d+:\d+",
                                "<ip:port>",
                                re.sub(r"[0-9a-f]{8,}", "<id>", p.get("matched_text", "")),
                            )
                            for p in patterns[area]
                        ]
                        if dedup_sig in existing_sigs:
                            # Increment count on the existing pattern instead
                            for p in patterns[area]:
                                p_sig = re.sub(
                                    r"\d+\.\d+\.\d+\.\d+:\d+",
                                    "<ip:port>",
                                    re.sub(r"[0-9a-f]{8,}", "<id>", p.get("matched_text", "")),
                                )
                                if p_sig == dedup_sig:
                                    p["occurrence_count"] = p.get("occurrence_count", 1) + 1
                                    break
                            continue

                        # Truncate content to max_content_length
                        truncated_content = line.strip()[:max_content_length]
                        if len(line.strip()) > max_content_length:
                            truncated_content += "..."
                        patterns[area].append(
                            {
                                "line_number": line_num,
                                "timestamp": timestamp,
                                "content": truncated_content,
                                "matched_text": matched_text,
                                "severity": assess_log_severity(line),
                                "occurrence_count": 1,
                            }
                        )

    return patterns


def extract_timestamp(log_line: str) -> Optional[str]:
    """Extract timestamp from log line using common patterns."""

    # Common timestamp patterns
    timestamp_patterns = [
        r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",  # ISO format
        r"(\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2})",  # MM/DD/YYYY HH:MM:SS
        r"(\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2})",  # Mon DD HH:MM:SS
        r"(\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})",  # MM-DD HH:MM:SS
        r"(\d{10,13})",  # Unix timestamp
    ]

    for pattern in timestamp_patterns:
        match = re.search(pattern, log_line)
        if match:
            return match.group(1)

    return None


def assess_log_severity(log_line: str) -> str:
    """Assess the severity of a log line."""

    line_lower = log_line.lower()

    # Critical indicators
    if any(word in line_lower for word in ["fatal", "panic", "crash", "oom", "killed"]):
        return "critical"

    # High severity indicators
    if any(word in line_lower for word in ["error", "exception", "failed", "failure"]):
        return "high"

    # Medium severity indicators
    if any(word in line_lower for word in ["warning", "warn", "deprecated", "timeout"]):
        return "medium"

    # Low severity (info, debug, etc.)
    return "low"


def sample_logs_by_time(
    log_lines: List[str],
    time_segments: int,
    max_logs_per_segment: int = 100,
    max_line_length: int = 300,
) -> Dict[str, List[str]]:
    """Sample logs by dividing into time segments with token-aware limits.

    Args:
        log_lines: List of log lines to segment
        time_segments: Number of time segments to create
        max_logs_per_segment: Maximum number of log lines per segment (default: 100)
        max_line_length: Maximum characters per log line (default: 300)
    """

    if not log_lines or time_segments <= 0:
        return {}

    # Extract timestamps and create segments
    timestamped_logs = []
    for line in log_lines:
        timestamp = extract_timestamp(line)
        if timestamp:
            timestamped_logs.append((timestamp, line))
        else:
            # If no timestamp, use current time as fallback
            timestamped_logs.append((datetime.now().isoformat(), line))

    if not timestamped_logs:
        # Limit even the fallback case
        limited_logs = log_lines[:max_logs_per_segment]
        return {
            "segment_1": [
                line[:max_line_length] + ("..." if len(line) > max_line_length else "")
                for line in limited_logs
            ]
        }

    # Sort by timestamp
    timestamped_logs.sort(key=lambda x: x[0])

    # Divide into segments
    segment_size = len(timestamped_logs) // time_segments
    segments = {}

    for i in range(time_segments):
        start_idx = i * segment_size
        end_idx = start_idx + segment_size if i < time_segments - 1 else len(timestamped_logs)

        # Get segment logs with limit
        segment_logs_raw = [log for _, log in timestamped_logs[start_idx:end_idx]]

        # Apply sampling if segment exceeds max_logs_per_segment
        if len(segment_logs_raw) > max_logs_per_segment:
            # Sample: first 30%, middle 40%, last 30%
            first_count = max_logs_per_segment * 30 // 100
            middle_count = max_logs_per_segment * 40 // 100
            last_count = max_logs_per_segment - first_count - middle_count

            first_logs = segment_logs_raw[:first_count]
            middle_start = len(segment_logs_raw) // 2 - middle_count // 2
            middle_logs = segment_logs_raw[middle_start : middle_start + middle_count]
            last_logs = segment_logs_raw[-last_count:]

            segment_logs_raw = first_logs + middle_logs + last_logs

        # Truncate long lines
        segment_logs = [
            line[:max_line_length] + ("..." if len(line) > max_line_length else "")
            for line in segment_logs_raw
        ]

        segments[f"segment_{i + 1}"] = segment_logs

    return segments


# ============================================================================
# STREAMING ANALYSIS FUNCTIONS
# ============================================================================


def generate_streaming_summary(chunk_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate summary from streaming chunk results."""

    if not chunk_results:
        return {"error": "No chunk results to summarize"}

    total_lines = sum(chunk.get("lines_processed", 0) for chunk in chunk_results)
    total_issues = sum(
        chunk.get("chunk_summary", {}).get("total_issues", 0) for chunk in chunk_results
    )

    # Aggregate patterns across chunks
    all_patterns = defaultdict(list)
    for chunk in chunk_results:
        patterns = chunk.get("patterns", {})
        for category, pattern_list in patterns.items():
            all_patterns[category].extend(pattern_list)

    # Find most common issues
    error_counter = Counter()
    for patterns in all_patterns.get("errors", []):
        error_counter[patterns.get("matched_text", "unknown")] += 1

    return {
        "total_chunks_processed": len(chunk_results),
        "total_lines_analyzed": total_lines,
        "total_issues_found": total_issues,
        "pattern_categories": list(all_patterns.keys()),
        "most_common_errors": dict(error_counter.most_common(5)),
        "analysis_timespan": {
            "first_chunk": chunk_results[0].get("timestamp"),
            "last_chunk": chunk_results[-1].get("timestamp"),
        },
    }


def analyze_trending_patterns(chunk_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze patterns that are trending across chunks."""

    if len(chunk_results) < 2:
        return {"trending": "insufficient_data"}

    # Track pattern frequency across chunks
    pattern_trends = defaultdict(list)

    for chunk in chunk_results:
        chunk_patterns = chunk.get("patterns", {})
        timestamp = chunk.get("timestamp", datetime.now().isoformat())

        for category, patterns in chunk_patterns.items():
            pattern_trends[category].append({"timestamp": timestamp, "count": len(patterns)})

    # Identify increasing trends
    trending_up = {}
    for category, trend_data in pattern_trends.items():
        if len(trend_data) >= 2:
            recent_avg = sum(d["count"] for d in trend_data[-2:]) / 2
            earlier_avg = sum(d["count"] for d in trend_data[:-2]) / max(1, len(trend_data) - 2)

            if recent_avg > earlier_avg * 1.5:  # 50% increase threshold
                trending_up[category] = {
                    "recent_average": recent_avg,
                    "earlier_average": earlier_avg,
                    "trend_strength": recent_avg / max(earlier_avg, 0.1),
                }

    return {"trending_up": trending_up, "pattern_trends": dict(pattern_trends)}


def generate_streaming_recommendations(
    overall_summary: Dict[str, Any], trending_patterns: Dict[str, Any]
) -> List[str]:
    """Generate recommendations based on streaming analysis."""

    recommendations = []

    # High issue count recommendations
    total_issues = overall_summary.get("total_issues_found", 0)
    if total_issues > 50:
        recommendations.append(
            f"High issue count detected ({total_issues}). Consider reviewing application stability."
        )
    elif total_issues > 10:
        recommendations.append(
            f"Moderate issue count ({total_issues}). Review error patterns for recurring problems."
        )

    # Trending pattern recommendations
    trending_up = trending_patterns.get("trending_up", {})
    if "errors" in trending_up:
        recommendations.append("Error rate is increasing. Immediate investigation recommended.")

    if "memory_issues" in trending_up:
        recommendations.append(
            "Memory issues trending up. Check for memory leaks or increase resource limits."
        )

    if "timeouts" in trending_up:
        recommendations.append(
            "Timeout patterns increasing. Review network connectivity and service dependencies."
        )

    # Pattern-specific recommendations
    common_errors = overall_summary.get("most_common_errors", {})
    for error, count in common_errors.items():
        if count > 10:
            recommendations.append(
                f"Frequent error pattern detected: '{error}' ({count} occurrences)"
            )

    if not recommendations:
        if total_issues == 0:
            total_lines = overall_summary.get("total_lines_analyzed", 1)
            if total_lines > 0:
                recommendations.append("No critical patterns detected. System appears stable.")
            else:
                recommendations.append(
                    "No lines were processed — system stability cannot be determined."
                )
        else:
            recommendations.append(
                f"{total_issues} issue(s) detected but no critical "
                "patterns identified. Review logs for details."
            )

    return recommendations


# ============================================================================
# ANALYSIS COMBINATION FUNCTIONS
# ============================================================================


def combine_analysis_results(
    summary_result: Dict[str, Any], streaming_result: Dict[str, Any]
) -> Dict[str, Any]:
    """Combine results from summary and streaming analysis."""

    combined = {
        "analysis_type": "hybrid",
        "summary_analysis": summary_result,
        "streaming_analysis": streaming_result,
        "combined_insights": [],
    }

    # Generate combined insights
    insights = []

    # Compare issue counts
    summary_issues = summary_result.get("summary", {}).get("total_issues", 0)
    streaming_issues = streaming_result.get("overall_summary", {}).get("total_issues_found", 0)

    if abs(summary_issues - streaming_issues) > 10:
        insights.append(
            f"Analysis divergence detected: Summary found "
            f"{summary_issues} issues, streaming found "
            f"{streaming_issues}"
        )

    # Check for consistency in error patterns
    summary_errors = set(summary_result.get("patterns", {}).get("errors", {}).keys())
    streaming_errors = set(
        streaming_result.get("overall_summary", {}).get("most_common_errors", {}).keys()
    )

    common_errors = summary_errors.intersection(streaming_errors)
    if common_errors:
        insights.append(
            f"Consistent error patterns identified: {', '.join(list(common_errors)[:3])}"
        )

    combined["combined_insights"] = insights
    return combined


def generate_supplementary_insights(
    primary_results: Dict[str, Any], context: LogAnalysisContext
) -> Dict[str, Any]:
    """Generate supplementary insights based on context."""

    insights = {"contextual_analysis": [], "recommendations": [], "follow_up_actions": []}

    # Context-specific insights
    if context.request_type == "troubleshooting":
        insights["contextual_analysis"].append(
            "Analysis focused on troubleshooting - prioritizing error patterns"
        )

        error_count = len(primary_results.get("patterns", {}).get("errors", []))
        if error_count > 5:
            insights["recommendations"].append(
                "Multiple error patterns found - recommend systematic investigation"
            )

    elif context.request_type == "monitoring":
        insights["contextual_analysis"].append(
            "Monitoring mode - tracking trends and performance indicators"
        )

        # Check for performance patterns
        perf_issues = len(primary_results.get("patterns", {}).get("performance", []))
        if perf_issues > 0:
            insights["recommendations"].append(
                "Performance issues detected - consider resource optimization"
            )

    # Urgency-based recommendations
    if context.urgency == "critical":
        insights["follow_up_actions"].append(
            "CRITICAL: Immediate escalation and remediation required"
        )
    elif context.urgency == "high":
        insights["follow_up_actions"].append("HIGH: Schedule investigation within 2 hours")

    return insights


def generate_hybrid_recommendations(
    primary_results: Dict[str, Any], context: LogAnalysisContext, strategy: LogAnalysisStrategy
) -> List[str]:
    """Generate recommendations based on hybrid analysis."""

    recommendations = []

    # Strategy-specific recommendations
    if strategy == LogAnalysisStrategy.STREAMING:
        recommendations.append("Real-time analysis completed - monitor for pattern evolution")
    elif strategy == LogAnalysisStrategy.SMART_SUMMARY:
        recommendations.append("Comprehensive analysis completed - detailed patterns extracted")

    # Context-driven recommendations
    total_issues = primary_results.get("summary", {}).get("total_issues", 0)

    if context.urgency == "critical" and total_issues > 10:
        recommendations.append(
            "IMMEDIATE ACTION: High issue count in critical context - activate incident response"
        )

    if context.follow_up_analysis:
        recommendations.append("Follow-up analysis recommended - schedule detailed investigation")

    # Pattern-specific recommendations
    patterns = primary_results.get("patterns", {})

    if "memory_issues" in patterns and len(patterns["memory_issues"]) > 3:
        recommendations.append(
            "Memory issues detected - review resource limits and check for leaks"
        )

    if "network_issues" in patterns and len(patterns["network_issues"]) > 2:
        recommendations.append(
            "Network connectivity issues - verify service mesh and DNS configuration"
        )

    return recommendations


# Create global cache instance
analysis_cache = AnalysisCache(max_size=50)


def generate_focused_summary(
    patterns: Dict[str, List[Dict[str, Any]]], focus_areas: List[str], summary_level: str
) -> Dict[str, Any]:
    """Generate a focused summary based on extracted patterns."""
    summary = {
        "overview": {},
        "key_findings": [],
        "recommendations": [],
        "pattern_counts": {},
        "timeline_analysis": {},
        "critical_issues": [],
    }

    # Count patterns
    for category, items in patterns.items():
        summary["pattern_counts"][category] = len(items)

    # Generate overview
    total_issues = sum(len(items) for items in patterns.values())
    error_count = len(patterns.get("errors", []))
    warning_count = len(patterns.get("warnings", []))

    summary["overview"] = {
        "total_issues_found": total_issues,
        "error_count": error_count,
        "warning_count": warning_count,
        "performance_issues": len(patterns.get("performance", [])),
        "critical_categories": [cat for cat, items in patterns.items() if len(items) > 5],
    }

    # Key findings based on summary level
    if summary_level in ["detailed", "comprehensive"]:
        # Add specific error patterns
        for category in focus_areas:
            if category in patterns and patterns[category]:
                # Get most frequent error patterns
                error_messages = [item["content"] for item in patterns[category][:10]]
                summary["key_findings"].append(
                    {
                        "category": category,
                        "count": len(patterns[category]),
                        "sample_messages": error_messages[:5],
                    }
                )

    # Timeline analysis for comprehensive summaries
    if summary_level == "comprehensive":
        timestamps = []
        for category, items in patterns.items():
            for item in items:
                if item.get("timestamp"):
                    timestamps.append(
                        {
                            "timestamp": item["timestamp"],
                            "category": category,
                            "line": item["line_number"],
                        }
                    )

        if timestamps:
            # Sort by timestamp (simplified)
            timestamps.sort(key=lambda x: x["timestamp"])
            summary["timeline_analysis"] = {
                "first_issue": timestamps[0] if timestamps else None,
                "last_issue": timestamps[-1] if timestamps else None,
                "issue_distribution": {},
            }

    # Critical issues (high-priority items)
    critical_patterns = ["exceptions", "timeouts", "memory_issues"]
    for pattern in critical_patterns:
        if pattern in patterns and patterns[pattern]:
            summary["critical_issues"].extend(patterns[pattern][:3])  # Top 3 critical issues

    # Recommendations
    if error_count > 10:
        summary["recommendations"].append(
            "High error count detected. Investigate application stability."
        )
    if len(patterns.get("memory_issues", [])) > 0:
        summary["recommendations"].append(
            "Memory issues detected. Consider increasing pod "
            "memory limits or investigating memory leaks."
        )
    if len(patterns.get("timeouts", [])) > 5:
        summary["recommendations"].append(
            "Multiple timeout issues found. Check network connectivity and service dependencies."
        )
    if len(patterns.get("performance", [])) > 5:
        summary["recommendations"].append(
            "Performance issues detected. Consider resource optimization or scaling."
        )

    return summary


def get_strategy_selection_reason(
    context: LogAnalysisContext, strategy: LogAnalysisStrategy
) -> str:
    """Get explanation for why a strategy was selected."""
    if strategy == LogAnalysisStrategy.STREAMING:
        if context.urgency == "critical":
            return "Streaming selected for critical urgency requiring immediate insights"
        elif context.request_type == "troubleshooting":
            return "Streaming selected for real-time troubleshooting support"
        else:
            return "Streaming selected for progressive analysis of medium-sized logs"

    elif strategy == LogAnalysisStrategy.SMART_SUMMARY:
        if context.log_size_estimate > 50000:
            return "Smart summary selected for large log size requiring efficient processing"
        elif context.request_type in ["investigation", "monitoring"]:
            return (
                f"Smart summary selected for "
                f"{context.request_type} requiring "
                "comprehensive analysis"
            )
        else:
            return "Smart summary selected as versatile default strategy"

    elif strategy == LogAnalysisStrategy.HYBRID:
        return "Hybrid strategy selected for comprehensive analysis requiring multiple approaches"

    else:
        return "Strategy selected based on automatic optimization"


def preprocess_log_data(log_lines: List[str]) -> pd.DataFrame:
    """Preprocess log data for ML analysis."""
    processed_data = []

    for line in log_lines:
        # Extract timestamp if present
        timestamp_match = re.search(r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}", line)
        timestamp = timestamp_match.group() if timestamp_match else None

        # Extract log level
        level_match = re.search(r"\b(DEBUG|INFO|WARN|ERROR|FATAL|PANIC)\b", line, re.IGNORECASE)
        log_level = level_match.group().upper() if level_match else "UNKNOWN"

        # Extract error patterns
        error_indicators = len(
            re.findall(r"\b(error|exception|failed|fatal|panic|timeout)\b", line, re.IGNORECASE)
        )

        # Calculate message length and entropy
        message_length = len(line)
        message_entropy = calculate_entropy(line)

        processed_data.append(
            {
                "timestamp": timestamp,
                "log_level": log_level,
                "error_indicators": error_indicators,
                "message_length": message_length,
                "message_entropy": message_entropy,
                "raw_message": line,
            }
        )

    return pd.DataFrame(processed_data)


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text."""
    if not text:
        return 0.0

    # Count character frequencies
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1

    # Calculate entropy
    text_length = len(text)
    entropy = 0.0
    for count in char_counts.values():
        probability = count / text_length
        if probability > 0:
            entropy -= probability * np.log2(probability)

    return entropy


def extract_log_features(df: pd.DataFrame) -> np.ndarray:
    """Extract features from preprocessed log data."""

    # Time-based features
    df["hour"] = pd.to_datetime(df["timestamp"], errors="coerce").dt.hour
    df["minute"] = pd.to_datetime(df["timestamp"], errors="coerce").dt.minute

    # Rolling window features (last 10 messages)
    window_size = 10
    df["error_rate_window"] = (
        df["error_indicators"].rolling(window=window_size, min_periods=1).mean()
    )
    df["avg_length_window"] = df["message_length"].rolling(window=window_size, min_periods=1).mean()
    df["entropy_trend"] = df["message_entropy"].rolling(window=window_size, min_periods=1).std()

    # Log level encoding
    level_encoding = {
        "DEBUG": 0,
        "INFO": 1,
        "WARN": 2,
        "ERROR": 3,
        "FATAL": 4,
        "PANIC": 5,
        "UNKNOWN": 0,
    }
    df["log_level_encoded"] = df["log_level"].map(level_encoding)

    # Select feature columns
    feature_columns = [
        "error_indicators",
        "message_length",
        "message_entropy",
        "hour",
        "minute",
        "error_rate_window",
        "avg_length_window",
        "entropy_trend",
        "log_level_encoded",
    ]

    return df[feature_columns].fillna(0).values


def train_anomaly_model(features: np.ndarray, contamination: float = 0.1):
    """Train isolation forest model for anomaly detection."""
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
    model.fit(features)
    return model


def train_enhanced_anomaly_model(
    features: np.ndarray, labels: Optional[np.ndarray] = None, contamination: float = 0.1
):
    """Train anomaly model with optional label guidance (semi-supervised).

    When labels are available, adjusts contamination based on actual failure rate.

    Args:
        features: Feature matrix for training
        labels: Optional binary labels (1=failure, 0=normal)
        contamination: Base contamination rate if no labels

    Returns:
        Trained IsolationForest model
    """
    from sklearn.ensemble import IsolationForest

    if labels is not None and len(labels) > 0:
        # Adjust contamination based on actual failure rate
        actual_contamination = np.mean(labels == 1)
        contamination = max(0.01, min(0.5, actual_contamination * 1.5))

    model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
        max_samples="auto",
        bootstrap=True,
    )

    model.fit(features)
    return model


def train_or_load_model(
    features: np.ndarray,
    model_manager,
    version_manager,
    labels: Optional[np.ndarray] = None,
    force_retrain: bool = False,
) -> Tuple[Any, str, Dict[str, Any]]:
    """Load existing model or train new one based on conditions.

    Args:
        features: Feature matrix for training/validation
        model_manager: ModelPersistenceManager instance
        version_manager: ModelVersionManager instance
        labels: Optional labels for semi-supervised training
        force_retrain: Force training even if model is valid

    Returns:
        Tuple of (model, model_id, training_metadata)
    """
    from datetime import datetime

    current_model_id = version_manager.get_current_model_id()

    # Try to load existing model
    if current_model_id and not force_retrain:
        should_retrain, reason = version_manager.should_retrain(current_model_id)
        if not should_retrain:
            try:
                model, metadata = model_manager.load_model(current_model_id)
                metadata["loaded_from_cache"] = True
                metadata["load_reason"] = "model_valid"
                return model, current_model_id, metadata
            except FileNotFoundError:
                pass  # Fall through to training

    # Train new model
    new_model_id = version_manager.generate_new_model_id()

    # Use enhanced training with labels if available
    model = train_enhanced_anomaly_model(features, labels)

    metadata = {
        "model_id": new_model_id,
        "model_type": "IsolationForest",
        "version": "1.0.0",
        "training_samples": len(features),
        "has_labels": labels is not None,
        "label_count": int(np.sum(labels)) if labels is not None else 0,
        "created_at": datetime.now().isoformat(),
        "loaded_from_cache": False,
        "training_config": {"contamination": 0.1, "n_estimators": 100, "random_state": 42},
    }

    # Save model to disk
    try:
        model_manager.save_model(model, new_model_id, metadata)
    except Exception as e:
        logger.warning(f"Failed to save model: {e}")

    return model, new_model_id, metadata


def analyze_log_patterns_for_failure_prediction(
    log_data: pd.DataFrame, historical_failures: List[Dict]
) -> Dict[str, Any]:
    """Analyze log patterns to predict potential failures.

    Args:
        log_data: DataFrame with preprocessed log data
        historical_failures: List of historical failure labels from TrainingDataStore

    Returns:
        Dict with failure_patterns, risk_score, and historical_context
    """
    failure_patterns = []
    historical_context = {
        "total_historical_failures": len(historical_failures),
        "failure_types_seen": {},
        "recent_failures": [],
    }

    # Pattern 1: High error rate
    error_rate = (
        log_data["error_indicators"].mean() if "error_indicators" in log_data.columns else 0
    )
    if error_rate > 0.1:  # More than 10% error indicators
        failure_patterns.append(
            {
                "pattern": "high_error_rate",
                "severity": "high" if error_rate > 0.3 else "medium",
                "value": error_rate,
            }
        )

    # Pattern 2: Entropy spikes (indicating unusual log patterns)
    if "message_entropy" in log_data.columns and len(log_data) > 0:
        entropy_mean = log_data["message_entropy"].mean()
        entropy_std = log_data["message_entropy"].std()
        if entropy_std > 0:
            entropy_threshold = entropy_mean + 2 * entropy_std
            entropy_spikes = (log_data["message_entropy"] > entropy_threshold).sum()
            if entropy_spikes > len(log_data) * 0.05:
                failure_patterns.append(
                    {
                        "pattern": "entropy_spikes",
                        "severity": "medium",
                        "value": entropy_spikes / len(log_data),
                    }
                )

    # Pattern 3: Message length anomalies
    if "message_length" in log_data.columns and len(log_data) > 0:
        length_mean = log_data["message_length"].mean()
        length_std = log_data["message_length"].std()
        if length_std > 0:
            length_threshold = length_mean + 3 * length_std
            length_anomalies = (log_data["message_length"] > length_threshold).sum()
            if length_anomalies > 0:
                failure_patterns.append(
                    {
                        "pattern": "message_length_anomalies",
                        "severity": "low",
                        "value": length_anomalies,
                    }
                )

    # Pattern 4: Analyze historical failures for predictive patterns
    if historical_failures:
        # Count failure types
        failure_type_counts = {}
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for failure in historical_failures:
            ftype = failure.get("failure_type", "unknown")
            severity = failure.get("severity", "medium")

            failure_type_counts[ftype] = failure_type_counts.get(ftype, 0) + 1
            if severity in severity_counts:
                severity_counts[severity] += 1

        historical_context["failure_types_seen"] = failure_type_counts
        historical_context["severity_distribution"] = severity_counts

        # Add recent failures to context (last 5)
        historical_context["recent_failures"] = [
            {
                "failure_type": f.get("failure_type"),
                "severity": f.get("severity"),
                "resource_name": f.get("resource_name"),
                "failure_time": f.get("failure_time"),
            }
            for f in historical_failures[:5]
        ]

        # Pattern: Recurring failure types indicate elevated risk
        for ftype, count in failure_type_counts.items():
            if count >= 2:  # Same failure type occurred 2+ times
                failure_patterns.append(
                    {
                        "pattern": "recurring_failure",
                        "severity": "high",
                        "value": count,
                        "failure_type": ftype,
                        "description": f"'{ftype}' failure occurred {count} times in last 24h",
                    }
                )

        # Pattern: Critical/high severity failures in recent history
        critical_high = severity_counts["critical"] + severity_counts["high"]
        if critical_high > 0:
            failure_patterns.append(
                {
                    "pattern": "recent_critical_failures",
                    "severity": "high" if severity_counts["critical"] > 0 else "medium",
                    "value": critical_high,
                    "description": f"{critical_high} critical/high severity failures in last 24h",
                }
            )

        # Pattern: High failure density (many failures in short time)
        if len(historical_failures) >= 5:
            failure_patterns.append(
                {
                    "pattern": "high_failure_density",
                    "severity": "high",
                    "value": len(historical_failures),
                    "description": (
                        f"{len(historical_failures)} failures "
                        "in last 24h indicates instability"
                    ),
                }
            )

    # Calculate risk score with historical failure weighting
    base_risk = (
        sum(1 for p in failure_patterns if p["severity"] == "high") * 0.5
        + sum(1 for p in failure_patterns if p["severity"] == "medium") * 0.3
        + sum(1 for p in failure_patterns if p["severity"] == "low") * 0.1
    )

    # Boost risk score based on historical failure count (up to 0.5 additional)
    historical_boost = min(len(historical_failures) * 0.05, 0.5) if historical_failures else 0

    # Total risk score capped at 2.0
    risk_score = min(base_risk + historical_boost, 2.0)

    return {
        "failure_patterns": failure_patterns,
        "risk_score": risk_score,
        "historical_context": historical_context,
    }


def generate_failure_predictions(
    patterns: Dict[str, Any],
    confidence_threshold: float,
    prediction_window: str,
    historical_failures: Optional[List[Dict]] = None,
    labels: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Generate failure predictions based on detected patterns and historical data.

    Args:
        patterns: Output from analyze_log_patterns_for_failure_prediction
        confidence_threshold: Minimum confidence for predictions
        prediction_window: Time window for predictions
        historical_failures: List of historical failure labels
        labels: Binary labels from log-failure correlations (numpy array)

    Returns:
        List of prediction dicts with failure_type, predicted_time, confidence, etc.
    """
    predictions = []
    historical_failures = historical_failures or []

    risk_score = patterns.get("risk_score", 0)
    failure_patterns = patterns.get("failure_patterns", [])
    historical_context = patterns.get("historical_context", {})

    # Calculate base confidence from risk score
    base_confidence = min(risk_score * 0.6, 0.95)

    # Boost confidence if we have labeled data correlations
    label_boost = 0.0
    if labels is not None:
        try:
            import numpy as np

            if isinstance(labels, np.ndarray) and len(labels) > 0:
                # Percentage of logs correlated with failures
                failure_correlation_rate = np.mean(labels)
                if failure_correlation_rate > 0.1:
                    label_boost = min(failure_correlation_rate * 0.3, 0.2)
        except Exception:
            pass

    # Boost confidence based on historical failure count
    historical_boost = 0.0
    if historical_failures:
        # More historical failures = higher confidence in prediction
        historical_boost = min(len(historical_failures) * 0.02, 0.15)

    # Combined confidence
    confidence = min(base_confidence + label_boost + historical_boost, 0.95)

    # Calculate predicted time based on window
    window_hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}.get(prediction_window, 6)

    predicted_time = (datetime.now() + timedelta(hours=window_hours)).isoformat()

    # Generate predictions from patterns
    if confidence >= confidence_threshold:
        failure_types = []
        affected_components = []
        warning_indicators = []
        recommended_actions = []

        for pattern in failure_patterns:
            pattern_type = pattern.get("pattern", "")

            if pattern_type == "high_error_rate":
                failure_types.append("service_degradation")
                affected_components.append("application_pods")
                warning_indicators.append(f"Error rate at {pattern['value']:.2%}")
                recommended_actions.append("Investigate error logs and increase monitoring")

            elif pattern_type == "entropy_spikes":
                failure_types.append("unusual_behavior")
                affected_components.append("logging_system")
                warning_indicators.append(f"Entropy spikes in {pattern['value']:.2%} of logs")
                recommended_actions.append("Check for configuration changes or new deployments")

            elif pattern_type == "recurring_failure":
                ftype = pattern.get("failure_type", "unknown")
                failure_types.append(ftype)
                affected_components.append(pattern.get("resource_type", "unknown"))
                warning_indicators.append(pattern.get("description", f"Recurring {ftype} failures"))
                recommended_actions.append(
                    f"Investigate root cause of recurring '{ftype}' failures"
                )

            elif pattern_type == "recent_critical_failures":
                failure_types.append("critical_failure_risk")
                affected_components.append("cluster")
                warning_indicators.append(
                    pattern.get("description", "Recent critical failures detected")
                )
                recommended_actions.append(
                    "Review recent critical failures and ensure fixes are in place"
                )

            elif pattern_type == "high_failure_density":
                failure_types.append("system_instability")
                affected_components.append("cluster")
                warning_indicators.append(
                    pattern.get("description", "High failure density detected")
                )
                recommended_actions.append("Perform comprehensive system health check")

        # Create prediction entry
        if failure_types:
            predictions.append(
                {
                    "failure_type": failure_types[0],
                    "all_failure_types": list(set(failure_types)),
                    "predicted_time": predicted_time,
                    "confidence": round(confidence, 3),
                    "affected_components": list(set(affected_components)),
                    "warning_indicators": warning_indicators,
                    "recommended_actions": list(set(recommended_actions)),
                    "based_on_patterns": len(failure_patterns),
                    "based_on_historical_failures": len(historical_failures),
                    "has_labeled_correlations": labels is not None and label_boost > 0,
                }
            )

    # Also generate predictions directly from historical failures if no pattern-based predictions
    # and we have enough historical data
    if not predictions and historical_failures and len(historical_failures) >= 3:
        # Find the most common failure type
        failure_type_counts = historical_context.get("failure_types_seen", {})
        if failure_type_counts:
            most_common = max(failure_type_counts.items(), key=lambda x: x[1])
            ftype, count = most_common

            # Generate prediction based on historical pattern
            historical_confidence = min(0.5 + (count * 0.1), 0.85)

            if historical_confidence >= confidence_threshold:
                predictions.append(
                    {
                        "failure_type": ftype,
                        "predicted_time": predicted_time,
                        "confidence": round(historical_confidence, 3),
                        "affected_components": ["cluster"],
                        "warning_indicators": [
                            f"'{ftype}' failure occurred {count} times recently",
                            f"Based on {len(historical_failures)} historical failures",
                        ],
                        "recommended_actions": [
                            f"Proactively address '{ftype}' failure patterns",
                            "Review recent changes that may have introduced instability",
                        ],
                        "prediction_source": "historical_pattern",
                        "based_on_historical_failures": len(historical_failures),
                    }
                )

    return predictions


def _build_log_params(search_params: Dict[str, Any]) -> Dict[str, Any]:
    """Build log retrieval parameters from search params."""
    time_range = search_params.get("time_range", "1h")

    # Convert time range to seconds
    time_mapping = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}

    since_seconds = time_mapping.get(time_range, 3600)

    return {
        "since_seconds": since_seconds,
        "tail_lines": 500,  # Reasonable limit for semantic analysis
    }


# ============================================================================
# TOKEN LIMIT TRUNCATION FUNCTIONS
# ============================================================================


def truncate_to_token_limit(
    data: Dict[str, Any], max_tokens: int, chars_per_token: int = 4
) -> Dict[str, Any]:
    """Truncate response data to fit within token limit.

    Args:
        data: The response dictionary to truncate
        max_tokens: Maximum number of tokens allowed
        chars_per_token: Estimated characters per token (default: 4)

    Returns:
        Truncated data that fits within the token limit
    """
    import json

    # Estimate current size
    try:
        current_chars = len(json.dumps(data, default=str))
        current_tokens = current_chars // chars_per_token
    except (TypeError, ValueError):
        current_tokens = max_tokens + 1  # Force truncation if serialization fails

    if current_tokens <= max_tokens:
        return data

    # Create a copy to avoid modifying original
    result = data.copy()

    # Progressive truncation strategy
    # Stage 1: Truncate patterns to top N per category
    if "patterns" in result and isinstance(result["patterns"], dict):
        max_per_category = max(5, max_tokens // 200)  # Scale with token limit
        for category in result["patterns"]:
            if isinstance(result["patterns"][category], list):
                result["patterns"][category] = result["patterns"][category][:max_per_category]
                # Also truncate content within each pattern
                for pattern in result["patterns"][category]:
                    if isinstance(pattern, dict) and "content" in pattern:
                        pattern["content"] = (
                            pattern["content"][:150] + "..."
                            if len(pattern.get("content", "")) > 150
                            else pattern.get("content", "")
                        )

    # Check size after stage 1
    try:
        current_tokens = len(json.dumps(result, default=str)) // chars_per_token
    except (TypeError, ValueError):
        pass

    if current_tokens <= max_tokens:
        result["_truncated"] = True
        result["_truncation_stage"] = 1
        return result

    # Stage 2: Convert time_segments to counts only
    if "time_segments" in result and isinstance(result["time_segments"], dict):
        result["time_segments"] = {
            k: len(v) if isinstance(v, list) else v for k, v in result["time_segments"].items()
        }
        result["time_segments"]["_note"] = "Counts only - full logs truncated for token limit"

    # Check size after stage 2
    try:
        current_tokens = len(json.dumps(result, default=str)) // chars_per_token
    except (TypeError, ValueError):
        pass

    if current_tokens <= max_tokens:
        result["_truncated"] = True
        result["_truncation_stage"] = 2
        return result

    # Stage 3: Truncate representative_samples
    if "representative_samples" in result and isinstance(result["representative_samples"], list):
        max_samples = max(3, max_tokens // 500)
        result["representative_samples"] = result["representative_samples"][:max_samples]
        for sample in result["representative_samples"]:
            if isinstance(sample, dict) and "content" in sample:
                sample["content"] = (
                    sample["content"][:100] + "..."
                    if len(sample.get("content", "")) > 100
                    else sample.get("content", "")
                )

    # Check size after stage 3
    try:
        current_tokens = len(json.dumps(result, default=str)) // chars_per_token
    except (TypeError, ValueError):
        pass

    if current_tokens <= max_tokens:
        result["_truncated"] = True
        result["_truncation_stage"] = 3
        return result

    # Stage 4: Truncate chunk results (for streaming analysis)
    if "chunks" in result and isinstance(result["chunks"], list):
        max_chunks = max(3, max_tokens // 1000)
        result["chunks"] = result["chunks"][:max_chunks]
        # Truncate patterns within each chunk
        for chunk in result["chunks"]:
            if isinstance(chunk, dict) and "patterns" in chunk:
                for category in chunk["patterns"]:
                    if isinstance(chunk["patterns"][category], list):
                        chunk["patterns"][category] = chunk["patterns"][category][:5]

    # Stage 5: Remove large metadata fields if still too large
    try:
        current_tokens = len(json.dumps(result, default=str)) // chars_per_token
    except (TypeError, ValueError):
        pass

    if current_tokens > max_tokens:
        # Remove optional large fields
        fields_to_trim = ["raw_logs", "full_timeline", "detailed_analysis", "chunk_details"]
        for field in fields_to_trim:
            if field in result:
                del result[field]

    result["_truncated"] = True
    result["_truncation_stage"] = "final"
    result["_original_token_estimate"] = current_tokens
    result["_max_tokens"] = max_tokens

    return result


def truncate_streaming_results(
    chunk_results: List[Dict[str, Any]], max_tokens: int
) -> List[Dict[str, Any]]:
    """Truncate streaming chunk results to fit within token limit.

    Args:
        chunk_results: List of chunk analysis results
        max_tokens: Maximum number of tokens allowed

    Returns:
        Truncated list of chunk results
    """
    import json

    if not chunk_results:
        return chunk_results

    chars_per_token = 4

    # Estimate current size
    try:
        current_tokens = len(json.dumps(chunk_results, default=str)) // chars_per_token
    except (TypeError, ValueError):
        current_tokens = max_tokens + 1

    if current_tokens <= max_tokens:
        return chunk_results

    # Calculate how many chunks we can afford
    avg_tokens_per_chunk = current_tokens // len(chunk_results) if chunk_results else 1
    max_chunks = max(3, max_tokens // max(avg_tokens_per_chunk, 100))

    # Keep most recent chunks (they're likely more relevant)
    truncated = chunk_results[-max_chunks:]

    # Further truncate patterns within each chunk
    for chunk in truncated:
        if "patterns" in chunk and isinstance(chunk["patterns"], dict):
            for category in chunk["patterns"]:
                if isinstance(chunk["patterns"][category], list):
                    chunk["patterns"][category] = chunk["patterns"][category][:10]

        if "new_issues" in chunk and isinstance(chunk["new_issues"], list):
            chunk["new_issues"] = chunk["new_issues"][:5]

    return truncated


def truncate_baseline_results(result: Dict, max_tokens: int) -> Dict:
    """Truncate ci_cd_performance_baselining_tool result to fit within token budget.

    Uses ÷4 heuristic (len(json.dumps(result)) // 4), consistent with this module.
    Progressive staged truncation while over budget:
      Stage 1: cap task_level_analysis per-pipeline lists to 5 entries
               (task_baselines, slowest_tasks, most_failed_tasks)
      Stage 2: cap pipeline_baselines to first-N (halving each step).
               first-N is the design: round-1 review confirmed no top-level
               deviation scalar in entries (data_points/avg_duration/failure_rate
               only); most-deviant sorting would silently degrade, so first-N
               is the correct approximation.
      Stage 3: drop performance_trends details keeping list counts as integers.
    Sets result["_truncation_stage"] at each stage applied.
    Returns the input dict unchanged when already within budget (pure function).

    Note: The characterization fixture reaches this tool via the Prometheus-absent
    early return (data_source=kubernetes_api_fallback) and is permanently tiny.
    The truncator proof is intentionally unit-level with synthetic large data.
    """
    import json as _json

    def _tokens(d: Dict) -> int:
        try:
            return len(_json.dumps(d, default=str)) // 4
        except (TypeError, ValueError):
            return max_tokens + 1

    if _tokens(result) <= max_tokens:
        return result

    # Operate on a shallow copy; lists are replaced (not mutated in-place)
    r = dict(result)

    # Stage 1: cap task_level_analysis per-pipeline lists to 5 entries
    if "task_level_analysis" in r and isinstance(r["task_level_analysis"], dict):
        tla = dict(r["task_level_analysis"])
        for key in ("task_baselines", "slowest_tasks", "most_failed_tasks"):
            if isinstance(tla.get(key), list):
                tla[key] = tla[key][:5]
        r["task_level_analysis"] = tla

    r["_truncation_stage"] = 1
    if _tokens(r) <= max_tokens:
        return r

    # Stage 2: cap pipeline_baselines to first-N (halving each step)
    if "pipeline_baselines" in r and isinstance(r["pipeline_baselines"], list):
        baselines = list(r["pipeline_baselines"])
        n = len(baselines)
        while n > 1 and _tokens(r) > max_tokens:
            n = max(n // 2, 1)
            r["pipeline_baselines"] = baselines[:n]
        # Final single-entry pass if halving left exactly 1 and still over
        if n == 1 and _tokens(r) > max_tokens:
            r["pipeline_baselines"] = baselines[:1]

    r["_truncation_stage"] = 2
    if _tokens(r) <= max_tokens:
        return r

    # Stage 3: drop performance_trends details keeping counts
    if "performance_trends" in r and isinstance(r["performance_trends"], dict):
        r["performance_trends"] = {
            k: len(v) if isinstance(v, list) else v
            for k, v in r["performance_trends"].items()
        }

    r["_truncation_stage"] = 3
    return r


# ============================================================================
# ADAPTIVE LOG PROCESSING HELPERS
# ============================================================================

class AdaptiveLogProcessor:
    """Helper class for adaptive log processing with token management."""

    def __init__(self, max_token_budget: int = 150000):
        self.max_token_budget = max_token_budget
        self.safety_buffer = 0.8  # Use 80% of budget for safety
        self.effective_budget = int(max_token_budget * self.safety_buffer)
        self.used_tokens = 0

    def can_process_more(self, estimated_tokens: int) -> bool:
        """Check if we can process more data within token budget."""
        return (self.used_tokens + estimated_tokens) <= self.effective_budget

    def record_usage(self, actual_tokens: int):
        """Record actual token usage."""
        self.used_tokens += actual_tokens

    def get_remaining_budget(self) -> int:
        """Get remaining token budget."""
        return max(0, self.effective_budget - self.used_tokens)

    def get_usage_percentage(self) -> float:
        """Get current token usage as percentage."""
        return (self.used_tokens / self.effective_budget) * 100


async def _estimate_pod_log_tokens(namespace: str, pod_name: str, tail_lines: int = 500, sample_ratio: float = 0.1, clients: Optional["K8sClientSet"] = None) -> int:
    """
    Estimate token usage for a pod's logs using representative sampling.

    Args:
        namespace: Kubernetes namespace
        pod_name: Pod name to estimate
        tail_lines: The actual tail_lines that will be used for fetching
        sample_ratio: Fraction of tail_lines to sample (default: 10%)
        clients: Optional K8sClientSet for per-instance dispatch; None uses _DefaultClientView.

    Returns:
        Estimated token count for the pod's logs (extrapolated from sample)
    """
    _c = clients if clients is not None else _DefaultClientView()
    try:
        # Sample a fraction of the logs to estimate token density
        sample_lines = max(50, int(tail_lines * sample_ratio))

        sample = await get_all_pod_logs(
            pod_name=pod_name,
            namespace=namespace,
            k8s_core_api=_c.core_api,
            tail_lines=sample_lines
        )

        if sample:
            sample_text = ""
            for container_logs in sample.values():
                if isinstance(container_logs, str):
                    sample_text += container_logs

            sample_tokens = calculate_context_tokens(sample_text)

            # Extrapolate to full tail_lines with capped multiplier to avoid over-estimation
            # Cap at 3x to handle cases where sample has unusually high token density
            raw_factor = tail_lines / sample_lines
            extrapolation_factor = min(raw_factor * 1.1, 3.0)  # Cap at 3x, use 1.1x safety margin
            estimated_tokens = int(sample_tokens * extrapolation_factor)

            logger.debug(f"Token estimate for {pod_name}: ~{estimated_tokens} tokens (sampled {sample_lines} lines, factor {extrapolation_factor:.2f}x)")
            return estimated_tokens

    except Exception as e:
        logger.debug(f"Token estimation failed for {pod_name}: {e}")

    # Conservative default: assume ~30 tokens per line
    return tail_lines * 30


async def _prioritize_pipeline_pods(pod_names: List[str], namespace: str, core_api) -> List[str]:
    """
    Prioritize pods for processing - failed pods first, recent pods next.

    Args:
        pod_names: List of pod names to prioritize
        namespace: Kubernetes namespace
        core_api: Kubernetes CoreV1 API client (raw or ReadOnly-wrapped)

    Returns:
        List of pod names in priority order
    """
    try:
        _ro = ReadOnlyCoreV1.wrap(core_api)
        pod_priorities = []

        for pod_name in pod_names:
            try:
                pod = await k8s_call(_ro.read_namespaced_pod, name=pod_name, namespace=namespace)

                priority_score = 0

                # Failed pods get highest priority
                if pod.status.phase in ['Failed', 'Error']:
                    priority_score += 1000

                # Recent pods get higher priority
                if pod.metadata.creation_timestamp:
                    age_hours = (datetime.now(pod.metadata.creation_timestamp.tzinfo) - pod.metadata.creation_timestamp).total_seconds() / 3600
                    priority_score += max(0, 100 - age_hours)

                # Pods with restart counts (indicating issues) get priority
                if pod.status.container_statuses:
                    for container_status in pod.status.container_statuses:
                        if container_status.restart_count and container_status.restart_count > 0:
                            priority_score += 50 + container_status.restart_count * 10

                pod_priorities.append((pod_name, priority_score))

            except Exception as e:
                logger.debug(f"Could not get details for pod {pod_name}: {e}")
                pod_priorities.append((pod_name, 1))

        # Sort by priority (highest first) and return pod names
        pod_priorities.sort(key=lambda x: x[1], reverse=True)
        prioritized_names = [pod_name for pod_name, _ in pod_priorities]

        logger.info(f"Pod prioritization: {prioritized_names[:3]}... (showing top 3)")
        return prioritized_names

    except Exception as e:
        logger.warning(f"Pod prioritization failed: {e}")
        return pod_names  # Return original order as fallback


def _calculate_adaptive_tail_lines(total_pods: int, processed_pods: int, remaining_budget: int) -> int:
    """
    Calculate adaptive tail_lines based on pipeline size and remaining token budget.

    Args:
        total_pods: Total number of pods in pipeline
        processed_pods: Number of pods already processed
        remaining_budget: Remaining token budget

    Returns:
        Optimal tail_lines for current pod
    """
    remaining_pods = total_pods - processed_pods
    tokens_per_pod = remaining_budget // max(remaining_pods, 1)

    # Convert tokens to approximate lines (assuming ~25 tokens per line)
    estimated_lines = tokens_per_pod // 25

    # Apply pipeline size strategy
    if total_pods <= 5:  # Small pipeline
        base_lines = min(2000, estimated_lines)
    elif total_pods <= 15:  # Medium pipeline
        base_lines = min(1000, estimated_lines)
    else:  # Large pipeline
        base_lines = min(500, estimated_lines)

    # Ensure minimum viable lines
    adaptive_lines = max(100, base_lines)

    logger.debug(f"Adaptive tail_lines: {adaptive_lines} (budget: {remaining_budget}, pods left: {remaining_pods})")
    return adaptive_lines


def _truncate_logs_to_token_limit(logs: str, max_tokens: int, pod_name: str) -> tuple[str, bool]:
    """
    Truncate logs if they exceed the token limit.

    Args:
        logs: Log content to potentially truncate
        max_tokens: Maximum allowed tokens
        pod_name: Pod name for logging

    Returns:
        Tuple of (truncated_logs, was_truncated)
    """
    current_tokens = calculate_context_tokens(logs)
    if current_tokens <= max_tokens:
        return logs, False

    # Estimate characters per token from current content
    chars_per_token = len(logs) / current_tokens if current_tokens > 0 else 4
    target_chars = int(max_tokens * chars_per_token * 0.9)  # 90% to be safe

    # Truncate and add notice
    truncated = logs[:target_chars]
    # Find last newline to avoid cutting mid-line
    last_newline = truncated.rfind('\n')
    if last_newline > target_chars * 0.8:  # Only use if we're not losing too much
        truncated = truncated[:last_newline]

    truncation_notice = f"\n\n[... TRUNCATED: {current_tokens:,} tokens exceeded budget of {max_tokens:,} tokens for pod {pod_name} ...]"
    truncated += truncation_notice

    logger.warning(f"Truncated logs for {pod_name}: {current_tokens:,} -> ~{max_tokens:,} tokens")
    return truncated, True


# ============================================================================
# SMART LOG ANALYSIS HELPER FUNCTIONS
# ============================================================================


def _filter_analysis_for_synthesis(pod_analysis: Dict[str, Any], focus_areas: List[str]) -> Dict[str, Any]:
    """
    Filter pod analysis results to keep only essential data for synthesis, preventing token overflow.

    Args:
        pod_analysis: Full pod analysis results
        focus_areas: Areas to focus on for filtering

    Returns:
        Filtered analysis with only essential data
    """
    try:
        # Keep only essential fields to prevent token overflow
        filtered = {
            "summary": pod_analysis.get("summary", {}),
            "metadata": {
                "total_log_lines": pod_analysis.get("metadata", {}).get("processing_metrics", {}).get("total_log_lines", 0),
                "patterns_extracted": pod_analysis.get("metadata", {}).get("processing_metrics", {}).get("patterns_extracted", 0),
                "processing_time_seconds": pod_analysis.get("metadata", {}).get("processing_metrics", {}).get("processing_time_seconds", 0)
            }
        }

        # Keep only focused patterns (top 3 items per focus area)
        if "patterns" in pod_analysis:
            filtered["patterns"] = {}
            for area in focus_areas:
                if area in pod_analysis["patterns"] and pod_analysis["patterns"][area]:
                    # Keep only top 3 most important items per area
                    filtered["patterns"][area] = pod_analysis["patterns"][area][:3]

        # Keep only essential representative samples (top 2 per area)
        if "representative_samples" in pod_analysis:
            filtered["representative_samples"] = {}
            for area in focus_areas:
                if area in pod_analysis["representative_samples"]:
                    # Keep only top 2 samples per area
                    filtered["representative_samples"][area] = pod_analysis["representative_samples"][area][:2]

        return filtered

    except Exception as e:
        logger.warning(f"Error filtering analysis: {e}")
        # Fallback: return minimal data
        return {
            "summary": pod_analysis.get("summary", "Analysis available but filtered due to size"),
            "metadata": {"filtered": True, "reason": "token_overflow_prevention"}
        }


def _get_logs_with_k8s_client(
    k8s_core_api: 'client.CoreV1Api',
    pod_names: List[str],
    namespace: str,
    container_name: str,
    target_logs_dict: Dict[str, str],
    log_params: Dict[str, Union[int, str, bool, None]]
) -> bool:
    """
    Enhanced helper to fetch logs for a list of pod names with flexible time and line filtering.

    Args:
        k8s_core_api: Initialized CoreV1Api client
        pod_names: List of pod names to fetch logs from
        namespace: Namespace of the pods
        container_name: Name of the container within the pods
        target_logs_dict: Dictionary to populate with logs or error messages
        log_params: Dictionary containing log retrieval parameters:
            - tail_lines: Number of lines from end of logs
            - since_seconds: Logs newer than this many seconds
            - since_time: Logs newer than this RFC3339 timestamp
            - follow: ignored; logs are always read as a snapshot (a
              streaming read never returns and pins a worker thread)
            - timestamps: Include timestamps in output
            - previous: Get logs from previous container instance

    Returns:
        bool: True if logs were successfully fetched for at least one pod
    """
    logger.debug(f"Fetching logs for {len(pod_names)} pods in namespace '{namespace}', container '{container_name}'")
    at_least_one_log_fetched = False

    for pod_name in pod_names:
        logger.info(f"Fetching logs for pod '{pod_name}' with params: {log_params}")

        try:
            # Build log retrieval parameters, filtering out None values
            log_kwargs = {
                'name': pod_name,
                'namespace': namespace,
                'container': container_name,
                'timestamps': log_params.get('timestamps', True),
                'follow': False,
                'previous': log_params.get('previous', False)
            }

            # Add time-based or line-based filtering (mutually exclusive in K8s API)
            if log_params.get('since_time'):
                # Convert RFC3339 since_time to relative since_seconds (kubernetes API
                # accepts only since_seconds; there is no since_time or since kwarg).
                _since_dt = datetime.fromisoformat(
                    log_params['since_time'].replace('Z', '+00:00'))
                # Treat offset-less (naive) timestamps as UTC so the computed
                # window is host-timezone-independent.
                if _since_dt.tzinfo is None:
                    _since_dt = _since_dt.replace(tzinfo=timezone.utc)
                log_kwargs['since_seconds'] = max(1, int(
                    time.time() - _since_dt.timestamp()))
            elif log_params.get('since_seconds'):
                log_kwargs['since_seconds'] = log_params['since_seconds']
            elif log_params.get('tail_lines'):
                log_kwargs['tail_lines'] = log_params['tail_lines']

            # Remove None values to avoid API errors
            log_kwargs = {k: v for k, v in log_kwargs.items() if v is not None}

            log_content = normalize_pod_log_text(
                k8s_core_api.read_namespaced_pod_log(**log_kwargs, _request_timeout=LOG_TIMEOUT))

            if log_content:
                # Clean etcd logs if this is an etcd container and cleaning is enabled
                if (container_name == "etcd" and
                    ("etcd" in pod_name.lower() or namespace in ["openshift-etcd", "kube-system"]) and
                    log_params.get('clean_logs', True)):
                    cleaned_content = clean_etcd_logs(log_content)
                    target_logs_dict[pod_name] = cleaned_content
                    logger.info(f"Successfully fetched and cleaned {len(cleaned_content)} characters of etcd logs for pod '{pod_name}'")
                else:
                    target_logs_dict[pod_name] = log_content
                    logger.info(f"Successfully fetched {len(log_content)} characters of logs for pod '{pod_name}'")
                at_least_one_log_fetched = True
            else:
                target_logs_dict[pod_name] = "INFO: No logs available for the specified time period/criteria"
                logger.info(f"No logs found for pod '{pod_name}' with current criteria")

        except ApiException as e:
            error_message = f"API error fetching logs for pod '{pod_name}': {e.status} - {e.reason}"
            if e.body:
                error_message += f" | Details: {str(e.body)[:200]}"

            logger.warning(error_message)
            target_logs_dict[pod_name] = f"ERROR: {error_message}"

        except Exception as e:
            error_message = f"Unexpected error fetching logs for pod '{pod_name}': {str(e)}"
            logger.error(error_message, exc_info=True)
            target_logs_dict[pod_name] = f"ERROR: {error_message}"

    return at_least_one_log_fetched


def _filter_logs_by_time_range(logs: str, until_time: datetime) -> str:
    """
    Filter log lines to only include entries before the specified until_time.

    Args:
        logs: Raw log content with timestamps
        until_time: Maximum timestamp (timezone-aware datetime)

    Returns:
        Filtered log content
    """
    if not logs or not until_time:
        return logs

    filtered_lines = []
    for line in logs.split('\n'):
        if not line.strip():
            continue

        # Try to extract timestamp from the beginning of the line
        # Common formats: "2024-01-15T10:30:45.123456Z" or "2024-01-15 10:30:45"
        try:
            # Check if line starts with a timestamp
            timestamp_match = line.split()[0] if line else None
            if timestamp_match:
                # Handle different timestamp formats
                if 'T' in timestamp_match:
                    # ISO format
                    log_time = datetime.fromisoformat(timestamp_match.replace('Z', '+00:00'))
                else:
                    # Try parsing date-time format
                    try:
                        # Try to get first two parts (date and time)
                        parts = line.split()
                        if len(parts) >= 2:
                            datetime_str = f"{parts[0]} {parts[1]}"
                            log_time = datetime.fromisoformat(datetime_str)
                        else:
                            continue
                    except:
                        continue

                # Only include logs before until_time
                if log_time <= until_time:
                    filtered_lines.append(line)
                else:
                    # Logs are typically chronological, so we can break early
                    break
            else:
                # Include lines without timestamps (might be continuation lines)
                filtered_lines.append(line)
        except (ValueError, IndexError):
            # If timestamp parsing fails, include the line to be safe
            filtered_lines.append(line)

    return '\n'.join(filtered_lines)


def _logbatch_to_legacy_envelope(batch) -> Dict[str, Any]:
    """LogBatch -> the legacy {"logs": {key: text}} envelope the log tools'
    analysis paths consume.

    The grouping attribute key is read from batch.provenance.grouping_attr
    (default 'file' for the file adapter; 'stream' for loki, etc.).
    Records with no matching attribute group under the fallback key "log".
    """
    if not batch.records:
        return {"logs": {}}
    attr_key = batch.provenance.grouping_attr
    groups: Dict[str, list] = {}
    for r in batch.records:
        groups.setdefault(r.attributes.get(attr_key, "log"), []).append(r.body)
    return {"logs": {k: "\n".join(v) for k, v in groups.items()}}


async def _quick_volume_estimate(namespace: str, pod_name: str, clients: Optional["K8sClientSet"] = None, *, get_logs_fn) -> int:
    """
    Quick estimate of log volume using minimal token budget.

    Args:
        namespace: Kubernetes namespace
        pod_name: Pod name to estimate
        clients: Optional K8sClientSet for per-instance dispatch; None uses _DefaultClientView.

    Returns:
        Estimated total log lines for the pod
    """
    try:
        # Sample last 5 minutes to estimate volume
        sample = await get_logs_fn(
            namespace=namespace,
            pod_name=pod_name,
            since_seconds=300,  # 5 minutes
            clients=clients,
        )

        if "logs" in sample and sample["logs"]:
            sample_lines = 0
            for container_logs in sample["logs"].values():
                if isinstance(container_logs, str):
                    sample_lines += len(container_logs.split('\n'))
                elif isinstance(container_logs, list):
                    sample_lines += len(container_logs)

            # Extrapolate to 24 hours (conservative estimate)
            # Assume sample represents 5 minutes, extrapolate to 24 hours
            estimated_total = sample_lines * (24 * 60 / 5)  # 24 hours / 5 minutes
            logger.info(f"Volume estimate for {pod_name}: {sample_lines} lines in 5min → ~{int(estimated_total)} total estimated")
            return int(estimated_total)

    except Exception as e:
        logger.debug(f"Volume estimation failed for {pod_name}: {e}")

    return 10000  # Conservative default estimate
