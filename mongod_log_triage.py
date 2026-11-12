#!/usr/bin/env python3
"""Sanitize MongoDB mongod logs, then generate local triage reports.

By default, input logs are first sanitized into a separate file and reports are
generated from that sanitized output. Supports newline-delimited structured
MongoDB logs and a best-effort legacy text fallback. Plain text and .gz inputs
are processed line-by-line. Raw log records, commands, namespaces, client
addresses, and arbitrary attr fields are never sent to the configured model;
only the explicit allow-listed payload is transmitted.

AI calls are opt-in via --summarize and require an explicitly configured
OpenAI-compatible Chat Completions endpoint and model in environment variables,
plus an explicit confirmation that your organization's data handling policy
permits submitting the generated redacted aggregate payload to that endpoint.
Never submit logs or derived artifacts that your organization prohibits sharing.

Parser design follows MongoDB's structured log message documentation:
https://www.mongodb.com/docs/manual/reference/log-messages/
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import gzip
import html
import ipaddress
import json
import math
import os
import re
import statistics
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable, TextIO

# Bounded collections keep memory usage predictable on large or noisy logs.
MAX_SIGNATURES = 5000
MAX_DURATION_SAMPLES = 20000
MAX_EXAMPLES_PER_SEVERITY = 12
MAX_AI_SIGNATURES = 20
MAX_AI_EXAMPLES = 24
MAX_SLOW_QUERY_GROUPS = 10000

SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|authorization|api[_ -]?key)\b"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
URI_RE = re.compile(r"(?i)\b(?:mongodb(?:\+srv)?|https?)://[^\s,\"']+")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d .()/-]{7,}\d)(?!\w)")
NAMESPACE_RE = re.compile(r"\b[A-Za-z0-9_$-]+\.[A-Za-z0-9_$.-]+\b")
OBJECT_ID_RE = re.compile(r"\b[0-9a-fA-F]{24}\b")
CONN_RE = re.compile(r"\bconn\d+\b", re.I)
LEGACY_TS_RE = re.compile(r"^([0-9]{4}-[0-9]{2}-[0-9]{2}[T ][^ ]+)")
LEGACY_LEVEL_RE = re.compile(r"\s([D I W E F])\s+([A-Z][A-Z0-9_.-]+)?\s*(.*)$")

SANITIZE_SECRET_KEY_RE = re.compile(r"(?i)(password|passwd|pwd|secret|token|credential|authorization|api.?key|access.?key|private.?key|cookie|signature|jwt)")
SANITIZE_USER_KEY_RE = re.compile(r"(?i)(?:^|[^a-z])(user(name|id)?|principal|actor|account|email|e.?mail)(?:$|[^a-z])")
SANITIZE_ADDRESS_KEY_RE = re.compile(r"(?i)(?:^|[^a-z])(ip|remote|address|peer|source.?address|client.?address|source.?ip|client.?ip)(?:$|[^a-z])")
SANITIZE_HOST_KEY_RE = re.compile(r"(?i)(?:^|[^a-z])(host(name)?|server.?host|node.?name|endpoint)(?:$|[^a-z])")
SANITIZE_NAMESPACE_KEY_RE = re.compile(r"(?i)^(ns|namespace|collection(name)?|database(name)?|db)$")
SANITIZE_IDENTIFIER_KEY_RE = re.compile(r"(?i)(connection.?id|session.?id|request.?id|operation.?id|tenant.?id|trace.?id|correlation.?id|lsid)")
SANITIZE_QUERY_KEYS = {"filter", "pipeline", "query", "command", "updates", "update", "deletes", "delete", "insert", "documents", "fullDocument", "documentKey", "criteria", "$query"}
SANITIZE_COLLECTION_KEYS = {"find", "aggregate", "insert", "update", "delete", "collMod", "findAndModify"}
SANITIZE_NUMERIC_SAFE_QUERY_KEYS = {"$limit", "$skip", "limit", "skip", "batchSize", "maxTimeMS", "maxAwaitTimeMS"}
SANITIZE_SAFE_VALUE_KEYS = {"queryShapeHash"}
SANITIZE_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
SANITIZE_UUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
SANITIZE_QUERY_TAIL_RE = re.compile(r"(?i)\b(filter|query|pipeline|command|criteria)\s*[:=]\s*(?:\{|\[).*$")
SANITIZE_SECRET_ASSIGN_RE = re.compile(r"(?i)\b(password|passwd|pwd|secret|token|credential|authorization|api.?key|access.?key|private.?key|cookie|signature|jwt)\b(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)")
SANITIZE_USER_ASSIGN_RE = re.compile(r"(?i)\b(username|user|principal|actor|email)\b(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)")
SANITIZE_OPAQUE_RE = re.compile(r"\b[A-Za-z0-9_-]{40,}\b")

SAFE_METRIC_KEYS = (
    "durationMillis", "workingMillis", "cpuNanos", "keysExamined",
    "docsExamined", "nreturned", "numYields",
)


def query_shape(value: Any) -> Any:
    """Return a value-free query shape that preserves fields/operators."""
    if isinstance(value, dict):
        shaped: dict[str, Any] = {}
        for key, child in value.items():
            if key == "queryShapeHash":
                shaped[key] = child
            elif key in {"$db", "$clusterTime", "lsid", "readConcern", "writeConcern", "cursor"}:
                continue
            elif key.startswith("$"):
                shaped[key] = "[...]" if isinstance(child, list) else query_shape(child)
            elif isinstance(child, (dict, list)):
                shaped[key] = query_shape(child)
            else:
                shaped[key] = 1
        return shaped
    if isinstance(value, list):
        return [query_shape(item) for item in value if isinstance(item, dict)] or "[...]"
    return 1


def shape_to_text(value: Any) -> str:
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{key}:{shape_to_text(child)}" for key, child in value.items()) + " }"
    if isinstance(value, list):
        return "[ " + ", ".join(shape_to_text(item) for item in value) + " ]"
    if isinstance(value, str):
        return value
    return str(value)


def command_operation(command: dict[str, Any], fallback: str) -> str:
    for name in ("find", "aggregate", "distinct", "count", "update", "delete", "insert", "findAndModify"):
        if name in command:
            return name
    return fallback or "unknown"


def command_namespace(attr: dict[str, Any], command: dict[str, Any]) -> str:
    ns = attr.get("ns")
    if isinstance(ns, str) and ns:
        return ns
    db = command.get("$db")
    for name in ("find", "aggregate", "distinct", "count", "update", "delete", "insert", "findAndModify"):
        coll = command.get(name)
        if isinstance(db, str) and isinstance(coll, str):
            return f"{db}.{coll}"
    return "unknown"


def command_query_pattern(command: dict[str, Any], query_shape_hash: Any = None) -> str:
    op = command_operation(command, "")
    pattern: Any
    if op == "aggregate" and isinstance(command.get("pipeline"), list):
        matches = [stage.get("$match") for stage in command["pipeline"] if isinstance(stage, dict) and isinstance(stage.get("$match"), dict)]
        pattern = query_shape({"$and": matches}) if len(matches) > 1 else query_shape(matches[0]) if matches else {}
    elif op in {"find", "count", "distinct"}:
        pattern = query_shape(command.get("filter") or command.get("query") or {})
    elif op in {"update", "delete", "findAndModify"}:
        pattern = query_shape(command.get("q") or command.get("filter") or command.get("query") or {})
    else:
        pattern = query_shape(command)
    text = shape_to_text(pattern)
    if query_shape_hash:
        text += f"\nqueryShapeHash: {query_shape_hash}"
    return text[:2000]


def sanitize_message(value: Any) -> str:
    """Redact common identifiers/secrets and bound free-text sent in reports."""
    text = str(value or "")
    text = URI_RE.sub("<uri>", text)
    text = SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", text)
    text = EMAIL_RE.sub("<email>", text)
    text = IPV4_RE.sub("<ip>", text)
    text = PHONE_RE.sub("<phone>", text)
    text = NAMESPACE_RE.sub("<namespace>", text)
    text = OBJECT_ID_RE.sub("<id>", text)
    text = CONN_RE.sub("conn#", text)
    return re.sub(r"\s+", " ", text).strip()[:280]


class SanitizerAliases:
    """Stable synthetic aliases so repeated values remain correlatable."""
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.counts: collections.Counter[str] = collections.Counter()

    def alias(self, category: str, raw: Any) -> str:
        value = str(raw)
        key = (category, value)
        if key in self.values:
            return self.values[key]
        self.counts[category] += 1
        number = self.counts[category]
        if category == "email":
            alias = f"user-{number:04d}@example.invalid"
        elif category == "ip":
            alias = f"192.0.2.{((number - 1) % 254) + 1}"
        elif category == "ipv6":
            alias = f"2001:db8::{number:x}"
        elif category == "host":
            alias = f"synthetic-host-{number:04d}.invalid"
        elif category == "namespace":
            alias = f"synthetic_db_{number:04d}.synthetic_collection_{number:04d}"
        elif category == "database":
            alias = f"synthetic_db_{number:04d}"
        elif category == "collection":
            alias = f"synthetic_collection_{number:04d}"
        elif category == "user":
            alias = f"synthetic-user-{number:04d}"
        elif category == "secret":
            alias = f"SYNTHETIC_SECRET_{number:04d}"
        elif category == "id":
            alias = f"synthetic-id-{number:04d}"
        elif category == "query-value":
            alias = f"synthetic-query-value-{number:04d}"
        else:
            alias = f"SYNTHETIC_VALUE_{number:04d}"
        self.values[key] = alias
        return alias


def sanitizer_category_for_key(key: str) -> str | None:
    if SANITIZE_SECRET_KEY_RE.search(key):
        return "secret"
    if SANITIZE_USER_KEY_RE.search(key):
        return "email" if "mail" in key.lower() else "user"
    if SANITIZE_ADDRESS_KEY_RE.search(key):
        return "ip"
    if SANITIZE_HOST_KEY_RE.search(key):
        return "host"
    if SANITIZE_NAMESPACE_KEY_RE.fullmatch(key):
        lowered = key.lower()
        if lowered in {"ns", "namespace"}:
            return "namespace"
        return "database" if lowered in {"db", "database", "databasename"} else "collection"
    if SANITIZE_IDENTIFIER_KEY_RE.search(key):
        return "id"
    if key.lower() in {"connection", "connectionstring", "uri", "mongodburi"}:
        return "secret"
    return None


def sanitize_log_text(value: str, aliases: SanitizerAliases) -> str:
    text = URI_RE.sub("<SYNTHETIC_CONNECTION_URI>", value)
    text = SANITIZE_QUERY_TAIL_RE.sub(lambda m: f"{m.group(1)}=<SYNTHETIC_QUERY_REDACTED>", text)
    text = SANITIZE_SECRET_ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{aliases.alias('secret', m.group(3))}", text)
    text = SANITIZE_USER_ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{aliases.alias('user', m.group(3))}", text)
    text = EMAIL_RE.sub(lambda m: aliases.alias("email", m.group(0)), text)

    def ipv4_sub(match: re.Match[str]) -> str:
        raw = match.group(0)
        address, sep, port = raw.partition(":")
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return "<SYNTHETIC_INVALID_ADDRESS>"
        if ip in ipaddress.ip_network("192.0.2.0/24"):
            return raw
        return aliases.alias("ip", address) + (f":{port}" if sep else "")

    text = IPV4_RE.sub(ipv4_sub, text)
    text = SANITIZE_IPV6_RE.sub(lambda m: aliases.alias("ipv6", m.group(0)), text)
    text = SANITIZE_UUID_RE.sub(lambda m: aliases.alias("id", m.group(0)), text)
    text = OBJECT_ID_RE.sub(lambda m: aliases.alias("id", m.group(0)), text)
    text = SANITIZE_OPAQUE_RE.sub("SYNTHETIC_OPAQUE_VALUE", text)
    return text


def sanitize_log_value(value: Any, aliases: SanitizerAliases, key: str = "", query_mode: bool = False) -> Any:
    if key in SANITIZE_SAFE_VALUE_KEYS:
        return value
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for raw_key, child in value.items():
            child_key = str(raw_key)
            safe_key = sanitize_log_text(child_key, aliases)
            child_category = sanitizer_category_for_key(child_key)
            if child_category == "secret" and child is not None:
                out[safe_key] = aliases.alias("secret", child if isinstance(child, (str, int, float, bool)) else "structured-secret")
            elif child_category and child is not None and not isinstance(child, (dict, list)):
                out[safe_key] = aliases.alias(child_category, child)
            elif query_mode or child_key in SANITIZE_QUERY_KEYS or child_key.lower() in {k.lower() for k in SANITIZE_QUERY_KEYS}:
                out[safe_key] = sanitize_log_value(child, aliases, child_key, True)
            else:
                out[safe_key] = sanitize_log_value(child, aliases, child_key, False)
        return out
    if isinstance(value, list):
        return [sanitize_log_value(item, aliases, key, query_mode) for item in value]
    if value is None:
        return None
    if query_mode:
        if key in SANITIZE_NUMERIC_SAFE_QUERY_KEYS and isinstance(value, (int, float, bool)):
            return value
        if isinstance(value, bool):
            return False
        if isinstance(value, (int, float)):
            return 0
        if isinstance(value, str):
            if key in SANITIZE_COLLECTION_KEYS:
                return aliases.alias("collection", value)
            if key == "$db":
                return aliases.alias("database", value)
            return aliases.alias("query-value", value)
        return "SYNTHETIC_QUERY_VALUE"
    if isinstance(value, str):
        category = sanitizer_category_for_key(key)
        return aliases.alias(category, value) if category else sanitize_log_text(value, aliases)
    return value


def sanitize_log_line(line: str, aliases: SanitizerAliases) -> str:
    ending = "\n" if line.endswith("\n") else ""
    body = line[:-1] if ending else line
    if body.endswith("\r"):
        ending = "\r\n" if ending else "\r"
        body = body[:-1]
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return sanitize_log_text(body, aliases) + ending
    return json.dumps(sanitize_log_value(parsed, aliases), ensure_ascii=False, separators=(",", ":")) + ending


def parse_timestamp(value: Any) -> dt.datetime | None:
    if isinstance(value, dict):
        value = value.get("$date", value.get("date"))
    if isinstance(value, (int, float)):
        # Extended JSON dates and epoch milliseconds are common.
        seconds = value / 1000 if abs(value) > 100_000_000_000 else value
        try:
            return dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except ValueError:
        return None


def parse_record(line: str) -> tuple[dict[str, Any] | None, str]:
    """Return normalized record and parser kind (json, legacy, malformed)."""
    try:
        data = json.loads(line)
        if isinstance(data, dict) and any(k in data for k in ("s", "c", "msg", "t")):
            attr = data.get("attr")
            return {
                "t": data.get("t"),
                "s": data.get("s", "?"),
                "c": data.get("c", "?"),
                "id": data.get("id"),
                "msg": data.get("msg", ""),
                "attr": attr if isinstance(attr, dict) else {},
            }, "json"
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    # Best-effort parser for older human-readable mongod log lines.
    ts_match = LEGACY_TS_RE.match(line)
    level_match = LEGACY_LEVEL_RE.search(line)
    if ts_match or level_match:
        ts = ts_match.group(1) if ts_match else None
        if level_match:
            level = level_match.group(1).strip() or "?"
            component = level_match.group(2) or "legacy"
            message = level_match.group(3) or ""
        else:
            level, component, message = "?", "legacy", line.strip()
        return {"t": ts, "s": level, "c": component, "id": None,
                "msg": message, "attr": {}}, "legacy"
    return None, "malformed"


def classify(severity: str, component: str, message: str) -> str:
    text = (component + " " + message).lower()
    if "slow query" in text or "slow operation" in text or "slow oplog" in text:
        return "slow_operation"
    if "startupwarning" in text or "startup warning" in text:
        return "startup_warning"
    if "authentication failed" in text or "auth failed" in text:
        return "authentication"
    if "election" in text or "stepdown" in text or "step down" in text:
        return "replica_set_election"
    if "replication" in text or component.upper().startswith(("REPL", "O2")):
        return "replication"
    if "wiredtiger" in text or component.upper() in {"STORAGE", "WT"}:
        return "storage"
    if "connection" in text or "socket" in text or component.upper() in {"NETWORK", "ASIO"}:
        return "network"
    if severity.upper() in {"F", "FATAL"}:
        return "fatal"
    if severity.upper() in {"E", "ERROR"}:
        return "error"
    if severity.upper() in {"W", "WARN", "WARNING"}:
        return "warning"
    return "other"


def as_number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = float(value)
        return result if math.isfinite(result) and result >= 0 else None
    except (TypeError, ValueError):
        return None


class Analyzer:
    def __init__(self) -> None:
        self.total = 0
        self.json_lines = 0
        self.legacy_lines = 0
        self.malformed_lines = 0
        self.severities: collections.Counter[str] = collections.Counter()
        self.components: collections.Counter[str] = collections.Counter()
        self.categories: collections.Counter[str] = collections.Counter()
        self.ids: collections.Counter[str] = collections.Counter()
        self.error_codes: collections.Counter[str] = collections.Counter()
        self.server_versions: collections.Counter[str] = collections.Counter()
        self.redacted_message_records = 0
        self.hourly: collections.Counter[str] = collections.Counter()
        self.signatures: collections.Counter[tuple[str, str, str, str]] = collections.Counter()
        self.duration_samples: list[float] = []
        self.working_samples: list[float] = []
        self.slow_count = 0
        self.collscan_count = 0
        self.ixscan_count = 0
        self.high_examined_ratio_count = 0
        self.slow_plan_summaries: collections.Counter[str] = collections.Counter()
        self.slow_query_groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        self.examples: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
        self.start: dt.datetime | None = None
        self.end: dt.datetime | None = None

    def add(self, rec: dict[str, Any], parser_kind: str) -> None:
        self.total += 1
        if parser_kind == "json":
            self.json_lines += 1
        elif parser_kind == "legacy":
            self.legacy_lines += 1

        severity = str(rec.get("s") or "?")[:16]
        component = str(rec.get("c") or "?")[:48]
        message = str(rec.get("msg") or "")
        safe_msg = sanitize_message(message)
        attr = rec.get("attr") if isinstance(rec.get("attr"), dict) else {}
        if "###" in message:
            self.redacted_message_records += 1
        build_info = attr.get("buildInfo") if isinstance(attr.get("buildInfo"), dict) else {}
        version = build_info.get("version")
        if isinstance(version, str) and version.strip():
            self.server_versions[version.strip()[:40]] += 1
        code = attr.get("code")
        code_name = attr.get("codeName")
        if isinstance(code, int) and not isinstance(code, bool):
            label = str(code_name)[:80] if isinstance(code_name, str) and code_name else str(code)
            if label != str(code):
                label += f" ({code})"
            self.error_codes[label] += 1
        elif isinstance(code_name, str) and code_name:
            self.error_codes[code_name[:80]] += 1
        rec_id = rec.get("id")
        id_text = str(rec_id)[:40] if rec_id is not None else ""
        category = classify(severity, component, message)
        self.severities[severity] += 1
        self.components[component] += 1
        self.categories[category] += 1
        if id_text:
            self.ids[id_text] += 1

        signature = (severity, component, id_text, safe_msg)
        if signature in self.signatures:
            self.signatures[signature] += 1
        elif len(self.signatures) < MAX_SIGNATURES:
            self.signatures[signature] = 1

        timestamp = parse_timestamp(rec.get("t"))
        if timestamp:
            self.start = timestamp if self.start is None else min(self.start, timestamp)
            self.end = timestamp if self.end is None else max(self.end, timestamp)
            self.hourly[timestamp.replace(minute=0, second=0, microsecond=0).isoformat()] += 1

        msg_lower = message.lower()
        is_slow = ("slow query" in msg_lower or "slow operation" in msg_lower
                   or "slow oplog" in msg_lower)
        # Slow-query records can have varied message text; accept performance
        # attributes only when a duration is present and the record is command-like.
        duration = as_number(attr.get("durationMillis"))
        working = as_number(attr.get("workingMillis"))
        if (not is_slow and duration is not None
                and any(k in attr for k in ("planSummary", "docsExamined", "keysExamined"))):
            is_slow = True
        if is_slow:
            self.slow_count += 1
            if duration is not None:
                self._bounded_sample(self.duration_samples, duration, MAX_DURATION_SAMPLES)
            if working is not None:
                self._bounded_sample(self.working_samples, working, MAX_DURATION_SAMPLES)
            plan = str(attr.get("planSummary") or "")[:120]
            if plan:
                self.slow_plan_summaries[plan] += 1
                if "COLLSCAN" in plan.upper():
                    self.collscan_count += 1
                if "IXSCAN" in plan.upper():
                    self.ixscan_count += 1
            docs = as_number(attr.get("docsExamined"))
            returned = as_number(attr.get("nreturned"))
            if docs is not None and returned is not None and docs >= 1000 and docs > max(returned, 1) * 10:
                self.high_examined_ratio_count += 1
            command = attr.get("command") if isinstance(attr.get("command"), dict) else {}
            op = command_operation(command, str(attr.get("type") or "unknown"))
            namespace = command_namespace(attr, command)
            index = plan or str(attr.get("planSummary") or "")[:300]
            pattern = command_query_pattern(command, attr.get("queryShapeHash"))
            key = (op, namespace, index, pattern)
            if key in self.slow_query_groups:
                group = self.slow_query_groups[key]
            elif len(self.slow_query_groups) < MAX_SLOW_QUERY_GROUPS:
                group = self.slow_query_groups[key] = {
                    "op": op,
                    "namespace": namespace,
                    "index": index,
                    "query_pattern": pattern,
                    "count": 0,
                    "total_ms": 0.0,
                    "max_ms": 0.0,
                    "reslen_total": 0.0,
                    "reslen_count": 0,
                }
            else:
                group = None
            if group is not None:
                group["count"] += 1
                if duration is not None:
                    group["total_ms"] += duration
                    group["max_ms"] = max(group["max_ms"], duration)
                reslen = as_number(attr.get("reslen"))
                if reslen is not None:
                    group["reslen_total"] += reslen
                    group["reslen_count"] += 1

        if severity.upper() in {"W", "WARN", "WARNING", "E", "ERROR", "F", "FATAL"}:
            bucket = "F" if severity.upper() in {"F", "FATAL"} else (
                "E" if severity.upper() in {"E", "ERROR"} else "W")
            if len(self.examples[bucket]) < MAX_EXAMPLES_PER_SEVERITY:
                self.examples[bucket].append(self._safe_example(rec, safe_msg, timestamp))

    @staticmethod
    def _bounded_sample(values: list[float], value: float, limit: int) -> None:
        # Deterministic thinning after reaching the cap keeps memory bounded.
        if len(values) < limit:
            values.append(value)
        else:
            idx = (len(values) * 2654435761) % (len(values) + 1)
            if idx < limit:
                values[idx] = value

    @staticmethod
    def _safe_example(rec: dict[str, Any], safe_msg: str,
                      timestamp: dt.datetime | None) -> dict[str, Any]:
        attr = rec.get("attr") if isinstance(rec.get("attr"), dict) else {}
        sample: dict[str, Any] = {
            "timestamp": timestamp.isoformat() if timestamp else None,
            "severity": str(rec.get("s") or "?")[:8],
            "component": str(rec.get("c") or "?")[:32],
            "message_id": str(rec.get("id"))[:32] if rec.get("id") is not None else None,
            "message": safe_msg,
        }
        # Allow-list numeric metrics only; never forward arbitrary attr or command.
        for key in SAFE_METRIC_KEYS:
            number = as_number(attr.get(key))
            if number is not None:
                sample[key] = int(number) if number.is_integer() else number
        return sample

    def report(self) -> dict[str, Any]:
        top_signatures = sorted(self.signatures.items(), key=lambda item: item[1], reverse=True)[:30]
        top_messages = [
            {"severity": s, "component": c, "message_id": i or None,
             "message": msg, "count": count}
            for (s, c, i, msg), count in top_signatures
        ]
        durations = sorted(self.duration_samples)
        working = sorted(self.working_samples)
        def percentile(values: list[float], p: float) -> float | None:
            if not values:
                return None
            pos = (len(values) - 1) * p
            lo = int(pos)
            hi = min(lo + 1, len(values) - 1)
            return values[lo] + (values[hi] - values[lo]) * (pos - lo)
        def rounded(value: float | None) -> float | None:
            return round(value, 2) if value is not None else None

        findings = []
        errors = sum(v for k, v in self.severities.items() if k.upper() in {"E", "ERROR", "F", "FATAL"})
        warnings = sum(v for k, v in self.severities.items() if k.upper() in {"W", "WARN", "WARNING"})
        if errors:
            findings.append({"type": "severity", "observation": f"{errors} error/fatal log entries"})
        if warnings:
            findings.append({"type": "severity", "observation": f"{warnings} warning log entries"})
        if self.slow_count:
            findings.append({"type": "slow_operations", "observation": f"{self.slow_count} slow-operation records detected"})
        if self.collscan_count:
            findings.append({"type": "query_plan", "observation": f"{self.collscan_count} sampled slow-operation records show COLLSCAN"})
        if self.high_examined_ratio_count:
            findings.append({"type": "query_efficiency", "observation": f"{self.high_examined_ratio_count} slow-operation records examined at least 1,000 documents and over 10x returned"})

        notes = [
            "Slow-operation latency percentiles use a bounded sample when more than 20,000 values are seen.",
            "Legacy text parsing is best-effort; structured JSON logs provide richer metrics.",
            "MongoDB log fields can vary by server version; absent fields are not treated as zero.",
            "Large attributes may be truncated in the source log even when the JSON record parses; missing detail is not proof it was absent.",
            "When redactClientLogData is enabled, message values may be obscured and provide less diagnostic detail.",
            "COLLSCAN and documents-examined ratios are triage signals, not standalone proof of a defect.",
        ]
        if any(re.match(r"^8(?:\.|$)", version) for version in self.server_versions):
            notes.append("For MongoDB 8.0+, slow-operation timing is based on server work time rather than total operation latency; interpret duration metrics accordingly.")

        return {
            "tool": "mongod_log_triage.py",
            "scope": {
                "lines_processed": self.total,
                "structured_json_lines": self.json_lines,
                "legacy_text_lines": self.legacy_lines,
                "unparsed_lines": self.malformed_lines,
                "first_timestamp_utc": self.start.isoformat() if self.start else None,
                "last_timestamp_utc": self.end.isoformat() if self.end else None,
                "hours_with_log_entries": len(self.hourly),
            },
            "counts": {
                "severity": dict(self.severities.most_common()),
                "component": dict(self.components.most_common(25)),
                "category": dict(self.categories.most_common()),
                "top_message_ids": dict(self.ids.most_common(25)),
                "top_error_codes": dict(self.error_codes.most_common(25)),
                "busiest_hours": dict(self.hourly.most_common(12)),
            },
            "server_versions": dict(self.server_versions.most_common()),
            "redacted_message_records": self.redacted_message_records,
            "slow_operations": {
                "count": self.slow_count,
                "durationMillis_sampled": len(durations),
                "durationMillis_p50": rounded(percentile(durations, 0.50)),
                "durationMillis_p95": rounded(percentile(durations, 0.95)),
                "durationMillis_max_sampled": rounded(max(durations) if durations else None),
                "workingMillis_p95": rounded(percentile(working, 0.95)),
                "plan_summary_counts": dict(self.slow_plan_summaries.most_common(15)),
                "collscan_records": self.collscan_count,
                "ixscan_records": self.ixscan_count,
                "high_docs_examined_to_returned_records": self.high_examined_ratio_count,
            },
            "top_messages": top_messages,
            "slow_query_table": self.slow_query_table(),
            "selected_examples": [e for severity in ("F", "E", "W") for e in self.examples.get(severity, [])],
            "findings": findings,
            "notes": notes,
        }

    def slow_query_table(self) -> list[dict[str, Any]]:
        rows = []
        for group in self.slow_query_groups.values():
            count = group["count"] or 1
            reslen_count = group["reslen_count"] or 1
            rows.append({
                "op": group["op"],
                "namespace": group["namespace"],
                "count": group["count"],
                "avg_ms": round(group["total_ms"] / count, 3),
                "max_ms": round(group["max_ms"], 3),
                "total_ms": round(group["total_ms"], 3),
                "reslen": round(group["reslen_total"] / reslen_count, 3) if group["reslen_count"] else None,
                "index": group["index"] or "n/a",
                "query_pattern": group["query_pattern"],
            })
        return sorted(rows, key=lambda row: (row["avg_ms"], row["total_ms"]), reverse=True)


def open_log(path: str) -> TextIO:
    if path.lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


def open_sanitized_output(path: Path) -> TextIO:
    if str(path).lower().endswith(".gz"):
        return gzip.open(path, "wt", encoding="utf-8", newline="")
    return path.open("wt", encoding="utf-8", newline="")


def sanitize_logs(paths: list[str], output: Path) -> list[dict[str, Any]]:
    """Write sanitized logs and return per-output metadata.

    For one input, output is a file. For multiple inputs, output is a directory.
    A single alias map is shared across all inputs so repeated values remain
    consistently synthetic across the sanitized batch.
    """
    if len(paths) > 1:
        output.mkdir(parents=True, exist_ok=True)
        if not output.is_dir():
            raise ValueError("--sanitize-output must be a directory when sanitizing multiple input files")
    elif output.exists() and output.is_dir():
        raise ValueError("--sanitize-output must be a file path when sanitizing one input file")
    elif output.exists():
        raise FileExistsError(f"refusing to overwrite existing sanitized output: {output}")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)

    aliases = SanitizerAliases()
    results: list[dict[str, Any]] = []
    created: list[Path] = []
    try:
        for index, raw_path in enumerate(paths, 1):
            source = Path(raw_path)
            if len(paths) == 1:
                destination = output
            else:
                suffix = ".gz" if source.name.lower().endswith(".gz") else source.suffix or ".log"
                destination = output / f"input-{index:03d}.sanitized{suffix}"
                if destination.exists():
                    raise FileExistsError(f"refusing to overwrite existing sanitized output: {destination}")
            lines = 0
            with open_log(str(source)) as stream, open_sanitized_output(destination) as sink:
                for line in stream:
                    sink.write(sanitize_log_line(line, aliases))
                    lines += 1
            created.append(destination)
            results.append({"input": str(source), "output": str(destination), "lines_sanitized": lines})
        return results
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def default_sanitized_output(paths: list[str]) -> Path:
    if len(paths) > 1:
        return Path("sanitized-logs")
    source = Path(paths[0])
    if source.name.lower().endswith(".gz"):
        return source.with_name(source.name[:-3] + ".sanitized.gz")
    suffix = source.suffix or ".log"
    stem = source.name[:-len(suffix)] if source.suffix else source.name
    return source.with_name(f"{stem}.sanitized{suffix}")


def analyze_files(paths: Iterable[str]) -> dict[str, Any]:
    analyzer = Analyzer()
    path_list = list(paths)
    for path in path_list:
        with open_log(path) as stream:
            for line in stream:
                if not line.strip():
                    continue
                rec, kind = parse_record(line)
                if rec is None:
                    analyzer.total += 1
                    analyzer.malformed_lines += 1
                else:
                    analyzer.add(rec, kind)
    report = analyzer.report()
    if len(path_list) == 1:
        report["scope"]["source"] = Path(path_list[0]).name
    return report


def make_ai_payload(report: dict[str, Any]) -> dict[str, Any]:
    """Construct a strict, redacted payload from local aggregates only."""
    return {
        "scope": report["scope"],
        "server_versions": report.get("server_versions", {}),
        "redacted_message_records": report.get("redacted_message_records", 0),
        "counts": report["counts"],
        "slow_operations": report["slow_operations"],
        "top_messages": report["top_messages"][:MAX_AI_SIGNATURES],
        "selected_examples": report["selected_examples"][:MAX_AI_EXAMPLES],
        "findings": report["findings"],
        "notes": report["notes"],
    }


def call_model(payload: dict[str, Any], base_url: str, api_key: str,
               model: str, timeout: int = 120) -> str:
    endpoint = base_url.rstrip("/")
    if not endpoint.endswith("/chat/completions"):
        endpoint += "/chat/completions"
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("AI endpoint must use HTTPS (HTTP is allowed only for localhost).")
    system = (
        "You are a MongoDB mongod-log triage assistant. Explain the evidence in plain English. "
        "Separate directly observed facts from hypotheses; do not claim a root cause from counts alone. "
        "Prioritize severity, time pattern, slow operations, and query-plan signals. "
        "State what additional context would confirm a hypothesis. Do not recommend destructive or "
        "production-changing actions. The supplied data is already redacted and contains aggregates "
        "plus selected safe examples; do not ask for credentials or raw logs."
    )
    user = "Summarize these MongoDB log triage results for an engineer:\n" + json.dumps(payload, ensure_ascii=False)
    body = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }).encode("utf-8")
    request = urllib.request.Request(
        endpoint, data=body, method="POST",
        headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read(1000).decode("utf-8", errors="replace")
        raise RuntimeError(f"AI endpoint returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach AI endpoint: {exc.reason}") from exc
    try:
        content = result["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("AI endpoint response did not contain choices[0].message.content") from exc
    if isinstance(content, list):
        content = "\n".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("AI endpoint returned an empty summary")
    return content.strip()


def render_markdown(report: dict[str, Any], ai_summary: str | None = None) -> str:
    scope = report["scope"]
    counts = report["counts"]
    slow = report["slow_operations"]
    versions = report.get("server_versions", {})
    redacted_records = report.get("redacted_message_records", 0)
    lines = [
        "# mongod log triage report", "",
        "- This report is intended to be generated from sanitized logs. Sanitization is best-effort and does not guarantee removal of every organization-specific sensitive value; review outputs before sharing.",
        "- `queryShapeHash` values are intentionally preserved so the same query shapes can be located in Atlas UI; the hash is not treated as private query data.",
        f"- Detected MongoDB version(s): **{', '.join(versions) if versions else 'not detected'}**",
        f"- Log messages visibly redacted with `###`: **{redacted_records:,}**",
        f"- Lines processed: **{scope['lines_processed']:,}** "
        f"(JSON: {scope['structured_json_lines']:,}; legacy: {scope['legacy_text_lines']:,}; "
        f"unparsed: {scope['unparsed_lines']:,})",
        f"- Time range (UTC): **{scope['first_timestamp_utc'] or 'not detected'}** to **{scope['last_timestamp_utc'] or 'not detected'}**",
        f"- Severity counts: `{json.dumps(counts['severity'], ensure_ascii=False)}`",
        f"- Categories: `{json.dumps(counts['category'], ensure_ascii=False)}`", "",
        "## Slow operations", "",
        f"- Records: **{slow['count']:,}**; sampled duration p50/p95/max: "
        f"**{slow['durationMillis_p50']} / {slow['durationMillis_p95']} / {slow['durationMillis_max_sampled']} ms**",
        f"- COLLSCAN / IXSCAN records: **{slow['collscan_records']} / {slow['ixscan_records']}**",
        f"- High docs-examined-to-returned signals: **{slow['high_docs_examined_to_returned_records']}**", "",
        "## Observations", "",
    ]
    if report["findings"]:
        lines.extend(f"- {item['observation']}" for item in report["findings"])
    else:
        lines.append("- No error, warning, or slow-operation signal was identified by the basic heuristics.")
    lines.extend(["", "## Frequent error codes", ""])
    error_codes = counts.get("top_error_codes", {})
    if error_codes:
        lines.extend(f"- `{code}`: {count:,}×" for code, count in error_codes.items())
    else:
        lines.append("- No structured error codes detected.")
    lines.extend(["", "## Frequent messages", ""])
    if report["top_messages"]:
        for item in report["top_messages"][:15]:
            lines.append(f"- `{item['severity']}` {item['component']} "
                         f"(id {item['message_id'] or 'n/a'}, {item['count']}×): {item['message']}")
    else:
        lines.append("- No parsed message signatures.")
    if ai_summary:
        lines.extend(["", "## AI high-level summary", "", ai_summary])
    lines.extend(["", "## Caveats", ""])
    lines.extend(f"- {note}" for note in report["notes"])
    lines.append("- Heuristic triage is not a substitute for reviewing the relevant full log context and workload metrics.")
    return "\n".join(lines) + "\n"


def render_html(report: dict[str, Any], ai_summary: str | None = None, limit: int = 500) -> str:
    scope = report["scope"]

    def esc(value: Any) -> str:
        return html.escape(str(value), quote=True)

    def fmt_num(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, float):
            value = round(value)
        if isinstance(value, (int, float)):
            return f"{value:,.0f}"
        return str(value)

    rows = report.get("slow_query_table", [])[:limit]
    table_rows = "".join(
        "<tr>"
        f"<td class=\"num\">{i}</td>"
        f"<td>{esc(row['op'])}</td>"
        f"<td class=\"break\">{esc(row['namespace'])}</td>"
        f"<td class=\"num\">{fmt_num(row['count'])}</td>"
        f"<td class=\"num\">{fmt_num(row['avg_ms'])}</td>"
        f"<td class=\"num\">{fmt_num(row['max_ms'])}</td>"
        f"<td class=\"num\">{fmt_num(row['total_ms'])}</td>"
        f"<td class=\"num\">{fmt_num(row['reslen'])}</td>"
        f"<td class=\"break {'collscan' if str(row['index']).upper() == 'COLLSCAN' else ''}\">{esc(row['index'])}</td>"
        f"<td class=\"break pattern\">{esc(row['query_pattern'])}</td>"
        "</tr>"
        for i, row in enumerate(rows, 1)
    ) or "<tr><td colspan=\"10\">No slow query records were detected.</td></tr>"

    title = "MongoDB Slow Query Summary"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
  :root {{ --text-color:#173b33; --header-color:#c6d9c7; --row-color:#eaf1ea; --border-color:#d8d8d8; }}
  body {{ font-family:Helvetica,Arial,sans-serif; margin:10px; color:#000; }}
  h1 {{ text-align:center; font-size:22px; font-weight:700; margin:0 0 4px; }}
  .meta {{ font-size:12px; color:#555; margin:0 0 8px; }}
  table {{ border-collapse:collapse; width:100%; table-layout:auto; }}
  th,td {{ border:1px solid var(--border-color); vertical-align:middle; padding:3px 4px; font-size:18px; line-height:1.05; }}
  th {{ background:var(--header-color); color:var(--text-color); font-weight:bold; text-align:left; cursor:pointer; user-select:none; }}
  th span {{ background:#a9cce8; padding:0 2px; }}
  th.sorted-asc span::after {{ content:" ▲"; }}
  th.sorted-desc span::after {{ content:" ▼"; }}
  tr:nth-child(even) td {{ background:var(--row-color); }}
  .num {{ text-align:right; white-space:nowrap; }}
  .break {{ word-break:break-word; white-space:pre-wrap; }}
  .pattern {{ min-width:420px; }}
  .collscan {{ color:red; }}
</style>
</head>
<body>
  <h1>{esc(title)}</h1>
  <p class="meta">Slow query groups sorted by avg ms. Rows shown: {len(rows):,} of {len(report.get('slow_query_table', [])):,}. Time range UTC: {esc(scope['first_timestamp_utc'] or 'not detected')} to {esc(scope['last_timestamp_utc'] or 'not detected')}.</p>
  <p class="meta">Generated from sanitized log output. Sanitization is best-effort; review this artifact before sharing. <code>queryShapeHash</code> values are intentionally preserved to support follow-up in Atlas UI.</p>
  <table id="slowQueryTable">
    <thead>
      <tr>
        <th data-type="number"><span>#</span></th>
        <th data-type="text"><span>op</span></th>
        <th data-type="text"><span>namespace</span></th>
        <th data-type="number"><span>count</span></th>
        <th data-type="number"><span>avg ms</span></th>
        <th data-type="number"><span>max ms</span></th>
        <th data-type="number"><span>total ms</span></th>
        <th data-type="number"><span>reslen</span></th>
        <th data-type="text"><span>index</span></th>
        <th data-type="text"><span>query pattern</span></th>
      </tr>
    </thead>
    <tbody>{table_rows}</tbody>
  </table>
  <script>
  (function() {{
    const table = document.getElementById('slowQueryTable');
    if (!table) return;
    const headers = Array.from(table.querySelectorAll('th'));
    const tbody = table.tBodies[0];
    function value(row, index, type) {{
      const text = row.cells[index].textContent.trim();
      if (type === 'number') {{
        const number = Number(text.replace(/,/g, ''));
        return Number.isFinite(number) ? number : Number.NEGATIVE_INFINITY;
      }}
      return text.toLowerCase();
    }}
    headers.forEach((header, index) => {{
      header.addEventListener('click', () => {{
        const type = header.dataset.type || 'text';
        const direction = header.classList.contains('sorted-asc') ? 'desc' : 'asc';
        headers.forEach(h => h.classList.remove('sorted-asc', 'sorted-desc'));
        header.classList.add(direction === 'asc' ? 'sorted-asc' : 'sorted-desc');
        const rows = Array.from(tbody.rows);
        rows.sort((a, b) => {{
          const av = value(a, index, type);
          const bv = value(b, index, type);
          if (av < bv) return direction === 'asc' ? -1 : 1;
          if (av > bv) return direction === 'asc' ? 1 : -1;
          return 0;
        }});
        rows.forEach(row => tbody.appendChild(row));
      }});
    }});
  }})();
  </script>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sanitize mongod logs, then generate local triage reports.")
    parser.add_argument("logs", nargs="+", help="mongod log file(s); plain text and .gz are supported")
    parser.add_argument("--out", default="mongod_log_report_sanitized.json", help="local JSON report path")
    parser.add_argument("--summary", default="mongod_log_summary_sanitized.md", help="local Markdown summary path")
    parser.add_argument("--html", help="standalone HTML slow-query table path (default: mongod_slow_queries_sanitized.html)")
    parser.add_argument("--no-html", action="store_true", help="do not generate the HTML slow-query table")
    parser.add_argument("--html-limit", type=int, default=500, help="maximum slow-query table rows in --html output")
    parser.add_argument("--summarize", action="store_true", help="send redacted aggregates/examples to the configured hosted model (requires policy confirmation)")
    parser.add_argument("--confirm-ai-policy-permitted", action="store_true", help="confirm your organization's data handling policy permits sending the redacted aggregate payload to the configured AI endpoint")
    parser.add_argument("--prepare-ai-payload", action="store_true", help="write the redacted payload for review without contacting a model")
    parser.add_argument("--ai-payload-out", help="path for the exact redacted payload (used with --summarize or --prepare-ai-payload)")
    parser.add_argument("--sanitize-output", type=Path, help="sanitized log output path; default is INPUT.sanitized.log for one input or ./sanitized-logs for multiple inputs")
    parser.add_argument("--sanitize-only", action="store_true", help="only write sanitized log output; do not generate JSON/Markdown/HTML reports")
    parser.add_argument("--analyze-raw", action="store_true", help="advanced: analyze the original input logs without sanitizing first")
    parser.add_argument("--analyze-sanitized", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    for path in args.logs:
        if not Path(path).is_file():
            parser.error(f"input file not found: {path}")
    base_url = os.environ.get("MONGOD_LOG_AI_BASE_URL", "").strip()
    api_key = os.environ.get("MONGOD_LOG_AI_API_KEY", "").strip()
    model = os.environ.get("MONGOD_LOG_AI_MODEL", "").strip()
    if args.summarize and args.prepare_ai_payload:
        parser.error("use either --summarize or --prepare-ai-payload, not both")
    if args.ai_payload_out and not (args.summarize or args.prepare_ai_payload):
        parser.error("--ai-payload-out requires --summarize or --prepare-ai-payload")
    if args.summarize and not args.confirm_ai_policy_permitted:
        parser.error("--summarize requires --confirm-ai-policy-permitted after verifying your organization's policy permits the redacted payload submission")
    if args.summarize and not (base_url and api_key and model):
        parser.error("--summarize requires MONGOD_LOG_AI_BASE_URL, MONGOD_LOG_AI_API_KEY, and MONGOD_LOG_AI_MODEL")
    if args.analyze_raw and args.sanitize_output:
        parser.error("--analyze-raw cannot be combined with --sanitize-output")
    if args.analyze_raw and args.sanitize_only:
        parser.error("--analyze-raw cannot be combined with --sanitize-only")
    if args.sanitize_only and (args.summarize or args.prepare_ai_payload or args.ai_payload_out or args.html):
        parser.error("--sanitize-only cannot be combined with report or AI output options")
    if args.no_html and args.html:
        parser.error("--no-html cannot be combined with --html")
    if not args.no_html and not args.sanitize_only and not args.html:
        args.html = "mongod_slow_queries_sanitized.html"
    if args.html_limit < 1:
        parser.error("--html-limit must be at least 1")

    try:
        analysis_inputs = args.logs
        sanitized_results = None
        if not args.analyze_raw:
            sanitize_output = args.sanitize_output or default_sanitized_output(args.logs)
            sanitized_results = sanitize_logs(args.logs, sanitize_output)
            if args.sanitize_only:
                print(json.dumps({
                    "status": "sanitized",
                    "outputs": sanitized_results,
                    "warning": "Best-effort sanitization only; manually review for organization-specific sensitive values before sharing.",
                }, indent=2, ensure_ascii=False))
                return 0
            analysis_inputs = [item["output"] for item in sanitized_results]

        report = analyze_files(analysis_inputs)
        Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        ai_summary = None
        if args.summarize or args.prepare_ai_payload:
            payload = make_ai_payload(report)
            if args.ai_payload_out or args.prepare_ai_payload:
                payload_path = args.ai_payload_out or "mongod_log_ai_payload.json"
                Path(payload_path).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            if args.summarize:
                ai_summary = call_model(payload, base_url, api_key, model)
        Path(args.summary).write_text(render_markdown(report, ai_summary), encoding="utf-8")
        if args.html and not args.no_html:
            Path(args.html).write_text(render_html(report, ai_summary, args.html_limit), encoding="utf-8")
    except (OSError, gzip.BadGzipFile, RuntimeError, ValueError) as exc:
        print(f"mongod-log-triage: {exc}", file=sys.stderr)
        return 1

    output_paths = f"{args.out} and {args.summary}" + (f" and {args.html}" if args.html and not args.no_html else "")
    if sanitized_results:
        sanitized_paths = ", ".join(item["output"] for item in sanitized_results)
        print(f"Sanitized input to: {sanitized_paths}")
    mode = "raw input" if args.analyze_raw else "sanitized input"
    print(f"Processed {report['scope']['lines_processed']:,} lines from {mode}; wrote {output_paths}.")
    if args.summarize:
        print("AI summary generated; only the allow-listed redacted aggregate payload was submitted. Confirm policy approval before sharing.")
    elif args.prepare_ai_payload:
        print(f"Prepared redacted AI payload at {args.ai_payload_out or 'mongod_log_ai_payload.json'}; no model was contacted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
