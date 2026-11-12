# MongoDB Log Triage

This script sanitizes MongoDB `mongod` logs and generates local triage artifacts for slow-query review.

## Requirements

- Python 3.10 or newer
- No external Python packages required

## Recommended Command

Run this from the folder containing `mongod_log_triage.py` and your log file:

```bash
python3 mongod_log_triage.py mongo.log \
  --out mongod_log_report_sanitized.json \
  --summary mongod_log_summary_sanitized.md
```

By default, the script first writes a sanitized copy of the input log, then analyzes that sanitized copy.
It also generates a standalone HTML slow-query table unless `--no-html` is set.

For `mongo.log`, the default sanitized log is:

```text
mongo.sanitized.log
```

## Generated Files

- `mongo.sanitized.log`: sanitized log output
- `mongod_log_report_sanitized.json`: detailed machine-readable report
- `mongod_log_summary_sanitized.md`: Markdown summary
- `mongod_slow_queries_sanitized.html`: shareable slow-query table

The HTML table includes sortable columns for:

```text
#, op, namespace, count, avg ms, max ms, total ms, reslen, index, query pattern
```

## Sanitization Notes

Sanitization is best-effort. It replaces common sensitive values such as emails, IP addresses, connection strings, secrets, namespaces, database names, collection names, IDs, and query literal values with synthetic placeholders.

Review generated files before sharing them outside your organization.

## queryShapeHash

`queryShapeHash` values are intentionally preserved. They are useful for finding the same query shape in Atlas/Ops Manager UI and are not treated as private query data by this sanitizer.

## Advanced Options

Only sanitize, without generating reports:

```bash
python3 mongod_log_triage.py mongo.log --sanitize-only
```

Choose the sanitized output path:

```bash
python3 mongod_log_triage.py mongo.log \
  --sanitize-output customer-safe.log \
  --out report.json \
  --summary summary.md \
  --html slow-queries.html
```

Skip HTML generation:

```bash
python3 mongod_log_triage.py mongo.log --no-html
```

Analyze raw logs without sanitizing first:

```bash
python3 mongod_log_triage.py mongo.log --analyze-raw
```

Use `--analyze-raw` only when you are certain raw log processing and generated artifacts are acceptable for your environment.
