#!/usr/bin/env python3
"""REA-output-to-forensic-report pipeline.

Consumes analysis JSON produced by the REA (Reverse Engineering Agent) plugin,
hashes each referenced artifact found on disk, writes an evidence manifest CSV,
and renders a self-contained HTML forensic report (inline CSS, no CDNs).

This pipeline does NOT run REA itself. It only consumes REA analysis JSON that
was exported from a Hermes session where the REA plugin was enabled.

Standard library only. Python 3.8+.
"""

import argparse
import csv
import datetime
import hashlib
import html
import json
import os
import sys

SCHEMA_VERSION = "1.0"
MISSING = "MISSING"
EXIT_INPUT_ERROR = 2
EXIT_INTEGRITY_FAILURE = 1

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# Verify verdicts. MATCH and ABSENT are consistent with the prior manifest and
# do not fail the run; DRIFT and MISSING are integrity failures (exit 1).
V_MATCH = "MATCH"
V_DRIFT = "DRIFT"
V_MISSING = "MISSING"
V_ABSENT = "ABSENT"
V_APPEARED = "APPEARED"

# Machine-readable verify report (--json). An explicit status vocabulary lets
# CI consume the result without parsing prose. Status/exit-code pairing mirrors
# the structured action reports of the workflow upstream-sync tooling.
VERIFY_REPORT_SCHEMA = "1.0"
R_STATUS_OK = "ok"
R_STATUS_INTEGRITY_FAILURE = "integrity-failure"
R_STATUS_INPUT_ERROR = "input-error"


class AnalysisError(Exception):
    """Raised when the analysis JSON fails validation."""


def _is_str(value):
    return isinstance(value, str) and value.strip() != ""


def validate_analysis(data):
    """Validate and normalize REA analysis JSON.

    Returns a normalized dict. Raises AnalysisError with a list of problems
    when the input is malformed. Gracefully accepts reasonable variants.
    """
    problems = []

    if not isinstance(data, dict):
        raise AnalysisError("top-level JSON value must be an object")

    # schema_version (optional but if present must be a string)
    schema = data.get("schema_version", SCHEMA_VERSION)
    if not _is_str(schema):
        problems.append("schema_version must be a non-empty string")

    # target identification
    target = data.get("target")
    if not isinstance(target, dict):
        problems.append("'target' must be an object")
        target = {}

    # toolchain / version
    toolchain = data.get("toolchain")
    if not isinstance(toolchain, dict):
        problems.append("'toolchain' must be an object")
        toolchain = {}

    # analysis summary
    summary = data.get("analysis_summary")
    if summary is None:
        summary = {}
    if not isinstance(summary, dict):
        problems.append("'analysis_summary' must be an object")
        summary = {}

    # findings
    findings = data.get("findings")
    if not isinstance(findings, list):
        problems.append("'findings' must be a list")
        findings = []
    else:
        for i, finding in enumerate(findings):
            if not isinstance(finding, dict):
                problems.append("findings[%d] must be an object" % i)
                continue
            for field in ("severity", "type"):
                if not _is_str(finding.get(field)):
                    problems.append(
                        "findings[%d].%s must be a non-empty string" % (i, field)
                    )
            if not (_is_str(finding.get("address")) or _is_str(finding.get("offset"))):
                problems.append(
                    "findings[%d] must have a non-empty 'address' or 'offset'" % i
                )
            if not _is_str(finding.get("description")):
                problems.append(
                    "findings[%d].description must be a non-empty string" % i
                )
            if finding.get("confidence") is not None and not _is_str(
                finding.get("confidence")
            ):
                problems.append(
                    "findings[%d].confidence must be a non-empty string when present" % i
                )

    # artifacts
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list):
        problems.append("'artifacts' must be a list")
        artifacts = []
    else:
        for i, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                problems.append("artifacts[%d] must be an object" % i)
                continue
            if not _is_str(artifact.get("path")):
                problems.append("artifacts[%d].path must be a non-empty string" % i)
            if not _is_str(artifact.get("role")):
                problems.append("artifacts[%d].role must be a non-empty string" % i)

    if problems:
        raise AnalysisError(problems)

    normalized = {
        "schema_version": schema,
        "target": target,
        "toolchain": toolchain,
        "analysis_summary": summary,
        "findings": findings,
        "artifacts": artifacts,
        "report_metadata": data.get("report_metadata")
        if isinstance(data.get("report_metadata"), dict)
        else {},
    }
    return normalized


def sha256_of_file(path):
    """Return (sha256_hex, size_bytes) for a file, or (None, None) if unreadable."""
    digest = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
    except OSError:
        return None, None
    return digest.hexdigest(), size


def hash_artifacts(analysis, artifacts_dir):
    """Hash each referenced artifact. Returns a list of evidence row dicts."""
    rows = []
    if not os.path.isdir(artifacts_dir):
        # Treat as an empty artifact store; every artifact will be marked MISSING.
        artifacts_dir_for_join = artifacts_dir
    else:
        artifacts_dir_for_join = artifacts_dir

    for index, artifact in enumerate(analysis["artifacts"], start=1):
        rel_path = artifact["path"]
        role = artifact["role"]
        candidate = rel_path
        if not os.path.isabs(candidate):
            candidate = os.path.join(artifacts_dir_for_join, rel_path)
        exists = os.path.isfile(candidate)
        sha, size = sha256_of_file(candidate) if exists else (None, None)
        rows.append(
            {
                "index": index,
                "path": rel_path,
                "resolved_path": candidate,
                "sha256": sha if sha else MISSING,
                "size": size if size is not None else MISSING,
                "role": role,
                "status": "PRESENT" if exists else MISSING,
                "description": artifact.get("description", ""),
            }
        )
    return rows


_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe_cell(value):
    """Neutralize spreadsheet formula injection in an evidence CSV cell.

    Artifact paths and roles come from an exported analysis file (untrusted
    input). A cell beginning with =, +, -, @, tab or carriage return is prefixed
    with a single quote so spreadsheet applications render it as text instead
    of executing it as a formula.
    """
    text = "" if value is None else str(value)
    if text and text[0] in _CSV_FORMULA_PREFIXES:
        return "'" + text
    return text


def write_manifest(rows, manifest_path):
    """Write the evidence manifest CSV (path, sha256, size, role).

    Every data cell is run through _csv_safe_cell before writing.
    """
    parent = os.path.dirname(os.path.abspath(manifest_path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(manifest_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["path", "sha256", "size", "role"])
        for row in rows:
            writer.writerow([_csv_safe_cell(row[key]) for key in
                             ("path", "sha256", "size", "role")])


def _unescape_cell(value):
    """Undo the apostrophe prefix that _csv_safe_cell may have added.

    A cell written as `'=...` is read back as `=...`. Only a leading apostrophe
    followed by a formula prefix is treated as an escape; any other apostrophe
    is a literal part of the cell and is preserved.
    """
    if value and value[0] == "'" and len(value) > 1 and value[1] in _CSV_FORMULA_PREFIXES:
        return value[1:]
    return value


def read_manifest(path):
    """Read an evidence manifest CSV written by write_manifest.

    Returns a list of row dicts with keys path, sha256, size, role. Raises
    AnalysisError on an unreadable file, a wrong header, or a ragged row so a
    malformed audit trail can never be silently trusted.
    """
    try:
        with open(path, newline="", encoding="utf-8") as handle:
            reader = csv.reader(handle)
            try:
                header = next(reader)
            except StopIteration:
                raise AnalysisError("manifest %r is empty (no header row)" % path)
            if header != ["path", "sha256", "size", "role"]:
                raise AnalysisError(
                    "unexpected manifest header %r; expected path,sha256,size,role"
                    % (header,)
                )
            rows = []
            for lineno, cells in enumerate(reader, start=2):
                if not cells:
                    continue
                if len(cells) != 4:
                    raise AnalysisError(
                        "manifest line %d has %d column(s); expected 4"
                        % (lineno, len(cells))
                    )
                rows.append({
                    "path": _unescape_cell(cells[0]),
                    "sha256": _unescape_cell(cells[1]),
                    "size": _unescape_cell(cells[2]),
                    "role": _unescape_cell(cells[3]),
                })
    except OSError as exc:
        raise AnalysisError("cannot read manifest %r: %s" % (path, exc))
    return rows


def verify_manifest(rows, artifacts_dir):
    """Re-hash each artifact and compare it to a prior evidence manifest.

    Returns (verdicts, counts). Each verdict records expected vs observed hash
    and a status. Statuses DRIFT (hash changed) and MISSING (recorded artifact
    disappeared) are integrity failures; MATCH, ABSENT and APPEARED are
    consistent with the manifest and do not fail the run.
    """
    verdicts = []
    for row in rows:
        rel_path = row["path"]
        candidate = rel_path
        if not os.path.isabs(candidate):
            candidate = os.path.join(artifacts_dir, rel_path)
        exists = os.path.isfile(candidate)
        actual_sha, actual_size = sha256_of_file(candidate) if exists else (None, None)
        expected = row["sha256"]

        if expected == MISSING or not expected:
            status = V_APPEARED if exists else V_ABSENT
        elif not exists:
            status = V_MISSING
        elif actual_sha == expected:
            status = V_MATCH
        else:
            status = V_DRIFT

        verdicts.append({
            "path": rel_path,
            "role": row["role"],
            "expected": expected if expected else MISSING,
            "actual": actual_sha if actual_sha else MISSING,
            "size_expected": row["size"],
            "size_actual": actual_size if actual_size is not None else MISSING,
            "status": status,
        })

    counts = {
        key: sum(1 for verdict in verdicts if verdict["status"] == key)
        for key in (V_MATCH, V_DRIFT, V_MISSING, V_ABSENT, V_APPEARED)
    }
    return verdicts, counts


def build_verify_report(manifest_path, verdicts, counts):
    """Build the machine-readable verify report emitted by --verify --json.

    The status and exit_code are derived from the same counts that decide the
    prose verdict, so the two modes can never disagree. Per-artifact entries
    rename the internal ``actual``/``size_actual`` keys to the clearer
    ``observed``/``size_observed`` for the public contract.
    """
    failures = counts[V_DRIFT] + counts[V_MISSING]
    return {
        "tool": "rea-forensics",
        "command": "verify",
        "schema_version": VERIFY_REPORT_SCHEMA,
        "status": R_STATUS_INTEGRITY_FAILURE if failures else R_STATUS_OK,
        "exit_code": EXIT_INTEGRITY_FAILURE if failures else 0,
        "manifest": manifest_path,
        "counts": {key: counts[key] for key in
                   (V_MATCH, V_DRIFT, V_MISSING, V_ABSENT, V_APPEARED)},
        "artifacts": [
            {
                "path": v["path"],
                "role": v["role"],
                "expected": v["expected"],
                "observed": v["actual"],
                "size_expected": v["size_expected"],
                "size_observed": v["size_actual"],
                "status": v["status"],
            }
            for v in verdicts
        ],
    }


def build_verify_error_report(manifest_path, problems):
    """Build the --json report for an unreadable or malformed manifest.

    A bad audit trail is a fail-closed input error: no verdicts are produced
    and the explicit status lets CI distinguish it from an integrity failure.
    """
    if isinstance(problems, str):
        problems = [problems]
    return {
        "tool": "rea-forensics",
        "command": "verify",
        "schema_version": VERIFY_REPORT_SCHEMA,
        "status": R_STATUS_INPUT_ERROR,
        "exit_code": EXIT_INPUT_ERROR,
        "manifest": manifest_path,
        "errors": [str(problem) for problem in problems],
        "artifacts": [],
    }


def _emit_json(report):
    """Write one JSON document, pretty-printed, as the only stdout content."""
    sys.stdout.write(json.dumps(report, indent=2) + "\n")


def _esc(value):
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _severity_class(value):
    key = "".join(
        c if c.isalnum() else "-" for c in str(value).strip().lower()
    )
    if not key:
        key = "unknown"
    return "sev-" + key


def _table_or_empty(headers, render_row, items, empty_message):
    if not items:
        return '<p class="empty">%s</p>' % _esc(empty_message)
    head = "".join("<th>%s</th>" % _esc(h) for h in headers)
    body = "".join(render_row(item) for item in items)
    return '<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>' % (head, body)


def render_html(analysis, rows, source_path, manifest_path, artifacts_dir):
    """Render a self-contained HTML report. No external CSS/JS/assets."""
    target = analysis["target"]
    toolchain = analysis["toolchain"]
    summary = analysis["analysis_summary"]
    findings = sorted(
        analysis["findings"],
        key=lambda f: (
            SEVERITY_ORDER.get(str(f.get("severity", "")).strip().lower(), 99),
            str(f.get("id", "")),
        ),
    )
    generated = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    # Target identification
    target_rows = "".join(
        "<tr><th>%s</th><td>%s</td></tr>" % (_esc(key), _esc(value))
        for key, value in target.items()
    )
    if not target_rows:
        target_rows = '<tr><td colspan="2" class="empty">No target metadata supplied.</td></tr>'

    # Toolchain / version
    toolchain_rows = "".join(
        "<tr><th>%s</th><td>%s</td></tr>" % (_esc(key), _esc(value))
        for key, value in toolchain.items()
    )
    if not toolchain_rows:
        toolchain_rows = '<tr><td colspan="2" class="empty">No toolchain metadata supplied.</td></tr>'

    # Analysis summary
    summary_rows = "".join(
        "<tr><th>%s</th><td>%s</td></tr>" % (_esc(key), _esc(value))
        for key, value in summary.items()
    )
    if not summary_rows:
        summary_rows = '<tr><td colspan="2" class="empty">No summary metadata supplied.</td></tr>'

    # Findings table
    def finding_row(f):
        location = f.get("address") or f.get("offset") or ""
        return (
            "<tr>"
            '<td class="%s">%s</td>'
            "<td>%s</td>"
            "<td>%s</td>"
            "<td class=\"mono\">%s</td>"
            "<td>%s</td>"
            "<td>%s</td>"
            "</tr>"
        ) % (
            _severity_class(f.get("severity")),
            _esc(f.get("id", "")),
            _esc(f.get("severity")),
            _esc(f.get("type")),
            _esc(location),
            _esc(f.get("confidence", "")),
            _esc(f.get("description")),
        )

    findings_table = _table_or_empty(
        ["ID", "Severity", "Type", "Address / Offset", "Confidence", "Description"],
        finding_row,
        findings,
        "No findings were reported in the analysis JSON.",
    )

    # Evidence chain table (with hashes + chain-of-custody actions)
    def evidence_row(r):
        status_class = "ok" if r["status"] == "PRESENT" else "missing"
        return (
            "<tr>"
            "<td class=\"mono\">%s</td>"
            "<td>%s</td>"
            "<td class=\"mono\">%s</td>"
            "<td class=\"mono\">%s</td>"
            "<td class=\"%s\">%s</td>"
            "<td>%s</td>"
            "</tr>"
        ) % (
            _esc(r["index"]),
            _esc(r["path"]),
            _esc(r["role"]),
            _esc(r["sha256"]),
            status_class,
            _esc(r["status"]),
            _esc("{} bytes".format(r["size"]) if r["size"] != MISSING else "n/a"),
        )

    evidence_table = _table_or_empty(
        ["#", "Artifact Path", "Role", "SHA-256", "Status", "Size"],
        evidence_row,
        rows,
        "No artifacts were referenced in the analysis JSON.",
    )

    # Chain of custody table (provenance of this report run)
    custody_items = [
        ("1", "analysis_json_ingested", _esc(os.path.abspath(source_path))),
        ("2", "artifact_store_resolved", _esc(os.path.abspath(artifacts_dir))),
        ("3", "sha256_hashed", "%d artifact(s)" % len(rows)),
        ("4", "manifest_written", _esc(os.path.abspath(manifest_path))),
        ("5", "report_rendered", "self-contained HTML"),
    ]
    custody_table = "".join(
        "<tr><td class=\"mono\">%s</td><td>%s</td><td class=\"mono\">%s</td></tr>" % item
        for item in custody_items
    )

    css = """
    :root { color-scheme: light; }
    * { box-sizing: border-box; }
    body {
      margin: 0; padding: 0 0 60px 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 15px; line-height: 1.55; color: #1a2027; background: #f4f6f8;
    }
    header { background: #0b2239; color: #fff; padding: 28px 32px; }
    header h1 { margin: 0 0 6px 0; font-size: 24px; letter-spacing: .3px; }
    header .meta { margin: 0; font-size: 13px; color: #b6c9dd; }
    main { max-width: 1080px; margin: 0 auto; padding: 0 24px; }
    section { background: #fff; border: 1px solid #dde3ea; border-radius: 6px;
              margin: 22px 0; padding: 20px 24px; }
    h2 { margin: 0 0 14px 0; font-size: 18px; color: #0b2239;
         border-bottom: 2px solid #0b2239; padding-bottom: 8px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; vertical-align: top; padding: 8px 10px;
             border-bottom: 1px solid #e3e8ee; }
    thead th { background: #eef2f6; color: #33404d; font-size: 12px;
               text-transform: uppercase; letter-spacing: .5px; }
    .kv th { width: 210px; color: #55636f; font-weight: 600; background: #fafbfc; }
    .kv td { color: #1a2027; }
    .mono { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 12.5px; word-break: break-all; }
    .empty { color: #6b7785; font-style: italic; }
    .sev-critical, .sev-high { color: #a4262c; font-weight: 700; }
    .sev-medium { color: #9a6700; font-weight: 700; }
    .sev-low, .sev-info, .sev-unknown { color: #2b6cb0; font-weight: 600; }
    .ok { color: #1b7f3a; font-weight: 700; }
    .missing { color: #a4262c; font-weight: 700; }
    .disclaimer { background: #fff8e1; border: 1px solid #f0c36d;
                  border-left: 5px solid #d99b00; border-radius: 6px;
                  padding: 16px 20px; margin: 22px 0; color: #5a4300; }
    .disclaimer h2 { color: #7a5b00; border-bottom-color: #d99b00; }
    footer { max-width: 1080px; margin: 0 auto; padding: 0 24px;
             font-size: 12px; color: #6b7785; }
    """

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>REA Forensic Analysis Report</title>
<style>%(css)s</style>
</head>
<body>
<header>
  <h1>REA Forensic Analysis Report</h1>
  <p class="meta">Generated %(generated)s &middot; schema v%(schema)s &middot; source: %(source)s</p>
</header>
<main>
  <section>
    <h2>1. Target Identification</h2>
    <table class="kv"><tbody>%(target)s</tbody></table>
  </section>

  <section>
    <h2>2. Toolchain / Version</h2>
    <table class="kv"><tbody>%(toolchain)s</tbody></table>
  </section>

  <section>
    <h2>3. Analysis Summary</h2>
    <table class="kv"><tbody>%(summary)s</tbody></table>
  </section>

  <section>
    <h2>4. Findings</h2>
    %(findings)s
  </section>

  <section>
    <h2>5. Evidence Chain (Artifact Hashes)</h2>
    %(evidence)s
  </section>

  <section>
    <h2>6. Chain of Custody</h2>
    <table>
      <thead><tr><th>Step</th><th>Action</th><th>Detail</th></tr></thead>
      <tbody>%(custody)s</tbody>
    </table>
  </section>

  <div class="disclaimer">
    <h2>Disclaimer</h2>
    <p><strong>These findings are reverse-engineering evidence, not a verdict.</strong>
    This report renders the observations produced by an automated reverse-engineering
    analysis and records integrity hashes of the referenced artifacts. It does not
    establish malicious intent, attribute authorship, or constitute a legal or
    final determination. All findings require independent review and corroboration
    by a qualified analyst before any conclusion is drawn. Artifacts marked
    %(missing)s were not present on disk and were not hashed.</p>
  </div>
</main>
<footer>
  Self-contained report &middot; no external resources &middot; produced by pipeline.py
  (standard library only).
</footer>
</body>
</html>
""" % {
        "css": css,
        "generated": _esc(generated),
        "schema": _esc(analysis["schema_version"]),
        "source": _esc(os.path.basename(source_path)),
        "target": target_rows,
        "toolchain": toolchain_rows,
        "summary": summary_rows,
        "findings": findings_table,
        "evidence": evidence_table,
        "custody": custody_table,
        "missing": MISSING,
    }


def load_analysis(path):
    """Read and parse the analysis JSON. Raises AnalysisError on any input fault."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise AnalysisError("cannot read analysis file %r: %s" % (path, exc))
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AnalysisError(
            "invalid JSON in %r: line %d column %d: %s"
            % (path, exc.lineno, exc.colno, exc.msg)
        )


def report_error(problems):
    if isinstance(problems, str):
        problems = [problems]
    sys.stderr.write("ERROR: input validation failed:\n")
    for problem in problems:
        sys.stderr.write("  - %s\n" % problem)
    sys.stderr.write("No report was generated.\n")


def _run_stamp():
    """UTC timestamp used to give each demo run its own audit file names."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")


def existing_output_paths(paths, overwrite):
    """Return output paths that already exist when replacement is not allowed.

    A report or manifest is the audit record of one pipeline run. Replacing one
    silently would destroy evidence from an earlier run, so the caller treats a
    non-empty result as a fail-closed input error and writes nothing. Passing
    ``overwrite=True`` is an explicit decision to allow replacement.
    """
    if overwrite:
        return []
    return [path for path in paths if path and os.path.exists(path)]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Consume REA analysis JSON and render a forensic HTML report "
        "with SHA-256 evidence hashing."
    )
    parser.add_argument("--analysis", help="Path to REA analysis JSON file")
    parser.add_argument("--artifacts", help="Directory containing referenced artifacts")
    parser.add_argument("--out", help="Output HTML report path")
    parser.add_argument("--manifest", help="Output evidence manifest CSV path (optional)")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow --out/--manifest to replace existing files (default: refuse).",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Re-hash artifacts against an existing --manifest and report hash drift "
        "(exit 1 on drift or a missing recorded artifact) instead of rendering a report.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="With --verify, emit a machine-readable JSON report on stdout instead of "
        "prose. Exit codes and the status vocabulary are unchanged.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Use bundled sample/rea_analysis.json and sample/artifacts/",
    )
    args = parser.parse_args(argv)

    script_dir = os.path.dirname(os.path.abspath(__file__))

    if args.json and not args.verify:
        parser.error("--json is only valid with --verify")

    if args.verify:
        if not args.manifest or not args.artifacts:
            parser.error("--verify requires both --manifest and --artifacts")
        try:
            prior_rows = read_manifest(args.manifest)
        except AnalysisError as exc:
            problems = exc.args[0] if exc.args else str(exc)
            if args.json:
                _emit_json(build_verify_error_report(args.manifest, problems))
            else:
                report_error(problems)
            return EXIT_INPUT_ERROR
        verdicts, counts = verify_manifest(prior_rows, args.artifacts)
        if args.json:
            # Structured output is the only thing on stdout: no prose to parse.
            _emit_json(build_verify_report(args.manifest, verdicts, counts))
        else:
            for verdict in verdicts:
                sys.stdout.write(
                    "%-8s %s (expected %s, observed %s)\n"
                    % (verdict["status"], verdict["path"], verdict["expected"], verdict["actual"])
                )
            sys.stdout.write(
                "Verified %d artifact(s): %d match, %d drift, %d missing, "
                "%d absent, %d appeared.\n"
                % (
                    len(verdicts), counts[V_MATCH], counts[V_DRIFT], counts[V_MISSING],
                    counts[V_ABSENT], counts[V_APPEARED],
                )
            )
        failures = counts[V_DRIFT] + counts[V_MISSING]
        if failures:
            if not args.json:
                sys.stderr.write(
                    "INTEGRITY FAILURE: %d recorded artifact(s) changed or disappeared.\n"
                    % failures
                )
            return EXIT_INTEGRITY_FAILURE
        if not args.json:
            sys.stdout.write("OK: evidence integrity confirmed against manifest.\n")
        return 0

    if args.demo:
        analysis_path = os.path.join(script_dir, "sample", "rea_analysis.json")
        artifacts_dir = os.path.join(script_dir, "sample", "artifacts")
        stamp = _run_stamp()
        out_path = args.out or os.path.join(os.getcwd(), "report-%s.html" % stamp)
        manifest_path = args.manifest or os.path.join(
            os.getcwd(), "manifest-%s.csv" % stamp
        )
    else:
        missing_args = [
            name
            for name, value in (
                ("--analysis", args.analysis),
                ("--artifacts", args.artifacts),
                ("--out", args.out),
            )
            if not value
        ]
        if missing_args:
            parser.error("required arguments missing: %s" % ", ".join(missing_args))
        analysis_path = args.analysis
        artifacts_dir = args.artifacts
        out_path = args.out
        manifest_path = args.manifest

    # Preflight: never clobber a prior run's audit record unless explicitly told
    # to. Check before reading input or writing anything so refusal is atomic.
    existing = existing_output_paths([out_path, manifest_path], args.overwrite)
    if existing:
        sys.stderr.write(
            "ERROR: refusing to replace existing output file(s): %s\n"
            % ", ".join(existing)
        )
        sys.stderr.write(
            "No report was generated. Pass --overwrite to allow replacement.\n"
        )
        return EXIT_INPUT_ERROR

    try:
        raw = load_analysis(analysis_path)
        analysis = validate_analysis(raw)
    except AnalysisError as exc:
        report_error(exc.args[0] if exc.args else str(exc))
        return EXIT_INPUT_ERROR

    rows = hash_artifacts(analysis, artifacts_dir)

    try:
        if manifest_path:
            write_manifest(rows, manifest_path)
        out_dir = os.path.dirname(os.path.abspath(out_path))
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write(
                render_html(
                    analysis, rows, analysis_path,
                    manifest_path or "(not requested)", artifacts_dir,
                )
            )
    except OSError as exc:
        sys.stderr.write("ERROR: could not write output: %s\n" % exc)
        return EXIT_INPUT_ERROR

    present = sum(1 for r in rows if r["status"] == "PRESENT")
    sys.stdout.write(
        "OK: report written to %s (%d bytes)\n" % (out_path, os.path.getsize(out_path))
    )
    if manifest_path:
        sys.stdout.write(
            "OK: manifest written to %s (%d bytes)\n"
            % (manifest_path, os.path.getsize(manifest_path))
        )
    sys.stdout.write(
        "Artifacts: %d present, %d missing, %d total; %d findings.\n"
        % (present, len(rows) - present, len(rows), len(analysis["findings"]))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
