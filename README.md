# REA-to-Forensic-Report Pipeline

This project turns a JSON analysis exported from the REA (Reverse Engineering
Agent) plugin into a self-contained forensic HTML report with a SHA-256 evidence
manifest. It uses only the Python standard library.

## Why this exists

The `rea` Hermes plugin's tools become available only in the **next** session
after it is installed and enabled. This pipeline therefore **does not run REA**.
It consumes the analysis JSON that REA produces and turns it into a report. The
handoff is:

1. **In this session:** install/enable the `rea` plugin. Its MCP tools are not
   yet callable.
2. **Next Hermes session:** REA tools are live. Run REA against your target and
   export its analysis JSON to a file, e.g. `analysis.json`.
3. **Here:** run this pipeline against that JSON and the directory of artifacts
   it references.

```
# next session: REA produces analysis.json
# then, in a regular shell:
python pipeline.py --analysis analysis.json --artifacts ./artifacts \
    --out report.html --manifest manifest.csv
```

For a no-argument smoke test using the bundled sample data:

```
python pipeline.py --demo
```

`--demo` writes a timestamped `report-<UTC stamp>.html` and
`manifest-<UTC stamp>.csv` into the current working directory, using
`sample/rea_analysis.json` and `sample/artifacts/`. Every demo run gets its own
file names, so an earlier report is never replaced by a later smoke test.

## CLI

```
python pipeline.py --analysis FILE --artifacts DIR --out report.html [--manifest manifest.csv]
python pipeline.py --demo
python pipeline.py --verify --manifest manifest.csv --artifacts DIR
python pipeline.py --verify --json --manifest manifest.csv --artifacts DIR
```

| Flag | Meaning |
|------|---------|
| `--analysis FILE` | Path to the REA analysis JSON (schema v1.0, see below). |
| `--artifacts DIR` | Directory containing every artifact path referenced in the JSON. |
| `--out report.html` | Destination for the self-contained HTML report. |
| `--manifest FILE` | Output destination for the evidence CSV, or input manifest with `--verify`. |
| `--overwrite` | Allow `--out` / `--manifest` to replace existing files. Without it, an existing output is a fail-closed error. |
| `--verify` | Re-hash artifacts against an existing `--manifest` and report hash drift instead of rendering a report. Requires `--manifest` and `--artifacts`. |
| `--json` | With `--verify`, print a machine-readable JSON report on stdout instead of prose. Exit codes and the status vocabulary are unchanged. Invalid without `--verify`. |
| `--demo` | Ignore the report flags above and use the bundled sample. |

Exit codes: `0` success (or integrity confirmed with `--verify`), `1` integrity
failure under `--verify` (a recorded artifact changed or disappeared), `2`
input/validation/output error (with a message on stderr and no partial report).
A refusal to overwrite an existing output is also exit `2` and leaves both
files untouched.

## Input JSON schema (v1.0)

```json
{
  "schema_version": "1.0",
  "target":        { "name": "...", "path": "...", "file_type": "...", "...": "..." },
  "toolchain":     { "engine": "...", "plugin_version": "...", "...": "..." },
  "analysis_summary": { "total_findings": 0, "...": "..." },
  "findings": [
    {
      "id": "F-001",
      "severity": "critical",
      "type": "hardcoded_credential",
      "address": "0x401f3a",
      "confidence": "high",
      "description": "..."
    }
  ],
  "artifacts": [
    { "path": "binary.bin", "role": "primary_binary", "description": "..." }
  ]
}
```

Validation rules:

- Top level must be an object.
- `target`, `toolchain`, `analysis_summary` must be objects (may be empty).
- `findings` must be a list; each finding needs non-empty `severity`, `type`,
  and `description`, plus at least one of `address` / `offset`.
- `artifacts` must be a list; each artifact needs non-empty `path` and `role`.
- `path` is resolved relative to `--artifacts` unless it is absolute.

Malformed JSON, unreadable files, and validation errors are reported clearly on
stderr and produce exit code 2.

## Outputs

**HTML report** (`--out`): fully self-contained, inline CSS, no CDN or external
assets. Sections: target identification, toolchain/version, analysis summary,
findings table (severity, type, address/offset, confidence, description),
evidence chain with SHA-256 hashes, chain-of-custody, and an explicit disclaimer
that the findings are reverse-engineering evidence, not a verdict. All dynamic
text is HTML-escaped.

**Manifest CSV** (`--manifest`): columns `path,sha256,size,role` — one row per
referenced artifact. Files found on disk are hashed with SHA-256 and their byte
size recorded; missing files get the sentinel `MISSING` for both hash and size.
Artifact paths and roles originate in an exported analysis file (untrusted
input). To prevent spreadsheet formula injection when the CSV is opened in Excel
or LibreOffice, any data cell whose first character is `=`, `+`, `-`, `@`, tab or
carriage return is prefixed with a single quote so it is read as text.

### Output safety: never overwrite an audit record

Both outputs are the audit record of a single pipeline run. Before reading any
input or writing anything, the CLI checks whether `--out` or `--manifest` already
exist. If either does, the run stops with exit `2`, names the conflicting path,
and leaves both files untouched. Replacing a prior report or manifest requires
an explicit `--overwrite`, which is an auditable operator decision rather than
a silent side effect. This mirrors the "new timestamped audit file per run,
refuse to replace" policy of the workflow scan trigger: a report that was
generated once is not quietly destroyed by the next invocation. `--demo` uses
UTC-stamped default file names for the same reason.

### Verifying evidence integrity

A manifest is only useful if it can be checked against the artifacts later.
`--verify` re-hashes every artifact on disk and compares it to the recorded
manifest, turning the CSV into a reuseable chain-of-custody record:

```bash
python pipeline.py --verify --manifest manifest.csv --artifacts ./artifacts
```

Each row is printed with an observed status:

- `MATCH` — the artifact is present and its SHA-256 is identical to the manifest.
- `DRIFT` — the artifact is present but its bytes changed. **Integrity failure.**
- `MISSING` — an artifact with a recorded hash is no longer on disk. **Integrity failure.**
- `ABSENT` — the manifest already recorded this artifact as `MISSING`, and it still is. Consistent, not a failure.
- `APPEARED` — the manifest recorded `MISSING`, but a file is now present. Noted with no baseline hash, not a failure.

The run exits `0` when every recorded artifact is consistent (`MATCH`/`ABSENT`)
and `1` if any `DRIFT` or `MISSING` is found. A malformed manifest (wrong header
or a ragged row) fails closed with exit `2` and no verdicts. Formula-safe cells
round-trip: the apostrophe prefix added on write is removed on read, so a
hostile artifact path resolves back to its original value. This mirrors the
reproducible, re-runnable audit trail of the workflow scan trigger — the same
manifest that documents a run can independently confirm or refute it later.

### Machine-readable verify report (`--json`)

CI needs to branch on a result, not parse English. `--verify --json` writes a
single JSON document to stdout and nothing else; prose lines to stdout and
stderr are suppressed so `json.loads()` on stdout is always sufficient. Exit
codes are identical to prose mode, and the top-level `status` is an explicit
vocabulary that pairs with them:

| `status` | exit | Meaning |
|----------|------|---------|
| `ok` | `0` | Every recorded artifact is consistent (`MATCH` / `ABSENT`). |
| `integrity-failure` | `1` | At least one `DRIFT` or `MISSING` recorded artifact. |
| `input-error` | `2` | Manifest unreadable or malformed; no verdicts were produced. |

```json
{
  "tool": "rea-forensics",
  "command": "verify",
  "schema_version": "1.0",
  "status": "integrity-failure",
  "exit_code": 1,
  "manifest": "manifest.csv",
  "counts": {"MATCH": 1, "DRIFT": 1, "MISSING": 0, "ABSENT": 0, "APPEARED": 0},
  "artifacts": [
    {
      "path": "primary.bin", "role": "primary",
      "expected": "abc123...", "observed": "def456...",
      "size_expected": 42, "size_observed": 50, "status": "DRIFT"
    }
  ]
}
```

`artifacts[]` carries `status`, `expected` and `observed` (plus sizes) for each
artifact, so a consumer can report exactly which file drifted without scraping
the human-readable output. An `input-error` report has an `errors` list and an
empty `artifacts` list instead. This structured-report contract follows the
pattern of the workflow upstream-sync tooling: an auditable status vocabulary,
machine-readable action data, and a stable exit-code contract.

## Tests

A standard-library `unittest` suite locks in the properties that keep a
report trustworthy: every manifest data cell is formula-safe, artifacts absent
from disk carry an explicit `MISSING` sentinel, malformed input fails closed
with concrete problems, an existing report or manifest is never replaced
without `--overwrite`, and `--verify` detects hash drift, missing artifacts and
malformed manifests with the documented exit codes. The JSON mode is locked in
too: stdout parses as one document, status and exit code agree with prose mode,
and a malformed manifest is a fail-closed `input-error`.

```bash
python -m unittest discover -s tests -v
```

The suite exercises the CSV writer with hostile path/role values, verifies real
SHA-256 hashing alongside the missing-file path, and checks validation and CLI
exit-2 behavior. Standard library only; no test runner to install.

## Design notes

- Standard library only: `argparse`, `csv`, `datetime`, `hashlib`, `html`,
  `json`, `os`, `sys`.
- Files are hashed in 1 MiB chunks, so large binaries are streamed.
- No code from the analyzed target is ever executed; only bytes are read.

## Disclaimer

Findings in the generated report are reverse-engineering observations, not a
verdict. They require independent review by a qualified analyst before any
conclusion is drawn.
