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

`--demo` writes `report.html` and `manifest.csv` into the current working
directory, using `sample/rea_analysis.json` and `sample/artifacts/`.

## CLI

```
python pipeline.py --analysis FILE --artifacts DIR --out report.html [--manifest manifest.csv]
python pipeline.py --demo
```

| Flag | Meaning |
|------|---------|
| `--analysis FILE` | Path to the REA analysis JSON (schema v1.0, see below). |
| `--artifacts DIR` | Directory containing every artifact path referenced in the JSON. |
| `--out report.html` | Destination for the self-contained HTML report. |
| `--manifest FILE` | Optional destination for the evidence CSV. Defaults to none. |
| `--demo` | Ignore the three flags above and use the bundled sample. |

Exit codes: `0` success, `2` input/validation/output error (with a message on
stderr and no partial report).

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

## Design notes

- Standard library only: `argparse`, `csv`, `datetime`, `hashlib`, `html`,
  `json`, `os`, `sys`.
- Files are hashed in 1 MiB chunks, so large binaries are streamed.
- No code from the analyzed target is ever executed; only bytes are read.

## Disclaimer

Findings in the generated report are reverse-engineering observations, not a
verdict. They require independent review by a qualified analyst before any
conclusion is drawn.
