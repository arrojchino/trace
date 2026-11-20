"""Repeatable unit tests for the REA-to-forensic-report pipeline.

Standard library only. Run from anywhere with:

    python -m unittest discover -s tests -v

Covers the guarantees that keep a forensic report trustworthy:

1. every manifest data cell is formula-safe (untrusted paths/roles cannot run
   as spreadsheet formulas),
2. artifacts not found on disk carry an explicit MISSING sentinel rather than
   an empty or fabricated hash,
3. malformed analysis input fails closed with a list of concrete problems,
4. an existing report or manifest is never replaced without --overwrite,
5. --verify --json emits a machine-readable, CI-consumable report whose status
   and exit code agree with the prose verdict and fail closed on bad input.
"""

import contextlib
import csv
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pipeline as p


def _row(path, role, sha="abc123", size=42):
    """Build a minimal evidence row as hash_artifacts would produce."""
    return {
        "index": 1,
        "path": path,
        "resolved_path": path,
        "sha256": sha,
        "size": size,
        "role": role,
        "status": "PRESENT",
        "description": "",
    }


class CsvSafetyTests(unittest.TestCase):
    def test_formula_prefixes_are_neutralized(self):
        for prefix in ("=", "+", "-", "@", "\t", "\r"):
            with self.subTest(prefix=repr(prefix)):
                self.assertEqual(
                    p._csv_safe_cell(prefix + "cmd|'/c calc'!A0"),
                    "'" + prefix + "cmd|'/c calc'!A0",
                )

    def test_safe_cells_are_unchanged(self):
        for value in ("binary.bin", "primary_binary", "", None, 42, "a=1"):
            with self.subTest(value=value):
                self.assertEqual(p._csv_safe_cell(value), "" if value is None else str(value))

    def test_write_manifest_escapes_hostile_cells_and_round_trips(self):
        hostile_path = "=HYPERLINK(\"http://evil\")"
        hostile_role = "@SUM(1+1)"
        with tempfile.TemporaryDirectory() as d:
            manifest = Path(d) / "manifest.csv"
            p.write_manifest(
                [_row(hostile_path, hostile_role), _row("clean.bin", "primary")],
                str(manifest),
            )
            with open(manifest, newline="", encoding="utf-8") as handle:
                rows = list(csv.reader(handle))

        self.assertEqual(rows[0], ["path", "sha256", "size", "role"])
        self.assertEqual(rows[1][0], "'" + hostile_path)
        self.assertEqual(rows[1][3], "'" + hostile_role)
        self.assertEqual(rows[2], ["clean.bin", "abc123", "42", "primary"])

    def test_write_manifest_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as d:
            manifest = Path(d) / "nested" / "dir" / "manifest.csv"
            p.write_manifest([], str(manifest))
            self.assertTrue(manifest.is_file())
            with open(manifest, newline="", encoding="utf-8") as handle:
                self.assertEqual(list(csv.reader(handle)), [["path", "sha256", "size", "role"]])


class EvidenceTests(unittest.TestCase):
    def test_present_artifact_is_hashed(self):
        with tempfile.TemporaryDirectory() as d:
            payload = b"MZ\x00\x00 forensic bytes"
            (Path(d) / "primary.bin").write_bytes(payload)
            analysis = {"artifacts": [{"path": "primary.bin", "role": "primary"}]}
            rows = p.hash_artifacts(analysis, d)

        self.assertEqual(rows[0]["status"], "PRESENT")
        self.assertEqual(rows[0]["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(rows[0]["size"], len(payload))

    def test_missing_artifact_carries_explicit_sentinel(self):
        with tempfile.TemporaryDirectory() as d:
            analysis = {"artifacts": [{"path": "does_not_exist.bin", "role": "primary"}]}
            rows = p.hash_artifacts(analysis, d)

        self.assertEqual(rows[0]["status"], p.MISSING)
        self.assertEqual(rows[0]["sha256"], p.MISSING)
        self.assertEqual(rows[0]["size"], p.MISSING)

    def test_missing_artifact_store_marks_everything_missing(self):
        analysis = {"artifacts": [{"path": "x.bin", "role": "primary"}]}
        rows = p.hash_artifacts(analysis, os.path.join("nonexistent", "store"))
        self.assertEqual(rows[0]["status"], p.MISSING)
        self.assertEqual(rows[0]["sha256"], p.MISSING)


class ValidationTests(unittest.TestCase):
    def _minimal(self):
        return {
            "schema_version": "1.0",
            "target": {"name": "sample"},
            "toolchain": {"engine": "rea"},
            "analysis_summary": {},
            "findings": [
                {
                    "id": "F-001",
                    "severity": "high",
                    "type": "credential",
                    "address": "0x10",
                    "description": "hardcoded secret",
                }
            ],
            "artifacts": [{"path": "a.bin", "role": "primary"}],
        }

    def test_valid_analysis_is_normalized(self):
        result = p.validate_analysis(self._minimal())
        self.assertEqual(result["target"]["name"], "sample")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["report_metadata"], {})

    def test_non_object_top_level_fails(self):
        with self.assertRaises(p.AnalysisError) as ctx:
            p.validate_analysis([])
        problem = ctx.exception.args[0]
        text = problem if isinstance(problem, str) else " ".join(problem)
        self.assertIn("must be an object", text)

    def test_bad_finding_fields_are_reported(self):
        data = self._minimal()
        data["findings"] = [{"severity": "", "type": 7}]
        with self.assertRaises(p.AnalysisError) as ctx:
            p.validate_analysis(data)
        problems = " ".join(ctx.exception.args[0])
        self.assertIn("findings[0].severity", problems)
        self.assertIn("findings[0].type", problems)
        self.assertIn("address' or 'offset", problems)
        self.assertIn("description", problems)

    def test_bad_artifact_fields_are_reported(self):
        data = self._minimal()
        data["artifacts"] = [{"path": "", "role": 5}]
        with self.assertRaises(p.AnalysisError) as ctx:
            p.validate_analysis(data)
        problems = " ".join(ctx.exception.args[0])
        self.assertIn("artifacts[0].path", problems)
        self.assertIn("artifacts[0].role", problems)

    def test_load_analysis_rejects_invalid_json(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            with self.assertRaises(p.AnalysisError) as ctx:
                p.load_analysis(str(bad))
        self.assertIn("invalid JSON", ctx.exception.args[0])

    def test_cli_fails_closed_on_malformed_input(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text("[]", encoding="utf-8")
            out = Path(d) / "report.html"
            code = p.main([
                "--analysis", str(bad),
                "--artifacts", d,
                "--out", str(out),
            ])
        self.assertEqual(code, p.EXIT_INPUT_ERROR)
        self.assertFalse(out.exists())


class OutputSafetyTests(unittest.TestCase):
    def _analysis_file(self, directory):
        data = {
            "schema_version": "1.0",
            "target": {"name": "sample"},
            "toolchain": {"engine": "rea"},
            "analysis_summary": {},
            "findings": [],
            "artifacts": [],
        }
        path = Path(directory) / "analysis.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def _paths(self, directory):
        return str(Path(directory) / "report.html"), str(Path(directory) / "manifest.csv")

    def test_existing_output_paths_helper(self):
        with tempfile.TemporaryDirectory() as d:
            out, manifest = self._paths(d)
            Path(out).write_text("OLD", encoding="utf-8")
            Path(manifest).write_text("OLD", encoding="utf-8")
            self.assertEqual(
                p.existing_output_paths([out, manifest], False), [out, manifest]
            )
            self.assertEqual(p.existing_output_paths([out, manifest], True), [])

    def test_cli_refuses_to_replace_existing_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            analysis = self._analysis_file(d)
            out, manifest = self._paths(d)
            Path(out).write_text("OLD REPORT", encoding="utf-8")
            Path(manifest).write_text("OLD MANIFEST", encoding="utf-8")
            code = p.main([
                "--analysis", analysis, "--artifacts", d,
                "--out", out, "--manifest", manifest,
            ])
            self.assertEqual(code, p.EXIT_INPUT_ERROR)
            self.assertEqual(Path(out).read_text(encoding="utf-8"), "OLD REPORT")
            self.assertEqual(Path(manifest).read_text(encoding="utf-8"), "OLD MANIFEST")

    def test_cli_refuses_when_only_manifest_exists(self):
        with tempfile.TemporaryDirectory() as d:
            analysis = self._analysis_file(d)
            out, manifest = self._paths(d)
            Path(manifest).write_text("OLD MANIFEST", encoding="utf-8")
            code = p.main([
                "--analysis", analysis, "--artifacts", d,
                "--out", out, "--manifest", manifest,
            ])
            self.assertEqual(code, p.EXIT_INPUT_ERROR)
            self.assertFalse(Path(out).exists())
            self.assertEqual(Path(manifest).read_text(encoding="utf-8"), "OLD MANIFEST")

    def test_cli_overwrite_allows_replacement(self):
        with tempfile.TemporaryDirectory() as d:
            analysis = self._analysis_file(d)
            out, manifest = self._paths(d)
            Path(out).write_text("OLD", encoding="utf-8")
            Path(manifest).write_text("OLD", encoding="utf-8")
            code = p.main([
                "--analysis", analysis, "--artifacts", d,
                "--out", out, "--manifest", manifest, "--overwrite",
            ])
            self.assertEqual(code, 0)
            self.assertIn("REA Forensic Analysis Report", Path(out).read_text(encoding="utf-8"))
            self.assertEqual(
                Path(manifest).read_text(encoding="utf-8").splitlines()[0],
                "path,sha256,size,role",
            )


class VerifyTests(unittest.TestCase):
    """Chain-of-custody verification against a prior evidence manifest."""

    def _build(self, directory, payload=b"original forensic bytes"):
        """Write one artifact plus its manifest; return (manifest, artifact)."""
        artifact = Path(directory) / "primary.bin"
        artifact.write_bytes(payload)
        manifest = Path(directory) / "manifest.csv"
        p.write_manifest([_row("primary.bin", "primary", hashlib.sha256(payload).hexdigest(), len(payload))], str(manifest))
        return str(manifest), str(artifact)

    def test_match_when_hash_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            manifest, _ = self._build(d)
            rows = p.read_manifest(manifest)
            verdicts, counts = p.verify_manifest(rows, d)
        self.assertEqual(verdicts[0]["status"], p.V_MATCH)
        self.assertEqual(counts[p.V_MATCH], 1)
        self.assertEqual(counts[p.V_DRIFT], 0)

    def test_drift_when_bytes_change(self):
        with tempfile.TemporaryDirectory() as d:
            manifest, artifact = self._build(d)
            with open(artifact, "ab") as handle:
                handle.write(b"tampered")
            verdicts, counts = p.verify_manifest(p.read_manifest(manifest), d)
        self.assertEqual(verdicts[0]["status"], p.V_DRIFT)
        self.assertNotEqual(verdicts[0]["expected"], verdicts[0]["actual"])

    def test_missing_recorded_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            manifest, artifact = self._build(d)
            os.remove(artifact)
            verdicts, counts = p.verify_manifest(p.read_manifest(manifest), d)
        self.assertEqual(verdicts[0]["status"], p.V_MISSING)

    def test_absent_and_appeared_are_not_failures(self):
        with tempfile.TemporaryDirectory() as d:
            # A manifest that recorded an artifact as MISSING, with no file.
            manifest = Path(d) / "m.csv"
            p.write_manifest([_row("ghost.bin", "external", p.MISSING, p.MISSING)], str(manifest))
            verdicts, counts = p.verify_manifest(p.read_manifest(manifest), d)
            self.assertEqual(verdicts[0]["status"], p.V_ABSENT)
            self.assertEqual(counts[p.V_DRIFT] + counts[p.V_MISSING], 0)

            # Same manifest, but the artifact now appears on disk.
            (Path(d) / "ghost.bin").write_bytes(b"surprise")
            verdicts, counts = p.verify_manifest(p.read_manifest(manifest), d)
            self.assertEqual(verdicts[0]["status"], p.V_APPEARED)
            self.assertEqual(counts[p.V_DRIFT] + counts[p.V_MISSING], 0)

    def test_formula_safe_path_round_trips_through_read_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            manifest = Path(d) / "m.csv"
            p.write_manifest([_row("=SUM(1+1).bin", "primary")], str(manifest))
            rows = p.read_manifest(manifest)
        self.assertEqual(rows[0]["path"], "=SUM(1+1).bin")

    def test_read_manifest_rejects_bad_header_and_ragged_rows(self):
        with tempfile.TemporaryDirectory() as d:
            bad_header = Path(d) / "bad_header.csv"
            bad_header.write_text("a,b,c\n", encoding="utf-8")
            with self.assertRaises(p.AnalysisError):
                p.read_manifest(str(bad_header))

            ragged = Path(d) / "ragged.csv"
            ragged.write_text("path,sha256,size,role\na,b,c\n", encoding="utf-8")
            with self.assertRaises(p.AnalysisError):
                p.read_manifest(str(ragged))

    def test_cli_verify_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            manifest, artifact = self._build(d)
            self.assertEqual(
                p.main(["--verify", "--manifest", manifest, "--artifacts", d]), 0
            )
            with open(artifact, "ab") as handle:
                handle.write(b"tampered")
            self.assertEqual(
                p.main(["--verify", "--manifest", manifest, "--artifacts", d]),
                p.EXIT_INTEGRITY_FAILURE,
            )

    def test_cli_verify_bad_manifest_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.csv"
            bad.write_text("wrong,header\n", encoding="utf-8")
            self.assertEqual(
                p.main(["--verify", "--manifest", str(bad), "--artifacts", d]),
                p.EXIT_INPUT_ERROR,
            )


class VerifyJsonTests(unittest.TestCase):
    """Structured, CI-consumable verify report (--verify --json)."""

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = p.main(argv)
        return code, out.getvalue(), err.getvalue()

    def _build(self, directory, payload=b"original forensic bytes"):
        artifact = Path(directory) / "primary.bin"
        artifact.write_bytes(payload)
        manifest = Path(directory) / "manifest.csv"
        digest = hashlib.sha256(payload).hexdigest()
        p.write_manifest([_row("primary.bin", "primary", digest, len(payload))], str(manifest))
        return str(manifest), str(artifact)

    def test_report_status_and_exit_agree_with_prose_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            manifest, artifact = self._build(d)
            verdicts, counts = p.verify_manifest(p.read_manifest(manifest), d)
            ok = p.build_verify_report(manifest, verdicts, counts)
            self.assertEqual(ok["status"], p.R_STATUS_OK)
            self.assertEqual(ok["exit_code"], 0)

            with open(artifact, "ab") as handle:
                handle.write(b"tampered")
            verdicts, counts = p.verify_manifest(p.read_manifest(manifest), d)
            bad = p.build_verify_report(manifest, verdicts, counts)
        self.assertEqual(bad["status"], p.R_STATUS_INTEGRITY_FAILURE)
        self.assertEqual(bad["exit_code"], p.EXIT_INTEGRITY_FAILURE)
        self.assertEqual(bad["artifacts"][0]["status"], p.V_DRIFT)

    def test_report_has_explicit_status_vocabulary_and_counts(self):
        with tempfile.TemporaryDirectory() as d:
            manifest, _ = self._build(d)
            verdicts, counts = p.verify_manifest(p.read_manifest(manifest), d)
            report = p.build_verify_report(manifest, verdicts, counts)
        self.assertEqual(report["schema_version"], p.VERIFY_REPORT_SCHEMA)
        self.assertEqual(report["tool"], "rea-forensics")
        self.assertEqual(report["command"], "verify")
        self.assertEqual(
            report["counts"],
            {p.V_MATCH: 1, p.V_DRIFT: 0, p.V_MISSING: 0, p.V_ABSENT: 0, p.V_APPEARED: 0},
        )

    def test_report_per_artifact_uses_expected_and_observed(self):
        with tempfile.TemporaryDirectory() as d:
            manifest, _ = self._build(d)
            verdicts, counts = p.verify_manifest(p.read_manifest(manifest), d)
            entry = p.build_verify_report(manifest, verdicts, counts)["artifacts"][0]
        self.assertIn("expected", entry)
        self.assertIn("observed", entry)
        self.assertNotIn("actual", entry)
        self.assertEqual(entry["expected"], entry["observed"])

    def test_error_report_is_fail_closed_and_machine_readable(self):
        report = p.build_verify_error_report("m.csv", ["unexpected header"])
        self.assertEqual(report["status"], p.R_STATUS_INPUT_ERROR)
        self.assertEqual(report["exit_code"], p.EXIT_INPUT_ERROR)
        self.assertEqual(report["errors"], ["unexpected header"])
        self.assertEqual(report["artifacts"], [])
        single = p.build_verify_error_report("m.csv", "one problem")
        self.assertEqual(single["errors"], ["one problem"])

    def test_cli_json_stdout_is_parseable_and_prose_free(self):
        with tempfile.TemporaryDirectory() as d:
            manifest, _ = self._build(d)
            code, out, err = self._run([
                "--verify", "--json", "--manifest", manifest, "--artifacts", d,
            ])
            report = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], p.R_STATUS_OK)
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(err, "")
        self.assertNotIn("OK: evidence", out)

    def test_cli_json_reports_drift_without_prose(self):
        with tempfile.TemporaryDirectory() as d:
            manifest, artifact = self._build(d)
            with open(artifact, "ab") as handle:
                handle.write(b"tampered")
            code, out, err = self._run([
                "--verify", "--json", "--manifest", manifest, "--artifacts", d,
            ])
            report = json.loads(out)
        self.assertEqual(code, p.EXIT_INTEGRITY_FAILURE)
        self.assertEqual(report["status"], p.R_STATUS_INTEGRITY_FAILURE)
        self.assertEqual(report["counts"][p.V_DRIFT], 1)
        self.assertNotEqual(
            report["artifacts"][0]["expected"], report["artifacts"][0]["observed"]
        )
        self.assertEqual(err, "")
        self.assertNotIn("INTEGRITY FAILURE", out)

    def test_cli_json_reports_bad_manifest_as_input_error(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.csv"
            bad.write_text("wrong,header\n", encoding="utf-8")
            code, out, err = self._run([
                "--verify", "--json", "--manifest", str(bad), "--artifacts", d,
            ])
            report = json.loads(out)
        self.assertEqual(code, p.EXIT_INPUT_ERROR)
        self.assertEqual(report["status"], p.R_STATUS_INPUT_ERROR)
        self.assertTrue(report["errors"])
        self.assertEqual(err, "")

    def test_cli_json_without_verify_is_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(io.StringIO()):
                p.main(["--json", "--demo"])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
