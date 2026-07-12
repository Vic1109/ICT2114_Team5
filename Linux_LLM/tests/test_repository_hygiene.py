"""Focused tests for the supported repository hygiene checker."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from check_repository import _human_output, scan_repository  # noqa: E402


class RepositoryHygieneTests(unittest.TestCase):
    def scan(self, root: Path, paths: list[str]):
        return scan_repository(
            root,
            tracked_paths=paths,
            production_prefixes=("Linux_LLM/config",),
        )

    def test_detects_production_dependencies_paths_secrets_and_generated_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Linux_LLM/config/application.py"
            source.parent.mkdir(parents=True)
            source.write_text(
                "\n".join(
                    (
                        "from evaluation.scoring import score",
                        'MODEL_PATH = "/home/alice/models/model.gguf"',
                        'settings = {"db_password": "actual-password"}',
                        'DATASET = "../evaluation-results/run/gold_manifest.json"',
                    )
                ),
                encoding="utf-8",
            )
            generated = root / "cache/__pycache__/application.pyc"
            generated.parent.mkdir(parents=True)
            generated.write_bytes(b"bytecode")
            model = root / "models/local-model.gguf"
            model.parent.mkdir(parents=True)
            model.write_bytes(b"model")

            result = self.scan(
                root,
                [
                    "Linux_LLM/config/application.py",
                    "cache/__pycache__/application.pyc",
                    "models/local-model.gguf",
                ],
            )

            rules = {finding["rule"] for finding in result["findings"]}
            self.assertFalse(result["ok"])
            self.assertIn("production_imports_nonproduction", rules)
            self.assertIn("personal_absolute_path", rules)
            self.assertIn("credential_literal", rules)
            self.assertIn("evaluation_path", rules)
            self.assertIn("gold_manifest_path", rules)
            self.assertIn("tracked_generated_artifact", rules)
            self.assertNotIn("actual-password", json.dumps(result))

    def test_placeholders_and_nonproduction_fixtures_do_not_trigger(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            production = root / "Linux_LLM/config/application.py"
            production.parent.mkdir(parents=True)
            production.write_text(
                "\n".join(
                    (
                        'MODEL_PATH = "/opt/soc/models/model.gguf"',
                        'DB_PASSWORD = "${DB_PASSWORD}"',
                        'EXAMPLE_PATH = "/home/<user>/model.gguf"',
                    )
                ),
                encoding="utf-8",
            )
            fixture = root / "Linux_LLM/tests/test_fixture.py"
            fixture.parent.mkdir(parents=True)
            fixture.write_text(
                'password = "fixture-secret"\npath = "/home/alice/private"\n',
                encoding="utf-8",
            )

            result = self.scan(
                root,
                ["Linux_LLM/config/application.py", "Linux_LLM/tests/test_fixture.py"],
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["scope"]["production_content_files_scanned"], 1)

    def test_explicit_configuration_file_and_likely_dump_are_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env_example = root / ".env.example"
            env_example.write_text(
                'WEB_PASSWORD="committed-value"\nDB_PASSWORD="${DB_PASSWORD}"\n',
                encoding="utf-8",
            )
            dump = root / "backups/database-snapshot.sql"
            dump.parent.mkdir(parents=True)
            dump.write_text("-- synthetic dump", encoding="utf-8")

            result = scan_repository(
                root,
                tracked_paths=[".env.example", "backups/database-snapshot.sql"],
                production_prefixes=(".env.example",),
            )

            findings = {(item["rule"], item["path"]) for item in result["findings"]}
            self.assertIn(("credential_literal", ".env.example"), findings)
            self.assertIn(
                ("tracked_generated_artifact", "backups/database-snapshot.sql"),
                findings,
            )

    def test_empty_secret_placeholder_does_not_consume_next_assignment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env_example = root / ".env.example"
            env_example.write_text(
                "SSH_PASSWORD=\nSSH_PORT=22\n",
                encoding="utf-8",
            )

            result = scan_repository(
                root,
                tracked_paths=[".env.example"],
                production_prefixes=(".env.example",),
            )

            self.assertTrue(result["ok"], result)

    def test_human_output_states_both_scopes(self):
        result = {
            "ok": True,
            "finding_count": 0,
            "findings": [],
            "scope": {
                "production_prefixes": ["Linux_LLM/config"],
                "production_content_files_scanned": 14,
                "generated_artifact_scope": "all tracked files present in the worktree",
                "tracked_files_scanned": 40,
            },
        }
        output = _human_output(result)
        self.assertIn("Production content scope: Linux_LLM/config", output)
        self.assertIn("Generated-artifact scope: all tracked files", output)


if __name__ == "__main__":
    unittest.main()
