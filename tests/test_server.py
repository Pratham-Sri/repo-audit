import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server

FIXTURES = Path(__file__).parent / "fixtures"


def no_scanner_findings(*args, **kwargs):
    return "not-installed", "mock scanner", []


class BuiltInRuleTests(unittest.TestCase):
    def test_each_rule_matches_known_bad_fixture(self):
        bad = (FIXTURES / "known_bad.py").read_text(encoding="utf-8")
        found = {rule_id for rule_id, _, _, pattern, _, _ in server.RULES if pattern.search(bad)}
        self.assertEqual(found, {rule[0] for rule in server.RULES})

    def test_safe_patterns_do_not_trigger_security_or_placeholder_rules(self):
        good = (FIXTURES / "known_good.py").read_text(encoding="utf-8")
        security_rules = {"secret", "private-key", "sql", "cors", "debug", "todo", "empty-handler", "loop-query"}
        found = {rule_id for rule_id, _, _, pattern, _, _ in server.RULES if pattern.search(good)}
        self.assertFalse(found & security_rules)


class FindingAndConfigTests(unittest.TestCase):
    def test_finding_uses_shared_schema_and_json_compatibility(self):
        item = server.finding("debug", "High", "Debug", "app.py", 4, "hidden", "Security")
        self.assertIsInstance(item, server.Finding)
        data = item.to_dict()
        self.assertEqual((data["id"], data["engine"], data["fix"]), ("debug", "RepoLens rules", item.fix_hint))
        self.assertEqual(data["confidence"], "medium")
        json.dumps(data)

    def test_yaml_subset_inline_suppression_rule_toggle_and_severity_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("# repolens-ignore: cors\ncors = True\ndebug = True\n", encoding="utf-8")
            (root / "generated").mkdir()
            (root / "generated" / "out.py").write_text("debug = True\n", encoding="utf-8")
            (root / ".repolens.yml").write_text(
                "ignore_paths:\n  - generated/**\ndisabled_rules:\n  - todo\n"
                "severity_overrides:\n  debug: Critical\nrules:\n  cors: true\n", encoding="utf-8")
            config = server.load_config(root)
            self.assertTrue(server.ignored_path("generated/out.py", config))
            findings = [server.finding("cors", "High", "CORS", "app.py", 2, "hidden", "Security"),
                        server.finding("debug", "High", "Debug", "app.py", 3, "hidden", "Security"),
                        server.finding("todo", "Low", "TODO", "app.py", 3, "hidden", "Completeness"),
                        server.finding("debug", "High", "Debug", "generated/out.py", 1, "hidden", "Security")]
            kept = server.apply_suppressions(root, findings, config)
            self.assertEqual([(f.rule_id, f.severity) for f in kept], [("debug", "Critical")])

    def test_dedupe_merges_scanner_sources(self):
        items = [server.external_finding("Bandit", "B602", "High", "Shell", "app.py", 5, "evidence", "Security", "fix"),
                 server.external_finding("Semgrep", "shell-injection", "High", "Shell", "app.py", 5, "evidence", "Security", "fix")]
        merged = server.dedupe(items)
        self.assertEqual(len(merged), 1)
        self.assertEqual(set(merged[0].sources), {"Bandit", "Semgrep"})


class ReportTests(unittest.TestCase):
    def test_scoring_uses_severity_confidence_and_exploitability(self):
        high = server.external_finding("Semgrep", "x", "High", "x", "a.py", 1, "x", "Security", "fix")
        low_confidence = server.Finding("x", "High", "low", "a.py", 1, "heuristic", "x", "x", "Security", "fix", "low")
        self.assertGreater(server.finding_penalty(high), server.finding_penalty(low_confidence))
        score, categories = server.calculate_scores([high])
        self.assertLess(score, 100)
        self.assertLess(categories["security"], 100)

    def test_sarif_2_1_contains_locations_and_fingerprints(self):
        data = server.finding("debug", "High", "Debug mode", "app.py", 7, "redacted", "Security").to_dict()
        sarif = server.to_sarif({"findings": [data]})
        self.assertEqual(sarif["version"], "2.1.0")
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 7)
        self.assertIn("primaryLocationLineHash", result["partialFingerprints"])
        json.dumps(sarif)

    def test_full_report_matches_golden_file(self):
        root = FIXTURES / "golden_repo"
        with tempfile.TemporaryDirectory() as tmp, \
             patch.multiple(server, run_gitleaks=no_scanner_findings, run_osv=no_scanner_findings, run_semgrep=no_scanner_findings,
                            run_bandit=no_scanner_findings, run_eslint=no_scanner_findings, run_radon=no_scanner_findings, run_codeql=no_scanner_findings):
            report = server.analyze(root, "golden", Path(tmp))
        expected = json.loads((FIXTURES / "golden_report.json").read_text(encoding="utf-8"))
        self.assertEqual(report, expected)


if __name__ == "__main__":
    unittest.main()
