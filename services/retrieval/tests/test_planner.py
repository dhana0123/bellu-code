import unittest

from retrieval_service import planner
from retrieval_service.planner import InvalidQuestion, classify, level1_plan, plan_handler


def kinds(sk):
    return [(i.kind, i.value) for i in sk.exact_ids]


class PlannerL1Test(unittest.TestCase):
    def test_extracts_all_identifier_kinds(self):
        q = ("Is CVE-2021-44228 / GHSA-jfh8-c2jp-5v3q (CWE-502) in pkg:maven/org.apache/log4j-core@2.14.1 "
             "reachable from `parseConfig` in src/app/main.go on arn:aws:s3:::my-bucket/key "
             "in repo acme/payments?")
        got = dict((k, v) for k, v in kinds(classify(q)))
        self.assertEqual(got["cve"], "CVE-2021-44228")
        self.assertEqual(got["ghsa"], "GHSA-jfh8-c2jp-5v3q")
        self.assertEqual(got["cwe"], "CWE-502")
        self.assertEqual(got["purl"], "pkg:maven/org.apache/log4j-core@2.14.1")
        self.assertEqual(got["arn"], "arn:aws:s3:::my-bucket/key")
        self.assertEqual(got["path"], "src/app/main.go")
        self.assertEqual(got["symbol"], "parseConfig")
        self.assertEqual(got["repo"], "acme/payments")

    def test_deterministic(self):
        q = "fix CVE-2024-0001 and CVE-2023-9999 in github.com/a/b"
        self.assertEqual(classify(q), classify(q))

    def test_invalid_questions(self):
        for q in ("", "   \n\t", "x" * 10_001, None):
            with self.assertRaises(InvalidQuestion):
                classify(q)
        classify("a" * 10_000)

    def test_skip_level2_single_intent_fully_covered(self):
        sk = classify("Tell me about CVE-2021-44228")
        self.assertEqual(sk.intents, ("cve_lookup",))
        self.assertFalse(sk.needs_level2)
        p = level1_plan(sk)
        self.assertEqual((p["level"], p["round"]), (1, 0))

    def test_level2_needed(self):
        self.assertTrue(classify("what should we worry about").needs_level2)  # general
        self.assertTrue(classify("fix CVE-2024-0001 and check reachable").needs_level2)  # two intents
        self.assertTrue(classify("fix CVE-2024-0001 before the quarterly audit meeting").needs_level2)  # free text

    def test_named_cwe_unit_without_llm(self):
        sk = classify("CWE-79 root cause: unescaped output\nvulnerable code: print(x)")
        self.assertEqual(len(sk.retrieval_units), 1)
        u = sk.retrieval_units[0]
        self.assertEqual((u.cwe, u.k), ("CWE-79", 4))
        self.assertEqual(u.root_cause, "unescaped output")
        self.assertEqual(u.vulnerable_snippet, "print(x)")
        bare = classify("explain CWE-89").retrieval_units[0]
        self.assertEqual((bare.root_cause, bare.vulnerable_snippet), ("", ""))

    def test_handler(self):
        r = plan_handler({"question": "patch CVE-2021-44228"}, None)
        self.assertEqual(r["llm_calls"], 0)
        self.assertEqual(r["plan"]["intents"], ["remediation"])
        r = plan_handler({"question": "hello"}, None)
        self.assertIsNone(r["plan"])
        self.assertTrue(r["needs_level2"])
        with self.assertRaises(InvalidQuestion):
            plan_handler({"question": " "}, None)


if __name__ == "__main__":
    unittest.main()
