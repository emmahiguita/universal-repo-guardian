import tempfile
import unittest
from pathlib import Path

from nano_repo_guardian.metrics import (
    blast_radius,
    bug_priority,
    concurrency_flags,
    confidence_score,
    cyclomatic_report,
    data_flow_issues,
    dependency_graph_metrics,
    function_risk,
    module_health,
    risk_score,
    state_complexity,
)


class MetricsTests(unittest.TestCase):
    def _tmp(self):
        return Path(tempfile.mkdtemp())

    def test_cyclomatic_known_complexity(self):
        r = self._tmp()
        # if + for + if = 3 decisiones => M = 4
        (r / "a.py").write_text(
            "def f(x):\n"
            "    if x:\n"
            "        for i in range(3):\n"
            "            if i > 1:\n"
            "                return 1\n"
            "    return 0\n", encoding="utf-8")
        rep = cyclomatic_report(r)
        self.assertEqual(rep["nature"], "CALCULADO")
        fn = next(x for x in rep["functions"] if x["name"] == "f")
        self.assertEqual(fn["complexity"], 4)

    def test_cyclomatic_sorts_descending(self):
        r = self._tmp()
        (r / "a.py").write_text("def simple():\n    return 1\n\ndef complex_one(x):\n    if x:\n        for i in range(3):\n            if i > 1:\n                if i > 2:\n                    return 1\n    return 0\n", encoding="utf-8")
        rep = cyclomatic_report(r)
        comps = [f["complexity"] for f in rep["functions"]]
        self.assertEqual(comps, sorted(comps, reverse=True))

    def test_risk_score_formula(self):
        out = risk_score("P1", 0.8, 0.7, 0.9, 0.8)
        self.assertEqual(out["nature"], "ESTIMADO")
        # 0.8 * 0.8 * 0.7 * 0.9 * 0.8 = 0.32256 -> 32.3
        self.assertAlmostEqual(out["risk_score"], 32.3, places=1)

    def test_bug_priority_formula(self):
        out = bug_priority("P1", 0.8, 0.7, 0.9, 0.0, 0.0)
        # 0.30*0.8 + 0.20*0.8 + 0.20*0.7 + 0.15*0.9 = 0.675 -> 67.5
        self.assertAlmostEqual(out["priority"], 67.5, places=1)

    def test_confidence_sums_to_one(self):
        out = confidence_score(1, 1, 1, 1, 1)
        self.assertEqual(out["confidence"], 1.0)
        self.assertEqual(out["band"], "MUY_ALTA")

    def test_module_health_clamps(self):
        self.assertEqual(module_health(20, 10, 10, 10, 10, 10)["health_index"], 30.0)
        self.assertEqual(module_health(999, 0, 0, 0, 0, 0)["health_index"], 0.0)

    def test_function_risk_bounded(self):
        out = function_risk(20, {"calls": 20, "assigns": 20, "branches": 20, "returns": 1,
                                 "raises": 1, "resources": 5, "concurrency": 5}, 1.0)
        self.assertEqual(out["nature"], "ESTIMADO")
        self.assertTrue(0.0 <= out["function_risk"] <= 1.0)
        self.assertEqual(out["classification"], "CRITICO")

    def test_data_flow_use_before_def(self):
        r = self._tmp()
        p = r / "a.py"
        p.write_text("def f():\n    print(x)\n    x = 1\n", encoding="utf-8")
        out = data_flow_issues(p)
        cats = {i["category"] for i in out["issues"]}
        self.assertIn("use_before_def_candidate", cats)
        issue = next(i for i in out["issues"] if i["category"] == "use_before_def_candidate")
        self.assertEqual(issue["name"], "x")
        self.assertEqual(issue["nature"], "CALCULADO")

    def test_dependency_graph_edges(self):
        r = self._tmp()
        (r / "a.py").write_text("import b\n", encoding="utf-8")
        (r / "b.py").write_text("def helper():\n    return 1\n", encoding="utf-8")
        out = dependency_graph_metrics(r)
        self.assertEqual(out["nodes"], 2)
        self.assertEqual(out["edges"], 1)
        self.assertEqual(out["nature"], "CALCULADO")

    def test_blast_radius_systemic(self):
        r = self._tmp()
        (r / "a.py").write_text("import b\n", encoding="utf-8")
        (r / "b.py").write_text("x = 1\n", encoding="utf-8")
        out = blast_radius(r, ["b.py"])
        res = out["results"][0]
        self.assertEqual(res["blast_radius"], 1.0)
        self.assertEqual(res["classification"], "SISTEMICO")

    def test_state_complexity_upper_bound(self):
        r = self._tmp()
        (r / "a.py").write_text("running = True\nconnected = False\n", encoding="utf-8")
        out = state_complexity(r)
        self.assertEqual(out["upper_bound_states"], 4)

    def test_concurrency_flags(self):
        r = self._tmp()
        (r / "a.rs").write_text("static mut COUNTER: i32 = 0;\n", encoding="utf-8")
        out = concurrency_flags(r)
        self.assertTrue(any(f["category"] == "rust_static_mut" for f in out["flags"]))
        self.assertEqual(out["nature"], "HEURISTICO")


if __name__ == "__main__":
    unittest.main()
