import tempfile
import unittest
from pathlib import Path
from nano_repo_guardian.language_adapters import detect_adapter
from nano_repo_guardian.semantic import python_semantic_analysis, generic_semantic_analysis, resource_ownership_scan

class SemanticV3Tests(unittest.TestCase):
    def test_detect_adapter(self):
        self.assertEqual(detect_adapter(Path("a.kt")).language, "kotlin")
        self.assertEqual(detect_adapter(Path("a.py")).language, "python")

    def test_python_ast_symbols_calls(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            p=r/"a.py"
            p.write_text("def a():\n    b()\n\ndef b():\n    return 1\n",encoding="utf-8")
            out=python_semantic_analysis(p,r)
            names={x["name"] for x in out["symbols"]}
            self.assertIn("a",names)
            self.assertIn("b",names)
            self.assertTrue(any(e["target"]=="b" for e in out["edges"]))

    def test_generic_kotlin_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            p=r/"a.kt"
            p.write_text("class A { fun run(){ helper() } }\nfun helper() {}",encoding="utf-8")
            out=generic_semantic_analysis(p,r,"kotlin")
            names={x["name"] for x in out["symbols"]}
            self.assertIn("A",names)
            self.assertIn("run",names)
            self.assertIn("helper",names)
            self.assertEqual(out["status"],"HEURISTIC")

    def test_resource_ownership_signal(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"a.c").write_text("void f(){ void* p=malloc(4); }",encoding="utf-8")
            out=resource_ownership_scan(r)
            self.assertTrue(any(x["resource"]=="malloc" for x in out))
            self.assertTrue(all(x["status"]=="HYPOTHESIS_TO_VALIDATE" for x in out))

if __name__=="__main__":
    unittest.main()
