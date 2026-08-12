import json
import tempfile
import unittest
from pathlib import Path

from nano_repo_guardian.core import (
    analyze_log_text, apply_knowledge, architecture_smells,
    build_compatibility_matrix, dependency_inventory, duplicate_scan,
    hotspot_scan, inventory, record_verified_outcome, risk_scan,
    search_code, syntax_scan
)

class GuardianV2Tests(unittest.TestCase):
    def test_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"a.kt").write_text("class A",encoding="utf-8")
            (r/"CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.22)",encoding="utf-8")
            x=inventory(r)
            self.assertEqual(x["files_scanned"],2)
            self.assertEqual(x["languages"]["kotlin"],1)

    def test_syntax_json_and_python(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"bad.json").write_text('{"a":}',encoding="utf-8")
            (r/"bad.py").write_text("def x(:\n pass",encoding="utf-8")
            out=syntax_scan(r)
            cats={x["category"] for x in out}
            self.assertIn("syntax_json",cats)
            self.assertIn("syntax_python",cats)

    def test_merge_conflict(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"a.kt").write_text("<<<<<<< HEAD\nx\n=======\ny\n>>>>>>> branch",encoding="utf-8")
            out=syntax_scan(r)
            self.assertTrue(any(x["category"]=="merge_conflict" for x in out))

    def test_risk_scan(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"native.c").write_text("void f(){ fork(); void* p=malloc(10); }",encoding="utf-8")
            cats={x["category"] for x in risk_scan(r)}
            self.assertIn("process_spawn",cats)
            self.assertIn("native_alloc",cats)

    def test_duplicate_scan(self):
        block="\n".join([f"line_{i} = value_{i};" for i in range(8)])
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"a.cpp").write_text(block,encoding="utf-8")
            (r/"b.cpp").write_text(block,encoding="utf-8")
            out=duplicate_scan(r,min_lines=6)
            self.assertGreaterEqual(len(out),1)

    def test_log_clustering(self):
        txt="""
E linker: dlopen failed: libfoo.so not found
E linker: dlopen failed: libfoo.so not found
E app: Permission denied rc=126
E BLASTBufferQueue: Can't acquire next buffer
"""
        out=analyze_log_text(txt)
        self.assertIn("linker",out["categories"])
        self.assertTrue(any(g["count"]>=2 for g in out["incident_groups"]))

    def test_dependency_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"package.json").write_text(json.dumps({"dependencies":{"react":"19.0.0"}}),encoding="utf-8")
            deps=dependency_inventory(r)
            self.assertEqual(deps[0]["name"],"react")

    def test_knowledge_adjustment(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"x.c").write_text("void f(){ fork(); }",encoding="utf-8")
            finding=risk_scan(r)[0]
            fp=finding["fingerprint"]
            record_verified_outcome(fp,"CONFIRMED",r,root_cause="test")
            adjusted=apply_knowledge([finding],r)[0]
            self.assertGreater(adjusted["confidence"],0.45)

    def test_search(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"a.kt").write_text("class WorkerClient",encoding="utf-8")
            self.assertEqual(len(search_code("WorkerClient",r)),1)

if __name__=="__main__":
    unittest.main()
