import json
import tempfile
import unittest
from pathlib import Path

from nano_repo_guardian.core import (
    analyze_log_text,
    android_manifest_audit,
    apply_knowledge,
    dead_code_scan,
    dependency_inventory,
    duplicate_scan,
    imports_audit,
    inventory,
    load_knowledge,
    record_verified_outcome,
    risk_scan,
    search_code,
    syntax_scan,
    verify,
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

    def test_invalid_outcome_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            with self.assertRaises(ValueError):
                record_verified_outcome("fp","GUESS",r)

    def test_empty_fingerprint_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            with self.assertRaises(ValueError):
                record_verified_outcome("   ","CONFIRMED",r)

    def test_knowledge_version_increments(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"x.c").write_text("void f(){ fork(); }",encoding="utf-8")
            fp=risk_scan(r)[0]["fingerprint"]
            first=record_verified_outcome(fp,"CONFIRMED",r)
            second=record_verified_outcome(fp,"FIX_PASS",r)
            self.assertEqual(second["knowledge_version"],first["knowledge_version"]+1)
            kb=load_knowledge(r)
            self.assertGreater(kb["verified_patterns"].get(fp,0),0)

    def test_verify_allowlist_rejects_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                verify("rm -rf /",Path(td))

    def test_fix_outcomes_capped(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            for i in range(510):
                record_verified_outcome(f"fp{i}","FALSE_POSITIVE",r)
            kb=load_knowledge(r)
            self.assertLessEqual(len(kb["fix_outcomes"]),500)

    def test_android_manifest_audit(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"AndroidManifest.xml").write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                '<uses-permission android:name="android.permission.CAMERA"/>'
                '<application android:debuggable="true" android:usesCleartextTraffic="true">'
                '<activity android:name=".Main" android:exported="true"/>'
                '<receiver android:name=".Rcv"><intent-filter/></receiver>'
                '</application></manifest>',encoding="utf-8")
            out=android_manifest_audit(r)
            cats={x["category"] for x in out}
            self.assertIn("manifest_permission",cats)
            self.assertIn("manifest_debuggable",cats)
            self.assertIn("manifest_cleartext",cats)
            self.assertIn("manifest_exported",cats)
            # permiso peligroso = HYPOTHESIS_TO_VALIDATE, no INFORMATIONAL
            perm=[x for x in out if x["category"]=="manifest_permission"][0]
            self.assertEqual(perm["status"],"HYPOTHESIS_TO_VALIDATE")

    def test_android_manifest_malformed(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"AndroidManifest.xml").write_text("<manifest><broken>",encoding="utf-8")
            out=android_manifest_audit(r)
            self.assertTrue(any(x["category"]=="manifest_malformed" for x in out))

    def test_imports_audit_duplicates_and_wildcard(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"a.kt").write_text(
                "import kotlinx.coroutines.flow.Flow\n"
                "import kotlinx.coroutines.flow.Flow\n"
                "import java.util.*\n"
                "fun main(){ println(\"x\") }\n",encoding="utf-8")
            out=imports_audit(r)
            self.assertEqual(len(out["duplicates"]),1)
            self.assertEqual(out["duplicates"][0]["status"],"CONFIRMED")
            self.assertEqual(len(out["wildcards"]),1)

    def test_imports_audit_unused_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"a.kt").write_text(
                "import com.example.UnusedThing\n"
                "fun main(){ val x = 1 }\n",encoding="utf-8")
            out=imports_audit(r)
            self.assertGreaterEqual(len(out["unused_candidates"]),1)
            cand=out["unused_candidates"][0]
            self.assertEqual(cand["status"],"HYPOTHESIS_TO_VALIDATE")

    def test_dead_code_scan(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td)
            (r/"a.kt").write_text(
                "fun helperMuerto(){ println(\"nadie me llama\") }\n"
                "fun usado(){ helperMuerto() }\n",encoding="utf-8")
            out=dead_code_scan(r)
            names={x["symbol"] for x in out}
            # 'helperMuerto' tiene 1 mención (la llamada en 'usado') + su definición excluida
            # -> <=1 mención fuera de definición la convierte en candidata... 'usado' tiene 0 menciones
            self.assertIn("usado",names)
            # cada candidato debe ser HYPOTHESIS_TO_VALIDATE
            self.assertTrue(all(x["status"]=="HYPOTHESIS_TO_VALIDATE" for x in out))
            self.assertTrue(all(x["severity"]=="P3" for x in out))

if __name__=="__main__":
    unittest.main()
