import tempfile
import unittest
from pathlib import Path

from nano_repo_guardian.correction import correction_gate


class CorrectionGateTests(unittest.TestCase):
    def _tmp(self):
        return Path(tempfile.mkdtemp())

    def test_register_attempt_increments(self):
        root = self._tmp()
        st = correction_gate("register_attempt", "FP-1", root=root)
        self.assertEqual(st["bugs"]["FP-1"]["attempts"], 1)
        self.assertEqual(st["bugs"]["FP-1"]["status"], "EN_CORRECCION")

    def test_attempt_limit_blocks(self):
        root = self._tmp()
        for _ in range(3):
            correction_gate("register_attempt", "FP-1", root=root)
        with self.assertRaises(ValueError) as ctx:
            correction_gate("register_attempt", "FP-1", root=root)
        self.assertIn("BLOQUEADO", str(ctx.exception))
        self.assertEqual(correction_gate("status", root=root)["bugs"]["FP-1"]["status"], "BLOQUEADO")

    def test_checkpoint_after_n_passes(self):
        root = self._tmp()
        for fp in ("FP-1", "FP-2", "FP-3"):
            correction_gate("register_attempt", fp, root=root)
            correction_gate("finalize", fp, verdict="PASS", root=root)
        st = correction_gate("status", root=root)
        self.assertTrue(st["checkpoint_pending"])
        self.assertEqual(st["next_action"], "resolve_checkpoint")

    def test_register_rejected_while_checkpoint_pending(self):
        root = self._tmp()
        for fp in ("FP-1", "FP-2", "FP-3"):
            correction_gate("finalize", fp, verdict="PASS", root=root)
        with self.assertRaises(ValueError) as ctx:
            correction_gate("register_attempt", "FP-4", root=root)
        self.assertIn("checkpoint", str(ctx.exception))

    def test_resolve_checkpoint_clears(self):
        root = self._tmp()
        for fp in ("FP-1", "FP-2", "FP-3"):
            correction_gate("finalize", fp, verdict="PASS", root=root)
        st = correction_gate("resolve_checkpoint", root=root)
        self.assertFalse(st["checkpoint_pending"])
        self.assertEqual(st["bugs_since_checkpoint"], 0)

    def test_fail_after_max_attempts_blocks(self):
        root = self._tmp()
        for _ in range(3):
            correction_gate("register_attempt", "FP-1", root=root)
        st = correction_gate("finalize", "FP-1", verdict="FAIL", root=root)
        self.assertEqual(st["bugs"]["FP-1"]["status"], "BLOQUEADO")

    def test_invalid_verdict_rejected(self):
        root = self._tmp()
        with self.assertRaises(ValueError):
            correction_gate("finalize", "FP-1", verdict="EXCELENTE", root=root)

    def test_invalid_action_rejected(self):
        root = self._tmp()
        with self.assertRaises(ValueError):
            correction_gate("volar", root=root)

    def test_fingerprint_required(self):
        root = self._tmp()
        with self.assertRaises(ValueError):
            correction_gate("register_attempt", "", root=root)

    def test_reset_clears_state(self):
        root = self._tmp()
        correction_gate("register_attempt", "FP-1", root=root)
        correction_gate("reset", root=root)
        st = correction_gate("status", root=root)
        self.assertEqual(st["bugs"], {})
        self.assertFalse(st["checkpoint_pending"])


if __name__ == "__main__":
    unittest.main()
