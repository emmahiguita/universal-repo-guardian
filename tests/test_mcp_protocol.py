"""Test de integración del protocolo MCP real (JSON-RPC sobre stdio).

Verifica que el servidor habla MCP de verdad: handshake `initialize`,
listado de `tools/list`, ejecución de una tool con datos reales y rechazo
de comandos no permitidos por la allow-list de seguridad.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


class MCPProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import mcp  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("SDK mcp no instalado")

    def _start(self, root: Path):
        env = dict(os.environ)
        env["NANO_REPO_ROOT"] = str(root)
        env.setdefault("PYTHONIOENCODING", "utf-8")
        return subprocess.Popen(
            [sys.executable, "-m", "nano_repo_guardian.server"],
            cwd=REPO,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )

    @staticmethod
    def _send(proc, obj):
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    @staticmethod
    def _recv(proc):
        line = proc.stdout.readline()
        if not line:
            return None
        line = line.strip()
        return json.loads(line) if line else None

    @staticmethod
    def _shutdown(proc):
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    def test_handshake_lists_and_runs_tool(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.py").write_text("x = 1\n", encoding="utf-8")
            proc = self._start(root)
            try:
                self._send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                  "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                             "clientInfo": {"name": "test", "version": "1"}}})
                r = self._recv(proc)
                self.assertIsNotNone(r, "sin respuesta a initialize")
                self.assertIn("serverInfo", r["result"])

                self._send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
                self._send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
                r = self._recv(proc)
                names = [t["name"] for t in r["result"]["tools"]]
                self.assertGreaterEqual(len(names), 28)
                self.assertIn("repo_inventory", names)

                self._send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "repo_inventory", "arguments": {}}})
                r = self._recv(proc)
                self.assertFalse(r["result"].get("isError"))
                text = r["result"]["content"][0]["text"]
                self.assertIn("files_scanned", text)
            finally:
                self._shutdown(proc)

    def test_security_allowlist_rejects_shell(self):
        with tempfile.TemporaryDirectory() as td:
            proc = self._start(Path(td))
            try:
                self._send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                  "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                             "clientInfo": {"name": "test", "version": "1"}}})
                self._recv(proc)
                self._send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
                self._send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                  "params": {"name": "run_verification",
                                             "arguments": {"check": "rm -rf /"}}})
                r = self._recv(proc)
                self.assertTrue(r["result"].get("isError"))
                self.assertIn("not allowed", r["result"]["content"][0]["text"])
            finally:
                self._shutdown(proc)


if __name__ == "__main__":
    unittest.main()
