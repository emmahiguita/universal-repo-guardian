import tempfile,unittest
from pathlib import Path
from guardian_security.scanner import scan_file
class Tests(unittest.TestCase):
    def test_secret(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"x.py"; p.write_text('api_key="abcdefghijk123456"\n',encoding="utf-8")
            self.assertTrue(any(x["category"]=="hardcoded_secret" for x in scan_file(p)))
if __name__=="__main__": unittest.main()
