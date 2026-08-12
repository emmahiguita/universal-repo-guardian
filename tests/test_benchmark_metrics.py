import unittest

from nano_repo_guardian.metrics import detection_metrics


class Tests(unittest.TestCase):
    def test_metrics(self):
        m = detection_metrics({"a", "b"}, {"a", "c"})
        self.assertEqual(m["tp"], 1)
        self.assertEqual(m["fp"], 1)
        self.assertEqual(m["fn"], 1)


if __name__ == "__main__":
    unittest.main()
