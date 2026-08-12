import unittest

from guardian_benchmark.metrics import metrics


class Tests(unittest.TestCase):
    def test_metrics(self):
        m = metrics({"a", "b"}, {"a", "c"})
        self.assertEqual(m["tp"], 1)
        self.assertEqual(m["fp"], 1)
        self.assertEqual(m["fn"], 1)


if __name__ == "__main__":
    unittest.main()
