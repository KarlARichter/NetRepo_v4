import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import os
import unittest
from security import safe_join, sha256_bytes

class TestSecurity(unittest.TestCase):
    def test_safe_join_blocks_traversal(self):
        repo = "/tmp/repo"
        self.assertIsNone(safe_join(repo, "../secret.txt"))
        self.assertIsNone(safe_join(repo, "a/../b"))
        self.assertIsNone(safe_join(repo, "a\\b"))
        self.assertIsNone(safe_join(repo, "/abs.txt"))

    def test_safe_join_allows_plain_filename(self):
        repo = "/tmp/repo"
        p = safe_join(repo, "file.txt")
        self.assertTrue(p.endswith(os.sep + "file.txt"))

    def test_sha256(self):
        self.assertEqual(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

if __name__ == "__main__":
    unittest.main()
