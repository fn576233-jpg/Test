import tempfile
import unittest
from pathlib import Path

import wallet_analyzer


class WalletAnalyzerTests(unittest.TestCase):
    def test_entropy_empty(self):
        self.assertEqual(wallet_analyzer.shannon_entropy(b""), 0.0)

    def test_extract_printable_strings(self):
        data = b"\x00abc\x00wallet.dat\x00mkey\x00"
        found = wallet_analyzer.extract_printable_strings(data, min_len=4)
        self.assertIn("wallet.dat", found)
        self.assertIn("mkey", found)
        self.assertNotIn("abc", found)

    def test_detect_berkeley_magic_offset_12(self):
        prefix = b"X" * 12
        data = prefix + bytes.fromhex("00053162") + b"Y" * 20
        likely, details = wallet_analyzer.detect_berkeley_db(data)
        self.assertTrue(likely)
        self.assertIn("offset 12", details)

    def test_detect_sqlite_container(self):
        data = b"SQLite format 3\x00" + b"x" * 32
        likely, _ = wallet_analyzer.detect_berkeley_db(data)
        self.assertEqual(wallet_analyzer.detect_wallet_container(data, likely), "sqlite")

    def test_analyze_wallet_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "wallet.dat"
            path.write_bytes(b"\x00\x05\x31\x62mkeypoolname")
            result = wallet_analyzer.analyze_wallet_file(str(path), max_strings=5)

            self.assertTrue(result.likely_berkeley_db)
            self.assertEqual(result.wallet_container_type, "berkeley_db")
            self.assertEqual(result.marker_counts["mkey"], 1)
            self.assertGreaterEqual(result.marker_counts["pool"], 1)
            self.assertGreater(result.wallet_marker_total, 0)


if __name__ == "__main__":
    unittest.main()
