"""PDF ingest tests:  python -m unittest discover -s tests -v"""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pii_sanitizer as ps  # noqa: E402


class BidiTests(unittest.TestCase):
    def test_clean_bidi_removes_controls_and_cr(self):
        s = "‫שם‬: ‪123456782‬\r\nb‏"
        self.assertEqual(ps.clean_bidi(s), "שם: 123456782\nb")

    def test_visual_lines_are_fixed(self):
        cases = {
            "םש 123456782 :ז.ת": "ת.ז: 123456782 שם",
            "הדות test@example.com :ןופלט": "טלפון: test@example.com תודה",
            "םולש world 2024 םולש": "שלום world 2024 שלום",
        }
        for visual, logical in cases.items():
            self.assertTrue(ps.is_visual_order(visual), visual)
            self.assertEqual(ps.fix_visual_order(visual), logical)

    def test_logical_line_unchanged(self):
        for line in ["שלום עולם", "ת.ז: 123456782 שם", "Email: test@example.com", "מייל: test@example.com תודה", ""]:
            self.assertFalse(ps.is_visual_order(line), line)
            self.assertEqual(ps.fix_visual_order(line), line)

    def test_line_without_final_letters_unchanged(self):
        self.assertEqual(ps.fix_visual_order("הדות test"), "הדות test")

    def test_is_readable(self):
        self.assertTrue(ps.is_readable("שם: ישראל ישראלי, test@example.com"))
        self.assertFalse(ps.is_readable("�� ab"))


if __name__ == "__main__":
    unittest.main()
