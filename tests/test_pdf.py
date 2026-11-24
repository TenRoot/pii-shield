"""PDF ingest tests:  python -m unittest discover -s tests -v"""
import shutil
import sys
import tempfile
import unittest
from unittest import mock
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


FIX = HERE / "fixtures"


@unittest.skipIf(ps.pdfium is None, "pypdfium2 not installed")
class ExtractTextTests(unittest.TestCase):
    def off(self):
        return ps.OcrSettings(enabled=False)

    def test_text_pdf_values_whole_and_logical(self):
        r = ps.extract_pdf_text(FIX / "he_text.pdf", self.off())
        self.assertEqual([p.method for p in r.pages], ["text"])
        self.assertTrue(r.text.startswith("--- page 1 ---\n"))
        for value in ["ישראל ישראלי", "123456782", "test@example.com", "רחוב הרצל 12", "שלום world 2024 שלום"]:
            self.assertIn(value, r.text)
        self.assertNotIn("\r", r.text)
        self.assertFalse(any(c in r.text for c in ps.BIDI_CONTROLS))

    def test_scan_pdf_skipped_with_reason(self):
        r = ps.extract_pdf_text(FIX / "he_scan.pdf", self.off())
        self.assertEqual(r.pages[0].method, "skipped")
        self.assertIn("--- page 1 (scanned, skipped: OCR turned off) ---", r.text)
        self.assertTrue(r.all_skipped)

    def test_scan_pdf_reason_when_ocr_on_but_missing(self):
        r = ps.extract_pdf_text(FIX / "he_scan.pdf", ps.OcrSettings(enabled=True))
        self.assertIn("skipped: Tesseract not installed", r.text)

    def test_mixed_pdf_keeps_page_order(self):
        r = ps.extract_pdf_text(FIX / "he_mixed.pdf", self.off())
        self.assertEqual([p.method for p in r.pages], ["text", "skipped", "text"])
        self.assertLess(r.text.index("--- page 1 ---"), r.text.index("--- page 2 (scanned"))
        self.assertLess(r.text.index("--- page 2 (scanned"), r.text.index("--- page 3 ---"))
        self.assertEqual(r.skipped_count, 1)
        self.assertFalse(r.all_skipped)

    def test_password_pdf_raises_pdf_error(self):
        with self.assertRaises(ps.PdfError) as cm:
            ps.extract_pdf_text(FIX / "he_password.pdf", self.off())
        self.assertEqual(str(cm.exception), "This PDF is password protected. PII Shield cannot open it.")

    def test_damaged_pdf_raises_pdf_error(self):
        bad = Path(tempfile.mkdtemp()) / "bad.pdf"
        self.addCleanup(shutil.rmtree, bad.parent, True)
        bad.write_bytes(b"%PDF-1.4 junk")
        with self.assertRaises(ps.PdfError):
            ps.extract_pdf_text(bad, self.off())

    def test_missing_pypdfium2_raises(self):
        with mock.patch.object(ps, "pdfium", None):
            with self.assertRaises(ps.PdfError) as cm:
                ps.extract_pdf_text(FIX / "he_text.pdf", self.off())
        self.assertEqual(str(cm.exception), "PDF support needs the pypdfium2 package.")

    def test_progress_reports_each_page(self):
        msgs = []
        ps.extract_pdf_text(FIX / "he_mixed.pdf", self.off(), progress=msgs.append)
        self.assertEqual(len([m for m in msgs if m.startswith("PDF: page ")]), 3)
        self.assertIn("PDF: page 2 of 3", msgs[1])

    def test_cancel_returns_pages_done(self):
        calls = []

        def cancel():
            calls.append(1)
            return len(calls) > 1
        r = ps.extract_pdf_text(FIX / "he_mixed.pdf", self.off(), cancel=cancel)
        self.assertEqual(len(r.pages), 1)


class ClassifyTests(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(ps.classify_page("short", 0.0), "scanned")
        self.assertEqual(ps.classify_page("x" * 40, 0.8), "mostly_image")
        self.assertEqual(ps.classify_page("\ue001" * 40, 0.0), "unreadable")
        self.assertEqual(ps.classify_page("שם: ישראל ישראלי, ת.ז 123456782", 0.1), "text")

    def test_partial_header_when_mostly_image_and_no_ocr(self):
        page = ps._finish_page(1, "x" * 40 + " page footer", "mostly_image", ocr_text=None, reason="Tesseract not installed")
        self.assertEqual(page.method, "partial")
        self.assertEqual(page.header, "--- page 1 (mostly image, image text not read: Tesseract not installed) ---")
        self.assertIn("page footer", page.text)

    def test_finish_page_ocr_headers(self):
        p = ps._finish_page(2, "", "scanned", ocr_text="hello", reason="")
        self.assertEqual((p.method, p.header, p.text), ("ocr", "--- page 2 (OCR) ---", "hello"))
        p = ps._finish_page(2, "", "scanned", ocr_text="hello", reason="", ocr_note="English only: Hebrew language data missing")
        self.assertEqual(p.header, "--- page 2 (OCR, English only: Hebrew language data missing) ---")

    def test_finish_page_unreadable_and_empty_partial(self):
        p = ps._finish_page(3, "\ue001" * 30, "unreadable", None, "OCR turned off")
        self.assertEqual(p.method, "partial")
        self.assertEqual(p.header, "--- page 3 (unreadable text, not read: OCR turned off) ---")
        p = ps._finish_page(3, "  ", "mostly_image", None, "OCR turned off")
        self.assertEqual(p.method, "skipped")


class OcrSettingsTests(unittest.TestCase):
    def test_defaults_and_config(self):
        d = ps.OcrSettings()
        self.assertEqual((d.enabled, d.tesseract_path, d.languages, d.dpi, d.timeout), (True, "", "heb+eng", 300, 120))
        cfg = ps.AppConfig(Path(tempfile.mkdtemp()) / "c.json")
        self.addCleanup(shutil.rmtree, cfg.path.parent, True)
        self.assertEqual(ps.OcrSettings.from_config(cfg), d)
        cfg.data["pdf"].update(ocr_enabled=False, ocr_dpi=200)
        s = ps.OcrSettings.from_config(cfg)
        self.assertFalse(s.enabled)
        self.assertEqual(s.dpi, 200)


if __name__ == "__main__":
    unittest.main()
