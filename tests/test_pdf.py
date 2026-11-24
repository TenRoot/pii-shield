"""PDF ingest tests:  python -m unittest discover -s tests -v"""
import os
import shutil
import subprocess
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
        with mock.patch.object(ps, "find_tesseract", return_value=None):
            r = ps.extract_pdf_text(FIX / "he_scan.pdf", ps.OcrSettings(enabled=True))
        self.assertIn("skipped: Tesseract not installed", r.text)

    def test_ocr_off_never_looks_for_tesseract(self):
        with mock.patch.object(ps, "find_tesseract") as find:
            r = ps.extract_pdf_text(FIX / "he_scan.pdf", self.off())
        find.assert_not_called()
        self.assertIn("skipped: OCR turned off", r.text)

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


@unittest.skipIf(ps.pdfium is None, "pypdfium2 not installed")
class ImageRatioTests(unittest.TestCase):
    def ratio(self, name, setup=None):
        doc = ps.pdfium.PdfDocument(str(FIX / name))
        try:
            page = doc[0]
            if setup:
                setup(page)
            r = ps._image_ratio(page)
            page.close()
            return r
        finally:
            doc.close()

    def test_ratio_values(self):
        self.assertEqual(self.ratio("he_text.pdf"), 0.0)
        self.assertGreater(self.ratio("he_scan.pdf"), 0.8)
        self.assertGreater(self.ratio("he_image_text.pdf"), 0.8)

    def test_rotated_page_ratio_matches_unrotated(self):
        self.assertAlmostEqual(self.ratio("he_image_text_rot90.pdf"), self.ratio("he_image_text.pdf"), places=6)

    def test_shifted_crop_box_uses_crop_box_space(self):
        # Crop box (400,500)-(700,800) overlaps the image (28.3..583.6 x 36.8..755.3) by 183.6x255.3 of 300x300.
        # Clipping to [0,300]x[0,300] (the old behavior) would give 1.0.
        r = self.ratio("he_scan.pdf", lambda p: p.set_cropbox(400, 500, 700, 800))
        self.assertAlmostEqual(r, (183.625 * 255.348) / (300 * 300), places=2)

    def test_image_outside_crop_box_is_zero(self):
        r = self.ratio("he_scan.pdf", lambda p: p.set_cropbox(1000, 1000, 1100, 1100))
        self.assertEqual(r, 0.0)

    def test_image_with_text_layer_is_mostly_image(self):
        for name in ("he_image_text.pdf", "he_image_text_rot90.pdf"):
            r = ps.extract_pdf_text(FIX / name, ps.OcrSettings(enabled=False))
            page = r.pages[0]
            self.assertEqual(page.method, "partial", name)
            self.assertEqual(page.header, "--- page 1 (mostly image, image text not read: OCR turned off) ---", name)
            self.assertIn("123456782", page.text, name)
            self.assertIn("test@example.com", page.text, name)


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


FAKE_TESSERACT = """#!{python}
import sys, time
from pathlib import Path
here = Path(__file__).resolve().parent
args = sys.argv[1:]
if args[:1] == ["--version"]:
    print("tesseract 5.0.0-fake"); print(" fake build"); sys.exit(0)
if args[:1] == ["--list-langs"]:
    print("List of available languages in \\"/fake\\" ({nlangs}):")
    for l in {langs!r}: print(l)
    sys.exit(0)
calls = here / "calls.txt"
with calls.open("a") as f: f.write(args[0] + "\\n")
n = len(calls.read_text().splitlines())
time.sleep({sleep})
if {fail_on_call!r} == n:
    sys.stderr.write("boom\\nsecond line\\n"); sys.exit(1)
sys.stdout.write({text!r})
"""


def fake_tesseract(dirpath: Path, langs=("eng", "heb", "osd"), text="שם: ישראל ישראלי\nת.ז 123456782",
                   fail_on_call=None, sleep=0) -> Path:
    """Write an executable fake tesseract. --version, --list-langs, and OCR (prints text to stdout).
    fail_on_call=N: the Nth OCR call exits 1 with 'boom' on stderr. sleep=S: each OCR call sleeps S seconds
    first (--version and --list-langs never sleep). Writes each OCR image path to calls.txt in dirpath."""
    exe = dirpath / "fake-tesseract"
    exe.write_text(FAKE_TESSERACT.format(python=sys.executable, langs=tuple(langs), nlangs=len(langs),
                                         sleep=sleep, fail_on_call=fail_on_call, text=text), encoding="utf-8")
    exe.chmod(0o755)
    return exe


@unittest.skipIf(ps.pdfium is None, "pypdfium2 not installed")
@unittest.skipIf(os.name == "nt", "fake tesseract is a POSIX script")
class OcrTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.tmp, True)

    def settings(self, exe):
        return ps.OcrSettings(enabled=True, tesseract_path=str(exe), timeout=5)

    def test_find_tesseract_order(self):
        exe = fake_tesseract(self.tmp)
        self.assertEqual(ps.find_tesseract(str(exe)), exe)
        with mock.patch.object(ps.shutil, "which", return_value=None), \
             mock.patch.object(ps, "APP_DIR", self.tmp / "none"), mock.patch.object(ps.os, "name", "posix"):
            self.assertIsNone(ps.find_tesseract(""))
        bundled = self.tmp / "app" / "tesseract"; bundled.mkdir(parents=True)
        shutil.copy(exe, bundled / "tesseract")
        with mock.patch.object(ps, "APP_DIR", self.tmp / "app"):
            self.assertEqual(ps.find_tesseract(""), bundled / "tesseract")

    def test_tesseract_info(self):
        version, langs = ps.tesseract_info(fake_tesseract(self.tmp, langs=("eng", "heb")))
        self.assertEqual(version, "tesseract 5.0.0-fake")
        self.assertEqual(langs, {"eng", "heb"})

    def test_scan_page_ocr(self):
        r = ps.extract_pdf_text(FIX / "he_scan.pdf", self.settings(fake_tesseract(self.tmp)))
        self.assertEqual(r.pages[0].method, "ocr")
        self.assertIn("--- page 1 (OCR) ---\nשם: ישראל ישראלי\nת.ז 123456782", r.text)
        self.assertEqual(r.ocr_count, 1)

    def test_image_text_page_uses_ocr_text(self):
        r = ps.extract_pdf_text(FIX / "he_image_text.pdf", self.settings(fake_tesseract(self.tmp)))
        self.assertEqual(r.pages[0].method, "ocr")
        self.assertTrue(r.pages[0].header.startswith("--- page 1 (OCR"))

    def test_availability_checked_once_and_lazily(self):
        exe = fake_tesseract(self.tmp)
        with mock.patch.object(ps, "find_tesseract", wraps=ps.find_tesseract) as find, \
             mock.patch.object(ps, "tesseract_info", wraps=ps.tesseract_info) as info:
            ps.extract_pdf_text(FIX / "he_text.pdf", self.settings(exe))
            find.assert_not_called()
            doc = self.tmp / "two_scans.pdf"
            subprocess.run(["qpdf", "--empty", "--pages", str(FIX / "he_scan.pdf"), "1", str(FIX / "he_scan.pdf"), "1",
                            "--", str(doc)], check=True)
            ps.extract_pdf_text(doc, self.settings(exe))
        self.assertEqual((find.call_count, info.call_count), (1, 1))

    def test_missing_hebrew_runs_english_only(self):
        r = ps.extract_pdf_text(FIX / "he_scan.pdf", self.settings(fake_tesseract(self.tmp, langs=("eng",))))
        self.assertIn("--- page 1 (OCR, English only: Hebrew language data missing) ---", r.text)

    def test_no_language_data_skips(self):
        r = ps.extract_pdf_text(FIX / "he_scan.pdf", self.settings(fake_tesseract(self.tmp, langs=("osd",))))
        self.assertIn("--- page 1 (scanned, skipped: no OCR language data) ---", r.text)

    def test_not_installed(self):
        with mock.patch.object(ps, "find_tesseract", return_value=None):
            r = ps.extract_pdf_text(FIX / "he_scan.pdf", ps.OcrSettings())
        self.assertIn("--- page 1 (scanned, skipped: Tesseract not installed) ---", r.text)

    @unittest.skipUnless(shutil.which("qpdf"), "qpdf needed")
    def test_ocr_failure_on_one_page_continues(self):
        doc = self.tmp / "two_scans.pdf"
        subprocess.run(["qpdf", "--empty", "--pages", str(FIX / "he_scan.pdf"), "1", str(FIX / "he_scan.pdf"), "1",
                        "--", str(doc)], check=True)
        r = ps.extract_pdf_text(doc, self.settings(fake_tesseract(self.tmp, fail_on_call=1)))
        self.assertEqual([p.method for p in r.pages], ["skipped", "ocr"])
        self.assertIn("--- page 1 (scanned, skipped: OCR failed: boom) ---", r.text)

    def test_timeout(self):
        s = self.settings(fake_tesseract(self.tmp, sleep=3)); s.timeout = 1
        r = ps.extract_pdf_text(FIX / "he_scan.pdf", s)
        self.assertIn("--- page 1 (scanned, skipped: OCR timed out) ---", r.text)

    def test_cancel_stops_between_pages_and_cleans_up(self):
        calls = []
        with mock.patch.object(ps.tempfile, "tempdir", str(self.tmp)):
            r = ps.extract_pdf_text(FIX / "he_mixed.pdf", self.settings(fake_tesseract(self.tmp)),
                                    cancel=lambda: (calls.append(1), len(calls) > 2)[1])
        self.assertEqual(len(r.pages), 2)
        self.assertEqual([p for p in self.tmp.rglob("*") if p.suffix in (".pgm", ".png")], [])

    def test_temp_images_removed_after_ocr(self):
        exe = fake_tesseract(self.tmp)
        ps.extract_pdf_text(FIX / "he_scan.pdf", self.settings(exe))
        used = [Path(l) for l in (self.tmp / "calls.txt").read_text().splitlines()]
        self.assertTrue(used)
        self.assertFalse(any(p.exists() for p in used))


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
