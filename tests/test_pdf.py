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

    def test_is_readable_other_scripts(self):
        # Invented placeholder text, no real names.
        russian = "Иванов Иван, паспорт 123456782, г. Пример"
        arabic = "هذا نص تجريبي للاختبار فقط، رقم 123456782"
        self.assertTrue(ps.is_readable(russian))
        self.assertTrue(ps.is_readable(arabic))
        self.assertEqual(ps.classify_page(russian, 0.0), "text")
        self.assertEqual(ps.classify_page(arabic, 0.0), "text")

    def test_is_readable_rejects_private_use_and_replacement(self):
        self.assertFalse(ps.is_readable("\ue001\ue002\ue003 ab"))
        self.assertFalse(ps.is_readable("\ufffd\ufffd\ufffd ab"))
        self.assertTrue(ps.is_readable("\u2022 \u20aa 100 \u00a9"))


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
    out = sys.stderr if {langs_to_stderr!r} else sys.stdout
    print("List of available languages in \\"/fake\\" ({nlangs}):", file=out)
    for l in {langs!r}: print(l, file=out)
    sys.exit(0)
calls = here / "calls.txt"
data = sys.stdin.buffer.read() if args[0] == "stdin" else b""
with calls.open("a") as f: f.write(args[0] + " " + str(len(data)) + " " + data.split(b"\\n", 1)[0].decode("ascii", "replace") + "\\n")
n = len(calls.read_text().splitlines())
time.sleep({sleep})
if {fail_on_call!r} == n:
    sys.stderr.write("boom\\nsecond line\\n"); sys.exit(1)
sys.stdout.write({text!r})
"""


def fake_tesseract(dirpath: Path, langs=("eng", "heb", "osd"), text="שם: ישראל ישראלי\nת.ז 123456782",
                   fail_on_call=None, sleep=0, langs_to_stderr=False) -> Path:
    """Write an executable fake tesseract. --version, --list-langs, and OCR (prints text to stdout).
    fail_on_call=N: the Nth OCR call exits 1 with 'boom' on stderr. sleep=S: each OCR call sleeps S seconds
    first (--version and --list-langs never sleep). Reads the image from stdin and writes one line per OCR call
    to calls.txt in dirpath: "stdin <byte count> <first PGM header line>". langs_to_stderr=True prints the
    --list-langs list to stderr, as old Tesseract versions do."""
    exe = dirpath / "fake-tesseract"
    exe.write_text(FAKE_TESSERACT.format(python=sys.executable, langs=tuple(langs), nlangs=len(langs),
                                         sleep=sleep, fail_on_call=fail_on_call, text=text,
                                         langs_to_stderr=langs_to_stderr), encoding="utf-8")
    exe.chmod(0o755)
    return exe


def two_scan_pdf(dirpath: Path) -> Path:
    doc = dirpath / "two_scans.pdf"
    subprocess.run(["qpdf", "--empty", "--pages", str(FIX / "he_scan.pdf"), "1", str(FIX / "he_scan.pdf"), "1",
                    "--", str(doc)], check=True)
    return doc


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

    def test_tesseract_info_reads_langs_from_stderr(self):
        _v, langs = ps.tesseract_info(fake_tesseract(self.tmp, langs=("eng", "heb"), langs_to_stderr=True))
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

    @unittest.skipUnless(shutil.which("qpdf"), "qpdf needed")
    def test_availability_checked_once_and_lazily(self):
        exe = fake_tesseract(self.tmp)
        with mock.patch.object(ps, "find_tesseract", wraps=ps.find_tesseract) as find, \
             mock.patch.object(ps, "tesseract_info", wraps=ps.tesseract_info) as info:
            ps.extract_pdf_text(FIX / "he_text.pdf", self.settings(exe))
            find.assert_not_called()
            doc = two_scan_pdf(self.tmp)
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
        r = ps.extract_pdf_text(two_scan_pdf(self.tmp), self.settings(fake_tesseract(self.tmp, fail_on_call=1)))
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

    def test_image_goes_to_tesseract_on_stdin(self):
        ps.extract_pdf_text(FIX / "he_scan.pdf", self.settings(fake_tesseract(self.tmp)))
        lines = (self.tmp / "calls.txt").read_text().splitlines()
        self.assertEqual(len(lines), 1)
        arg, size, magic, w, h, maxval = lines[0].split()
        self.assertEqual((arg, magic, maxval), ("stdin", "P5", "255"))
        self.assertEqual(int(size), len(f"P5 {w} {h} 255\n") + int(w) * int(h))

    def test_no_image_file_written_during_ocr(self):
        with mock.patch.object(ps.tempfile, "tempdir", str(self.tmp)):
            ps.extract_pdf_text(FIX / "he_scan.pdf", self.settings(fake_tesseract(self.tmp)))
        self.assertEqual([p for p in self.tmp.rglob("*") if p.suffix in (".pgm", ".png")], [])
        self.assertTrue((self.tmp / "calls.txt").exists())

    def test_blank_ocr_result_gives_reason_scanned(self):
        r = ps.extract_pdf_text(FIX / "he_scan.pdf", self.settings(fake_tesseract(self.tmp, text="  \n\n")))
        self.assertEqual(r.pages[0].method, "skipped")
        self.assertEqual(r.pages[0].header, "--- page 1 (scanned, skipped: OCR found no text) ---")

    def test_blank_ocr_result_gives_reason_mostly_image(self):
        r = ps.extract_pdf_text(FIX / "he_image_text.pdf", self.settings(fake_tesseract(self.tmp, text=" \n")))
        self.assertIn("(mostly image, image text not read: OCR found no text) ---", r.pages[0].header)


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


def _qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = ps.QtWidgets.QApplication.instance() or ps.QtWidgets.QApplication([])
    # Earlier tests in the run leave queued signals that point at deleted windows. Drop them
    # before these tests call processEvents, or they run against dead widgets and crash.
    ps.QtCore.QThreadPool.globalInstance().waitForDone(10000)
    ps.QtCore.QCoreApplication.removePostedEvents(None)
    return app


@unittest.skipUnless(ps.QT_OK, "PyQt6 not installed")
@unittest.skipIf(ps.pdfium is None, "pypdfium2 not installed")
class PdfLoadGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = _qapp()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        cfg = ps.AppConfig(self.tmp / "config.json")
        cfg.data["pdf"]["ocr_enabled"] = False
        with mock.patch.object(ps.MainWindow, "_start_engine"):
            self.win = ps.MainWindow(cfg)
        self.addCleanup(self.win.deleteLater)

    def wait(self):
        ps.QtCore.QThreadPool.globalInstance().waitForDone(10000)
        self.app.processEvents()

    def test_text_pdf_fills_input(self):
        self.win.load_path(FIX / "he_text.pdf"); self.wait()
        self.assertIn("123456782", self.win.input.toPlainText())
        self.assertTrue(self.win.statusBar().currentMessage().startswith("PDF loaded: 1 page(s), 0 by OCR, 0 skipped"))
        self.assertTrue(self.win.btn_load.isEnabled())
        self.assertIsNone(self.win._pdf_task)

    def test_all_pages_skipped_warns(self):
        with mock.patch.object(ps.QtWidgets.QMessageBox, "warning") as warn:
            self.win.load_path(FIX / "he_scan.pdf"); self.wait()
        self.assertIn("--- page 1 (scanned, skipped: OCR turned off) ---", self.win.input.toPlainText())
        warn.assert_called_once()
        self.assertEqual(warn.call_args.args[1], "Load PDF")
        self.assertEqual(warn.call_args.args[2], "No text was found in this PDF.\nPage 1: OCR turned off")

    def test_some_pages_skipped_no_box(self):
        with mock.patch.object(ps.QtWidgets.QMessageBox, "warning") as warn:
            self.win.load_path(FIX / "he_mixed.pdf"); self.wait()
        warn.assert_not_called()
        self.assertIn("1 skipped", self.win.statusBar().currentMessage())

    def test_load_error_keeps_input(self):
        self.win.input.setPlainText("old text")
        with mock.patch.object(ps.QtWidgets.QMessageBox, "warning") as warn:
            self.win.load_path(FIX / "he_password.pdf"); self.wait()
        self.assertEqual(self.win.input.toPlainText(), "old text")
        self.assertEqual(warn.call_args.args[2], "This PDF is password protected. PII Shield cannot open it.")
        self.assertTrue(self.win.btn_load.isEnabled())
        self.assertIsNone(self.win._pdf_task)

    def test_result_after_close_is_ignored(self):
        self.win.input.setPlainText("old text")
        self.win._closing = True
        self.win._on_pdf_done(ps.PdfExtraction(pages=[], text="new"))
        self.assertEqual(self.win.input.toPlainText(), "old text")
        with mock.patch.object(ps.QtWidgets.QMessageBox, "warning") as warn:
            self.win._on_pdf_error("boom")
        warn.assert_not_called()

    def test_text_file_still_loads(self):
        f = self.tmp / "a.txt"
        f.write_text("host SRV-DC01", "utf-8")
        self.win.load_path(f)
        self.assertEqual(self.win.input.toPlainText(), "host SRV-DC01")

    def test_uppercase_extension_loads_pdf(self):
        f = self.tmp / "A.PDF"
        shutil.copy(FIX / "he_text.pdf", f)
        self.win.load_path(f); self.wait()
        self.assertIn("123456782", self.win.input.toPlainText())

    def test_second_load_while_running_is_refused(self):
        self.win._pdf_task = object()
        with mock.patch.object(ps.QtCore.QThreadPool.globalInstance(), "start") as start:
            self.win.load_path(FIX / "he_text.pdf")
        start.assert_not_called()
        self.assertEqual(self.win.statusBar().currentMessage(), "A PDF is already loading")
        self.win._pdf_task = None

    def test_close_sets_flags_only_when_accepted(self):
        self.win.vault.commit("SRV-DC01", "<HOSTNAME_1>", "HOSTNAME")
        self.assertEqual(len(self.win.vault), 1)
        ev = ps.QtGui.QCloseEvent()
        with mock.patch.object(ps.QtWidgets.QMessageBox, "question",
                               return_value=ps.QtWidgets.QMessageBox.StandardButton.No):
            self.win.closeEvent(ev)
        self.assertFalse(ev.isAccepted())
        self.assertFalse(self.win._closing)
        self.assertFalse(self.win._pdf_cancel)
        ev2 = ps.QtGui.QCloseEvent()
        with mock.patch.object(ps.QtWidgets.QMessageBox, "question",
                               return_value=ps.QtWidgets.QMessageBox.StandardButton.Yes):
            self.win.closeEvent(ev2)
        self.assertTrue(ev2.isAccepted())
        self.assertTrue(self.win._closing)
        self.assertTrue(self.win._pdf_cancel)


@unittest.skipUnless(ps.QT_OK, "PyQt6 not installed")
class PdfSettingsGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = _qapp()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cfg = ps.AppConfig(self.tmp / "config.json")

    def dialog(self):
        dlg = ps.SettingsDialog(None, self.cfg, mock.Mock(builtin_supported=[]))
        self.addCleanup(dlg.deleteLater)
        return dlg

    def test_settings_saves_pdf_options(self):
        with mock.patch.object(ps, "find_tesseract", return_value=None):
            dlg = self.dialog()
        dlg.chk_ocr.setChecked(False)
        dlg.ed_tesseract.setText("/opt/x/tesseract")
        dlg._accept()
        self.assertFalse(self.cfg.data["pdf"]["ocr_enabled"])
        self.assertEqual(self.cfg.data["pdf"]["tesseract_path"], "/opt/x/tesseract")

    def test_label_when_not_found(self):
        with mock.patch.object(ps, "find_tesseract", return_value=None):
            dlg = self.dialog()
        self.assertEqual(dlg.lbl_tesseract.text(), "Tesseract not found")

    def test_label_shows_version_and_languages(self):
        with mock.patch.object(ps, "find_tesseract", return_value=Path("/opt/x/tesseract")), \
                mock.patch.object(ps, "tesseract_info", return_value=("tesseract 5.3.0", {"eng", "osd"})):
            dlg = self.dialog()
            self.assertEqual(dlg.lbl_tesseract.text(), "Tesseract 5.3.0: Hebrew no, English yes")

    def test_label_when_info_raises(self):
        with mock.patch.object(ps, "find_tesseract", return_value=Path("/opt/x/tesseract")), \
                mock.patch.object(ps, "tesseract_info", side_effect=RuntimeError("x")):
            dlg = self.dialog()
        self.assertEqual(dlg.lbl_tesseract.text(), "Tesseract not found")

    def test_label_updates_on_path_change(self):
        with mock.patch.object(ps, "find_tesseract", return_value=None):
            dlg = self.dialog()
        with mock.patch.object(ps, "find_tesseract", return_value=Path("/opt/x/tesseract")), \
                mock.patch.object(ps, "tesseract_info", return_value=("5.3.0", {"heb", "eng"})):
            dlg.ed_tesseract.setText("/opt/x/tesseract")
            dlg.ed_tesseract.editingFinished.emit()
        self.assertEqual(dlg.lbl_tesseract.text(), "Tesseract 5.3.0: Hebrew yes, English yes")

    def test_typing_does_not_probe_until_editing_finished(self):
        with mock.patch.object(ps, "find_tesseract", return_value=None):
            dlg = self.dialog()
        with mock.patch.object(ps, "find_tesseract", return_value=Path("/opt/x/tesseract")) as find, \
                mock.patch.object(ps, "tesseract_info", return_value=("tesseract 5.3.0", {"heb"})) as info:
            dlg.ed_tesseract.setText("/opt/x/tess")
            dlg.ed_tesseract.setText("/opt/x/tesseract")
            find.assert_not_called()
            info.assert_not_called()
            dlg.ed_tesseract.editingFinished.emit()
            info.assert_called_once()
        self.assertEqual(dlg.lbl_tesseract.text(), "Tesseract 5.3.0: Hebrew yes, English no")

    def test_label_when_file_cannot_run(self):
        bad = self.tmp / "not_a_program.txt"
        bad.write_text("hello")
        self.cfg.data["pdf"]["tesseract_path"] = str(bad)
        dlg = self.dialog()
        self.assertEqual(dlg.lbl_tesseract.text(), "Tesseract not found")


if __name__ == "__main__":
    unittest.main()
