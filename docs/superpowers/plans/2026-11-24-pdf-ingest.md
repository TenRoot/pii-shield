# PDF Ingest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** "Load file" accepts PDFs. The app extracts the text (pypdfium2), runs local Tesseract OCR (`heb+eng`) on scanned pages when Tesseract is installed, and puts the text in the input box for the existing masking flow.

**Architecture:** A Qt-free extraction layer in `pii_sanitizer.py` (bidi cleanup, visual-order fallback, page classification, Tesseract runner, `extract_pdf_text`). The GUI runs `extract_pdf_text` in the existing `Task` QRunnable and shows per-page results in the text headers, the Log tab and the status bar. A "PDF" group in the Settings dialog edits the new `pdf` config section.

**Tech Stack:** Python 3, PyQt6, pypdfium2 5.15.2 (Apache-2.0/BSD), Tesseract CLI (optional, external), unittest.

**Spec:** `docs/superpowers/specs/2026-11-24-pdf-ingest-design.md`

## Global Constraints

- All new code goes in `pii_sanitizer.py`. Tests go in `tests/test_pdf.py` (new file, same header pattern as `tests/test_core.py`).
- Run tests with `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest discover -s tests`. Never with the system python (it has no PyQt6 or Presidio).
- No network calls in extraction or OCR.
- The repo is public. Fixtures and tests use invented values only: `ישראל ישראלי`, `test@example.com`, ID `123456782`, `contoso`, `example`. Never a real person's name.
- pypdfium2 is optional at import time: `try: import pypdfium2 as pdfium` / `except ImportError: pdfium = None`. Text-file loading must work without it.
- Tesseract is called by `subprocess.run([...], capture_output=True, timeout=..., shell=False)`; on Windows add `creationflags=subprocess.CREATE_NO_WINDOW`. No `pytesseract`.
- Temp page images are deleted in a `finally` block. No temp file may remain after a run, also after an error or a cancel.
- Bidi control characters to remove: U+200E, U+200F, U+202A–U+202E, U+2066–U+2069.
- Page header format, exact:
  - text page: `--- page N ---`
  - OCR page: `--- page N (OCR) ---`
  - OCR with a missing language: `--- page N (OCR, English only: Hebrew language data missing) ---` (or `Hebrew only: English language data missing`)
  - skipped scanned page: `--- page N (scanned, skipped: <reason>) ---`
  - little-text page (fewer than 20 characters) with some text layer and no OCR text: `--- page N (little text, image text not read: <reason>) ---` (the text layer is kept)
  - any header above, when the page's form fields or notes cannot be read: ` (form fields or notes not read)` goes before the closing ` ---`. Read values go under the page text after a `[form fields and notes]` line, one per line.
  - mostly-image or unreadable page kept as text layer: `--- page N (mostly image, image text not read: <reason>) ---` / `--- page N (unreadable text, not read: <reason>) ---`
- Reasons, exact strings: `Tesseract not installed`, `OCR turned off`, `Hebrew language data missing`, `English language data missing`, `no OCR language data`, `OCR failed`, `OCR timed out`, `OCR found no text`. The OCR failure detail (OSError text or the first stderr line) goes to the Log tab only, never into the header.
- Classification thresholds: fewer than `20` non-space characters → scanned; image area ≥ `0.5` of page area → mostly image; fewer than `0.5` of non-space characters readable → unreadable.
- Config defaults (exact): `"pdf": {"ocr_enabled": True, "tesseract_path": "", "ocr_languages": "heb+eng", "ocr_dpi": 300, "ocr_timeout": 120}`.
- Error messages (exact): `PDF support needs the pypdfium2 package.` / `This PDF is password protected. PII Shield cannot open it.`
- Write user-facing text and docs in ASD-STE100 style: short sentences, active voice.

## Review Focus

1. **A PDF where every page is skipped** (scanned PDF, no Tesseract). The user expects the header lines in the box and one warning box that says why, not an empty box with no message. → Task 4 test `test_all_pages_skipped_warns`.
2. **A line that is already in logical order with Hebrew final letters at word ends** (for example `שלום עולם`). The visual-order fallback must not touch it. → Task 1 test `test_logical_line_unchanged`.
3. **OCR fails on one page in the middle of a document.** The other pages still come through and the failed page has a header with the reason. → Task 3 test `test_ocr_failure_on_one_page_continues`.
4. **The window closes during a long OCR run.** No crash, no write into a deleted widget, temp files removed. → Task 4 test `test_result_after_close_is_ignored` and Task 3 test `test_cancel_stops_between_pages_and_cleans_up`.
5. **A password-protected or damaged PDF.** A clear message box, the input box keeps its old text. → Task 2 tests `test_password_pdf_raises_pdf_error`, `test_damaged_pdf_raises_pdf_error`; Task 4 test `test_load_error_keeps_input`.

---

### Task 1: Dependency, bidi cleanup and visual-order fallback

**Files:**
- Modify: `pii_sanitizer.py` (imports near the other optional imports; new helpers in a new `# ---- PDF ingest ----` section after the rules code, before the Qt section)
- Modify: `requirements.txt` (add `pypdfium2>=5.0`), `requirements-build.txt` (add `pypdfium2==5.15.2`)
- Create: `tests/test_pdf.py`

**Interfaces:**
- Produces:
  - `pdfium` module or `None`
  - `BIDI_CONTROLS: str` (the characters from Global Constraints)
  - `clean_bidi(text: str) -> str` — removes bidi controls, turns `\r\n` and `\r` into `\n`
  - `is_visual_order(line: str) -> bool`
  - `fix_visual_order(line: str) -> str` — returns the line unchanged when `is_visual_order` is False
  - `is_readable(text: str) -> bool`

- [ ] **Step 1: Install pypdfium2 into `.venv`**

Run: `.venv/bin/pip install pypdfium2==5.15.2`
Expected: `Successfully installed pypdfium2-5.15.2` (or "already satisfied").

- [ ] **Step 2: Write the failing tests in `tests/test_pdf.py`**

```python
class BidiTests(unittest.TestCase):
    def test_clean_bidi_removes_controls_and_cr(self):
        s = "\u202bשם\u202c: \u202a123456782\u202c\r\nb\u200f"
        self.assertEqual(ps.clean_bidi(s), "שם: 123456782\nb")

    def test_visual_lines_are_fixed(self):
        cases = {
            "םש 123456782 :ז.ת": "ת.ז: 123456782 שם",
            "הדות test@example.com :ליימ": "מייל: test@example.com תודה",
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
        self.assertFalse(ps.is_readable("\ue001\ue002\ue003\ufffd\ufffd ab"))
```

- [ ] **Step 3: Run the tests to see them fail**

Run: `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest tests.test_pdf -v`
Expected: FAIL with `AttributeError: module 'pii_sanitizer' has no attribute 'clean_bidi'`.

- [ ] **Step 4: Implement the helpers**

- `is_visual_order`: count Hebrew words (maximal runs of U+05D0–U+05EA) that **start** with a final letter (ך ם ן ף ץ) and words that **end** with one. True only when the start count is greater than the end count.
- `fix_visual_order`: split into runs with this regex, then reverse the run order and reverse the characters inside Hebrew runs only:

```python
_HE = "\u05d0-\u05ea"
_RUN_RE = re.compile(rf"[A-Za-z0-9](?:[^{_HE}]*[A-Za-z0-9])?|[{_HE}]+|.", re.S)
```

- `is_readable`: True when the text has no non-space characters, or when at least `0.5` of the non-space characters are Hebrew letters, ASCII letters or digits, or punctuation from `string.punctuation` plus `־׳״–—’“”•`.

- [ ] **Step 5: Run the tests to see them pass**

Run: `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest tests.test_pdf -v`
Expected: all `BidiTests` pass.

- [ ] **Step 6: Commit**

```bash
git add pii_sanitizer.py requirements.txt requirements-build.txt tests/test_pdf.py
git commit -m "PDF ingest: pypdfium2 dependency, bidi cleanup and visual-order fallback"
```

---

### Task 2: Text extraction and page classification

**Files:**
- Modify: `pii_sanitizer.py` (PDF ingest section)
- Create: `tests/fixtures/make_pdf_fixtures.sh`, `tests/fixtures/he_text.pdf`, `tests/fixtures/he_scan.pdf`, `tests/fixtures/he_mixed.pdf`, `tests/fixtures/he_password.pdf`
- Test: `tests/test_pdf.py`

**Interfaces:**
- Consumes: `clean_bidi`, `fix_visual_order`, `is_readable` (Task 1).
- Produces:
  - `class PdfError(Exception)` — add it to the `isinstance` tuple in `Task.run`, so its message reaches the user without the class name.
  - `@dataclass OcrSettings: enabled: bool = True; tesseract_path: str = ""; languages: str = "heb+eng"; dpi: int = 300; timeout: int = 120` and `OcrSettings.from_config(cfg: AppConfig) -> OcrSettings` (reads `cfg.data["pdf"]`, falls back to the defaults)
  - `@dataclass PdfPage: number: int; method: str  # "text" | "ocr" | "skipped" | "partial"; reason: str = ""; text: str = ""; header: str = ""`
  - `@dataclass PdfExtraction: pages: List[PdfPage]; text: str` with properties `ocr_count`, `skipped_count`, `all_skipped` (True when no page has non-space text)
  - `classify_page(text: str, image_ratio: float) -> str` — returns `"text"`, `"scanned"`, `"mostly_image"` or `"unreadable"`, in that priority: scanned, mostly_image, unreadable, text
  - `extract_pdf_text(path: Path, ocr: OcrSettings, progress: Optional[Callable[[str], None]] = None, cancel: Optional[Callable[[], bool]] = None) -> PdfExtraction`
  - Add `"pdf"` defaults to `DEFAULT_CONFIG` (values in Global Constraints).

In this task, OCR is not built yet. A page that needs OCR gets the reason `Tesseract not installed` when `ocr.enabled` is True, and `OCR turned off` when it is False. Task 3 replaces that branch.

- [ ] **Step 1: Write `tests/fixtures/make_pdf_fixtures.sh` and run it**

The script writes the four PDFs next to itself, with LibreOffice, `pdftoppm` and `qpdf`. Values to use:
- `he_text.pdf`: from a UTF-8 text file with these 4 lines:
  `שם: ישראל ישראלי, ת.ז 123456782` / `כתובת: רחוב הרצל 12 תל אביב` / `Email: test@example.com` / `Mixed: שלום world 2024 שלום`
  (`soffice --headless --convert-to pdf`)
- `he_scan.pdf`: page 1 of `he_text.pdf` rendered with `pdftoppm -r 100 -png`, then converted to PDF with `soffice --headless --convert-to pdf` (image only, no text layer).
- `he_mixed.pdf`: 3 pages: page 1 and 3 text (from a 2-page text source split by a form feed, or by joining with `qpdf --empty --pages`), page 2 the scan page. Use `qpdf --empty --pages he_text.pdf 1 he_scan.pdf 1 he_text.pdf 1 -- he_mixed.pdf`.
- `he_password.pdf`: `qpdf --encrypt user owner 256 -- he_text.pdf he_password.pdf`.

Commit the script and the four PDFs. Each PDF must be under 200 KB.

- [ ] **Step 2: Write the failing tests**

```python
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
```

`_finish_page(number: int, layer_text: str, kind: str, ocr_text: Optional[str], reason: str, ocr_note: str = "") -> PdfPage` is the internal helper that builds a `PdfPage` with the right `method` and `header` from the classification and the OCR result. Task 3 uses it with OCR text.

- [ ] **Step 3: Run the tests to see them fail**

Run: `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest tests.test_pdf -v`
Expected: FAIL with `AttributeError` on `OcrSettings` / `extract_pdf_text`.

- [ ] **Step 4: Implement**

- Open with `pdfium.PdfDocument(str(path))`. Catch `pdfium.PdfiumError`: when `exc.err_code == pdfium.raw.FPDF_ERR_PASSWORD`, raise `PdfError` with the password message; otherwise raise `PdfError(f"Cannot open this PDF: {exc}")`. Close the document in `finally`.
- Page text: `page.get_textpage().get_text_bounded()`, then `clean_bidi`, then `fix_visual_order` on each line.
- Image ratio: sum of `obj.get_bounds()` areas for `page.get_objects(filter=[pdfium.raw.FPDF_PAGEOBJ_IMAGE], max_depth=5)`, clipped to the page box, divided by the page area from `page.get_size()`; cap at `1.0`.
- `progress(f"PDF: page {n} of {total}")` before each page; append ` (OCR)` when the page goes to OCR.
- Check `cancel()` before each page. When it returns True, stop and return the pages done so far (no exception).
- Join pages as `header + "\n" + text`, pages separated by a blank line.
- Log one line per page with `log.info` (the Log tab shows it), for example `PDF page 2: skipped (OCR turned off)`.

- [ ] **Step 5: Run the tests to see them pass**

Run: `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest tests.test_pdf -v`
Expected: all tests in `tests/test_pdf.py` pass.

- [ ] **Step 6: Commit**

```bash
git add pii_sanitizer.py tests/test_pdf.py tests/fixtures
git commit -m "PDF ingest: text extraction, page classification and PDF fixtures"
```

---

### Task 3: Tesseract OCR

**Files:**
- Modify: `pii_sanitizer.py` (PDF ingest section)
- Test: `tests/test_pdf.py`

**Interfaces:**
- Consumes: `OcrSettings`, `_finish_page`, `extract_pdf_text` (Task 2), `APP_DIR`.
- Produces:
  - `find_tesseract(configured: str = "") -> Optional[Path]` — order: configured path (if it is a file), `APP_DIR / "tesseract" / ("tesseract.exe" if os.name == "nt" else "tesseract")`, `shutil.which("tesseract")`, and on Windows `Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe")`.
  - `tesseract_info(exe: Path) -> Tuple[str, Set[str]]` — version (first line of `--version`) and the language set from `--list-langs` (skip the header line).
  - `ocr_image(exe: Path, image: Path, languages: str, timeout: int) -> str` — runs `[exe, image, "stdout", "-l", languages]`, returns `clean_bidi(stdout)`; raises `PdfError("OCR failed")` or `PdfError("OCR timed out")`; the detail (stderr first line or exit code) goes to `log.warning` only.
  - `extract_pdf_text` now runs OCR for `scanned`, `mostly_image` and `unreadable` pages.

- [ ] **Step 1: Write the failing tests**

Tests use a fake Tesseract: a Python script written to a temp dir, made executable, that reads its args. Helper in the test file:

```python
def fake_tesseract(dirpath: Path, langs=("eng", "heb", "osd"), text="שם: ישראל ישראלי\nת.ז 123456782",
                   fail_on_call=None, sleep=0) -> Path:
    """Write an executable fake tesseract. --version, --list-langs, and OCR (prints text to stdout).
    fail_on_call=N: the Nth OCR call exits 1 with 'boom' on stderr. sleep=S: each OCR call sleeps S seconds
    first (--version and --list-langs never sleep). Writes each OCR image path to calls.txt in dirpath."""
```

On Windows the helper is not needed; mark the class `@unittest.skipIf(os.name == "nt", "fake tesseract is a POSIX script")`.

```python
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

    def test_scan_page_ocr(self):
        r = ps.extract_pdf_text(FIX / "he_scan.pdf", self.settings(fake_tesseract(self.tmp)))
        self.assertEqual(r.pages[0].method, "ocr")
        self.assertIn("--- page 1 (OCR) ---\nשם: ישראל ישראלי\nת.ז 123456782", r.text)
        self.assertEqual(r.ocr_count, 1)

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

    def test_ocr_failure_on_one_page_continues(self):
        doc = self.tmp / "two_scans.pdf"
        subprocess.run(["qpdf", "--empty", "--pages", str(FIX / "he_scan.pdf"), "1", str(FIX / "he_scan.pdf"), "1",
                        "--", str(doc)], check=True)
        r = ps.extract_pdf_text(doc, self.settings(fake_tesseract(self.tmp, fail_on_call=1)))
        self.assertEqual([p.method for p in r.pages], ["skipped", "ocr"])
        self.assertIn("--- page 1 (scanned, skipped: OCR failed) ---", r.text)

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
```

`he_mixed.pdf` page order: text, scan, text. In the cancel test, `cancel` returns True on the third check, so pages 1 and 2 are done.

- [ ] **Step 2: Run the tests to see them fail**

Run: `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest tests.test_pdf.OcrTests -v`
Expected: FAIL with `AttributeError: ... 'find_tesseract'`.

- [ ] **Step 3: Implement**

- Call `find_tesseract` and `tesseract_info` once per `extract_pdf_text` run, and only when the first page needs OCR.
- Languages: keep the entries of `ocr.languages.split("+")` that are in the installed set. The note for a missing language uses the names `Hebrew` (`heb`) and `English` (`eng`); for other codes use the code.
- Page image: `page.render(scale=ocr.dpi / 72, grayscale=True)`. Write a binary PGM (`P5`) file without Pillow: header `f"P5 {w} {h} 255\n"`, then each row `buffer[y*stride : y*stride + w]`. Use `tempfile.mkstemp(suffix=".pgm")`; delete it in `finally`.
- `ocr_image` timeout: `subprocess.TimeoutExpired` → `PdfError("OCR timed out")`.
- When OCR raises `PdfError` for a page, call `_finish_page` with `ocr_text=None` and the error message as `reason`, and continue.

- [ ] **Step 4: Run the tests to see them pass**

Run: `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest tests.test_pdf -v`
Expected: all pass.

- [ ] **Step 5: Optional real check**

If `tesseract --list-langs` shows `heb` on the machine, run the scan fixture with the real binary and confirm the output contains `123456782`. Write the result in the report. Do not add a test that needs a real Tesseract.

- [ ] **Step 6: Commit**

```bash
git add pii_sanitizer.py tests/test_pdf.py
git commit -m "PDF ingest: optional Tesseract OCR for scanned pages"
```

---

### Task 4: Load PDFs in the main window, and the Settings PDF group

**Files:**
- Modify: `pii_sanitizer.py` — `MainWindow.load_file` (around line 4493), `MainWindow.closeEvent` (around line 5050), `SettingsDialog` (class at line 3690)
- Test: `tests/test_pdf.py`

**Interfaces:**
- Consumes: `extract_pdf_text`, `OcrSettings.from_config`, `PdfExtraction`, `PdfError`, `find_tesseract`, `tesseract_info`.
- Produces:
  - `MainWindow.load_path(path: Path) -> None` — text files as today; `.pdf` (case-insensitive) starts the PDF task. `load_file` opens the dialog and calls `load_path`.
  - `MainWindow._pdf_task: Optional[Task]`, `MainWindow._pdf_cancel: bool`, `MainWindow._closing: bool`
  - `MainWindow._on_pdf_done(result: PdfExtraction)`, `MainWindow._on_pdf_error(msg: str)`
  - Settings dialog widgets: `chk_ocr: QCheckBox`, `ed_tesseract: QLineEdit`, `lbl_tesseract: QLabel`

Behavior:
- File dialog filter: add `*.pdf` to the existing "Text" filter list, and add a separate `PDF (*.pdf)` entry.
- While the task runs: the Load button is disabled; the status bar shows the task's progress messages.
- On done: `clear_review()`, `input.setPlainText(result.text)`, Load button enabled, status bar `PDF loaded: {n} page(s), {ocr} by OCR, {skipped} skipped (see Log)` (8000 ms). If `result.all_skipped`, also a warning box titled `Load PDF` with the text `No text was found in this PDF.` followed by one line per page reason.
- On error: warning box titled `Load PDF` with the message; the input box keeps its old text; Load button enabled.
- `closeEvent` sets `_closing = True` and `_pdf_cancel = True`. `_on_pdf_done` and `_on_pdf_error` return at once when `_closing` is True.
- Settings "PDF" group: `chk_ocr` ("OCR scanned pages (Tesseract)"), `ed_tesseract` with a Browse button, `lbl_tesseract` showing `Tesseract {version}: Hebrew yes/no, English yes/no` or `Tesseract not found`. The label updates when the dialog opens and when the path field changes. Saving writes `pdf.ocr_enabled` and `pdf.tesseract_path`.

- [ ] **Step 1: Write the failing tests**

Use the `MainWindowGuiTests.setUp` pattern from `tests/test_core.py:615-628` (offscreen, `_start_engine` patched). Wait for the task with `ps.QtCore.QThreadPool.globalInstance().waitForDone(10000)` followed by `self.app.processEvents()`.

```python
@unittest.skipIf(ps.pdfium is None, "pypdfium2 not installed")
class PdfLoadGuiTests(unittest.TestCase):
    # setUpClass/setUp as MainWindowGuiTests; config in a temp dir with pdf.ocr_enabled False

    def wait(self):
        ps.QtCore.QThreadPool.globalInstance().waitForDone(10000); self.app.processEvents()

    def test_text_pdf_fills_input(self):
        self.win.load_path(FIX / "he_text.pdf"); self.wait()
        self.assertIn("123456782", self.win.input.toPlainText())
        self.assertTrue(self.win.statusBar().currentMessage().startswith("PDF loaded: 1 page(s), 0 by OCR, 0 skipped"))

    def test_all_pages_skipped_warns(self):
        with mock.patch.object(ps.QtWidgets.QMessageBox, "warning") as warn:
            self.win.load_path(FIX / "he_scan.pdf"); self.wait()
        self.assertIn("--- page 1 (scanned, skipped: OCR turned off) ---", self.win.input.toPlainText())
        warn.assert_called_once()
        self.assertIn("No text was found in this PDF.", warn.call_args.args[2])

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

    def test_result_after_close_is_ignored(self):
        self.win.input.setPlainText("old text")
        self.win._closing = True
        self.win._on_pdf_done(ps.PdfExtraction(pages=[], text="new"))
        self.assertEqual(self.win.input.toPlainText(), "old text")

    def test_text_file_still_loads(self):
        f = Path(tempfile.mkdtemp()) / "a.txt"; self.addCleanup(shutil.rmtree, f.parent, True)
        f.write_text("host SRV-DC01", "utf-8")
        self.win.load_path(f)
        self.assertEqual(self.win.input.toPlainText(), "host SRV-DC01")


class PdfSettingsGuiTests(unittest.TestCase):
    def test_settings_saves_pdf_options(self):
        # build SettingsDialog the same way the existing Settings tests in tests/test_core.py do
        # set chk_ocr False and ed_tesseract "/opt/x/tesseract", save, then:
        self.assertFalse(cfg.data["pdf"]["ocr_enabled"])
        self.assertEqual(cfg.data["pdf"]["tesseract_path"], "/opt/x/tesseract")

    def test_label_when_not_found(self):
        with mock.patch.object(ps, "find_tesseract", return_value=None):
            # open the dialog
            self.assertEqual(dlg.lbl_tesseract.text(), "Tesseract not found")
```

Find how existing tests build `SettingsDialog` (`grep -n "SettingsDialog(" tests/test_core.py`) and copy that setup. If no test builds it yet, build it with `ps.SettingsDialog(cfg, engine_mock, ...)` matching the signature at `pii_sanitizer.py:3805`.

- [ ] **Step 2: Run the tests to see them fail**

Run: `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest tests.test_pdf.PdfLoadGuiTests tests.test_pdf.PdfSettingsGuiTests -v`
Expected: FAIL with `AttributeError: 'MainWindow' object has no attribute 'load_path'`.

- [ ] **Step 3: Implement** as in Behavior above. Run the PDF task with `Task(extract_pdf_text, path, OcrSettings.from_config(self.config), wants_progress=True, cancel=lambda: self._pdf_cancel)` and `QtCore.QThreadPool.globalInstance().start(task)`; keep a reference in `self._pdf_task`.

- [ ] **Step 4: Run the full suite**

Run: `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest discover -s tests`
Expected: `OK` (191 earlier tests plus the new ones).

- [ ] **Step 5: Commit**

```bash
git add pii_sanitizer.py tests/test_pdf.py
git commit -m "PDF ingest: load PDFs from the main window; PDF group in Settings"
```

---

### Task 5: Windows packaging and README

**Files:**
- Modify: `packaging/pii_shield.spec`, `README.md`

- [ ] **Step 1: Packaging**

In `packaging/pii_shield.spec`, add `"pypdfium2"` and `"pypdfium2_raw"` to the `collect_all` package tuple, and `"pypdfium2"` to the `copy_metadata` tuple. Check that `pypdfium2_raw` is the module name in the installed wheel: `.venv/bin/python -c "import pypdfium2_raw, os; print(os.path.dirname(pypdfium2_raw.__file__))"`.

- [ ] **Step 2: Verify the spec loads**

Run: `.venv/bin/python -c "import ast,sys; ast.parse(open('packaging/pii_shield.spec').read()); print('ok')"`
Expected: `ok`. A full PyInstaller build runs in CI on Windows (`.github/workflows/build-windows.yml`); do not run it here.

- [ ] **Step 3: README "PDF files" section**

Add a section after the section that describes "Load file". It says, in ASD-STE100 style:
- "Load file" opens PDF files. Text pages are read directly. Each page starts with a `--- page N ---` line.
- Scanned pages need Tesseract with Hebrew and English data. Without it, the app skips them and the page line says why.
- Install: Windows — the UB Mannheim Tesseract installer, with "Hebrew" selected under additional languages; the app finds `C:\Program Files\Tesseract-OCR\tesseract.exe`, or set the path in Settings → PDF. Debian/Ubuntu — `sudo apt install tesseract-ocr tesseract-ocr-heb`.
- Limit: the app finds names and organizations with an English model. In Hebrew text, only rules and word lists find PII.
- Password-protected PDFs are not supported.

- [ ] **Step 4: Commit**

```bash
git add packaging/pii_shield.spec README.md
git commit -m "PDF ingest: package pypdfium2; README PDF section"
```
