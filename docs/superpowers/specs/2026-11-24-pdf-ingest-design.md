# PDF ingest — design

Date: 2026-11-24
Status: draft, waiting for approval

## Intent

The user wants to mask the PII in PDF files. The output is masked text, the same
output the app gives for text files today. The user pastes that text into an LLM.

No file content goes to an external service. Extraction and OCR run on the local
machine only.

The PDFs can contain Hebrew, English, or both on one line.

## Goals

1. "Load file" accepts `.pdf`. The app puts the PDF text into the input box. The
   masking flow after that does not change.
2. Pages with a text layer: the app extracts the text with **pypdfium2**.
3. Scanned pages (no text layer): the app runs **Tesseract** with `heb+eng`, if
   Tesseract is installed. If it is not installed, the app skips those pages and
   says so.
4. Hebrew text comes out in logical (reading) order. Values in the text stay intact,
   so the existing rules (for example `israeli_id`, `hebrew_street`, email, phone)
   match them.

## Non-goals

- **No masked PDF output.** The user decided that masked text is enough.
- **No Hebrew name or organization detection.** NER uses the English spaCy model
  (`engine.spacy_model: en_core_web_lg`, `language: en`). In Hebrew text, only rules
  and word lists find PII. This is the app's behavior today, and this design does
  not change it. A Hebrew NER model is a separate project.
- No separate OCR of single images inside a text page. A page that is mostly an
  image goes to OCR as a whole page (see "Page classification").
- No password-protected PDFs. The app shows an error.
- No bundled Tesseract in the Windows release. The user installs Tesseract.
- No drag and drop. The app has no drag and drop for text files either.

## Anti-goals (a failure even if it works)

- **A silent gap.** If the app skips a page, or OCR fails on a page, the text box
  and the log must show it. Missing text that the user does not know about is
  unmasked PII that the user never reviewed.
- Any network call during extraction or OCR.
- A frozen window during a long OCR run.
- A temp file with page images left on disk after the run.

## Constraints

- Single file app: `pii_sanitizer.py`. The new code goes in that file, the same as
  the rest of the app.
- Portable Windows release built with PyInstaller (`packaging/pii_shield.spec`,
  `requirements-build.txt`, pinned versions). pypdfium2 must build into it.
- pypdfium2 is optional at import time, the same way the app treats `keyring`. If
  it is missing, "Load file" shows a clear error for `.pdf` and text files still work.
- Tests run with `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest discover -s tests`.
- The repo is public. Test PDFs use invented values only (for example
  "ישראל ישראלי", `test@example.com`, the valid test ID `123456782`).

## Approaches

| | Text PDFs | Scanned pages | Trade-off |
|---|---|---|---|
| **A (picked)** | pypdfium2 | Tesseract `heb+eng`, optional | Official Hebrew OCR model, mature. Tesseract is a separate install. |
| B | pypdfium2 | RapidOCR + community Hebrew model | pip only, but the Hebrew model is from one author with unknown accuracy. RapidOCR has no official Hebrew model. |
| C | PyMuPDF | Tesseract | Good extraction, but the AGPL license is a risk for the release. |

pypdfium2 has an Apache/BSD license and ships as a wheel with no system
dependencies. The user picked pypdfium2 for text and Tesseract for scans.

## Design

### Flow

1. The user clicks "Load file" and picks a `.pdf`. The file filter adds `*.pdf`.
2. The app runs the extraction in a background `Task` (the existing `QRunnable`
   class), so the window stays responsive. The status line shows progress, for
   example "PDF: page 3 of 12 (OCR)".
3. When the task finishes, the app calls `clear_review()` and puts the text into
   the input box. The app writes one line per page to the Log tab (the Python
   `logging` handler that feeds `log_box`). The status bar shows a summary, for
   example "PDF loaded: 12 pages, 3 by OCR, 1 skipped (see Log)".
4. While the task runs, the "Load file" button is disabled. The extraction checks
   a cancel flag between pages. Closing the window sets the flag. The app ignores
   a result that arrives after the window starts to close.

### Extraction function (no Qt)

A function with no Qt dependency, so tests can call it directly:

`extract_pdf_text(path, ocr: OcrSettings, progress=None) -> PdfExtraction`

`PdfExtraction` holds the full text and one record per page: page number, method
(`text`, `ocr`, `skipped`), and a reason when the method is `skipped` (for example
"Tesseract not installed", "Hebrew language data missing", "OCR failed: ...").

The output text has one header line per page:

```
--- page 1 ---
<text>
--- page 2 (OCR) ---
<text>
--- page 3 (scanned, skipped: Tesseract not installed) ---
```

The header lines make a skipped page visible in the text itself (anti-goal 1). They
contain no PII, so they can go to the LLM.

### Page classification

The app sends a page to OCR when one of these is true:

1. **Little text:** the text layer has fewer than 20 non-space characters.
2. **Mostly image:** image objects cover 50% or more of the page area. This catches
   a scanned page that also has a small text layer, for example a stamp, a footer
   or a page number. OCR reads the rendered page, so it also reads the text layer.
3. **Unreadable text:** fewer than 50% of the non-space characters are Hebrew,
   Latin, digits or common punctuation. This catches a PDF with a broken font map,
   where pypdfium2 returns private-use or replacement characters.

If OCR is not available for such a page, the app keeps the text layer (if any) and
writes a warning in the header, for example
`--- page 4 (mostly image, image text not read: Tesseract not installed) ---`.
The user always sees which text the app did not read.

The builder can change the 20-character and 50% values if a fixture shows better
values.

### Hebrew text order

pypdfium2 returns characters in the order the PDF stores them. Producers differ:

- Most producers (Word, LibreOffice, browsers) store Hebrew in logical order.
  LibreOffice also adds bidi control characters.
- Some producers store Hebrew in visual order. The extracted text is then reversed.

The app does two things to each extracted line:

1. **Remove bidi control characters:** U+200E, U+200F, U+202A to U+202E,
   U+2066 to U+2069. They are invisible, but they can split a value. Then a rule
   regex fails, and value propagation misses the value.
2. **Fix visual order.** Hebrew final letters (ך ם ן ף ץ) occur only at the end of
   a word. If, in a line, final letters occur at the start of Hebrew words more
   often than at the end, the line is in visual order. The app splits the line into
   runs:
   - a **Hebrew run**: one or more Hebrew letters;
   - an **LTR run**: from a Latin letter or digit to the last Latin letter or digit
     before the next Hebrew letter, with the spaces and punctuation between them
     (so `test@example.com` and `world 2024` are one run each);
   - every other character (space, punctuation) is a run of its own.

   The app then reverses the order of all runs, and reverses the characters inside
   each Hebrew run only. LTR runs keep their characters in the same order.

   Examples (checked with a short script):
   - `םש 123456782 :ז.ת` becomes `ת.ז: 123456782 שם`
   - `הדות test@example.com :ליימ` becomes `מייל: test@example.com תודה`
   - `םולש world 2024 םולש` becomes `שלום world 2024 שלום`

   This is the reverse of how a viewer draws a right-to-left line. It is a simple
   form of the Unicode bidi rules, and it is enough for one-line runs of text.

The builder confirms this with fixture PDFs: one in logical order (made with
LibreOffice) and one in visual order. Both must give the same text. A value such as
`123456782` or `test@example.com` must come out whole and in the correct order.

### OCR

- The app renders the page with pypdfium2 at 300 DPI into a temp PNG. It runs the
  Tesseract command line: `tesseract <png> stdout -l heb+eng`. The app calls the
  binary with `subprocess` (no shell, with a timeout). It does not add a Python
  wrapper dependency. The app deletes the temp file in a `finally` block.
- Tesseract returns Hebrew in logical order. The app removes bidi control
  characters from the result, the same as for the text layer. It does not apply the
  visual-order fix to OCR text.
- **Find Tesseract** in this order:
  1. The `pdf.tesseract_path` setting.
  2. `shutil.which("tesseract")`.
  3. On Windows: `C:\Program Files\Tesseract-OCR\tesseract.exe`.
- **Check languages** once per run with `tesseract --list-langs`. The app uses the
  languages from `pdf.ocr_languages` that are installed. If one is missing, OCR
  runs with the others, and each OCR header says so, for example
  `--- page 2 (OCR, English only: Hebrew language data missing) ---`. If none is
  installed, the app skips the scanned pages with that reason.
- On Windows, the app starts Tesseract with `CREATE_NO_WINDOW`, so no console
  window opens.
- If OCR fails on a page (non-zero exit, timeout), the app marks the page
  `skipped` with the reason and continues with the next page.

### Settings

New config section, merged into `DEFAULT_CONFIG`:

```yaml
pdf:
  ocr_enabled: true        # false = never run OCR; scanned pages are skipped
  tesseract_path: ""       # empty = find it automatically
  ocr_languages: "heb+eng"
  ocr_dpi: 300
  ocr_timeout: 120         # seconds per page
```

The Settings dialog gets a "PDF" group: an "OCR scanned pages" checkbox, a
Tesseract path field with Browse, and a status line. The status line shows the
Tesseract version and whether `heb` and `eng` are installed, or "Tesseract not
found".

### Errors

- pypdfium2 not installed: "PDF support needs the pypdfium2 package."
- Password-protected PDF: "This PDF is password protected. PII Shield cannot open it."
- Damaged file: the pypdfium2 error text.
- A PDF with no text at all (all pages skipped): the text box gets the header lines
  only, and a warning box says that no text was found and why.
- Some pages skipped or not fully read: no box. The headers, the status bar and the
  Log tab show it.

### Packaging and docs

- Add `pypdfium2` to `requirements.txt` and a pinned version to
  `requirements-build.txt`.
- `packaging/pii_shield.spec`: collect the pypdfium2 data and binaries
  (`pypdfium2` and `pypdfium2_raw`), the same way the spec collects other packages.
- README: a "PDF files" section. It covers the text and OCR paths, how to install
  Tesseract with Hebrew on Windows and Linux, and the Hebrew NER limit.

## Calls I made (the user did not decide these)

- Page header lines in the output text, including skipped pages.
- The 20-character scanned page test.
- Removing bidi control characters, and the final-letter test for visual order.
- Calling the Tesseract command line instead of adding `pytesseract`.
- A PDF group in the Settings dialog, so the user does not edit the config file.
- The extraction runs in the background, with progress in the status line.
- Mostly-image and unreadable-text pages go to OCR (from the builder check).
- Visual-order fix reverses all runs; only Hebrew runs reverse their characters.
- A missing OCR language degrades OCR instead of skipping the page.
- Load is disabled during extraction; a cancel flag stops it between pages.
- A warning box only when no page gave text.

## Left to the builder

- Exact names of internal helpers.
- How to make the visual-order fixture PDF (for example a PDF written by hand with
  reversed Hebrew strings).
- How tests fake Tesseract when it is not installed (for example a stub script on
  `PATH`, or a mocked `subprocess.run`).
