# Full Build Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A second Windows build ("full") that detects Hebrew persons, organizations and places with the 8-bit DictaBERT NER ONNX model and bundles Tesseract with Hebrew and English data; the small build is unchanged.

**Architecture:** `pii_sanitizer.py` gets `bundle_dir()`, model discovery, a Presidio `HebrewNerRecognizer` (pure chunk/offset/span logic over an injectable tokenizer and ONNX session), a setting, a self-test check and full-aware updater fields. `packaging/fetch_full_assets.py` downloads pinned assets. The PyInstaller spec builds either flavor from `PII_SHIELD_FLAVOR`. The workflow builds both flavors and publishes once.

**Tech Stack:** Python 3.12 (CI) / 3.13 (local), PyQt6, Presidio, onnxruntime 1.32.0, tokenizers 0.23.3, PyInstaller, GitHub Actions (windows-latest, pwsh).

**Spec:** `docs/superpowers/specs/2026-11-24-full-build-design.md`

## Global Constraints

- App code stays in `pii_sanitizer.py`. New tests go in `tests/test_hebrew_ner.py` (same header pattern as `tests/test_core.py`), except updater tests, which go next to the existing updater tests.
- Run tests ONLY with `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest ...`. Full suite: `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest discover -s tests` (269 pass on `main`; ~70–120 s, use a 600 s timeout).
- `onnxruntime` and `tokenizers` are optional imports: `try: import onnxruntime as ort` / `except ImportError: ort = None`; same for `from tokenizers import Tokenizer`. The small build and all non-model tests must work without them.
- Model pin (exact): repo `onnx-community/dictabert-ner-ONNX`, revision `4f0aabf58566526df6f3fb548e0fd2619fbf2b1d`. Files and SHA-256:
  - `config.json` — `ba12e2d104a01d60b22641dcdedd6d01a7743be917d489ab60f0722953232336` (1690 bytes)
  - `tokenizer.json` — `00657b39a8a73b96ddcc3cda245c5e8fa02be36e31e318bd13a9169eb89c999b` (3577623 bytes)
  - `onnx/model_quantized.onnx` — `fd7ac841768f11197e1d46ea6bbfe82d9cd9e21289be8761af63dbc996a32007` (184984466 bytes), stored locally as `model_quantized.onnx`
- Model folder name: `models/dictabert-ner/`. Valid when it holds `config.json`, `tokenizer.json`, `model_quantized.onnx`.
- Label map (exact): `PER`→`PERSON`, `ORG`→`ORGANIZATION`, `GPE`/`LOC`/`FAC`→`LOCATION`; every other label is ignored.
- Hebrew line test: the line contains a character in U+05D0–U+05EA.
- Chunking: at most `256` tokens per chunk, `50` tokens overlap. (First `400`; changed to `256` after the real-model test, ruling R3.)
- `intra_op_num_threads = 1`.
- Finding source for Hebrew findings: `"hebrew_ner"`; `SOURCE_LABEL["hebrew_ner"] = "Hebrew NER"`; recognizer name `"HebrewNerRecognizer"`.
- Config key: `engine.hebrew_ner` (default `True`).
- Self-test Hebrew sentence (exact): `דנה כהן נפגשה עם משה לוי בחיפה.`; CLI flag `--require-hebrew`.
- Zip names: small `PII-Shield-<version>-win64.zip` (unchanged), full `PII-Shield-<version>-win64-full.zip`. `version.json` new fields: `windows_full_zip_url`, `windows_full_zip_sha256`.
- Updater message when a full build finds no full fields (exact): `No full build is available for this version.`
- Settings checkbox label (exact): `Hebrew name detection (DictaBERT NER)`; disabled label suffix in the small build: `Hebrew model not installed`.
- Downloaded assets go to `build-assets/` (gitignored); the dev model copy goes to `models/` next to `pii_sanitizer.py` (gitignored).
- Public repo: invented values only. Never commit model or Tesseract binaries.
- ASD-STE100 style for user-facing text and docs.

## Review Focus

1. **A full install where onnxruntime fails to load.** It must still count as full for updates and must not update to the small zip. → Task 5 test `test_full_build_with_broken_runtime_still_uses_full_fields`.
2. **Mixed Hebrew/English text and English-only text.** The Hebrew recognizer must not run the model on English-only input and must not shift offsets in mixed text. → Task 2 tests `test_english_only_text_never_calls_session`, `test_offsets_map_back_in_mixed_text`.
3. **A long Hebrew document (more than 400 tokens).** An entity inside the overlap must be reported once; an entity cut by a chunk edge must still be found in the next chunk. → Task 2 test `test_entity_in_overlap_reported_once`.
4. **The small build CI job.** It must contain no onnxruntime files and no `models/` folder. → Task 6 workflow step "Check small build content".
5. **A release where one flavor fails to build.** Nothing is published. → Task 6 workflow `publish` job `needs: build`.

---

### Task 1: Bundle folder, model discovery, Tesseract search, setting

**Files:**
- Modify: `pii_sanitizer.py` (near `APP_DIR`/`is_frozen`; `find_tesseract`; `DEFAULT_CONFIG["engine"]`; `SOURCE_LABEL`, `SOURCE_PRIORITY`)
- Modify: `.gitignore` (add `build-assets/` and `/models/`)
- Create: `tests/test_hebrew_ner.py`
- Modify: `tests/test_pdf.py` (the `find_tesseract` order test)

**Interfaces:**
- Produces:
  - `bundle_dir() -> Path` — `Path(sys._MEIPASS)` when frozen, else `Path(__file__).resolve().parent`
  - `HEBREW_MODEL_DIRNAME = "dictabert-ner"`, `HEBREW_MODEL_FILES = ("config.json", "tokenizer.json", "model_quantized.onnx")`
  - `bundled_model_dir() -> Path` (= `bundle_dir() / "models" / HEBREW_MODEL_DIRNAME`)
  - `find_hebrew_model() -> Optional[Path]` — first valid of `bundled_model_dir()`, `APP_DIR / "models" / HEBREW_MODEL_DIRNAME`
  - `is_full_build() -> bool` — True only when all `HEBREW_MODEL_FILES` exist in `bundled_model_dir()`; never loads anything
  - `find_tesseract` step 2 uses `bundle_dir() / "tesseract"`
  - `DEFAULT_CONFIG["engine"]["hebrew_ner"] = True`; `SOURCE_LABEL["hebrew_ner"] = "Hebrew NER"`; `SOURCE_PRIORITY["hebrew_ner"]` equal to the value for `"presidio"`

- [ ] **Step 1: Write the failing tests** (in `tests/test_hebrew_ner.py`, class `DiscoveryTests`; use temp dirs and `mock.patch.object(ps, "bundle_dir", ...)` / `mock.patch.object(ps, "APP_DIR", ...)`)

```python
def test_is_full_build_needs_all_three_files(self): ...   # 2 files -> False, 3 files -> True
def test_full_build_ignores_app_dir_model(self): ...       # model only under APP_DIR/models -> is_full_build False, find_hebrew_model returns it
def test_find_hebrew_model_prefers_bundle(self): ...       # both present -> bundle path
def test_find_hebrew_model_none(self): ...                 # neither -> None
def test_bundle_dir_frozen(self): ...                      # patch sys.frozen and sys._MEIPASS -> that path
def test_defaults(self):
    self.assertTrue(ps.DEFAULT_CONFIG["engine"]["hebrew_ner"])
    self.assertEqual(ps.SOURCE_LABEL["hebrew_ner"], "Hebrew NER")
```
Update the existing `find_tesseract` order test in `tests/test_pdf.py` to patch `bundle_dir` instead of `APP_DIR` for the bundled step.

- [ ] **Step 2: Run to see them fail** — `QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest tests.test_hebrew_ner tests.test_pdf -v` → `AttributeError: ... 'bundle_dir'`.
- [ ] **Step 3: Implement** the interfaces above.
- [ ] **Step 4: Run the tests and the full suite** — all pass.
- [ ] **Step 5: Commit** — `git commit -m "Full build: bundle folder, Hebrew model discovery, setting"`.

---

### Task 2: Hebrew NER core (no Presidio, no real model)

**Files:**
- Modify: `pii_sanitizer.py` (new `# ---- Hebrew NER ----` section after the PDF ingest section)
- Modify: `requirements.txt` (comment block: optional full-build packages), create `requirements-full.txt` (`onnxruntime==1.32.0`, `tokenizers==0.23.3`)
- Test: `tests/test_hebrew_ner.py`

**Interfaces:**
- Consumes: `find_hebrew_model` (Task 1).
- Produces:
  - `ort`, `HfTokenizer` (optional imports, `None` when missing)
  - `HEBREW_LABEL_MAP = {"PER": "PERSON", "ORG": "ORGANIZATION", "GPE": "LOCATION", "LOC": "LOCATION", "FAC": "LOCATION"}`
  - `@dataclass HebrewSpan: start: int; end: int; entity: str; score: float`
  - `class HebrewNerModel` with `__init__(self, tokenizer, session, id2label: Dict[int, str], max_tokens: int = 400, overlap: int = 50)` and `predict(self, text: str) -> List[HebrewSpan]` (offsets into `text`)
  - `load_hebrew_model(model_dir: Path) -> HebrewNerModel` — builds the real tokenizer (`HfTokenizer.from_file`) and `ort.InferenceSession` (CPU provider, `intra_op_num_threads = 1`), reads `id2label` from `config.json`; raises `RuntimeError` with a clear message when `ort`/`HfTokenizer` is missing

Behavior of `predict`:
- Only lines that contain a Hebrew letter are processed. Consecutive Hebrew lines are joined (keeping their offsets) and tokenized together; a non-Hebrew line ends a group.
- Each group is split into windows of at most `max_tokens` tokens with `overlap` tokens of overlap (plus the model's special tokens, which the tokenizer adds). Feeds: `input_ids`, `attention_mask`, and `token_type_ids` only if the session declares it (int64).
- Per token: softmax over the logits, winning label. Consecutive `B-X`/`I-X` tokens of the same type form one span; an `I-X` after `O` or after another type starts a new span. Special tokens (offset `(0,0)`) are skipped.
- Span score = mean winning-label probability over its tokens. Spans with unmapped labels are dropped.
- A span found in two windows (same start, end and entity) is kept once, with the higher score.

- [ ] **Step 1: Write the failing tests** with a fake tokenizer and a fake session.

The fake tokenizer splits on spaces and returns an object with `ids`, `offsets`, `word_ids` like `tokenizers.Encoding` (offsets relative to the string passed in), adding `[CLS]`/`[SEP]` with offset `(0, 0)`. The fake session returns logits from a dict `{token_text: label}` (one-hot ×10, so the score is ~1.0), declares inputs `input_ids`, `attention_mask`, and records every call.

```python
class HebrewNerCoreTests(unittest.TestCase):
    def test_person_and_place(self):
        # "דנה כהן נפגשה בחיפה" with דנה=B-PER, כהן=I-PER, בחיפה=B-GPE
        spans = model.predict(text)
        self.assertEqual([(text[s.start:s.end], s.entity) for s in spans],
                         [("דנה כהן", "PERSON"), ("בחיפה", "LOCATION")])
    def test_ignored_labels_dropped(self): ...            # B-TIMEX token -> no span
    def test_i_after_o_starts_new_span(self): ...
    def test_english_only_text_never_calls_session(self): ...   # "John Smith met SRV-DC01" -> [], session.calls == 0
    def test_offsets_map_back_in_mixed_text(self): ...    # "Ticket 12\nשם: דנה כהן\nEnd" -> span text == "דנה כהן" at the right offsets
    def test_entity_in_overlap_reported_once(self): ...   # max_tokens=6, overlap=2, a PER token inside the overlap -> one span
    def test_entity_cut_by_window_edge_found(self): ...   # 2-token PER split across a window edge -> found whole in the next window
    def test_token_type_ids_only_when_declared(self): ...
    def test_load_without_runtime_raises(self):
        with mock.patch.object(ps, "ort", None):
            with self.assertRaises(RuntimeError): ps.load_hebrew_model(Path("/nonexistent"))
```

- [ ] **Step 2: Run to see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and the full suite.**
- [ ] **Step 5: Commit** — `"Full build: Hebrew NER core (chunking, offsets, spans)"`.

---

### Task 3: Presidio integration, Settings checkbox, self-test

**Files:**
- Modify: `pii_sanitizer.py` — `DetectionEngine.initialize` / `_build_registry` / `analyze` (source mapping, around the `rname`/`custom_names` code), `SettingsDialog` (near the "detect organizations" checkbox), `self_test`, the `--self-test` CLI block
- Test: `tests/test_hebrew_ner.py`

**Interfaces:**
- Consumes: `find_hebrew_model`, `load_hebrew_model`, `HebrewNerModel` (Tasks 1–2).
- Produces:
  - `HebrewNerRecognizer(EntityRecognizer)`: name `"HebrewNerRecognizer"`, `supported_language="en"`, entities `PERSON`, `ORGANIZATION`, `LOCATION`; `analyze()` returns `RecognizerResult`s from `HebrewNerModel.predict`, filtered to the requested entities.
  - `DetectionEngine.hebrew_model: Optional[HebrewNerModel]`, `DetectionEngine.hebrew_status: str` (for example `"loaded"`, `"not installed"`, `"off"`, `"failed: <reason>"`)
  - `self_test(engine=None, require_hebrew: bool = False)`
- Behavior:
  - `initialize` loads the model once (only when `engine.hebrew_ner` is on and `find_hebrew_model()` returns a folder); a load error logs a warning and sets `hebrew_status` to `failed: ...`; the engine continues.
  - `_build_registry` adds the recognizer when the model is loaded and the setting is on. `detect_organizations` off removes Hebrew `ORGANIZATION` the same way it removes spaCy ORG.
  - Findings from `HebrewNerRecognizer` get `source="hebrew_ner"`. `skip_ner_on_logs` drops them on log input the same way it drops spaCy PERSON/ORG/LOCATION. The allow list and score threshold apply unchanged.
  - Settings: checkbox `Hebrew name detection (DictaBERT NER)` bound to `engine.hebrew_ner`; disabled with the label suffix `— Hebrew model not installed` when `find_hebrew_model()` is None; tooltip `Model: DictaBERT NER by Dicta, CC BY 4.0.`. A change needs an engine reload, as for other detection settings.
  - `self_test`: when the model is loaded, analyze `דנה כהן נפגשה עם משה לוי בחיפה.` and add a check `PERSON (Hebrew NER)` that passes when any `PERSON` finding with source `hebrew_ner` exists. With `require_hebrew=True`, add a check `Hebrew model loaded` that fails unless `hebrew_status == "loaded"`. `--require-hebrew` passes `require_hebrew=True`.

- [ ] **Step 1: Write the failing tests.** Inject a fake `HebrewNerModel` (patch `ps.load_hebrew_model` to return a model built with the Task 2 fakes, and `ps.find_hebrew_model` to return a temp path). Build the engine as `tests/test_core.py` `EngineTests` does.

```python
def test_hebrew_person_found_with_source(self): ...        # finding PERSON "דנה כהן", source "hebrew_ner"
def test_setting_off_skips_model(self): ...                 # engine.hebrew_ner False -> hebrew_status "off", no hebrew_ner findings
def test_detect_organizations_off_drops_hebrew_org(self): ...
def test_allow_list_applies_to_hebrew(self): ...
def test_load_failure_keeps_engine_running(self): ...       # load raises -> status startswith "failed", English findings still work
def test_not_installed_status(self): ...
def test_self_test_require_hebrew_fails_without_model(self): ...
def test_self_test_hebrew_check_passes_with_fake_model(self): ...
def test_settings_checkbox_disabled_without_model(self): ...   # offscreen SettingsDialog, label contains "Hebrew model not installed"
def test_settings_checkbox_saves(self): ...
```

- [ ] **Step 2–4:** fail, implement, pass (tests + full suite).
- [ ] **Step 5: Commit** — `"Full build: Hebrew NER recognizer in the engine; Settings; self-test"`.

---

### Task 4: Asset fetch script and real-model tests

**Files:**
- Create: `packaging/fetch_full_assets.py`
- Create: `tests/fixtures/hebrew_ner_sentences.json`
- Test: `tests/test_hebrew_ner.py` (class `RealModelTests`)

**Interfaces:**
- Produces: `python packaging/fetch_full_assets.py [--dest build-assets] [--model-only] [--install-dev]`
  - Downloads the three model files from the pinned revision (Global Constraints) with `requests` (stream, timeout), verifies size and SHA-256, writes `<dest>/models/dictabert-ner/` plus `LICENSE.txt` (CC BY 4.0 credit: model name `dicta-il/dictabert-ner`, ONNX conversion `onnx-community/dictabert-ner-ONNX` at the pinned revision, author Dicta, license link `https://creativecommons.org/licenses/by/4.0/`).
  - Unless `--model-only`, and only on Windows (`os.name == "nt"`): downloads the UB Mannheim Tesseract 5.x installer (pinned URL + SHA-256), extracts it with `7z x` into a temp folder (fallback: run it with `/S /D=<folder>`), copies `tesseract.exe`, all `*.dll` next to it, and `tessdata/osd.traineddata` to `<dest>/tesseract/`; then downloads `heb.traineddata` and `eng.traineddata` from `tesseract-ocr/tessdata_best` at a pinned commit (URL + SHA-256) into `<dest>/tesseract/tessdata/`. Writes `<dest>/THIRD_PARTY_NOTICES.txt` (DictaBERT NER CC BY 4.0; Tesseract and tessdata Apache-2.0; onnxruntime MIT; tokenizers Apache-2.0; and every DLL copied, with its license as stated in the Tesseract install's own notice files).
  - `--install-dev` copies `<dest>/models/dictabert-ner/` to `models/dictabert-ner/` next to `pii_sanitizer.py`.
  - A hash mismatch deletes the file and exits non-zero with the file name.
  - The implementer finds the current UB Mannheim installer URL and the tessdata_best commit, downloads each once to compute the SHA-256, and records them as constants at the top of the script. (The Windows-only part cannot run on the Linux dev box; the CI job is its test.)

- [ ] **Step 1: Write `tests/fixtures/hebrew_ner_sentences.json`** — exactly these 20 items (invented values), as `[{"text": ..., "entities": [[surface, "PER"|"ORG"|"LOC"], ...]}, ...]`:

```
דנה כהן נפגשה עם משה לוי במשרד בחיפה. | דנה כהן PER; משה לוי PER; חיפה LOC
העובד יוסי אברהמי מחברת אורנים תוכנה התקשר אתמול. | יוסי אברהמי PER; אורנים תוכנה ORG
שם: ישראל ישראלי, ת.ז 123456782, כתובת: רחוב הרצל 12 תל אביב | ישראל ישראלי PER; תל אביב LOC
רונית שפירא עובדת בבנק הדקל בירושלים. | רונית שפירא PER; בנק הדקל ORG; ירושלים LOC
הלקוח אבי מזרחי ביקש להעביר את התיק למשרד בבאר שבע. | אבי מזרחי PER; באר שבע LOC
ד"ר מיכל ברק מבית החולים נווה צדק שלחה את התוצאות. | מיכל ברק PER; נווה צדק ORG
עו"ד אלון פרידמן ייצג את חברת גלבוע מערכות בע"מ. | אלון פרידמן PER; גלבוע מערכות ORG
נועה גולן ויעל רוזן טסו מנתב"ג לברלין. | נועה גולן PER; יעל רוזן PER; נתב"ג LOC; ברלין LOC
השרת הותקן במרכז הנתונים של קבוצת תמר בפתח תקווה. | קבוצת תמר ORG; פתח תקווה LOC
איתי שלום שלח מייל ל-test@example.com בנושא החשבונית. | איתי שלום PER
הפגישה עם אורית דהן נדחתה לשבוע הבא. | אורית דהן PER
מנהל הפרויקט, עמית נחום, דיווח על תקלה בשרת SRV-DC01. | עמית נחום PER
משפחת אזולאי עברה מנתניה לרחובות. | אזולאי PER; נתניה LOC; רחובות LOC
עיריית הרצליה פרסמה מכרז חדש. | עיריית הרצליה ORG
טלפון של שירה ביטון: 054-1234567 | שירה ביטון PER
הדוח נשלח למחלקת הכספים של אוניברסיטת הגליל. | אוניברסיטת הגליל ORG
גיל וקנין ותמר אלמוג מצוות אבטחת המידע בדקו את הלוגים. | גיל וקנין PER; תמר אלמוג PER
המשלוח יצא מאשדוד ויגיע לאילת ביום שני. | אשדוד LOC; אילת LOC
הסיסמה לשרת שונתה אתמול בערב. | (none)
לפי הנוהל, יש לעדכן את המערכת פעם בחודש. | (none)
```

- [ ] **Step 2: Write `RealModelTests`**, skipped unless `ps.find_hebrew_model()` is not None and `ps.ort` and `ps.HfTokenizer` are importable:

```python
def test_f1_on_fixture(self):
    # match rule: same type (PER/ORG/LOC from the map) and one surface contains the other, both >= 2 chars
    self.assertGreaterEqual(f1, 0.85)
def test_every_person_found(self): ...   # every PER surface is matched by a PERSON span
def test_speed_long_text(self): ...      # 1500-char Hebrew text predicted in < 5 s (generous CI bound); prints the time
```

- [ ] **Step 3: Run the fetch script locally with `--model-only --install-dev`**, then install `requirements-full.txt` into `.venv`, then run `RealModelTests`. Expected: F1 ≥ 0.85 (the spike measured 0.93), all persons found. Record the numbers in the report.
- [ ] **Step 4: Full suite** — passes (real-model tests run locally now; they skip where the model is absent).
- [ ] **Step 5: Commit** — `"Full build: asset fetch script; real-model accuracy tests"`. Do not commit `build-assets/` or `models/`.

---

### Task 5: Updater picks the full zip for a full build

**Files:**
- Modify: `pii_sanitizer.py` (the update download code around `windows_zip_url` / `windows_zip_sha256`)
- Test: the file that holds the existing updater tests (`grep -n "windows_zip_url" tests/*.py`)

**Interfaces:**
- Consumes: `is_full_build()` (Task 1).
- Produces: `update_zip_fields(info: Dict, full: bool) -> Tuple[str, str]` — returns `(url, sha256)` from `windows_full_zip_url`/`windows_full_zip_sha256` when `full`, else from the current fields; raises `SyncError("No full build is available for this version.")` when `full` and either full field is missing. The download code calls it with `is_full_build()`. The https check applies to both.

- [ ] **Step 1: Tests**

```python
def test_small_build_uses_small_fields(self): ...
def test_full_build_uses_full_fields(self): ...
def test_full_build_without_full_fields_refuses(self): ...   # exact message
def test_full_build_with_broken_runtime_still_uses_full_fields(self): ...  # model files present, ps.ort None -> full fields
def test_full_url_must_be_https(self): ...
```
- [ ] **Step 2–4:** fail, implement, pass (+ full suite).
- [ ] **Step 5: Commit** — `"Full build: updater keeps full installs on the full zip"`.

---

### Task 6: PyInstaller flavor, CI workflow, docs

**Files:**
- Modify: `packaging/pii_shield.spec`, `.github/workflows/build-windows.yml`, `README.md`

- [ ] **Step 1: Spec file.** Read `PII_SHIELD_FLAVOR` (default `small`). For `full`: `collect_all("onnxruntime")`, `collect_all("tokenizers")`; add datas `build-assets/models/dictabert-ner` → `models/dictabert-ner`, `build-assets/tesseract` → `tesseract`, `build-assets/THIRD_PARTY_NOTICES.txt` → `.`; fail the build with a clear message if a source folder is missing. For `small`: add `"onnxruntime"`, `"tokenizers"` to `excludes`. Check: `.venv/bin/python -c "import ast; ast.parse(open('packaging/pii_shield.spec').read()); print('ok')"`.

- [ ] **Step 2: Workflow.** Restructure into:
  - `build` job, `strategy.matrix.flavor: [small, full]`, `env: PII_SHIELD_FLAVOR: ${{ matrix.flavor }}`:
    - install `requirements-build.txt`; for `full` also `requirements-full.txt`;
    - for `full`: cache `build-assets/` keyed on a hash of `packaging/fetch_full_assets.py`, then `python packaging/fetch_full_assets.py --dest build-assets` and `python packaging/fetch_full_assets.py --dest build-assets --install-dev` (so `RealModelTests` run);
    - unit tests; read version (same tag check as today); PyInstaller;
    - smoke test as today; the full job runs `--self-test --require-hebrew`;
    - step "Check small build content" (small only): fail if `dist\PII-Shield\_internal` contains `onnxruntime*` or `models`;
    - zip as `PII-Shield-<v>-win64.zip` (small) or `PII-Shield-<v>-win64-full.zip` (full), write its `.sha256`, upload as artifact `zip-${{ matrix.flavor }}`.
    - Keep the updater-script parse check in the small job only.
  - `publish` job, `needs: build`: download both artifacts; do the existing stamped-`version.json` check; write `out/version.json` and `out/root-version.json` with the existing fields plus `windows_full_zip_url` and `windows_full_zip_sha256`; upload all as one artifact; for a `v*` tag, create the release with both zips, both `.sha256` files and `version.json`, and do whatever the current workflow does with `root-version.json`. Release notes name both zips and say the full zip adds Hebrew name detection and Tesseract.
  - Validate YAML: `.venv/bin/python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/build-windows.yml')); print('ok')"`.

- [ ] **Step 3: README.** Add a "Full build" section under "Windows build": what the full zip adds (Hebrew persons, organizations and places; bundled Tesseract with Hebrew and English), its approximate size, that both run locally, the CC BY 4.0 credit to Dicta (model `dicta-il/dictabert-ner`, link to the license), that a full install updates only to the full zip, and how to run from source (`pip install -r requirements-full.txt`, `python packaging/fetch_full_assets.py --model-only --install-dev`). Update the PDF section's Tesseract search order (bundled copy is inside `_internal/tesseract`).

- [ ] **Step 4: Full suite** passes.
- [ ] **Step 5: Commit** — `"Full build: PyInstaller flavor, two-build CI, README"`.
