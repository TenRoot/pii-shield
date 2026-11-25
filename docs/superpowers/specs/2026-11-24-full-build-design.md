# Full Windows build (Hebrew names and bundled Tesseract) — design

Date: 2026-11-24
Status: draft, waiting for approval

## Intent

PII Shield finds names, organizations and places only in English text. In Hebrew text, it finds
only the values that the rules and word lists match. The user wants Hebrew names masked too.

The user wants two Windows builds:

- **Small build:** the current build. No Hebrew name detection. No bundled Tesseract.
- **Full build:** the small build, plus a Hebrew name model and a bundled Tesseract with Hebrew
  and English data.

Both builds come from the same code. All processing stays on the local machine.

## Goals

1. The full build finds Hebrew person names, organizations and places, and masks them the same
   way as English findings.
2. The full build reads scanned PDF pages with no separate Tesseract install.
3. The small build does not change in size or behavior.
4. One code base. The app finds out at start if the Hebrew model is present.
5. The in-app updater keeps each install on its own build: a full build updates to the full zip.

## Non-goals

- Hebrew name detection in the small build.
- Other languages (Arabic, Russian).
- The model's other labels: dates (TIMEX), titles (TTL), events (EVE), works of art (WOA), and
  similar. The app ignores them.
- GPU support. The model runs on the CPU only.
- Training or fine-tuning a model.
- macOS or Linux bundles. From source, a developer can download the model with a script (see
  "From source").
- A change to how the English spaCy model handles Hebrew text.

## Anti-goals (a failure even if it works)

- **A full build that updates to the small build** and loses Hebrew detection without a message.
- **A slower start that blocks the window.** The model loads in the background, with the engine.
- **Any network call during analysis.** The model and Tesseract run locally.
- **Unpinned downloads in the build.** Every downloaded file has a fixed version and a SHA-256.
- **Missing license credit.** DictaBERT NER is CC BY 4.0. Credit to Dicta is required.

## Constraints

- Single-file app: `pii_sanitizer.py`. Tests: `QT_QPA_PLATFORM=offscreen .venv/bin/python -m
  unittest discover -s tests`.
- PyInstaller one-folder build (`packaging/pii_shield.spec`): `PII-Shield.exe` and `_internal/`.
- The CI smoke test fails if the build folder holds anything other than `PII-Shield.exe` and
  `_internal/`.
- The updater (`write_update_script`) swaps only `PII-Shield.exe` and `_internal/`. It never
  touches `config.json`, `rules/` or `backups/`.
- The model is not committed to the repo (185 MB). The repo is public.
- Test values are invented only.

## Approaches

| | How the model runs | Size added | Result |
|---|---|---|---|
| **A (picked)** | 8-bit ONNX model with onnxruntime and `tokenizers` | approximately 185 MB model + 30 to 60 MB libraries | F1 0.93 in the test. 2 to 3 times faster than full precision. |
| B | PyTorch and transformers | approximately 1 to 1.5 GB | Full accuracy. The zip becomes very large and the build fragile. |
| C | Full-precision ONNX model | approximately 735 MB | F1 0.96 in the test. Use only if A loses too much accuracy. |

Model choice: **DictaBERT NER** (`dicta-il/dictabert-ner`, CC BY 4.0). The ONNX file comes from
`onnx-community/dictabert-ner-ONNX`, revision `4f0aabf58566526df6f3fb548e0fd2619fbf2b1d`, file
`onnx/model_quantized.onnx`. HeBERT NER was rejected because it has no license.

### Test result (2026-11-24, 20 invented sentences, 35 correct answers)

| Model | Size | Precision | Recall | F1 | One sentence | 200 tokens | Load |
|---|---|---|---|---|---|---|---|
| Full ONNX | 735 MB | 94% | 97% | 0.96 | 39 ms | 540 ms | approximately 10 s |
| 8-bit ONNX | 185 MB | 92% | 94% | 0.93 | 14 ms | 150 ms | approximately 2 s |

CPU: Intel Core Ultra 7 165H. One thread was faster than 8 threads. The 8-bit model missed the
city "רחובות" (also a common word) and tagged "למחלקת הכספים" as an organization. Both models
tagged "רחוב הרצל 12" as a place. That is useful, because a street address is PII.

## Design

### Where the bundled files go

All bundled files go inside `_internal/`, so the updater replaces them together with the exe:

```
PII-Shield/
  PII-Shield.exe
  _internal/
    models/dictabert-ner/        config.json, tokenizer.json, model_quantized.onnx, LICENSE.txt
    tesseract/                   tesseract.exe, its DLLs, tessdata/ (eng, heb, osd)
    THIRD_PARTY_NOTICES.txt
```

A new helper, `bundle_dir()`, returns `sys._MEIPASS` in a frozen build, and the folder of
`pii_sanitizer.py` from source.

**Change to the PDF feature:** `find_tesseract` step 2 looks in `bundle_dir() / "tesseract"`, not
in `APP_DIR / "tesseract"`. The order stays the same: the Settings path, then the bundled copy,
then `PATH`, then the Windows default folder. `APP_DIR` can point to the data folder (`PII_SHIELD_HOME`), so it is the
wrong place for program files.

### Model search order

1. `bundle_dir() / "models" / "dictabert-ner"` (the full build).
2. `APP_DIR / "models" / "dictabert-ner"` (a user or developer puts the model there by hand).

The folder is valid when it has `config.json`, `tokenizer.json` and `model_quantized.onnx`, and
when `onnxruntime` and `tokenizers` can be imported. If the folder is not valid, the app runs as the
small build and logs the reason once.

### Hebrew recognizer

A new Presidio recognizer, `HebrewNerRecognizer(EntityRecognizer)`, joins the existing registry in
`_build_registry`, when the model is valid and the setting is on.

- **Entities:** PER → `PERSON`, ORG → `ORGANIZATION`, GPE, LOC and FAC → `LOCATION`. The
  recognizer ignores all other labels.
- **Language:** the registry uses `en` only. The recognizer declares `supported_language="en"`.
  It runs on all input, but it does work only on lines that contain Hebrew letters
  (U+05D0 to U+05EA).
- **Long text:** the model takes at most 512 tokens. The recognizer joins Hebrew lines into
  chunks of up to 256 tokens, with an overlap of 50 tokens between chunks. A finding in the
  overlap is kept once. (The first draft said 400. With the real 8-bit model, a 400-token window
  missed 4 of 48 person names that 128, 200, 256 and 300-token windows all found. A smaller
  window is not slower.)
- **Offsets:** `tokenizers` gives character offsets for each token. The recognizer maps them back
  to offsets in the full input text.
- **Spans:** consecutive B- and I- tokens of the same type form one span. A span that starts with
  an I- token also starts a new span.

The builder added four steps after testing with the real model:

- **Word extension:** the model labels sub-word tokens, so a span can stop inside a word. The
  recognizer grows each span edge to the full word. Same-type spans that overlap after this
  step become one span.
- **Overlap union-merge:** the chunk overlap and the word extension can make spans that overlap,
  also of different types. The recognizer merges each group of overlapping spans into one union
  span. The type is `PERSON` if one part is `PERSON`, else the type of the best part. The score
  is the best part score. Without this step, the overlap resolution keeps only one span and can
  leave a part of a name unmasked.
- **spaCy-on-Hebrew cut with coverage give-back:** the English spaCy model reads Hebrew as noise
  and makes long, wrong spans. When the Hebrew model is on, the engine keeps only the parts of a
  spaCy span on Hebrew text that no Hebrew NER span covers. When a rule finding covers only a
  part of a Hebrew NER span (or of a propagated copy with Hebrew letters), the engine gives back
  the uncovered words as separate findings. The given-back pieces never overlap.
- **Per-call merge cutoff:** the recognizer joins two same-type spans that one gap character
  (space, `-`, maqaf, geresh) separates, but only when one of them scores under the score
  threshold of the current analyze call. Two strong spans stay two names. The engine sets the
  cutoff for each call in a context variable, so two threads with different thresholds do not
  mix.
- **Score:** the mean of the winning label's softmax value over the span's tokens. The existing
  score threshold (`engine.score_threshold`, the slider) applies, the same as for other findings.
- **Threads:** `intra_op_num_threads = 1`. The test showed that one thread is fastest.
- **Load:** the session loads in `DetectionEngine.initialize`, which already runs in the
  background. A load failure logs a warning, and the app continues without Hebrew detection.
- **Existing settings apply:** `detect_organizations` off removes Hebrew ORG findings too.
  `skip_ner_on_logs` drops Hebrew findings on log input too. The allow list applies.
- **Source label:** Hebrew findings show the recognizer name `Hebrew NER` in the review table, so
  the user can see where a finding came from.

### Settings

- New key `engine.hebrew_ner` (default `true`).
- The Settings dialog gets a "Hebrew name detection (DictaBERT NER)" checkbox.
- In the small build, the checkbox is disabled. The label says "Hebrew model not installed".
- A change takes effect when the engine reloads, the same as other detection settings.

### Self-test

`--self-test` also analyzes the invented sentence `דנה כהן נפגשה עם משה לוי בחיפה.` when the
model is valid. It fails if it finds no `PERSON`.

A new flag, `--require-hebrew`, makes `--self-test` fail when the model is missing or does not
load. The CI full job runs `--self-test --require-hebrew`, so a broken model fails the build. The
small job runs `--self-test` as today, and it also checks that the build folder contains no
`onnxruntime` files and no `models/` folder.

### Two builds in CI

`.github/workflows/build-windows.yml` changes to three jobs:

1. `build` with a matrix `flavor: [small, full]`. Each job runs the tests, builds, runs the smoke
   test and uploads its zip and SHA-256 as an artifact. It does not publish.
2. `publish` runs after both build jobs succeed. It downloads both artifacts, writes one
   `version.json` and one `root-version.json` with the small and the full fields, and (for a `v*`
   tag) creates one GitHub Release with both zips. The version and stamp checks run here once.
3. **If one build job fails, nothing is published.** A release always has both zips. A full
   install therefore always finds full fields in a new `version.json`.

The full job runs the model tests after the asset download.

| | Small | Full |
|---|---|---|
| Python packages | `requirements-build.txt` (unchanged) | also `requirements-full.txt`: pinned `onnxruntime` and `tokenizers` |
| Downloads | none | model (3 files) and Tesseract, each pinned with a SHA-256 |
| Zip name | `PII-Shield-<version>-win64.zip` (unchanged) | `PII-Shield-<version>-win64-full.zip` |
| PyInstaller | `packaging/pii_shield.spec` with `PII_SHIELD_FLAVOR=small` | same spec with `PII_SHIELD_FLAVOR=full` |

- The spec file adds the `models/` and `tesseract/` folders and collects `onnxruntime` and
  `tokenizers` only when `PII_SHIELD_FLAVOR=full`. The small build also excludes these two
  packages, so its size does not change.
- **Tesseract for the build:** a script downloads the UB Mannheim Tesseract 5.x installer (a fixed
  version and SHA-256) and extracts it with `7z x` (the installer is an NSIS package, so no install
  and no admin rights are necessary). If extraction fails, a silent install into a temp folder
  (`/S /D=<folder>`) is the fallback. It then copies
  `tesseract.exe`, its DLLs and `tessdata/` into the build. It adds `heb.traineddata` and
  `eng.traineddata` from `tessdata_best` (a fixed commit and SHA-256). The builder records the
  exact URLs and hashes in the script.
- **Model for the build:** the same script downloads the three model files from the fixed
  revision and checks each SHA-256. The CI caches the downloads.
- **One script for both CI and developers:** `packaging/fetch_full_assets.py`. It writes to
  `build-assets/` (gitignored). It downloads the Tesseract files on Windows only.

### Updater

- `version.json` gets two new fields: `windows_full_zip_url` and `windows_full_zip_sha256`.
- **"Full build" means only this:** the three model files are present in
  `bundle_dir() / "models" / "dictabert-ner"`. The check does not load the model. If onnxruntime
  fails on a machine, the install still counts as full and still updates to the full zip. A model
  that a user put in `APP_DIR/models/` by hand does not make the install "full".
- A full build updates from the full fields.
- The updater streams the download with no size limit, so a zip of 400 MB or more works.
- If a full build finds no full fields, it does not update. It shows "No full build is available
  for this version." It never falls back to the small zip.
- A small build keeps the current fields. Old installs keep working.

### Licenses and credit

- `_internal/models/dictabert-ner/LICENSE.txt`: the CC BY 4.0 credit to Dicta, with the model
  name, source and license link.
- `_internal/THIRD_PARTY_NOTICES.txt`: DictaBERT NER (CC BY 4.0), Tesseract and tessdata
  (Apache-2.0), the DLLs that the Tesseract build includes (the builder lists them and their
  licenses), and onnxruntime (MIT).
- The About text and the README name Dicta and the license.

### From source

1. A developer installs `requirements-full.txt`.
2. The developer runs `python packaging/fetch_full_assets.py --model-only`.
3. The developer copies the model folder to `models/dictabert-ner/` next to `pii_sanitizer.py`,
   or runs with `bundle_dir()` pointing there.
4. On Linux, OCR uses the system Tesseract, as today.

### Tests

- **Unit tests (no model):** a fake ONNX session that returns fixed logits. The tests cover
  chunking and overlap, offset mapping, B/I span building, label mapping, the score, Hebrew-line
  selection, the `detect_organizations` and allow-list effects, and "model missing → small build
  behavior".
- **Model tests (only when the model is present):** the 20 invented sentences from the test
  become a fixture. The test asserts F1 ≥ 0.85 and that every person name is found. The CI full
  job runs these tests after the asset download.
- **Updater tests:** a full build picks the full fields. A full build with no full fields refuses
  to update. A small build behaves as today.

### Docs

- README: a "Full build" section. It says what the full build adds, its size, the model license
  and how to run it from source.
- The release notes name both zips.

## Calls I made (the user did not decide these)

- Bundled files in `_internal/`, so the updater replaces them with the exe.
- `find_tesseract` uses `bundle_dir()`, not `APP_DIR` (a change to the PDF feature).
- Zip names: the small zip keeps its current name. The full zip adds `-full`.
- The existing score slider and settings also control Hebrew findings.
- `tessdata_best` for Hebrew and English, for accuracy over speed.
- A user can also put the model in `APP_DIR/models/` by hand.
- F1 ≥ 0.85 on the 20-sentence fixture as the regression limit.
- CI: build jobs per build type plus one publish job. No release unless both builds succeed.
- "Full build" is decided by the model files in `bundle_dir()` only, not by a successful load.
- `--require-hebrew` flag for the CI full job; content check on the small build.
- Tesseract installer extracted with `7z`, with a silent install as the fallback.

## Left to the builder

- The exact Tesseract installer version, the URLs and the SHA-256 values.
- The pinned versions of `onnxruntime` and `tokenizers`.
- The fake-session test helper.
- Internal helper names.
