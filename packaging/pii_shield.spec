# PyInstaller spec for the portable PII Shield build (one folder: PII-Shield.exe + _internal/).
# Build from the repo root:  pyinstaller --noconfirm packaging/pii_shield.spec
# PII_SHIELD_FLAVOR selects the build: "small" (default) or "full". The full build also bundles
# onnxruntime, tokenizers, the Hebrew NER model, Tesseract and THIRD_PARTY_NOTICES.txt. Run
# python packaging/fetch_full_assets.py --dest build-assets first (on Windows, for Tesseract).
import os

from PyInstaller.utils.hooks import collect_all, copy_metadata

FLAVOR = os.environ.get("PII_SHIELD_FLAVOR", "small").strip().lower() or "small"
if FLAVOR not in ("small", "full"):
    raise SystemExit(f"PII_SHIELD_FLAVOR must be 'small' or 'full', not {FLAVOR!r}.")
# Relative to the repo root, not to the current folder: PyInstaller resolves relative data
# sources against the spec folder (SPECPATH).
ASSETS = os.path.normpath(os.path.join(SPECPATH, "..", "build-assets"))

datas, binaries, hiddenimports = [], [], []
# spaCy and Presidio load models, configs and registered functions at runtime (data files,
# entry points, dynamic imports), so collect each package whole, with its dist metadata.
for pkg in ("spacy", "thinc", "en_core_web_lg", "presidio_analyzer", "presidio_anonymizer", "tldextract",
            "phonenumbers", "srsly", "blis", "cymem", "preshed", "murmurhash", "catalogue", "confection",
            "spacy_legacy", "spacy_loggers", "weasel", "wasabi", "pypdfium2", "pypdfium2_raw"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h
# spacy.util.is_package() and the PyPI version check read these through importlib.metadata
for dist in ("spacy", "en_core_web_lg", "thinc", "presidio-analyzer", "presidio-anonymizer",
             "spacy-legacy", "spacy-loggers", "requests", "keyring", "pypdfium2"):
    datas += copy_metadata(dist)
hiddenimports += ["keyring.backends.Windows", "keyring.backends.fail", "keyring.backends.null"]

excludes = ["tkinter", "matplotlib", "torch", "tensorflow", "transformers", "IPython", "pytest"]
if FLAVOR == "full":
    for pkg in ("onnxruntime", "tokenizers"):
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    # (source in build-assets/, folder in _internal/, folder or file)
    model = os.path.join("models", "dictabert-ner")
    full_assets = [(model, model, True), ("tesseract", "tesseract", True),
                   ("THIRD_PARTY_NOTICES.txt", ".", False)]
    for src, dest, is_dir in full_assets:
        path = os.path.join(ASSETS, src)
        if not (os.path.isdir(path) if is_dir else os.path.isfile(path)):
            raise SystemExit(f"Full build: {path} is missing. Run 'python "
                             "packaging/fetch_full_assets.py --dest build-assets' on Windows first.")
        datas.append((path, dest))
else:
    # The small build must not grow if these packages are installed in the build environment.
    excludes += ["onnxruntime", "tokenizers"]

a = Analysis(
    ["../pii_sanitizer.py"],
    datas=datas,
    binaries=binaries,
    hiddenimports=hiddenimports,
    excludes=excludes,
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PII-Shield",
    console=False,          # GUI app; use --log-file for CLI output (--self-test, --validate-rules)
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="PII-Shield", upx=False)
