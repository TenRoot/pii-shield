# PyInstaller spec for the portable PII Shield build (one folder: PII-Shield.exe + _internal/).
# Build from the repo root:  pyinstaller --noconfirm packaging/pii_shield.spec
from PyInstaller.utils.hooks import collect_all, copy_metadata

datas, binaries, hiddenimports = [], [], []
# spaCy and Presidio load models, configs and registered functions at runtime (data files,
# entry points, dynamic imports), so collect each package whole, with its dist metadata.
for pkg in ("spacy", "thinc", "en_core_web_lg", "presidio_analyzer", "presidio_anonymizer", "tldextract",
            "phonenumbers", "srsly", "blis", "cymem", "preshed", "murmurhash", "catalogue", "confection",
            "spacy_legacy", "spacy_loggers", "weasel", "wasabi"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h
# spacy.util.is_package() and the PyPI version check read these through importlib.metadata
for dist in ("spacy", "en_core_web_lg", "thinc", "presidio-analyzer", "presidio-anonymizer",
             "spacy-legacy", "spacy-loggers", "requests", "keyring"):
    datas += copy_metadata(dist)
hiddenimports += ["keyring.backends.Windows", "keyring.backends.fail", "keyring.backends.null"]

a = Analysis(
    ["../pii_sanitizer.py"],
    datas=datas,
    binaries=binaries,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "matplotlib", "torch", "tensorflow", "transformers", "IPython", "pytest"],
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
