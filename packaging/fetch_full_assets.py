#!/usr/bin/env python3
"""Download the assets for the PII Shield full build into build-assets/.

    python packaging/fetch_full_assets.py [--dest build-assets] [--model-only] [--install-dev]

The model files always download. The Tesseract files download only on Windows
(os.name == "nt") and only without --model-only. Every file is checked for size and
SHA-256. A mismatch deletes the file and stops the script with a non-zero exit code.
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent

# ---- model pin (onnx-community/dictabert-ner-ONNX) ----
MODEL_REPO = "onnx-community/dictabert-ner-ONNX"
MODEL_REVISION = "4f0aabf58566526df6f3fb548e0fd2619fbf2b1d"
MODEL_DIRNAME = "dictabert-ner"
# (path in the repo, local file name, SHA-256, size in bytes)
MODEL_FILES = [
    ("config.json", "config.json",
     "ba12e2d104a01d60b22641dcdedd6d01a7743be917d489ab60f0722953232336", 1690),
    ("tokenizer.json", "tokenizer.json",
     "00657b39a8a73b96ddcc3cda245c5e8fa02be36e31e318bd13a9169eb89c999b", 3577623),
    ("onnx/model_quantized.onnx", "model_quantized.onnx",
     "fd7ac841768f11197e1d46ea6bbfe82d9cd9e21289be8761af63dbc996a32007", 184984466),
]

# ---- Tesseract pin (UB Mannheim build, 5.5.3.20260724) ----
# The UB Mannheim wiki links this file on the tesseract-ocr/tesseract release page.
TESSERACT_INSTALLER_URL = ("https://github.com/tesseract-ocr/tesseract/releases/download/"
                           "5.5.3/tesseract-ocr-w64-setup-5.5.3.20260724.exe")
TESSERACT_INSTALLER_SHA256 = "bee9e3434bd94fd65387d9be28cd467a41f61b1275383b55b0f59a1331270ae4"
TESSERACT_INSTALLER_SIZE = 26573224
TESSERACT_VERSION = "5.5.3.20260724"

# tesseract-ocr/tessdata_best at a pinned commit (2024-03-09)
TESSDATA_COMMIT = "e12c65a915945e4c28e237a9b52bc4a8f39a0cec"
TESSDATA_URL = "https://github.com/tesseract-ocr/tessdata_best/raw/%s/{name}" % TESSDATA_COMMIT
# (file name, SHA-256, size in bytes)
TESSDATA_FILES = [
    ("heb.traineddata",
     "dbaa827aea6bc21215638447f17783a1004987c2d0bf5573d111fee397abdae5", 3704077),
    ("eng.traineddata",
     "8280aed0782fe27257a68ea10fe7ef324ca0f8d85bd2fd145d1c2b560bcb66ba", 15400601),
    # The installer holds no osd.traineddata, so it comes from tessdata_best too.
    ("osd.traineddata",
     "9cf5d576fcc47564f11265841e5ca839001e7e6f38ff7f7aacf46d15a96b00ff", 10562727),
]

TIMEOUT = 60
CHUNK = 1 << 20

Downloader = Callable[[str, Path], None]


class AssetError(Exception):
    """A download failed its size or hash check, or a tool failed."""


def http_download(url: str, dest: Path) -> None:
    import requests
    dest.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(url, stream=True, timeout=TIMEOUT) as r:
        r.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in r.iter_content(CHUNK):
                f.write(chunk)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_verified(url: str, dest: Path, sha256: str, size: int,
                   downloader: Downloader = http_download) -> Path:
    """Download url to dest and check size and SHA-256. A bad file is deleted."""
    if dest.is_file() and dest.stat().st_size == size and sha256_of(dest) == sha256:
        return dest
    downloader(url, dest)
    actual_size = dest.stat().st_size
    actual_hash = sha256_of(dest)
    if actual_size != size or actual_hash != sha256:
        dest.unlink()
        raise AssetError(f"{dest.name}: size or SHA-256 mismatch "
                         f"(expected {size} bytes / {sha256}, got {actual_size} bytes / {actual_hash})")
    return dest


def model_license_text() -> str:
    return (
        "DictaBERT NER model files\n"
        "=========================\n"
        "Model: dicta-il/dictabert-ner\n"
        "Author: Dicta (Dicta - The Israel Center for Text Analysis)\n"
        f"ONNX conversion: {MODEL_REPO}, revision {MODEL_REVISION}\n"
        "License: Creative Commons Attribution 4.0 International (CC BY 4.0)\n"
        "License text: https://creativecommons.org/licenses/by/4.0/\n"
        "The conversion to ONNX and the int8 quantization were made by the "
        "onnx-community project. PII Shield uses the files unchanged.\n"
    )


def fetch_model(dest: Path, downloader: Downloader = http_download) -> Path:
    out = dest / "models" / MODEL_DIRNAME
    out.mkdir(parents=True, exist_ok=True)
    for repo_path, local, sha, size in MODEL_FILES:
        url = f"https://huggingface.co/{MODEL_REPO}/resolve/{MODEL_REVISION}/{repo_path}"
        print(f"model: {local}")
        fetch_verified(url, out / local, sha, size, downloader)
    (out / "LICENSE.txt").write_text(model_license_text(), encoding="utf-8")
    return out


def find_7z() -> Optional[str]:
    for name in ("7z", "7z.exe"):
        found = shutil.which(name)
        if found:
            return found
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if base and (Path(base) / "7-Zip" / "7z.exe").is_file():
            return str(Path(base) / "7-Zip" / "7z.exe")
    return None


def extract_installer(installer: Path, target: Path) -> None:
    """Unpack the NSIS installer with 7z. Fallback: run it silently into target."""
    target.mkdir(parents=True, exist_ok=True)
    seven = find_7z()
    if seven:
        res = subprocess.run([seven, "x", "-y", f"-o{target}", str(installer)],
                             capture_output=True, text=True)
        if res.returncode == 0 and (target / "tesseract.exe").is_file():
            return
        print("7z could not unpack the installer; trying a silent install.")
    res = subprocess.run([str(installer), "/S", f"/D={target}"])
    if res.returncode != 0 or not (target / "tesseract.exe").is_file():
        raise AssetError("Could not unpack the Tesseract installer (7z and /S both failed).")


def thirdparty_notices(dlls: List[str], tesseract_license: str) -> str:
    lines = [
        "PII Shield third-party notices",
        "==============================",
        "",
        "DictaBERT NER (dicta-il/dictabert-ner)",
        "  License: CC BY 4.0, https://creativecommons.org/licenses/by/4.0/",
        f"  ONNX conversion: {MODEL_REPO}, revision {MODEL_REVISION}",
        "  Author: Dicta. The files are used unchanged.",
        "",
        "Tesseract OCR (UB Mannheim Windows build %s)" % TESSERACT_VERSION,
        "  License: Apache License 2.0, https://www.apache.org/licenses/LICENSE-2.0",
        "  Source: https://github.com/tesseract-ocr/tesseract",
        "",
        "tessdata_best (heb, eng, osd trained data)",
        "  License: Apache License 2.0",
        f"  Source: https://github.com/tesseract-ocr/tessdata_best (commit {TESSDATA_COMMIT})",
        "",
        "onnxruntime",
        "  License: MIT, https://github.com/microsoft/onnxruntime/blob/main/LICENSE",
        "",
        "tokenizers (Hugging Face)",
        "  License: Apache License 2.0, https://github.com/huggingface/tokenizers",
        "",
        "Libraries copied from the Tesseract installer (folder tesseract/)",
        "  The installer has no notice file for each library. It has one license file,",
        "  the Tesseract Apache License 2.0, which is copied to tesseract/LICENSE.",
        "  Each library below keeps the license of its own upstream project.",
    ]
    lines += [f"    {d}" for d in sorted(dlls)]
    lines += ["", "Tesseract license text", "----------------------", tesseract_license.strip(), ""]
    return "\n".join(lines)


def fetch_tesseract(dest: Path, downloader: Downloader = http_download) -> Path:
    out = dest / "tesseract"
    tessdata = out / "tessdata"
    tessdata.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="pii-tess-"))
    try:
        print("tesseract: installer")
        installer = fetch_verified(TESSERACT_INSTALLER_URL, work / "tesseract-setup.exe",
                                   TESSERACT_INSTALLER_SHA256, TESSERACT_INSTALLER_SIZE, downloader)
        unpacked = work / "unpacked"
        extract_installer(installer, unpacked)
        shutil.copy2(unpacked / "tesseract.exe", out / "tesseract.exe")
        dlls = []
        for dll in sorted(unpacked.glob("*.dll")):
            shutil.copy2(dll, out / dll.name)
            dlls.append(dll.name)
        licence = unpacked / "doc" / "LICENSE"
        licence_text = licence.read_text(encoding="utf-8", errors="replace") if licence.is_file() else ""
        (out / "LICENSE").write_text(licence_text, encoding="utf-8")
        osd = unpacked / "tessdata" / "osd.traineddata"
        if osd.is_file():
            shutil.copy2(osd, tessdata / "osd.traineddata")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for name, sha, size in TESSDATA_FILES:
        if name == "osd.traineddata" and (tessdata / name).is_file():
            continue
        print(f"tesseract: {name}")
        fetch_verified(TESSDATA_URL.format(name=name), tessdata / name, sha, size, downloader)
    (dest / "THIRD_PARTY_NOTICES.txt").write_text(thirdparty_notices(dlls, licence_text),
                                                  encoding="utf-8")
    return out


def write_model_only_notices(dest: Path) -> None:
    (dest / "THIRD_PARTY_NOTICES.txt").write_text(thirdparty_notices([], ""), encoding="utf-8")


def install_dev(dest: Path, root: Path = ROOT) -> Path:
    src = dest / "models" / MODEL_DIRNAME
    target = root / "models" / MODEL_DIRNAME
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(src, target)
    return target


def run(dest: Path, model_only: bool, dev: bool, downloader: Downloader = http_download,
        root: Path = ROOT, windows: Optional[bool] = None) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    fetch_model(dest, downloader)
    if not model_only and (os.name == "nt" if windows is None else windows):
        fetch_tesseract(dest, downloader)
    else:
        write_model_only_notices(dest)
    if dev:
        print(f"dev copy: {install_dev(dest, root)}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dest", default=str(ROOT / "build-assets"))
    ap.add_argument("--model-only", action="store_true", help="skip the Tesseract files")
    ap.add_argument("--install-dev", action="store_true",
                    help="copy the model to models/ next to pii_sanitizer.py")
    args = ap.parse_args(argv)
    try:
        run(Path(args.dest), args.model_only, args.install_dev, downloader=http_download)
    except AssetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
