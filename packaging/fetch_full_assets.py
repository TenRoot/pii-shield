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
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

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

# ---- licenses of the DLLs copied from the Tesseract installer ----
# The installer has no notice file per DLL. Each DLL is mapped here to its upstream project,
# SPDX license and project URL; THIRD_PARTY_NOTICES.txt is generated from this table. The script
# copies only the DLLs that tesseract.exe loads (see needed_dlls). A needed DLL that is not in
# this table stops the script, so an installer update cannot ship an unlisted DLL.
# DLL file name (lower case) -> (project, SPDX license, URL, extra duty or "")
LGPL_DUTY = ("LGPL: the license text and the library source must be available. The full license "
             "text, the source link and the source offer are at the end of this file. You can "
             "replace the DLL with your own build of the same version.")
GPL_DUTY = ("GPL: the license text and the complete source must be available. The full license "
            "text, the source link and the source offer are at the end of this file.")
GCC_DUTY = ("Covered by the GCC Runtime Library Exception 3.1: no source duty for programs "
            "that use it. The GPL-3.0 text and the exception text are at the end of this file.")
DLL_LICENSES: Dict[str, Tuple[str, str, str, str]] = {
    "libtesseract-5.dll": ("Tesseract OCR", "Apache-2.0", "https://github.com/tesseract-ocr/tesseract", ""),
    "libleptonica-6.dll": ("Leptonica", "BSD-2-Clause", "http://www.leptonica.org/", ""),
    "libarchive-13.dll": ("libarchive", "BSD-2-Clause", "https://www.libarchive.org/", ""),
    "libcurl-4.dll": ("curl (libcurl)", "curl", "https://curl.se/", ""),
    "libssh2-1.dll": ("libssh2", "BSD-3-Clause", "https://libssh2.org/", ""),
    "libpsl-5.dll": ("libpsl", "MIT", "https://github.com/rockdaboot/libpsl", ""),
    "libidn2-0.dll": ("GNU Libidn2", "LGPL-3.0-or-later OR GPL-2.0-or-later",
                      "https://www.gnu.org/software/libidn/", LGPL_DUTY),
    "libunistring-5.dll": ("GNU libunistring", "LGPL-3.0-or-later OR GPL-2.0-or-later",
                           "https://www.gnu.org/software/libunistring/", LGPL_DUTY),
    "libiconv-2.dll": ("GNU libiconv", "LGPL-2.1-or-later",
                       "https://www.gnu.org/software/libiconv/", LGPL_DUTY),
    "libintl-8.dll": ("GNU gettext (libintl)", "LGPL-2.1-or-later",
                      "https://www.gnu.org/software/gettext/", LGPL_DUTY),
    "libbrotlicommon.dll": ("Brotli", "MIT", "https://github.com/google/brotli", ""),
    "libbrotlidec.dll": ("Brotli", "MIT", "https://github.com/google/brotli", ""),
    "libzstd.dll": ("Zstandard", "BSD-3-Clause OR GPL-2.0-only (used under BSD-3-Clause)",
                    "https://github.com/facebook/zstd", ""),
    "zlib1.dll": ("zlib", "Zlib", "https://zlib.net/", ""),
    "libdeflate.dll": ("libdeflate", "MIT", "https://github.com/ebiggers/libdeflate", ""),
    "liblzma-5.dll": ("XZ Utils (liblzma)", "0BSD", "https://tukaani.org/xz/", ""),
    "liblz4.dll": ("LZ4", "BSD-2-Clause", "https://github.com/lz4/lz4", ""),
    "libbz2-1.dll": ("bzip2", "bzip2-1.0.6", "https://sourceware.org/bzip2/", ""),
    "libb2-1.dll": ("libb2 (BLAKE2)", "CC0-1.0 OR OpenSSL OR Apache-2.0",
                    "https://github.com/BLAKE2/libb2", ""),
    "libexpat-1.dll": ("Expat", "MIT", "https://libexpat.github.io/", ""),
    "libtiff-6.dll": ("LibTIFF", "libtiff", "https://libtiff.gitlab.io/libtiff/", ""),
    "libjpeg-8.dll": ("libjpeg-turbo", "IJG AND BSD-3-Clause AND Zlib",
                      "https://libjpeg-turbo.org/", ""),
    "libjbig-0.dll": ("JBIG-KIT", "GPL-2.0-or-later",
                      "https://www.cl.cam.ac.uk/~mgk25/jbigkit/", GPL_DUTY),
    "liblerc.dll": ("LERC (Esri)", "Apache-2.0", "https://github.com/Esri/lerc", ""),
    "libpng16-16.dll": ("libpng", "libpng-2.0", "http://www.libpng.org/pub/png/libpng.html", ""),
    "libopenjp2-7.dll": ("OpenJPEG", "BSD-2-Clause", "https://www.openjpeg.org/", ""),
    "libgif-7.dll": ("GIFLIB", "MIT", "https://giflib.sourceforge.net/", ""),
    "libwebp-7.dll": ("libwebp", "BSD-3-Clause", "https://chromium.googlesource.com/webm/libwebp", ""),
    "libwebpmux-3.dll": ("libwebp", "BSD-3-Clause", "https://chromium.googlesource.com/webm/libwebp", ""),
    "libsharpyuv-0.dll": ("libwebp (sharpyuv)", "BSD-3-Clause",
                          "https://chromium.googlesource.com/webm/libwebp", ""),
    "libgcc_s_seh-1.dll": ("GCC runtime (libgcc)", "GPL-3.0-or-later WITH GCC-exception-3.1",
                           "https://gcc.gnu.org/", GCC_DUTY),
    "libstdc++-6.dll": ("GCC runtime (libstdc++)", "GPL-3.0-or-later WITH GCC-exception-3.1",
                        "https://gcc.gnu.org/", GCC_DUTY),
    "libwinpthread-1.dll": ("mingw-w64 winpthreads", "MIT AND BSD-3-Clause",
                            "https://www.mingw-w64.org/", ""),
}

# GPL and LGPL DLLs: (source URL of the exact version, vendored license text files in
# packaging/licenses/). The versions come from the version resources and embedded strings of the
# DLLs in the pinned installer (libiconv 1.19, gettext 1.0, libidn2 2.3.8, libunistring 1.4.2);
# update them when the installer pin changes.
# The texts are the FSF texts (GPL-3.0 and LGPL-3.0 match gnu.org byte for byte; GPL-2.0 and
# LGPL-2.1 are the Debian common-licenses copies with the current FSF address). LGPL-3.0 adds
# permissions to GPL-3.0, so the GPL-3.0 text ships with it. Every DLL with a GPL or LGPL duty
# above must have an entry here (check_copyleft_sources).
LICENSES_DIR = Path(__file__).resolve().parent / "licenses"
COPYLEFT_SOURCES: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "libjbig-0.dll": ("https://www.cl.cam.ac.uk/~mgk25/jbigkit/download/jbigkit-2.1.tar.gz",
                      ("GPL-2.0.txt",)),
    "libiconv-2.dll": ("https://ftp.gnu.org/gnu/libiconv/libiconv-1.19.tar.gz", ("LGPL-2.1.txt",)),
    "libintl-8.dll": ("https://ftp.gnu.org/gnu/gettext/gettext-1.0.tar.gz", ("LGPL-2.1.txt",)),
    "libidn2-0.dll": ("https://ftp.gnu.org/gnu/libidn/libidn2-2.3.8.tar.gz",
                      ("LGPL-3.0.txt", "GPL-3.0.txt", "GPL-2.0.txt")),
    "libunistring-5.dll": ("https://ftp.gnu.org/gnu/libunistring/libunistring-1.4.2.tar.gz",
                           ("LGPL-3.0.txt", "GPL-3.0.txt", "GPL-2.0.txt")),
}
# The GCC runtime DLLs (GCC_DUTY) ship with these texts. GCC-exception-3.1.txt is COPYING.RUNTIME
# from the GCC source tree.
GCC_RUNTIME_TEXTS = ("GPL-3.0.txt", "GCC-exception-3.1.txt")
SOURCE_OFFER = ("The source code of these components is available at the URLs above; on request "
                "we provide it for at least three years. To ask for it, open an issue at "
                "https://github.com/TenRoot/pii-shield/issues.")

# License texts (files in packaging/licenses/) of every DLL in DLL_LICENSES. The permissive
# licenses (BSD, MIT, curl, libpng, IJG, ...) require the copyright notice and the license text
# in a binary distribution, so every text goes into THIRD_PARTY_NOTICES.txt, each text once.
# packaging/licenses/SOURCES.txt names the source and version of each file. A copied DLL
# without an entry here, or with a missing file, stops the script (check_dll_texts).
APACHE_TEXT = "Apache-2.0.txt"
DLL_TEXTS: Dict[str, Tuple[str, ...]] = {
    "libtesseract-5.dll": (APACHE_TEXT,),
    "libleptonica-6.dll": ("leptonica.txt",),
    "libarchive-13.dll": ("libarchive.txt",),
    "libcurl-4.dll": ("curl.txt",),
    "libssh2-1.dll": ("libssh2.txt",),
    "libpsl-5.dll": ("libpsl.txt",),
    "libidn2-0.dll": ("LGPL-3.0.txt", "GPL-3.0.txt", "GPL-2.0.txt"),
    "libunistring-5.dll": ("LGPL-3.0.txt", "GPL-3.0.txt", "GPL-2.0.txt"),
    "libiconv-2.dll": ("LGPL-2.1.txt",),
    "libintl-8.dll": ("LGPL-2.1.txt",),
    "libbrotlicommon.dll": ("brotli.txt",),
    "libbrotlidec.dll": ("brotli.txt",),
    "libzstd.dll": ("zstd.txt",),
    "zlib1.dll": ("zlib.txt",),
    "libdeflate.dll": ("libdeflate.txt",),
    "liblzma-5.dll": ("xz.txt", "xz-0BSD.txt"),
    "liblz4.dll": ("lz4.txt",),
    "libbz2-1.dll": ("bzip2.txt",),
    "libb2-1.dll": ("libb2-CC0-1.0.txt",),
    "libexpat-1.dll": ("expat.txt",),
    "libtiff-6.dll": ("libtiff.txt",),
    "libjpeg-8.dll": ("libjpeg-turbo.txt", "libjpeg-turbo-README.ijg.txt"),
    "libjbig-0.dll": ("GPL-2.0.txt",),
    "liblerc.dll": (APACHE_TEXT,),
    "libpng16-16.dll": ("libpng.txt",),
    "libopenjp2-7.dll": ("openjpeg.txt",),
    "libgif-7.dll": ("giflib.txt",),
    "libwebp-7.dll": ("libwebp.txt",),
    "libwebpmux-3.dll": ("libwebp.txt",),
    "libsharpyuv-0.dll": ("libwebp.txt",),
    "libgcc_s_seh-1.dll": GCC_RUNTIME_TEXTS,
    "libstdc++-6.dll": GCC_RUNTIME_TEXTS,
    "libwinpthread-1.dll": ("winpthreads.txt",),
}
# Copyright lines for texts that do not hold one (see SOURCES.txt).
DLL_COPYRIGHT: Dict[str, str] = {
    "liblerc.dll": "Copyright 2015-2026 Esri",
    "libgif-7.dll": "Copyright (C) Eric S. Raymond and the GIFLIB authors",
}

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
    """Download url to <dest>.part, check size and SHA-256, then rename it to dest.
    On any failure the .part file is deleted and AssetError names the file."""
    if dest.is_file() and dest.stat().st_size == size and sha256_of(dest) == sha256:
        return dest
    part = dest.with_name(dest.name + ".part")
    try:
        downloader(url, part)
        actual_size = part.stat().st_size
        actual_hash = sha256_of(part)
        if actual_size != size or actual_hash != sha256:
            raise AssetError(f"{dest.name}: size or SHA-256 mismatch (expected {size} bytes / "
                             f"{sha256}, got {actual_size} bytes / {actual_hash})")
        part.replace(dest)
    except OSError as exc:  # requests.RequestException is an OSError subclass
        part.unlink(missing_ok=True)
        raise AssetError(f"{dest.name}: {exc}") from exc
    except BaseException:  # AssetError, Ctrl+C, anything else: never leave a .part
        part.unlink(missing_ok=True)
        raise
    return dest


def model_license_text() -> str:
    return (
        "DictaBERT NER model files\n"
        "=========================\n"
        "Model: dicta-il/dictabert-ner, https://huggingface.co/dicta-il/dictabert-ner\n"
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


def silent_install_command(installer: Path, target: Path) -> str:
    """NSIS wants /D= last and unquoted, also with spaces in the path. A list argument would
    make subprocess quote the whole "/D=..." and NSIS rejects that, so pass one string."""
    return f'"{installer}" /S /D={target}'


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
    res = subprocess.run(silent_install_command(installer, target))
    if res.returncode != 0 or not (target / "tesseract.exe").is_file():
        raise AssetError("Could not unpack the Tesseract installer (7z and /S both failed).")


# ---- PE import tables (pure Python: the script runs on Windows CI, where objdump is absent) ----
def pe_imports(path: Path) -> List[str]:
    """DLL names in the import and delay-import tables of a PE file. Static imports only:
    a DLL loaded with LoadLibrary at run time does not show here."""
    data = path.read_bytes()
    try:
        if data[:2] != b"MZ":
            raise ValueError("no MZ header")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("no PE signature")
        n_sections, opt_size = struct.unpack_from("<H", data, pe + 6)[0], \
            struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        dirs = opt + {0x10B: 96, 0x20B: 112}[magic]
        n_dirs = struct.unpack_from("<I", data, dirs - 4)[0]
        sections = []
        for i in range(n_sections):
            sh = opt + opt_size + 40 * i
            vsize, va, rsize, raw = struct.unpack_from("<IIII", data, sh + 8)
            sections.append((va, max(vsize, rsize), raw))

        def off(rva: int) -> int:
            for va, size, raw in sections:
                if va <= rva < va + size:
                    return raw + rva - va
            raise ValueError(f"RVA {rva:#x} outside the sections")

        def cstr(rva: int) -> str:
            o = off(rva)
            return data[o:data.index(b"\0", o)].decode("ascii")

        names: List[str] = []
        for index, entry_size, name_at in ((1, 20, 12), (13, 32, 4)):  # import, delay import
            if index >= n_dirs:
                continue
            rva = struct.unpack_from("<I", data, dirs + 8 * index)[0]
            if not rva:
                continue
            o = off(rva)
            while True:
                entry = data[o:o + entry_size]
                if len(entry) < entry_size or not any(entry):
                    break
                name_rva = struct.unpack_from("<I", entry, name_at)[0]
                if not name_rva:
                    break
                names.append(cstr(name_rva))
                o += entry_size
        return names
    except (ValueError, KeyError, struct.error) as exc:
        raise AssetError(f"{path.name}: cannot read the PE import table ({exc})") from exc


def needed_dlls(folder: Path, exe: str = "tesseract.exe") -> List[str]:
    """The DLLs in folder that exe loads, directly or through other DLLs in folder.
    DLLs not in folder (Windows system DLLs) are skipped."""
    present = {p.name.lower(): p.name for p in folder.glob("*.dll")}
    seen: Dict[str, str] = {}
    todo = [folder / exe]
    while todo:
        for name in pe_imports(todo.pop()):
            key = name.lower()
            if key in present and key not in seen:
                seen[key] = present[key]
                todo.append(folder / present[key])
    return sorted(seen.values(), key=str.lower)


def check_dll_licenses(dlls: Iterable[str]) -> None:
    dlls = list(dlls)
    missing = sorted(d for d in dlls if d.lower() not in DLL_LICENSES)
    if missing:
        raise AssetError("DLL not in the license table: " + ", ".join(missing) +
                         ". Add each one to DLL_LICENSES in packaging/fetch_full_assets.py "
                         "with its upstream project and license.")
    check_dll_texts(dlls)


def check_dll_texts(dlls: Iterable[str]) -> None:
    """Every DLL needs its license text files in packaging/licenses/."""
    bad = sorted(d for d in dlls if not DLL_TEXTS.get(d.lower())
                 or not all((LICENSES_DIR / f).is_file() for f in DLL_TEXTS[d.lower()]))
    if bad:
        raise AssetError("DLL without a license text file: " + ", ".join(bad) +
                         ". Add its license text to packaging/licenses/ (record the source in "
                         "SOURCES.txt) and map it in DLL_TEXTS in packaging/fetch_full_assets.py.")


def license_texts_section(users: Dict[str, List[str]]) -> List[str]:
    """The full text of each file in users (file name -> components that use it), each once,
    in the order of users."""
    lines: List[str] = []
    for name, who in users.items():
        title = "License text: " + name[:-len(".txt")]
        lines += ["", title, "-" * len(title), "Used by: " + ", ".join(who) + ".", "",
                  (LICENSES_DIR / name).read_text(encoding="utf-8").strip()]
    return lines


def _use(users: Dict[str, List[str]], files: Iterable[str], who: str) -> None:
    for f in files:
        if who not in users.setdefault(f, []):
            users[f].append(who)


def thirdparty_notices(dlls: List[str], tesseract_license: str, tesseract: bool = True) -> str:
    """Notices for what was fetched. tesseract=False: the model build (model, onnxruntime,
    tokenizers only)."""
    lines = [
        "PII Shield third-party notices",
        "==============================",
        "",
        "DictaBERT NER (dicta-il/dictabert-ner)",
        "  License: CC BY 4.0, https://creativecommons.org/licenses/by/4.0/",
        f"  ONNX conversion: {MODEL_REPO}, revision {MODEL_REVISION}",
        "  Author: Dicta. The files are used unchanged.",
        "",
        "onnxruntime",
        "  License: MIT, https://github.com/microsoft/onnxruntime/blob/main/LICENSE",
        "  Copyright (c) Microsoft Corporation. The license text is at the end of this file.",
        "",
        "tokenizers (Hugging Face)",
        "  License: Apache License 2.0, https://github.com/huggingface/tokenizers",
        "  Copyright: the tokenizers authors (Anthony Moi, Nicolas Patry, Hugging Face, Inc.)",
        "  and contributors. The license text is at the end of this file.",
    ]
    users: Dict[str, List[str]] = {}
    _use(users, ["onnxruntime.txt"], "onnxruntime")
    _use(users, [APACHE_TEXT], "tokenizers")
    if not tesseract:
        return "\n".join(lines + license_texts_section(users) + [""])
    check_dll_licenses(dlls)
    copyleft = copyleft_section(dlls)
    _use(users, [APACHE_TEXT], "Tesseract OCR")
    _use(users, [APACHE_TEXT], "tessdata_best")
    lines += [
        "",
        "Tesseract OCR (UB Mannheim Windows build %s)" % TESSERACT_VERSION,
        "  License: Apache License 2.0, https://www.apache.org/licenses/LICENSE-2.0",
        "  Copyright: Hewlett-Packard Company, Google Inc. and the Tesseract contributors.",
        "  Source: https://github.com/tesseract-ocr/tesseract",
        "",
        "tessdata_best (heb, eng, osd trained data)",
        "  License: Apache License 2.0",
        f"  Source: https://github.com/tesseract-ocr/tessdata_best (commit {TESSDATA_COMMIT})",
        "",
        "Libraries copied from the Tesseract installer (folder tesseract/)",
        "  The installer has no notice file for each library. Each library keeps the license",
        "  of its upstream project, given below as an SPDX identifier. The full license texts,",
        "  with the copyright notices, are at the end of this file.",
    ]
    for d in sorted(dlls, key=str.lower):
        project, spdx, url, duty = DLL_LICENSES[d.lower()]
        texts = DLL_TEXTS[d.lower()]
        lines += ["", f"  {d}", f"    Project: {project}", f"    License: {spdx}", f"    URL: {url}"]
        if d.lower() in DLL_COPYRIGHT:
            lines.append(f"    {DLL_COPYRIGHT[d.lower()]}")
        lines.append("    License text: " + ", ".join(t[:-len(".txt")] for t in texts))
        if duty:
            lines.append(f"    Note: {duty}")
        _use(users, texts, d)
    # The installer's doc/LICENSE is the Apache-2.0 text; print it only if it differs.
    if tesseract_license.split() != (LICENSES_DIR / APACHE_TEXT).read_text(encoding="utf-8").split():
        lines += ["", "Tesseract license text (doc/LICENSE in the installer)",
                  "-----------------------------------------------------", tesseract_license.strip()]
    lines += copyleft
    lines += ["", "License texts", "============="] + license_texts_section(users)
    return "\n".join(lines + [""])


def check_copyleft_sources() -> None:
    missing = sorted(d for d, (_, _, _, duty) in DLL_LICENSES.items()
                     if duty in (GPL_DUTY, LGPL_DUTY) and d not in COPYLEFT_SOURCES)
    if missing:
        raise AssetError("GPL or LGPL DLL without a source link and license text: " +
                         ", ".join(missing) + ". Add each one to COPYLEFT_SOURCES.")


def copyleft_section(dlls: List[str]) -> List[str]:
    """Source links and the written source offer for the GPL and LGPL DLLs in dlls, and a note
    for the GCC runtime DLLs. Empty when there are none. The license texts are in the license
    texts section (DLL_TEXTS)."""
    check_copyleft_sources()
    present = sorted((d for d in dlls if d.lower() in COPYLEFT_SOURCES), key=str.lower)
    gcc = sorted((d for d in dlls if d.lower() in DLL_LICENSES
                  and DLL_LICENSES[d.lower()][3] == GCC_DUTY), key=str.lower)
    if not present and not gcc:
        return []
    lines: List[str] = []
    if present:
        lines += ["", "GPL and LGPL components: source code", "------------------------------------"]
        for d in present:
            project, spdx, _, _ = DLL_LICENSES[d.lower()]
            url, files = COPYLEFT_SOURCES[d.lower()]
            lines += [f"  {d} ({project}, {spdx})", f"    Source: {url}"]
        lines += ["", SOURCE_OFFER]
    if gcc:
        lines += ["", "GCC runtime libraries", "---------------------",
                  f"  {', '.join(gcc)}: GPL-3.0-or-later WITH GCC-exception-3.1. The GPL-3.0 "
                  "text and the GCC Runtime Library Exception 3.1 text are at the end of this "
                  "file."]
    return lines


def fetch_tesseract(dest: Path, downloader: Downloader = http_download) -> Path:
    out = dest / "tesseract"
    if out.exists():  # old files (a DLL of an earlier installer) must not ship
        shutil.rmtree(out)
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
        # only the DLLs tesseract.exe loads; the installer also holds the training tools'
        # libraries (pango, cairo, ICU, ...), which tesseract.exe never loads
        dlls = needed_dlls(unpacked)
        check_dll_licenses(dlls)
        for name in dlls:
            shutil.copy2(unpacked / name, out / name)
        licence = unpacked / "doc" / "LICENSE"
        if not licence.is_file():
            raise AssetError("doc/LICENSE: the Tesseract installer holds no license file. "
                             "Check the installer pin.")
        licence_text = licence.read_text(encoding="utf-8", errors="replace")
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
    (dest / "THIRD_PARTY_NOTICES.txt").write_text(thirdparty_notices([], "", tesseract=False),
                                                  encoding="utf-8")


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
    except AssetError as exc:  # its message starts with the file name
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:  # also requests.RequestException, an OSError subclass
        name = Path(exc.filename).name if getattr(exc, "filename", None) else "download"
        print(f"ERROR: {name}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
