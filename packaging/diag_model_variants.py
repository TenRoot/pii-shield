"""Diagnostic (temporary): F1 of the DictaBERT NER model files on THIS machine's CPU.

8-bit ONNX models can lose accuracy on CPUs without VNNI instructions. This script scores each
model file of the pinned onnx-community/dictabert-ner-ONNX revision on the 20 invented
fixture sentences (tests/fixtures/hebrew_ner_sentences.json) and prints one line per file.

Usage: python packaging/diag_model_variants.py [--dest build-assets/diag]
Every download is checked against the pinned size and SHA-256 before use.
"""
import argparse
import hashlib
import json
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

REPO = "https://huggingface.co/onnx-community/dictabert-ner-ONNX/resolve/4f0aabf58566526df6f3fb548e0fd2619fbf2b1d/"
# (label, file, size, sha256). model_int8.onnx has the same bytes as model_quantized.onnx.
VARIANTS = [
    ("model_quantized (= model_int8)", "onnx/model_quantized.onnx", 184984466,
     "fd7ac841768f11197e1d46ea6bbfe82d9cd9e21289be8761af63dbc996a32007"),
    ("model_uint8", "onnx/model_uint8.onnx", 184984466,
     "7e822a39c03add6a3c334253688d1d2bc16cbecc55072056fa6fc89bdb582e57"),
    ("model (full precision, baseline)", "onnx/model.onnx", None, None),
]
SUPPORT = [("config.json", 1690, "ba12e2d104a01d60b22641dcdedd6d01a7743be917d489ab60f0722953232336"),
           ("tokenizer.json", 3577623, "00657b39a8a73b96ddcc3cda245c5e8fa02be36e31e318bd13a9169eb89c999b")]


def fetch(name: str, dest: Path, size, sha) -> Path:
    import requests
    out = dest / name.replace("/", "_")
    if not out.exists() or (size and out.stat().st_size != size):
        part = out.with_suffix(out.suffix + ".part")
        with requests.get(REPO + name, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(part, "wb") as fh:
                for chunk in r.iter_content(1 << 20):
                    fh.write(chunk)
        part.replace(out)
    h = hashlib.sha256(out.read_bytes()).hexdigest()
    if sha and h != sha:
        out.unlink()
        raise SystemExit(f"ERROR: {name}: SHA-256 {h} does not match the pin")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default=str(ROOT / "build-assets" / "diag"))
    args = ap.parse_args()
    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)

    import onnxruntime as ort
    from tokenizers import Tokenizer
    import pii_sanitizer as ps
    import test_hebrew_ner as T

    print(f"machine: {platform.platform()} | processor: {platform.processor()} | "
          f"onnxruntime {ort.__version__}", flush=True)
    cfg = json.loads(fetch("config.json", dest, *SUPPORT[0][1:]).read_text("utf-8"))
    tok_path = fetch("tokenizer.json", dest, *SUPPORT[1][1:])
    id2label = {int(k): v for k, v in cfg["id2label"].items()}
    items = json.loads(T.FIXTURE.read_text(encoding="utf-8"))
    for label, name, size, sha in VARIANTS:
        path = fetch(name, dest, size, sha)
        tok = Tokenizer.from_file(str(tok_path))
        tok.no_truncation()
        tok.no_padding()
        so = ort.SessionOptions()
        so.intra_op_num_threads = 1
        sess = ort.InferenceSession(str(path), so, providers=["CPUExecutionProvider"])
        model = ps.HebrewNerModel(tok, sess, id2label)
        t = time.time()
        tp, fp, fn, missed, extra = T._score(model, items)
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        print(f"{label}: F1={f1:.3f} P={p:.3f} R={r:.3f} tp={tp} fp={fp} fn={fn} "
              f"seconds={time.time() - t:.1f} missed={missed} extra={extra}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
