"""Hebrew NER tests:  python -m unittest discover -s tests -v"""
import os
import re
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pii_sanitizer as ps  # noqa: E402


def make_model(root: Path, names=ps.HEBREW_MODEL_FILES) -> Path:
    d = root / "models" / ps.HEBREW_MODEL_DIRNAME
    d.mkdir(parents=True)
    for n in names:
        (d / n).write_bytes(b"x")
    return d


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_is_full_build_needs_all_three_files(self):
        bundle = self.tmp / "bundle"
        make_model(bundle, ps.HEBREW_MODEL_FILES[:2])
        with mock.patch.object(ps, "bundle_dir", return_value=bundle):
            self.assertFalse(ps.is_full_build())
        (bundle / "models" / ps.HEBREW_MODEL_DIRNAME / ps.HEBREW_MODEL_FILES[2]).write_bytes(b"x")
        with mock.patch.object(ps, "bundle_dir", return_value=bundle):
            self.assertTrue(ps.is_full_build())

    def test_full_build_ignores_app_dir_model(self):
        app, bundle = self.tmp / "app", self.tmp / "bundle"
        bundle.mkdir()
        model = make_model(app)
        with mock.patch.object(ps, "bundle_dir", return_value=bundle), \
             mock.patch.object(ps, "APP_DIR", app):
            self.assertFalse(ps.is_full_build())
            self.assertEqual(ps.find_hebrew_model(), model)

    def test_find_hebrew_model_prefers_bundle(self):
        app, bundle = self.tmp / "app", self.tmp / "bundle"
        make_model(app)
        model = make_model(bundle)
        with mock.patch.object(ps, "bundle_dir", return_value=bundle), \
             mock.patch.object(ps, "APP_DIR", app):
            self.assertEqual(ps.find_hebrew_model(), model)

    def test_find_hebrew_model_none(self):
        with mock.patch.object(ps, "bundle_dir", return_value=self.tmp / "b"), \
             mock.patch.object(ps, "APP_DIR", self.tmp / "a"):
            self.assertIsNone(ps.find_hebrew_model())

    def test_bundle_dir_frozen(self):
        with mock.patch.object(sys, "frozen", True, create=True), \
             mock.patch.object(sys, "_MEIPASS", str(self.tmp), create=True):
            self.assertEqual(ps.bundle_dir(), self.tmp)
        self.assertEqual(ps.bundle_dir(), Path(ps.__file__).resolve().parent)

    def test_defaults(self):
        self.assertTrue(ps.DEFAULT_CONFIG["engine"]["hebrew_ner"])
        self.assertEqual(ps.SOURCE_LABEL["hebrew_ner"], "Hebrew NER")
        self.assertEqual(ps.SOURCE_PRIORITY["hebrew_ner"], ps.SOURCE_PRIORITY["presidio"])


class FakeEnc:
    def __init__(self, ids, offsets):
        self.ids, self.offsets = ids, offsets
        self.word_ids = [None if o == (0, 0) else i for i, o in enumerate(offsets)]


class FakeTokenizer:
    CLS, SEP = 1, 2

    def __init__(self):
        self.vocab = {}

    def token_to_id(self, tok):
        return {"[CLS]": self.CLS, "[SEP]": self.SEP}[tok]

    def encode(self, text, add_special_tokens=True):
        ids, offs = [], []
        for m in re.finditer(r"\S+", text):
            ids.append(self.vocab.setdefault(m.group(), 10 + len(self.vocab)))
            offs.append((m.start(), m.end()))
        if add_special_tokens:
            ids, offs = [self.CLS] + ids + [self.SEP], [(0, 0)] + offs + [(0, 0)]
        return FakeEnc(ids, offs)


class FakeSession:
    LABELS = ["O", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-GPE", "I-GPE", "B-TIMEX", "I-TIMEX"]

    def __init__(self, tok, table, with_type_ids=False):
        self.tok, self.table, self.calls = tok, table, []
        self.names = ["input_ids", "attention_mask"] + (["token_type_ids"] if with_type_ids else [])

    def get_inputs(self):
        return [types.SimpleNamespace(name=n) for n in self.names]

    def run(self, _outputs, feeds):
        self.calls.append(feeds)
        inv = {v: k for k, v in self.tok.vocab.items()}
        out = np.zeros((1, feeds["input_ids"].shape[1], len(self.LABELS)))
        for i, tid in enumerate(feeds["input_ids"][0]):
            out[0, i, self.LABELS.index(self.table.get(inv.get(int(tid)), "O"))] = 10.0
        return [out]


def build(table, with_type_ids=False, **kw):
    tok = FakeTokenizer()
    sess = FakeSession(tok, table, with_type_ids)
    id2label = dict(enumerate(FakeSession.LABELS))
    return ps.HebrewNerModel(tok, sess, id2label, **kw), sess


class HebrewNerCoreTests(unittest.TestCase):
    def spans(self, model, text):
        return [(text[s.start:s.end], s.entity) for s in model.predict(text)]

    def test_person_and_place(self):
        text = "דנה כהן נפגשה בחיפה"
        model, _ = build({"דנה": "B-PER", "כהן": "I-PER", "בחיפה": "B-GPE"})
        self.assertEqual(self.spans(model, text), [("דנה כהן", "PERSON"), ("בחיפה", "LOCATION")])
        self.assertGreater(model.predict(text)[0].score, 0.99)

    def test_ignored_labels_dropped(self):
        model, _ = build({"מחר": "B-TIMEX"})
        self.assertEqual(model.predict("נפגש מחר"), [])

    def test_i_after_o_starts_new_span(self):
        model, _ = build({"דנה": "B-PER", "כהן": "I-PER", "לוי": "I-PER", "משה": "I-ORG"})
        text = "דנה כהן נפגשה לוי משה"
        self.assertEqual(self.spans(model, text),
                         [("דנה כהן", "PERSON"), ("לוי", "PERSON"), ("משה", "ORGANIZATION")])

    def test_english_only_text_never_calls_session(self):
        model, sess = build({"John": "B-PER"})
        self.assertEqual(model.predict("John Smith met SRV-DC01"), [])
        self.assertEqual(len(sess.calls), 0)

    def test_offsets_map_back_in_mixed_text(self):
        text = "Ticket 12\nשם: דנה כהן\nEnd"
        model, _ = build({"דנה": "B-PER", "כהן": "I-PER"})
        spans = model.predict(text)
        self.assertEqual(len(spans), 1)
        self.assertEqual(text[spans[0].start:spans[0].end], "דנה כהן")
        self.assertEqual(spans[0].start, text.index("דנה"))

    def test_consecutive_hebrew_lines_form_one_group(self):
        text = "x\nדנה\nכהן\ny"
        model, sess = build({"דנה": "B-PER", "כהן": "I-PER"})
        self.assertEqual(self.spans(model, text), [("דנה\nכהן", "PERSON")])
        self.assertEqual(len(sess.calls), 1)

    def test_entity_in_overlap_reported_once(self):
        words = ["אאא", "בבב", "גגג", "דדד", "ההה", "ווו", "זזז", "חחח"]
        model, sess = build({"ההה": "B-PER"}, max_tokens=6, overlap=2)
        text = " ".join(words)
        self.assertEqual(self.spans(model, text), [("ההה", "PERSON")])
        self.assertEqual(len(sess.calls), 2)

    def test_entity_cut_by_window_edge_found(self):
        words = ["אאא", "בבב", "גגג", "דדד", "ההה", "ווו", "זזז", "חחח"]
        model, _ = build({"ההה": "B-PER", "ווו": "I-PER"}, max_tokens=5, overlap=2)
        text = " ".join(words)
        self.assertEqual(self.spans(model, text), [("ההה ווו", "PERSON")])

    def test_token_type_ids_only_when_declared(self):
        for declared in (False, True):
            model, sess = build({}, with_type_ids=declared)
            model.predict("שלום עולם")
            feeds = sess.calls[0]
            self.assertEqual("token_type_ids" in feeds, declared)
            self.assertEqual(feeds["input_ids"].dtype, np.int64)
            self.assertEqual(feeds["input_ids"][0][0], FakeTokenizer.CLS)

    def test_load_without_runtime_raises(self):
        with mock.patch.object(ps, "ort", None):
            with self.assertRaises(RuntimeError):
                ps.load_hebrew_model(Path("/nonexistent"))


if __name__ == "__main__":
    unittest.main()
