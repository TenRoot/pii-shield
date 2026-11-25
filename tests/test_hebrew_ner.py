"""Hebrew NER tests:  python -m unittest discover -s tests -v"""
import io
import json
import os
import random
import re
import shutil
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pii_sanitizer as ps  # noqa: E402

sys.path.insert(0, str(HERE.parent / "packaging"))
import fetch_full_assets as fa  # noqa: E402


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
        # the BIO decode, before the gap merge
        with mock.patch.object(ps.HebrewNerModel, "_merge_gaps", staticmethod(lambda t, sp, w=None: sp)):
            self.assertEqual(self.spans(model, text),
                             [("דנה כהן", "PERSON"), ("לוי", "PERSON"), ("משה", "ORGANIZATION")])
        # both spans score over the merge cutoff, so the gap merge keeps them separate
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


class LoadHebrewModelGuardTests(unittest.TestCase):
    """load_hebrew_model with fakes: truncation off, special tokens present."""

    def load(self, token_ids):
        tok = mock.MagicMock()
        tok.token_to_id.side_effect = lambda t: token_ids.get(t)
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "config.json").write_text(json.dumps({"id2label": {"0": "O"}}), encoding="utf-8")
        ort_fake = mock.MagicMock()
        with mock.patch.object(ps, "ort", ort_fake), \
             mock.patch.object(ps, "HfTokenizer", mock.Mock(from_file=mock.Mock(return_value=tok))):
            model = ps.load_hebrew_model(tmp)
        return tok, model

    def test_truncation_and_padding_switched_off(self):
        tok, _ = self.load({"[CLS]": 1, "[SEP]": 2})
        tok.no_truncation.assert_called_once()
        tok.no_padding.assert_called_once()

    def test_missing_special_token_raises(self):
        for ids in ({"[CLS]": 1}, {"[SEP]": 2}, {}):
            with self.assertRaises(RuntimeError) as cm:
                self.load(ids)
            self.assertRegex(str(cm.exception), r"\[(CLS|SEP)\]")


class WindowOverlapDedupeTests(unittest.TestCase):
    def test_shorter_span_of_other_type_inside_longer_span_dropped(self):
        spans = [ps.HebrewSpan(10, 17, "PERSON", 0.99), ps.HebrewSpan(10, 13, "ORGANIZATION", 0.93),
                 ps.HebrewSpan(30, 35, "LOCATION", 0.9)]
        out = ps.HebrewNerModel._dedupe(spans)
        self.assertEqual([(s.start, s.end, s.entity) for s in out],
                         [(10, 17, "PERSON"), (30, 35, "LOCATION")])

    def test_same_range_other_type_keeps_higher_score(self):
        spans = [ps.HebrewSpan(0, 5, "ORGANIZATION", 0.97), ps.HebrewSpan(0, 5, "PERSON", 0.99)]
        out = ps.HebrewNerModel._dedupe(spans)
        self.assertEqual([(s.entity) for s in out], ["PERSON"])


class UnionMergeTests(unittest.TestCase):
    """predict never returns overlapping spans and never loses coverage (fake spans)."""

    def merged(self, spans):
        return [(s.start, s.end, s.entity, s.score) for s in ps.HebrewNerModel._dedupe(spans)]

    def test_partial_cross_type_overlap_becomes_one_union_span(self):
        # one window: LOCATION "בבית אבי"; other window: PERSON "אבי לוי"
        spans = [ps.HebrewSpan(0, 8, "LOCATION", 0.95), ps.HebrewSpan(5, 12, "PERSON", 0.7)]
        self.assertEqual(self.merged(spans), [(0, 12, "PERSON", 0.95)])

    def test_without_person_highest_score_type_wins(self):
        spans = [ps.HebrewSpan(0, 6, "ORGANIZATION", 0.6), ps.HebrewSpan(4, 10, "LOCATION", 0.9)]
        self.assertEqual(self.merged(spans), [(0, 10, "LOCATION", 0.9)])

    def test_chain_of_overlaps_becomes_one_span(self):
        spans = [ps.HebrewSpan(0, 4, "LOCATION", 0.5), ps.HebrewSpan(3, 8, "ORGANIZATION", 0.8),
                 ps.HebrewSpan(7, 12, "PERSON", 0.6), ps.HebrewSpan(20, 25, "LOCATION", 0.9)]
        self.assertEqual(self.merged(spans), [(0, 12, "PERSON", 0.8), (20, 25, "LOCATION", 0.9)])

    def test_touching_spans_stay_separate(self):
        spans = [ps.HebrewSpan(0, 4, "PERSON", 0.9), ps.HebrewSpan(4, 8, "LOCATION", 0.8)]
        self.assertEqual(self.merged(spans), [(0, 4, "PERSON", 0.9), (4, 8, "LOCATION", 0.8)])

    def test_input_order_does_not_matter(self):
        spans = [ps.HebrewSpan(7, 12, "PERSON", 0.6), ps.HebrewSpan(0, 4, "LOCATION", 0.5),
                 ps.HebrewSpan(3, 8, "ORGANIZATION", 0.8)]
        self.assertEqual(self.merged(spans), [(0, 12, "PERSON", 0.8)])

    def test_predict_merges_after_word_extension(self):
        # PERSON "ז'" grows to "ז'אן" and then overlaps ORGANIZATION "אן-פייר"
        text = "ואת ז'אן-פייר לוי."
        z = text.index("ז'")
        table = {}
        model, _ = build(table)
        raw = [ps.HebrewSpan(z, z + 2, "PERSON", 0.6), ps.HebrewSpan(z + 2, z + 13, "ORGANIZATION", 0.9)]
        with mock.patch.object(model, "_predict_group", return_value=raw):
            out = model.predict(text)
        self.assertEqual([(text[s.start:s.end], s.entity) for s in out], [("ז'אן-פייר לוי", "PERSON")])


class GapMergeTests(unittest.TestCase):
    """Spans split by one gap character (space, '-', maqaf, geresh) become one span when one of
    them is weak, so the engine threshold sees the whole name and cannot drop a weak half. Two
    strong spans stay separate (fake spans)."""

    def merged(self, text, spans):
        return [(text[s.start:s.end], s.entity, s.score)
                for s in ps.HebrewNerModel._merge_gaps(text, spans)]

    def span(self, text, sub, entity, score):
        s = text.index(sub)
        return ps.HebrewSpan(s, s + len(sub), entity, score)

    def test_weak_first_name_part_joins_strong_surname(self):
        t = "ואת ז'אן-פייר לוי."
        spans = [self.span(t, "ז'אן-פייר", "PERSON", 0.52), self.span(t, "לוי", "PERSON", 0.92)]
        self.assertEqual(self.merged(t, spans), [("ז'אן-פייר לוי", "PERSON", 0.92)])

    def test_weak_person_joins_strong_other_type(self):
        # final review I-4b: the weak PERSON half would be dropped; the joined span is PERSON
        t = "ואת ז'אן-פייר לוי."
        spans = [self.span(t, "ז'אן-פייר", "ORGANIZATION", 0.94), self.span(t, "לוי", "PERSON", 0.6)]
        self.assertEqual(self.merged(t, spans), [("ז'אן-פייר לוי", "PERSON", 0.94)])

    def test_weak_other_type_joins_strong_person(self):
        t = "ואת ז'אן-פייר לוי."
        spans = [self.span(t, "ז'אן-פייר", "LOCATION", 0.5), self.span(t, "לוי", "PERSON", 0.9)]
        self.assertEqual(self.merged(t, spans), [("ז'אן-פייר לוי", "PERSON", 0.9)])

    def test_cross_type_without_person_takes_higher_score_type(self):
        t = "בבנק הדקל בירושלים."
        spans = [self.span(t, "בבנק הדקל", "ORGANIZATION", 0.7),
                 self.span(t, "בירושלים", "LOCATION", 0.95)]
        self.assertEqual(self.merged(t, spans), [("בבנק הדקל בירושלים", "LOCATION", 0.95)])

    def test_two_strong_cross_type_spans_stay_separate(self):
        t = "ואת ז'אן-פייר לוי."
        spans = [self.span(t, "ז'אן-פייר", "ORGANIZATION", 0.99), self.span(t, "לוי", "PERSON", 0.9)]
        self.assertEqual(len(self.merged(t, spans)), 2)

    def test_cross_type_merge_types_by_wanted_part(self):
        t = "בבנק הדקל בירושלים."
        spans = [self.span(t, "בבנק הדקל", "ORGANIZATION", 0.95),
                 self.span(t, "בירושלים", "LOCATION", 0.7)]
        got = ps.HebrewNerModel._merge_gaps(t, spans, {"LOCATION", "PERSON"})
        self.assertEqual([(t[s.start:s.end], s.entity) for s in got],
                         [("בבנק הדקל בירושלים", "LOCATION")])

    def test_person_and_city_stay_separate(self):
        t = "דנה כהן נפגשה עם משה לוי בחיפה."
        spans = [self.span(t, "דנה כהן", "PERSON", 0.99), self.span(t, "משה לוי", "PERSON", 0.98),
                 self.span(t, "בחיפה", "LOCATION", 0.97)]
        self.assertEqual(self.merged(t, spans), [("דנה כהן", "PERSON", 0.99),
                                                 ("משה לוי", "PERSON", 0.98),
                                                 ("בחיפה", "LOCATION", 0.97)])

    def test_same_type_without_person_joins(self):
        t = "בבית אבי לוי."
        spans = [self.span(t, "בבית", "LOCATION", 0.6), self.span(t, "אבי לוי", "LOCATION", 0.8)]
        self.assertEqual(self.merged(t, spans), [("בבית אבי לוי", "LOCATION", 0.8)])

    def test_two_strong_same_type_spans_stay_separate(self):
        # coordinated names: both halves pass the threshold, so each is a whole name
        t = "נועה גולן ויעל רוזן טסו."
        spans = [self.span(t, "נועה גולן", "PERSON", 1.0), self.span(t, "ויעל רוזן", "PERSON", 0.9)]
        self.assertGreaterEqual(0.9, ps.HEBREW_MERGE_BELOW)
        self.assertEqual(self.merged(t, spans), [("נועה גולן", "PERSON", 1.0),
                                                 ("ויעל רוזן", "PERSON", 0.9)])

    def test_weak_half_at_cutoff_edge(self):
        t = "ואת ז'אן-פייר לוי."
        below = ps.HEBREW_MERGE_BELOW - 0.01
        spans = [self.span(t, "ז'אן-פייר", "PERSON", below), self.span(t, "לוי", "PERSON", 0.99)]
        self.assertEqual(len(self.merged(t, spans)), 1)
        spans = [self.span(t, "ז'אן-פייר", "PERSON", ps.HEBREW_MERGE_BELOW),
                 self.span(t, "לוי", "PERSON", 0.99)]
        self.assertEqual(len(self.merged(t, spans)), 2)

    def test_each_gap_character(self):
        for gap in (" ", "-", "\u05be", "'", "\u05f3"):
            with self.subTest(gap=repr(gap)):
                t = "את אבו" + gap + "סאלח."
                spans = [self.span(t, "אבו", "PERSON", 0.6), self.span(t, "סאלח", "PERSON", 0.9)]
                self.assertEqual(self.merged(t, spans), [("אבו" + gap + "סאלח", "PERSON", 0.9)])

    def test_other_single_characters_do_not_join(self):
        for gap in (",", ".", "\n", "/", ":"):
            with self.subTest(gap=repr(gap)):
                t = "את דנה" + gap + "כהן."
                spans = [self.span(t, "דנה", "PERSON", 0.6), self.span(t, "כהן", "PERSON", 0.9)]
                self.assertEqual(len(self.merged(t, spans)), 2)

    def test_two_character_gap_does_not_join(self):
        t = "את דנה, כהן."
        spans = [self.span(t, "דנה", "PERSON", 0.6), self.span(t, "כהן", "PERSON", 0.9)]
        self.assertEqual(len(self.merged(t, spans)), 2)

    def test_touching_spans_do_not_join(self):
        t = "אבגדהו"
        spans = [ps.HebrewSpan(0, 3, "PERSON", 0.6), ps.HebrewSpan(3, 6, "PERSON", 0.9)]
        self.assertEqual(len(self.merged(t, spans)), 2)

    def test_chain_becomes_one_span(self):
        t = "את מוחמד אבו-סאלח היום"
        spans = [self.span(t, "מוחמד", "PERSON", 0.7), self.span(t, "אבו", "PERSON", 0.5),
                 self.span(t, "סאלח", "PERSON", 0.95)]
        self.assertEqual(self.merged(t, spans), [("מוחמד אבו-סאלח", "PERSON", 0.95)])

    def test_weak_other_type_in_chain_joins(self):
        t = "את מוחמד אבו-סאלח היום"
        spans = [self.span(t, "מוחמד", "PERSON", 0.7), self.span(t, "אבו", "LOCATION", 0.5),
                 self.span(t, "סאלח", "PERSON", 0.95)]
        self.assertEqual(self.merged(t, spans), [("מוחמד אבו-סאלח", "PERSON", 0.95)])

    def test_input_order_does_not_matter(self):
        t = "ואת ז'אן-פייר לוי."
        spans = [self.span(t, "לוי", "PERSON", 0.92), self.span(t, "ז'אן-פייר", "PERSON", 0.52)]
        self.assertEqual(self.merged(t, spans), [("ז'אן-פייר לוי", "PERSON", 0.92)])

    def test_cutoff_follows_call_threshold(self):
        # at threshold 0.9 a 0.87 half would be dropped, so it must join its 0.95 neighbour
        t = "ואת ז'אן-פייר לוי."
        spans = [self.span(t, "ז'אן-פייר", "PERSON", 0.95), self.span(t, "לוי", "PERSON", 0.87)]
        self.assertEqual(len(self.merged(t, spans)), 2)
        token = ps.HEBREW_MERGE_CUTOFF.set(0.9)
        try:
            self.assertEqual(self.merged(t, spans), [("ז'אן-פייר לוי", "PERSON", 0.95)])
        finally:
            ps.HEBREW_MERGE_CUTOFF.reset(token)
        self.assertEqual(len(self.merged(t, spans)), 2)

    def test_predict_runs_gap_merge(self):
        text = "ואת ז'אן-פייר לוי."
        model, _ = build({})
        raw = [self.span(text, "ז'אן-פייר", "PERSON", 0.52), self.span(text, "לוי", "PERSON", 0.92)]
        with mock.patch.object(model, "_predict_group", return_value=raw):
            out = model.predict(text)
        self.assertEqual([(text[s.start:s.end], s.entity, s.score) for s in out],
                         [("ז'אן-פייר לוי", "PERSON", 0.92)])


class WordBoundaryTests(unittest.TestCase):
    def test_extend_span_to_whole_words(self):
        text = "הגיעו ומתתיהו אלקבץ מאלפי מנשה."
        sp = ps.HebrewSpan(text.index("ומת"), text.index("ומת") + 3, "PERSON", 1.0)
        out = ps._extend_to_words(text, [sp])
        self.assertEqual([text[s.start:s.end] for s in out], ["ומתתיהו"])

    def test_overlapping_same_type_spans_merge_after_extension(self):
        text = "הגיעו ומתתיהו אלקבץ."
        a = text.index("ומת")
        spans = [ps.HebrewSpan(a, a + 3, "PERSON", 0.9),
                 ps.HebrewSpan(a + 5, a + 13, "PERSON", 0.8)]
        out = ps._extend_to_words(text, spans)
        self.assertEqual([text[s.start:s.end] for s in out], ["ומתתיהו אלקבץ"])
        self.assertEqual(out[0].score, 0.9)

    def test_different_types_not_merged_and_hyphen_kept(self):
        text = "אביגיל רוזנצוויג-שטרנברג בחיפה"
        spans = [ps.HebrewSpan(0, 8, "PERSON", 1.0), ps.HebrewSpan(7, 24, "PERSON", 1.0),
                 ps.HebrewSpan(25, 29, "LOCATION", 1.0)]
        out = ps._extend_to_words(text, spans)
        self.assertEqual([(text[s.start:s.end], s.entity) for s in out],
                         [("אביגיל רוזנצוויג-שטרנברג", "PERSON"), ("בחיפה", "LOCATION")])


import hashlib  # noqa: E402

REAL_MODEL_FILES = list(fa.MODEL_FILES)


def _fake_model_files():
    blobs = {"config.json": b"{}", "tokenizer.json": b"tok", "model_quantized.onnx": b"onnx"}
    table = [(("onnx/" if n.endswith(".onnx") else "") + n, n, hashlib.sha256(b).hexdigest(), len(b))
             for n, b in blobs.items()]
    return table, blobs


def make_pe(imports, delay=()):
    """A minimal PE32+ file with an import table (and a delay-import table) naming DLLs."""
    import struct
    sec_rva, sec_raw = 0x1000, 0x200
    n_imp, n_del = len(imports), len(delay)
    imp_off = 0
    del_off = 20 * (n_imp + 1)
    names_off = del_off + 32 * (n_del + 1)
    body = bytearray(names_off)
    names = bytearray()
    for i, name in enumerate(imports):
        struct.pack_into("<I", body, imp_off + 20 * i + 12, sec_rva + names_off + len(names))
        names += name.encode("ascii") + b"\0"
    for i, name in enumerate(delay):
        struct.pack_into("<II", body, del_off + 32 * i, 1, sec_rva + names_off + len(names))
        names += name.encode("ascii") + b"\0"
    body += names
    opt_size = 112 + 16 * 8
    head = bytearray(sec_raw)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x40)
    head[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HH", head, 0x44, 0x8664, 1)
    struct.pack_into("<H", head, 0x44 + 16, opt_size)
    opt = 0x58
    struct.pack_into("<H", head, opt, 0x20B)
    struct.pack_into("<I", head, opt + 108, 16)
    if imports:
        struct.pack_into("<II", head, opt + 112 + 8 * 1, sec_rva + imp_off, 20 * (n_imp + 1))
    if delay:
        struct.pack_into("<II", head, opt + 112 + 8 * 13, sec_rva + del_off, 32 * (n_del + 1))
    sh = opt + opt_size
    head[sh:sh + 8] = b".idata\0\0"
    struct.pack_into("<IIII", head, sh + 8, len(body), sec_rva, len(body), sec_raw)
    return bytes(head + body)


class FetchAssetsTests(unittest.TestCase):
    """The fetch script with a fake downloader. No network."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.table, self.blobs = _fake_model_files()
        p = mock.patch.object(fa, "MODEL_FILES", self.table)
        p.start()
        self.addCleanup(p.stop)
        self.urls = []

    def downloader(self, corrupt=None):
        def dl(url, dest):
            self.urls.append(url)
            name = Path(url).name
            data = self.blobs[name] + (b"!" if name == corrupt else b"")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        return dl

    def test_constants_match_global_constraints(self):
        self.assertEqual(fa.MODEL_REVISION, "4f0aabf58566526df6f3fb548e0fd2619fbf2b1d")
        self.assertEqual(
            {f[1]: (f[2], f[3]) for f in REAL_MODEL_FILES},
            {"config.json": ("ba12e2d104a01d60b22641dcdedd6d01a7743be917d489ab60f0722953232336", 1690),
             "tokenizer.json": ("00657b39a8a73b96ddcc3cda245c5e8fa02be36e31e318bd13a9169eb89c999b", 3577623),
             "model_quantized.onnx": ("fd7ac841768f11197e1d46ea6bbfe82d9cd9e21289be8761af63dbc996a32007", 184984466)})
        self.assertEqual(sorted(f[1] for f in REAL_MODEL_FILES), sorted(ps.HEBREW_MODEL_FILES))

    def test_pinned_values_have_the_right_shape(self):
        for value in [f[1] for f in fa.TESSDATA_FILES] + [fa.TESSERACT_INSTALLER_SHA256]:
            self.assertRegex(value, r"^[0-9a-f]{64}$")
        self.assertRegex(fa.TESSDATA_COMMIT, r"^[0-9a-f]{40}$")
        self.assertIn(fa.TESSDATA_COMMIT, fa.TESSDATA_URL)
        self.assertTrue(fa.TESSERACT_INSTALLER_URL.startswith("https://"))

    def test_model_download_writes_files_and_license(self):
        out = fa.fetch_model(self.tmp, self.downloader())
        for name in self.blobs:
            self.assertEqual((out / name).read_bytes(), self.blobs[name])
        lic = (out / "LICENSE.txt").read_text(encoding="utf-8")
        for needle in ("dicta-il/dictabert-ner", "onnx-community/dictabert-ner-ONNX",
                       fa.MODEL_REVISION, "https://creativecommons.org/licenses/by/4.0/", "Dicta"):
            self.assertIn(needle, lic)
        self.assertTrue(all(u.startswith("https://huggingface.co/") and fa.MODEL_REVISION in u
                            for u in self.urls))

    def test_hash_mismatch_deletes_file_and_exits_non_zero(self):
        with mock.patch.object(fa, "http_download", self.downloader(corrupt="tokenizer.json")), \
             mock.patch("sys.stderr"):
            rc = fa.main(["--dest", str(self.tmp / "out"), "--model-only"])
        self.assertEqual(rc, 1)
        self.assertFalse((self.tmp / "out" / "models" / fa.MODEL_DIRNAME / "tokenizer.json").exists())

    def test_hash_mismatch_message_names_the_file(self):
        with self.assertRaises(fa.AssetError) as cm:
            fa.fetch_verified("https://x/tokenizer.json", self.tmp / "tokenizer.json",
                              self.table[1][2], self.table[1][3], self.downloader(corrupt="tokenizer.json"))
        self.assertIn("tokenizer.json", str(cm.exception))

    def test_valid_file_is_not_downloaded_again(self):
        fa.fetch_model(self.tmp, self.downloader())
        self.urls.clear()
        fa.fetch_model(self.tmp, self.downloader())
        self.assertEqual(self.urls, [])

    def test_model_only_never_touches_tesseract_code(self):
        with mock.patch.object(fa, "fetch_tesseract", side_effect=AssertionError("tesseract")), \
             mock.patch.object(fa, "extract_installer", side_effect=AssertionError("7z")):
            fa.run(self.tmp / "out", model_only=True, dev=False, downloader=self.downloader(),
                   windows=True)
        self.assertTrue((self.tmp / "out" / "THIRD_PARTY_NOTICES.txt").is_file())

    def test_tesseract_skipped_off_windows(self):
        with mock.patch.object(fa, "fetch_tesseract", side_effect=AssertionError("tesseract")):
            fa.run(self.tmp / "out", model_only=False, dev=False, downloader=self.downloader(),
                   windows=False)

    def test_install_dev_copies_model(self):
        root = self.tmp / "root"
        fa.run(self.tmp / "out", model_only=True, dev=True, downloader=self.downloader(), root=root)
        for name in self.blobs:
            self.assertTrue((root / "models" / fa.MODEL_DIRNAME / name).is_file())

    def test_notices_content(self):
        text = fa.thirdparty_notices(["zlib1.dll", "libjbig-0.dll", "libiconv-2.dll"],
                                     "Apache License text here")
        for needle in ("DictaBERT", "CC BY 4.0", "Tesseract", "Apache License 2.0", "onnxruntime",
                       "MIT", "tokenizers", "tessdata_best", "zlib1.dll", "libjbig-0.dll",
                       "Apache License text here", "License: Zlib", "GPL-2.0-or-later",
                       "LGPL-2.1-or-later", "https://www.gnu.org/software/libiconv/"):
            self.assertIn(needle, text)
        self.assertLess(text.index("libiconv-2.dll"), text.index("zlib1.dll"))
        # LGPL and GPL entries name the duty (license text and source)
        iconv = text[text.index("libiconv-2.dll"):text.index("libjbig-0.dll")]
        self.assertIn("LGPL: the license text and the library source", iconv)
        jbig = text[text.index("libjbig-0.dll"):text.index("zlib1.dll")]
        self.assertIn("GPL: the license text and the complete source", jbig)

    def test_notices_hold_gpl_texts_source_links_and_offer(self):
        text = fa.thirdparty_notices(["zlib1.dll", "libjbig-0.dll", "libiconv-2.dll"], "Apache")
        self.assertIn("https://www.cl.cam.ac.uk/~mgk25/jbigkit/download/jbigkit-2.1.tar.gz", text)
        self.assertIn("https://ftp.gnu.org/gnu/libiconv/libiconv-1.19.tar.gz", text)
        self.assertIn("The source code of these components is available at the URLs above; on "
                      "request we provide it for at least three years.", text)
        # full texts, each once: GPL-2.0 for JBIG-KIT, LGPL-2.1 for libiconv
        self.assertEqual(text.count("GNU GENERAL PUBLIC LICENSE\n                       Version 2, June 1991"), 1)
        self.assertEqual(text.count("Version 2.1, February 1999"), 1)
        self.assertIn("END OF TERMS AND CONDITIONS", text)
        self.assertNotIn("Version 3, 29 June 2007", text)
        # the DLL -> SPDX table stays
        self.assertIn("License: GPL-2.0-or-later", text)

    def test_lgpl3_component_ships_gpl3_text(self):
        text = fa.thirdparty_notices(["libidn2-0.dll"], "")
        self.assertIn("GNU LESSER GENERAL PUBLIC LICENSE\n                       Version 3", text)
        self.assertIn("GNU GENERAL PUBLIC LICENSE\n                       Version 3", text)

    def test_source_links_name_exact_versions(self):
        # versions read from the version resources and strings of the DLLs in the pinned installer
        self.assertEqual(fa.COPYLEFT_SOURCES["libiconv-2.dll"][0],
                         "https://ftp.gnu.org/gnu/libiconv/libiconv-1.19.tar.gz")
        self.assertEqual(fa.COPYLEFT_SOURCES["libintl-8.dll"][0],
                         "https://ftp.gnu.org/gnu/gettext/gettext-1.0.tar.gz")
        self.assertEqual(fa.COPYLEFT_SOURCES["libidn2-0.dll"][0],
                         "https://ftp.gnu.org/gnu/libidn/libidn2-2.3.8.tar.gz")
        self.assertEqual(fa.COPYLEFT_SOURCES["libunistring-5.dll"][0],
                         "https://ftp.gnu.org/gnu/libunistring/libunistring-1.4.2.tar.gz")
        for url, _ in fa.COPYLEFT_SOURCES.values():
            self.assertTrue(url.endswith((".tar.gz", ".tar.xz")), url)

    def test_gcc_runtime_ships_gpl3_and_exception_text(self):
        text = fa.thirdparty_notices(["libgcc_s_seh-1.dll", "libstdc++-6.dll", "zlib1.dll"], "")
        self.assertEqual(text.count("GCC RUNTIME LIBRARY EXCEPTION\n\nVersion 3.1, 31 March 2009"), 1)
        self.assertEqual(text.count("GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007"), 1)
        self.assertIn("libgcc_s_seh-1.dll, libstdc++-6.dll", text)
        self.assertNotIn("source code of these components", text)  # the exception: no source duty

    def test_gcc_runtime_and_lgpl3_share_one_gpl3_text(self):
        text = fa.thirdparty_notices(["libstdc++-6.dll", "libidn2-0.dll"], "")
        self.assertEqual(text.count("GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007"), 1)
        self.assertEqual(text.count("GCC RUNTIME LIBRARY EXCEPTION\n\nVersion 3.1"), 1)

    def test_library_header_says_where_license_texts_are(self):
        def header(dlls):
            text = fa.thirdparty_notices(dlls, "")
            start = text.index("Libraries copied from the Tesseract installer")
            return " ".join(text[start:text.index("\n\n", start)].split())
        plain = header(["zlib1.dll"])
        self.assertIn("at the project URL", plain)
        self.assertNotIn("end of this file", plain)
        for dlls in (["zlib1.dll", "libjbig-0.dll"], ["libgcc_s_seh-1.dll"]):
            with self.subTest(dlls=dlls):
                self.assertIn("at the end of this file", header(dlls))

    def test_no_copyleft_section_without_copyleft_dlls(self):
        text = fa.thirdparty_notices(["zlib1.dll"], "")
        self.assertNotIn("source code of these components", text)
        self.assertNotIn("GNU GENERAL PUBLIC LICENSE", text)

    def test_every_gpl_and_lgpl_dll_has_source_and_vendored_text(self):
        fa.check_copyleft_sources()
        for dll, (url, files) in fa.COPYLEFT_SOURCES.items():
            self.assertIn(dll, fa.DLL_LICENSES)
            self.assertTrue(url.startswith("https://"))
            for f in files:
                self.assertTrue((fa.LICENSES_DIR / f).is_file(), f)
        gcc = [d for d, (_, _, _, duty) in fa.DLL_LICENSES.items() if duty == fa.GCC_DUTY]
        self.assertEqual(sorted(gcc), ["libgcc_s_seh-1.dll", "libstdc++-6.dll"])
        for f in fa.GCC_RUNTIME_TEXTS:
            self.assertTrue((fa.LICENSES_DIR / f).is_file(), f)
        with mock.patch.dict(fa.COPYLEFT_SOURCES, clear=True):
            with self.assertRaises(fa.AssetError) as cm:
                fa.thirdparty_notices(["libjbig-0.dll"], "")
        self.assertIn("libjbig-0.dll", str(cm.exception))

    def test_notices_with_unlisted_dll_fail(self):
        with self.assertRaises(fa.AssetError) as cm:
            fa.thirdparty_notices(["zlib1.dll", "libnew-9.dll"], "")
        self.assertIn("libnew-9.dll", str(cm.exception))
        self.assertIn("DLL_LICENSES", str(cm.exception))

    def test_model_only_notices_list_only_what_was_fetched(self):
        fa.write_model_only_notices(self.tmp)
        text = (self.tmp / "THIRD_PARTY_NOTICES.txt").read_text(encoding="utf-8")
        for needle in ("DictaBERT", "onnxruntime", "tokenizers"):
            self.assertIn(needle, text)
        for needle in ("Tesseract", "tessdata", ".dll"):
            self.assertNotIn(needle, text)

    def test_download_goes_to_part_file_then_renamed(self):
        seen = []

        def dl(url, dest):
            seen.append(dest.name)
            self.downloader()(url, dest)
        out = fa.fetch_model(self.tmp, dl)
        self.assertEqual(seen, [n + ".part" for n in self.blobs])
        self.assertEqual(list(out.glob("*.part")), [])

    def test_hash_mismatch_deletes_part_file(self):
        with self.assertRaises(fa.AssetError):
            fa.fetch_verified("https://x/tokenizer.json", self.tmp / "tokenizer.json",
                              self.table[1][2], self.table[1][3], self.downloader(corrupt="tokenizer.json"))
        self.assertEqual(list(self.tmp.iterdir()), [])

    def _main_with_failing_download(self, exc):
        def dl(url, dest):
            dest.parent.mkdir(parents=True, exist_ok=True)
            if Path(url).name == "tokenizer.json":
                dest.write_bytes(b"half")
                raise exc
            self.downloader()(url, dest)
        err = io.StringIO()
        with mock.patch.object(fa, "http_download", dl), mock.patch("sys.stderr", err):
            rc = fa.main(["--dest", str(self.tmp / "out"), "--model-only"])
        folder = self.tmp / "out" / "models" / fa.MODEL_DIRNAME
        return rc, err.getvalue(), folder

    def test_network_error_prints_one_line_and_exits_non_zero(self):
        import requests
        rc, err, folder = self._main_with_failing_download(requests.ConnectionError("boom"))
        self.assertEqual(rc, 1)
        self.assertEqual(err.strip(), "ERROR: tokenizer.json: boom")
        self.assertNotIn("Traceback", err)
        self.assertFalse((folder / "tokenizer.json.part").exists())
        self.assertFalse((folder / "tokenizer.json").exists())

    def test_os_error_prints_one_line_and_exits_non_zero(self):
        rc, err, folder = self._main_with_failing_download(OSError(28, "No space left on device"))
        self.assertEqual(rc, 1)
        self.assertTrue(err.startswith("ERROR: tokenizer.json: "), err)
        self.assertEqual(len(err.strip().splitlines()), 1)
        self.assertFalse((folder / "tokenizer.json.part").exists())

    def test_interrupt_during_download_deletes_part_file(self):
        def dl(url, dest):
            dest.write_bytes(b"half")
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            fa.fetch_verified("https://x/tokenizer.json", self.tmp / "tokenizer.json",
                              self.table[1][2], self.table[1][3], dl)
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_os_error_outside_download_is_caught_in_main(self):
        err = io.StringIO()
        boom = PermissionError(13, "Permission denied", str(self.tmp / "out" / "LICENSE.txt"))
        with mock.patch.object(fa, "run", side_effect=boom), mock.patch("sys.stderr", err):
            rc = fa.main(["--dest", str(self.tmp / "out"), "--model-only"])
        self.assertEqual(rc, 1)
        self.assertEqual(err.getvalue().strip(), "ERROR: LICENSE.txt: Permission denied")

    def test_silent_install_command_with_spaces(self):
        installer = Path("C:/Build Temp/tesseract-setup.exe")
        target = Path("C:/Build Temp/un packed")
        cmd = fa.silent_install_command(installer, target)
        self.assertEqual(cmd, f'"{installer}" /S /D={target}')
        self.assertTrue(cmd.endswith(f"/D={target}"))  # last and unquoted
        self.assertNotIn('"/D=', cmd)

    def test_extract_fallback_passes_one_command_string(self):
        target = self.tmp / "with space" / "unpacked"
        installer = self.tmp / "with space" / "setup.exe"
        calls = []

        def fake_run(cmd, *a, **kw):
            calls.append(cmd)
            (target / "tesseract.exe").write_bytes(b"exe")
            return types.SimpleNamespace(returncode=0)
        with mock.patch.object(fa, "find_7z", return_value=None), \
             mock.patch.object(fa.subprocess, "run", fake_run):
            fa.extract_installer(installer, target)
        self.assertEqual(calls, [f'"{installer}" /S /D={target}'])

    def test_pe_imports_reads_import_and_delay_import_tables(self):
        exe = self.tmp / "a.exe"
        exe.write_bytes(make_pe(["libone.dll", "KERNEL32.dll"], delay=["libtwo.dll"]))
        self.assertEqual(fa.pe_imports(exe), ["libone.dll", "KERNEL32.dll", "libtwo.dll"])

    def test_pe_imports_rejects_non_pe(self):
        bad = self.tmp / "bad.dll"
        bad.write_bytes(b"not a pe file")
        with self.assertRaises(fa.AssetError) as cm:
            fa.pe_imports(bad)
        self.assertIn("bad.dll", str(cm.exception))

    def test_needed_dlls_is_the_import_closure(self):
        d = self.tmp / "unpacked"
        d.mkdir()
        (d / "tesseract.exe").write_bytes(make_pe(["libtesseract-5.dll", "KERNEL32.dll"]))
        (d / "libtesseract-5.dll").write_bytes(make_pe(["libleptonica-6.dll", "msvcrt.dll"]))
        (d / "libleptonica-6.dll").write_bytes(make_pe(["ZLIB1.DLL"], delay=["libpng16-16.dll"]))
        (d / "zlib1.dll").write_bytes(make_pe([]))
        (d / "libpng16-16.dll").write_bytes(make_pe(["zlib1.dll"]))
        # a training-tool library that tesseract.exe never loads
        (d / "libpango-1.0-0.dll").write_bytes(make_pe(["zlib1.dll"]))
        self.assertEqual(fa.needed_dlls(d), ["libleptonica-6.dll", "libpng16-16.dll",
                                             "libtesseract-5.dll", "zlib1.dll"])

    def test_tesseract_path_with_unlisted_dll_fails(self):
        def unpack(installer, target):
            target.mkdir(parents=True)
            (target / "tesseract.exe").write_bytes(make_pe(["libnew-9.dll"]))
            (target / "libnew-9.dll").write_bytes(make_pe([]))
        with mock.patch.object(fa, "TESSERACT_INSTALLER_SHA256", hashlib.sha256(b"setup").hexdigest()), \
             mock.patch.object(fa, "TESSERACT_INSTALLER_SIZE", 5), \
             mock.patch.object(fa, "extract_installer", unpack):
            with self.assertRaises(fa.AssetError) as cm:
                fa.fetch_tesseract(self.tmp / "out", lambda url, dest: dest.write_bytes(b"setup"))
        self.assertIn("libnew-9.dll", str(cm.exception))
        self.assertFalse((self.tmp / "out" / "tesseract" / "libnew-9.dll").exists())

    def test_tesseract_path_with_fake_installer(self):
        """Windows path with a fake unpacker and fake downloads (the real run is CI-only)."""
        small = [("heb.traineddata", hashlib.sha256(b"h").hexdigest(), 1),
                 ("eng.traineddata", hashlib.sha256(b"e").hexdigest(), 1),
                 ("osd.traineddata", hashlib.sha256(b"o").hexdigest(), 1)]
        blobs = {"heb.traineddata": b"h", "eng.traineddata": b"e", "osd.traineddata": b"o",
                 "tesseract-setup.exe": b"setup"}

        def dl(url, dest):
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(blobs[Path(url).name if "tessdata" in url else "tesseract-setup.exe"])

        def unpack(installer, target):
            (target / "doc").mkdir(parents=True)
            (target / "tesseract.exe").write_bytes(make_pe(["libtesseract-5.dll", "KERNEL32.dll"]))
            (target / "libtesseract-5.dll").write_bytes(make_pe(["zlib1.dll"]))
            (target / "zlib1.dll").write_bytes(make_pe([]))
            (target / "libpango-1.0-0.dll").write_bytes(make_pe([]))  # not loaded: not copied
            (target / "doc" / "LICENSE").write_text("Apache License", encoding="utf-8")

        with mock.patch.object(fa, "TESSDATA_FILES", small), \
             mock.patch.object(fa, "TESSERACT_INSTALLER_SHA256", hashlib.sha256(b"setup").hexdigest()), \
             mock.patch.object(fa, "TESSERACT_INSTALLER_SIZE", 5), \
             mock.patch.object(fa, "extract_installer", unpack):
            out = fa.fetch_tesseract(self.tmp / "out", dl)
        self.assertTrue((out / "tesseract.exe").is_file())
        self.assertTrue((out / "libtesseract-5.dll").is_file())
        self.assertTrue((out / "zlib1.dll").is_file())
        self.assertFalse((out / "libpango-1.0-0.dll").exists())
        for n in ("heb", "eng", "osd"):
            self.assertTrue((out / "tessdata" / f"{n}.traineddata").is_file())
        notices = (self.tmp / "out" / "THIRD_PARTY_NOTICES.txt").read_text(encoding="utf-8")
        self.assertIn("libtesseract-5.dll", notices)


TEMPLATE_RULES = HERE.parent / "github-repo-template" / "rules"
HE_TEXT = "דנה כהן נפגשה בחיפה עם אקמה"
HE_TABLE = {"דנה": "B-PER", "כהן": "I-PER", "בחיפה": "B-GPE", "אקמה": "B-ORG",
            "משה": "B-PER", "לוי": "I-PER"}


def fake_model():
    return build(HE_TABLE)[0]


def make_engine(tmp: Path, *, hebrew=True, orgs=True, model="fake", allow=None):
    """Build an engine with a fake Hebrew model. model: 'fake', 'none' (not installed), 'fail'."""
    rules = tmp / "rules"
    shutil.copytree(TEMPLATE_RULES, rules / "remote")
    (rules / "local").mkdir()
    cfg = ps.AppConfig(tmp / "config.json")
    cfg["engine"]["hebrew_ner"] = hebrew
    cfg["engine"]["detect_organizations"] = orgs
    folder = tmp / "he-model" if model != "none" else None
    loader = mock.Mock(side_effect=RuntimeError("boom")) if model == "fail" \
        else mock.Mock(return_value=fake_model())
    eng = ps.DetectionEngine(cfg, rules)
    with mock.patch.object(ps, "find_hebrew_model", return_value=folder), \
         mock.patch.object(ps, "load_hebrew_model", loader):
        eng.initialize()
    return eng, loader


def hebrew_findings(eng, text=HE_TEXT, vault=None):
    return eng.analyze(text, [], vault or ps.SessionVault())


class HebrewEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.engine, _ = make_engine(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_hebrew_person_found_with_source(self):
        self.assertEqual(self.engine.hebrew_status, "loaded")
        fs = hebrew_findings(self.engine)
        person = [f for f in fs if f.entity == "PERSON" and f.text == "דנה כהן"]
        self.assertEqual(len(person), 1)
        self.assertEqual(person[0].source, "hebrew_ner")
        self.assertEqual(person[0].recognizer, "HebrewNerRecognizer")
        loc = [f for f in fs if f.entity == "LOCATION" and f.text == "בחיפה"]
        self.assertEqual(loc[0].source, "hebrew_ner")

    def test_allow_list_applies_to_hebrew(self):
        with mock.patch.object(self.engine.ruleset, "allow_list", {"דנה כהן"}):
            fs = hebrew_findings(self.engine)
        self.assertFalse([f for f in fs if f.text == "דנה כהן"])

    def test_threshold_applies_to_hebrew(self):
        fs = self.engine.analyze(HE_TEXT, [], ps.SessionVault(), threshold=1.01)
        self.assertFalse([f for f in fs if f.source == "hebrew_ner"])

    def test_skip_ner_on_logs_drops_hebrew(self):
        fs = self.engine.analyze(HE_TEXT, [], ps.SessionVault(), skip_ner=True)
        self.assertFalse([f for f in fs if f.source == "hebrew_ner"])

    def test_merge_cutoff_follows_analyze_threshold(self):
        text = "פגשתי את ז'אן-פייר לוי היום."
        raw = [ps.HebrewSpan(text.index("ז'אן"), text.index(" לוי"), "PERSON", 0.95),
               ps.HebrewSpan(text.index("לוי"), text.index("לוי") + 3, "PERSON", 0.87)]

        def hebrew(threshold):
            with mock.patch.object(self.engine.hebrew_model, "_predict_group", return_value=raw):
                fs = self.engine.analyze(text, [], ps.SessionVault(), threshold=threshold)
            return sorted(f.text for f in fs if f.source == "hebrew_ner")
        self.assertEqual(hebrew(0.9), ["ז'אן-פייר לוי"])
        self.assertEqual(hebrew(0.85), ["ז'אן-פייר", "לוי"])
        self.assertEqual(ps.HEBREW_MERGE_CUTOFF.get(), ps.HEBREW_MERGE_BELOW)

    def test_recognizer_filters_requested_entities(self):
        rec = ps.HebrewNerRecognizer(fake_model())
        res = rec.analyze(HE_TEXT, ["LOCATION"])
        self.assertEqual({r.entity_type for r in res}, {"LOCATION"})
        self.assertEqual(rec.name, "HebrewNerRecognizer")
        self.assertEqual(rec.supported_language, "en")


class HebrewEngineVariantTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_setting_off_skips_model(self):
        eng, loader = make_engine(self.tmp, hebrew=False)
        self.assertEqual(eng.hebrew_status, "off")
        self.assertIsNone(eng.hebrew_model)
        loader.assert_not_called()
        self.assertFalse([f for f in hebrew_findings(eng) if f.source == "hebrew_ner"])

    def test_detect_organizations_off_drops_hebrew_org(self):
        eng, _ = make_engine(self.tmp, orgs=False)
        self.assertEqual(eng.hebrew_status, "loaded")
        fs = hebrew_findings(eng)
        self.assertFalse([f for f in fs if f.entity == "ORGANIZATION"])
        self.assertTrue([f for f in fs if f.entity == "PERSON" and f.source == "hebrew_ner"])
        rec = ps.HebrewNerRecognizer(fake_model(), organizations=False)
        self.assertNotIn("ORGANIZATION", rec.supported_entities)
        self.assertFalse([r for r in rec.analyze(HE_TEXT, ["PERSON", "ORGANIZATION"])
                          if r.entity_type == "ORGANIZATION"])

    def test_load_failure_keeps_engine_running(self):
        eng, _ = make_engine(self.tmp, model="fail")
        self.assertTrue(eng.hebrew_status.startswith("failed"))
        self.assertIn("boom", eng.hebrew_status)
        self.assertIsNone(eng.hebrew_model)
        fs = eng.analyze("John Smith logged in from 10.20.30.40", [], ps.SessionVault())
        self.assertIn("PERSON", {f.entity for f in fs})
        self.assertIn("INTERNAL_IP", {f.entity for f in fs})

    def test_not_installed_status(self):
        eng, loader = make_engine(self.tmp, model="none")
        self.assertEqual(eng.hebrew_status, "not installed")
        self.assertIsNone(eng.hebrew_model)
        loader.assert_not_called()


# ---- spaCy findings on Hebrew text (task 4b, change A; fix round R8) ----
# The English spaCy model reads Hebrew as junk and gives long spans such as LOCATION
# "אברהמי מחברת אורנים". When the Hebrew model is on, such a spaCy finding is cut before overlap
# resolution: only its Hebrew words that no Hebrew NER finding overlaps stay, so it cannot beat a
# Hebrew PERSON span, and a surname that the Hebrew model misses stays masked.
SPACY_HE_TEXT = "יוסי אברהמי מחברת אורנים met John Smith, ת.ז. 123456782"


def _spacy_he_results(rule_name):
    t = SPACY_HE_TEXT

    def res(sub, entity, rname, score=0.9):
        s = t.index(sub)
        return ps.RecognizerResult(entity_type=entity, start=s, end=s + len(sub), score=score,
                                   recognition_metadata={"recognizer_name": rname})
    return [res("אברהמי מחברת אורנים", "LOCATION", "SpacyRecognizer", 0.85),
            res("John Smith", "PERSON", "SpacyRecognizer"),
            res("יוסי אברהמי", "PERSON", ps.HEBREW_RECOGNIZER, 1.0),
            res("ת.ז. 123456782", "IL_ID", rule_name, 1.0)]


class SpacyOnHebrewTests(unittest.TestCase):
    # one engine for the class: each engine loads the spaCy model (memory)
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.engine, _ = make_engine(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        cls.engine = None

    def run_engine(self, model_loaded=True, setting=True):
        eng = self.engine
        rule = eng.ruleset.rules[0].name
        with mock.patch.object(eng.analyzer, "analyze", return_value=_spacy_he_results(rule)), \
             mock.patch.dict(eng.config["engine"], {"hebrew_ner": setting}), \
             mock.patch.object(eng, "hebrew_model", eng.hebrew_model if model_loaded else None):
            fs = eng.analyze(SPACY_HE_TEXT, [], ps.SessionVault())
        return {(f.text, f.source) for f in fs}

    def test_engine_has_the_model(self):
        self.assertEqual(self.engine.hebrew_status, "loaded")

    def test_spacy_finding_with_hebrew_letter_dropped(self):
        got = self.run_engine()
        self.assertNotIn(("אברהמי מחברת אורנים", "presidio"), got)
        self.assertIn(("יוסי אברהמי", "hebrew_ner"), got)

    def test_spacy_finding_on_latin_text_kept(self):
        self.assertIn(("John Smith", "presidio"), self.run_engine())

    def test_rule_finding_on_hebrew_text_kept(self):
        self.assertIn(("ת.ז. 123456782", "custom"), self.run_engine())

    def test_no_drop_when_setting_off(self):
        self.assertIn(("אברהמי מחברת אורנים", "presidio"), self.run_engine(setting=False))

    # R8: a spaCy finding on Hebrew text keeps the Hebrew words that no Hebrew NER finding
    # overlaps (the Hebrew model misses some surnames in long text; spaCy junk can cover them).
    def run_with(self, text, specs):
        eng = self.engine

        def res(sub, entity, rname, score):
            s = text.index(sub)
            return ps.RecognizerResult(entity_type=entity, start=s, end=s + len(sub), score=score,
                                       recognition_metadata={"recognizer_name": rname})
        results = [res(*spec) for spec in specs]
        with mock.patch.object(eng.analyzer, "analyze", return_value=results):
            fs = eng.analyze(text, [], ps.SessionVault())
        return sorted((f.text, f.source) for f in fs)

    def test_spacy_keeps_uncovered_hebrew_words(self):
        got = self.run_engine()
        self.assertIn(("מחברת אורנים", "presidio"), got)
        self.assertIn(("יוסי אברהמי", "hebrew_ner"), got)

    def test_spacy_keeps_missed_surname(self):
        t = "משפחת אזולאי עברה מנתניה לרחובות."
        got = self.run_with(t, [("משפחת אזולאי עברה מנתניה לרחובות", "ORGANIZATION", "SpacyRecognizer", 0.85),
                                ("מנתניה", "LOCATION", ps.HEBREW_RECOGNIZER, 1.0)])
        self.assertEqual(got, [("לרחובות", "presidio"), ("מנתניה", "hebrew_ner"),
                               ("משפחת אזולאי עברה", "presidio")])

    def test_spacy_fully_covered_gives_nothing(self):
        t = "העובד יוסי אברהמי התקשר."
        got = self.run_with(t, [("יוסי אברהמי התקשר", "PERSON", "SpacyRecognizer", 0.85),
                                ("יוסי אברהמי", "PERSON", ps.HEBREW_RECOGNIZER, 1.0),
                                ("התקשר", "LOCATION", ps.HEBREW_RECOGNIZER, 0.9)])
        self.assertEqual(got, [("התקשר", "hebrew_ner"), ("יוסי אברהמי", "hebrew_ner")])

    def test_partly_overlapped_word_counts_as_covered(self):
        t = "העובד יוסי אברהמי התקשר."
        got = self.run_with(t, [("ברהמי התקשר", "PERSON", "SpacyRecognizer", 0.85),
                                ("יוסי אברהמי", "PERSON", ps.HEBREW_RECOGNIZER, 1.0)])
        self.assertEqual(got, [("התקשר", "presidio"), ("יוסי אברהמי", "hebrew_ner")])

    def test_piece_without_hebrew_letter_kept(self):
        t = "אורנים met John today"
        got = self.run_with(t, [("אורנים met", "PERSON", "SpacyRecognizer", 0.85),
                                ("אורנים", "ORGANIZATION", ps.HEBREW_RECOGNIZER, 1.0)])
        self.assertEqual(got, [("met", "presidio"), ("אורנים", "hebrew_ner")])

    def sanitized(self, text, specs):
        eng = self.engine
        results = []
        for sub, entity, rname, score, nth in specs:
            s = -1
            for _ in range(nth + 1):
                s = text.index(sub, s + 1)
            results.append(ps.RecognizerResult(entity_type=entity, start=s, end=s + len(sub),
                                               score=score,
                                               recognition_metadata={"recognizer_name": rname}))
        vault = ps.SessionVault()
        with mock.patch.object(eng.analyzer, "analyze", return_value=results):
            fs = eng.analyze(text, [], vault)
        return ps.sanitize(text, fs, vault)[0]

    def test_latin_name_in_mixed_span_masked(self):
        out = self.sanitized("Hello John Smith מחיפה, how are you?",
                             [("John Smith מחיפה", "PERSON", "SpacyRecognizer", 0.85, 0),
                              ("מחיפה", "LOCATION", ps.HEBREW_RECOGNIZER, 1.0, 0)])
        self.assertNotIn("John", out)
        self.assertNotIn("Smith", out)

    # a Hebrew span that stops at a maqaf does not cover the rest of the word
    def test_word_rest_after_hebrew_span_masked(self):
        out = self.sanitized("פגשתי את מוחמד אבו-סאלח היום.",
                             [("מוחמד אבו-סאלח", "PERSON", "SpacyRecognizer", 0.85, 0),
                              ("מוחמד אבו", "PERSON", ps.HEBREW_RECOGNIZER, 0.9, 0)])
        self.assertNotIn("סאלח", out)

    # give-back pieces of two dropped copies must not overlap: sanitize would drop one
    def test_give_back_pieces_do_not_overlap(self):
        t = "רון דני משה לוי כהן הגיעו. אתמול רון דני משה התקשר. גם משה לוי כהן בא."
        H = ps.HEBREW_RECOGNIZER
        out = self.sanitized(t, [("רון", "PERSON", H, 1.0, 0), ("כהן", "PERSON", H, 1.0, 0),
                                 ("רון דני משה", "PERSON", H, 1.0, 1),
                                 ("משה לוי כהן", "PERSON", H, 1.0, 1)])
        for name in ("רון", "דני", "משה", "לוי", "כהן"):
            self.assertNotIn(name, out)

    def test_no_drop_when_model_not_loaded(self):
        self.assertIn(("אברהמי מחברת אורנים", "presidio"), self.run_engine(model_loaded=False))


# ---- a propagated copy of a Hebrew name keeps the words that no kept finding covers ----
# After R7 (no cross-type gap merge), "ז'אן-פייר לוי" can come back as ORGANIZATION "ז'אן-פייר"
# 0.99 + PERSON "לוי" 0.77 (under the threshold). The propagated copy of the full name from
# another occurrence loses to the ORGANIZATION (priority), and "לוי" stayed unmasked.
class PropagatedCoverageTests(unittest.TestCase):
    T = "פגשתי את ז'אן-פייר לוי היום."

    def f(self, sub, entity, source, score=0.99):
        s = self.T.index(sub)
        return ps.Finding(s, s + len(sub), sub, entity, score, source, source)

    def got(self, findings, hebrew_copies=True):
        return [(f.text, f.entity, f.source)
                for f in ps.resolve_keep_hebrew_coverage(findings, self.T, hebrew_copies)]

    def test_no_give_back_without_hebrew_model(self):
        # small build or setting off: propagated copies behave as before
        got = self.got([self.f("ז'אן-פייר", "ORGANIZATION", "custom"),
                        self.f("ז'אן-פייר לוי", "PERSON", "propagated")], hebrew_copies=False)
        self.assertEqual(got, [("ז'אן-פייר", "ORGANIZATION", "custom")])
        self.assertEqual(self.got([self.f("ז'אן-פייר", "ORGANIZATION", "custom"),
                                   self.f("ז'אן-פייר לוי", "PERSON", "propagated")]),
                         [("ז'אן-פייר", "ORGANIZATION", "custom"), ("לוי", "PERSON", "propagated")])

    def test_dropped_hebrew_copy_keeps_uncovered_words(self):
        got = self.got([self.f("ז'אן-פייר", "ORGANIZATION", "hebrew_ner"),
                        self.f("ז'אן-פייר לוי", "PERSON", "propagated")])
        self.assertEqual(got, [("ז'אן-פייר", "ORGANIZATION", "hebrew_ner"),
                               ("לוי", "PERSON", "propagated")])

    def test_give_back_pieces_trimmed_against_each_other(self):
        t = "קק אא בב גג דד"

        def f(sub, source):
            s = t.index(sub)
            return ps.Finding(s, s + len(sub), sub, "PERSON", 0.9, source, source)
        out = ps.resolve_keep_hebrew_coverage(
            [f("קק", "hebrew_ner"), f("דד", "hebrew_ner"),
             f("קק אא בב", "propagated"), f("בב גג דד", "propagated")], t, True)
        spans = sorted((x.start, x.end) for x in out)
        for (a, b), (c, d) in zip(spans, spans[1:]):
            self.assertLessEqual(b, c)
        self.assertEqual(" ".join(x.text for x in sorted(out, key=lambda x: x.start)),
                         "קק אא בב גג דד")

    def test_identical_give_back_piece_kept_once(self):
        # a session finding beats a Hebrew span and its own propagated copy
        got = self.got([self.f("ז'אן-פייר", "PERSON", "session"),
                        self.f("ז'אן-פייר לוי", "PERSON", "hebrew_ner"),
                        self.f("ז'אן-פייר לוי", "PERSON", "propagated")])
        self.assertEqual(got, [("ז'אן-פייר", "PERSON", "session"), ("לוי", "PERSON", "hebrew_ner")])

    def test_dropped_latin_copy_gives_nothing(self):
        t = "host fs01.corp.local and corp.local"
        s = t.index("fs01")
        fs = [ps.Finding(s, s + 4, "fs01", "HOSTNAME", 0.9, "presidio", "x"),
              ps.Finding(s, s + 15, "fs01.corp.local", "HOSTNAME", 0.9, "propagated", "p")]
        self.assertEqual([f.text for f in ps.resolve_keep_hebrew_coverage(fs, t, True)], ["fs01"])


# ---- a Hebrew NER span that loses to a rule finding keeps its other words (task 4b) ----
RULE_HE_TEXT = "גרה ברחוב הרצל 12 תל אביב רונית שפירא, כך נמסר."


class HebrewPersonCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.engine, _ = make_engine(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        cls.engine = None

    def analyze(self, results, hebrew=True):
        eng = self.engine
        with mock.patch.object(eng.analyzer, "analyze", return_value=results(eng)), \
             mock.patch.dict(eng.config["engine"], {"hebrew_ner": hebrew}):
            return eng.analyze(RULE_HE_TEXT, [], ps.SessionVault())

    @staticmethod
    def res(sub, entity, rname, score):
        s = RULE_HE_TEXT.index(sub)
        return ps.RecognizerResult(entity_type=entity, start=s, end=s + len(sub), score=score,
                                   recognition_metadata={"recognizer_name": rname})

    def test_person_words_outside_rule_finding_stay_masked(self):
        rule = lambda eng: eng.ruleset.rules[0].name
        fs = self.analyze(lambda eng: [
            self.res("רחוב הרצל 12 תל אביב רונית שפירא", "PERSON", ps.HEBREW_RECOGNIZER, 1.0),
            self.res("רחוב הרצל 12", "IL_ADDRESS", rule(eng), 0.9)])
        got = sorted((f.text, f.entity, f.source) for f in fs)
        self.assertEqual(got, [("רחוב הרצל 12", "IL_ADDRESS", "custom"),
                               ("תל אביב רונית שפירא", "PERSON", "hebrew_ner")])

    def test_rest_split_in_two_pieces(self):
        rule = lambda eng: eng.ruleset.rules[0].name
        fs = self.analyze(lambda eng: [
            self.res("ברחוב הרצל 12 תל אביב רונית שפירא", "PERSON", ps.HEBREW_RECOGNIZER, 1.0),
            self.res("הרצל 12", "IL_ADDRESS", rule(eng), 0.9)])
        got = sorted((f.text, f.source) for f in fs)
        self.assertEqual(got, [("ברחוב", "hebrew_ner"), ("הרצל 12", "custom"),
                               ("תל אביב רונית שפירא", "hebrew_ner")])

    def test_other_hebrew_types_keep_coverage_too(self):
        # the gap merge can give LOCATION "רחוב הרצל 12 תל אביב משפחת אזולאי" (measured)
        rule = lambda eng: eng.ruleset.rules[0].name
        fs = self.analyze(lambda eng: [
            self.res("רחוב הרצל 12 תל אביב רונית שפירא", "LOCATION", ps.HEBREW_RECOGNIZER, 1.0),
            self.res("רחוב הרצל 12", "IL_ADDRESS", rule(eng), 0.9)])
        self.assertEqual([f.text for f in fs], ["רחוב הרצל 12", "תל אביב רונית שפירא"])

    def test_other_sources_unchanged(self):
        # a dropped spaCy or rule finding gives nothing back
        rule = lambda eng: eng.ruleset.rules[0].name
        fs = self.analyze(lambda eng: [
            self.res("רחוב הרצל 12 תל אביב", "LOCATION", "SpacyRecognizer", 0.85),
            self.res("תל אביב רונית שפירא", "PERSON", rule(eng), 0.9)], hebrew=False)
        self.assertEqual([f.text for f in fs], ["תל אביב רונית שפירא"])


class HebrewSelfTestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_self_test_require_hebrew_fails_without_model(self):
        eng, _ = make_engine(self.tmp, model="none")
        ok, lines = ps.self_test(eng, require_hebrew=True)
        self.assertFalse(ok)
        self.assertTrue(any("FAIL" in l and "Hebrew model loaded" in l for l in lines))
        self.assertFalse(any("PERSON (Hebrew NER)" in l for l in lines))

    def test_self_test_without_require_ignores_missing_model(self):
        eng, _ = make_engine(self.tmp, model="none")
        _, lines = ps.self_test(eng)
        self.assertFalse(any("Hebrew" in l for l in lines))

    def test_self_test_hebrew_check_passes_with_fake_model(self):
        eng, _ = make_engine(self.tmp)
        _, lines = ps.self_test(eng, require_hebrew=True)
        self.assertTrue(any(l.startswith("ok") and "PERSON (Hebrew NER)" in l for l in lines))
        self.assertTrue(any(l.startswith("ok") and "Hebrew model loaded" in l for l in lines))

    def test_cli_flag_passes_require_hebrew(self):
        with mock.patch.object(ps, "self_test", return_value=(True, ["x"])) as st:
            rc = ps.main(["--self-test", "--require-hebrew"])
        self.assertEqual(rc, 0)
        st.assert_called_once_with(require_hebrew=True)


@unittest.skipUnless(ps.QT_OK, "PyQt6 not installed")
class HebrewSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        cls.app = ps.QtWidgets.QApplication.instance() or ps.QtWidgets.QApplication([])

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cfg = ps.AppConfig(self.tmp / "config.json")

    def dialog(self, model):
        # the small CI build has no runtime; these tests are about the model folder only
        with mock.patch.object(ps, "find_hebrew_model", return_value=model), \
             mock.patch.object(ps, "hebrew_runtime_ok", return_value=True):
            dlg = ps.SettingsDialog(None, self.cfg, mock.Mock(builtin_supported=[]))
        self.addCleanup(dlg.deleteLater)
        return dlg

    def test_settings_checkbox_disabled_without_model(self):
        dlg = self.dialog(None)
        self.assertFalse(dlg.chk_hebrew.isEnabled())
        self.assertIn("Hebrew model not installed", dlg.chk_hebrew.text())
        self.assertIn("Hebrew name detection (DictaBERT NER)", dlg.chk_hebrew.text())

    def test_settings_checkbox_enabled_with_model_and_tooltip(self):
        dlg = self.dialog(self.tmp)
        self.assertTrue(dlg.chk_hebrew.isEnabled())
        self.assertEqual(dlg.chk_hebrew.text(), "Hebrew name detection (DictaBERT NER)")
        self.assertEqual(dlg.chk_hebrew.toolTip(), "Model: DictaBERT NER by Dicta, CC BY 4.0.")

    def test_settings_checkbox_saves(self):
        dlg = self.dialog(self.tmp)
        self.assertTrue(dlg.chk_hebrew.isChecked())
        dlg.chk_hebrew.setChecked(False)
        dlg._accept()
        self.assertFalse(self.cfg.data["engine"]["hebrew_ner"])
        self.assertTrue(dlg.needs_engine_restart)

    def test_unchanged_checkbox_needs_no_restart(self):
        dlg = self.dialog(self.tmp)
        dlg._accept()
        self.assertFalse(dlg.needs_engine_restart)

    def test_disabled_checkbox_keeps_saved_value(self):
        self.cfg["engine"]["hebrew_ner"] = True
        dlg = self.dialog(None)
        dlg._accept()
        self.assertTrue(self.cfg.data["engine"]["hebrew_ner"])



FIXTURE = HERE / "fixtures" / "hebrew_ner_sentences.json"
KIND_TO_ENTITY = ps.HEBREW_LABEL_MAP


def _real_model_available():
    return ps.find_hebrew_model() is not None and ps.ort is not None and ps.HfTokenizer is not None


def _match(pred_text, pred_entity, gold_text, gold_kind):
    if pred_entity != KIND_TO_ENTITY[gold_kind] or len(pred_text) < 2 or len(gold_text) < 2:
        return False
    return pred_text in gold_text or gold_text in pred_text


def _score(model, items):
    """(tp, fp, fn, pairs) with greedy one-to-one matching per sentence."""
    tp = fp = fn = 0
    missed, extra = [], []
    for item in items:
        text = item["text"]
        preds = [(text[s.start:s.end], s.entity) for s in model.predict(text)]
        gold = [tuple(e) for e in item["entities"]]
        used = set()
        for g_text, g_kind in gold:
            hit = next((i for i, (p, e) in enumerate(preds)
                        if i not in used and _match(p, e, g_text, g_kind)), None)
            if hit is None:
                fn += 1
                missed.append((g_text, g_kind, text))
            else:
                used.add(hit)
                tp += 1
        for i, (p, e) in enumerate(preds):
            if i not in used:
                fp += 1
                extra.append((p, e, text))
    return tp, fp, fn, missed, extra


@unittest.skipUnless(_real_model_available(), "Hebrew model or runtime not installed")
class RealModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = ps.load_hebrew_model(ps.find_hebrew_model())
        cls.items = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def spans(self, text):
        return [(text[s.start:s.end], s.entity) for s in self.model.predict(text)]

    def test_f1_on_fixture(self):
        tp, fp, fn, missed, extra = _score(self.model, self.items)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        print(f"\nF1={f1:.3f} P={precision:.3f} R={recall:.3f} tp={tp} fp={fp} fn={fn}")
        print("missed:", missed)
        print("extra:", extra)
        # 0.930 with the pinned model; 0.862 when the gap merge joined across types (R7)
        self.assertGreaterEqual(f1, 0.90)

    # A bare family name after "משפחת" comes back as ORGANIZATION "משפחת אזולאי". The text is
    # still masked, only the type differs. Known model limit, measured with the pinned model.
    KNOWN_PERSON_AS_ORG = {"אזולאי"}

    def test_every_person_found(self):
        for item in self.items:
            text = item["text"]
            preds = self.spans(text)
            for g_text, g_kind in item["entities"]:
                if g_kind != "PER":
                    continue
                if g_text in self.KNOWN_PERSON_AS_ORG:
                    # never unmasked: some span of any type must cover the name
                    self.assertTrue(any(g_text in p for p, _ in preds), f"{g_text!r}: {preds}")
                    continue
                self.assertTrue(any(_match(p, e, g_text, g_kind) for p, e in preds),
                                f"person {g_text!r} missed in {text!r}: {preds}")

    def test_speed_long_text(self):
        base = " ".join(i["text"] for i in self.items)
        text = (base * 3)[:1500]
        start = time.perf_counter()
        self.model.predict(text)
        took = time.perf_counter() - start
        print(f"\nspeed: {len(text)} chars in {took:.2f} s")
        self.assertLess(took, 5.0)

    # ---- R2 checks ----
    def test_tokenizer_has_no_truncation_or_padding(self):
        self.assertIsNone(self.model.tokenizer.truncation)
        self.assertIsNone(self.model.tokenizer.padding)

    def test_special_tokens_and_label_map(self):
        tok = self.model.tokenizer
        self.assertIsNotNone(tok.token_to_id("[CLS]"))
        self.assertIsNotNone(tok.token_to_id("[SEP]"))
        self.assertEqual(len(self.model.id2label), 27)
        self.assertIn("O", self.model.id2label.values())

    def test_logits_shape(self):
        tok = self.model.tokenizer
        ids = [tok.token_to_id("[CLS]")] + tok.encode("דנה כהן", add_special_tokens=False).ids \
            + [tok.token_to_id("[SEP]")]
        self.assertEqual(self.model._run(ids).shape, (len(ids), 27))

    def test_name_after_600_tokens_found(self):
        filler = " ".join(["הדוח נשלח למחלקת הכספים אתמול בערב והמערכת עודכנה לפי הנוהל."] * 70)
        text = filler + " בסוף נפגשה אורית דהן עם הצוות."
        tokens = len(self.model.tokenizer.encode(text, add_special_tokens=False).ids)
        self.assertGreater(tokens, 600)
        self.assertTrue(any(e == "PERSON" and "דהן" in t for t, e in self.spans(text)),
                        self.spans(text)[-3:])

    def test_spans_cover_whole_words(self):
        texts = [
            "דנה כהן נפגשה עם משה לוי בחיפה.",
            "אביגיל רוזנצוויג-שטרנברג נפגשה עם זלמן שכטמן-קורנפלד בקריית שמונה.",
            "הגיעו הדס ברגמן, אנאבל מרקוביץ ומתתיהו אלקבץ מאלפי מנשה.",
        ]
        for text in texts:
            for s in self.model.predict(text):
                if s.start > 0:
                    self.assertFalse(text[s.start - 1].isalnum(), (text, text[s.start:s.end]))
                if s.end < len(text):
                    self.assertFalse(text[s.end].isalnum(), (text, text[s.start:s.end]))
        found = self.spans(texts[2])
        self.assertTrue(any("מתתיהו" in t for t, e in found), found)
        self.assertTrue(any("אנאבל" in t for t, e in found), found)

    def test_split_name_is_one_person_span(self):
        text = "פגשתי את מוחמד אבו-סאלח ואת ז'אן-פייר לוי."
        found = self.model.predict(text)
        s = text.index("ז'אן-פייר לוי")
        self.assertTrue(any(sp.entity == "PERSON" and sp.start <= s and s + 13 <= sp.end
                            for sp in found), self.spans(text))

    def test_window_default_is_not_the_lossy_400(self):
        # a 400-token window missed 4 of 48 persons with the pinned model (see HEBREW_WINDOW_TOKENS)
        self.assertLessEqual(ps.HEBREW_WINDOW_TOKENS, 300)
        self.assertEqual(self.model.max_tokens, ps.HEBREW_WINDOW_TOKENS)

    def test_long_text_matches_its_parts(self):
        # sentences the model types alone with high confidence; 8 of them, 8 times over
        good = [self.items[k] for k in (0, 3, 4, 10, 13, 14, 15, 17)]
        parts = [self.spans(i["text"]) for i in good]
        whole_text = " ".join([i["text"] for i in good] * 8)
        tokens = len(self.model.tokenizer.encode(whole_text, add_special_tokens=False).ids)
        self.assertGreater(tokens, 2 * ps.HEBREW_WINDOW_TOKENS)
        found = self.model.predict(whole_text)
        # no duplicate or overlapping spans
        for a, b in zip(found, found[1:]):
            self.assertLessEqual(a.end, b.start, (whole_text[a.start:a.end], whole_text[b.start:b.end]))
        # Context shifts some ORGANIZATION and LOCATION labels in a long text (measured: one
        # repeated company name loses its tail). PERSON is the leak-critical type: every PERSON
        # found in a part is found again at every repeat in the whole text.
        for entity_text, entity in sorted({p for part in parts for p in part}):
            if entity != "PERSON":
                continue
            for m in re.finditer(re.escape(entity_text), whole_text):
                self.assertTrue(any(s.entity == "PERSON" and s.start <= m.start() and m.end() <= s.end
                                    for s in found), (entity_text, m.start()))
        for s in found:
            for ch_pos in (s.start - 1, s.end):
                if 0 <= ch_pos < len(whole_text):
                    self.assertFalse(whole_text[ch_pos].isalnum())


# ---- shuffled long text: overlapping spans must never leave part of a name unmasked ----
# Two sentences from the review that gave partly unmasked names before the union merge:
# window disagreement (LOCATION "בבית אבי" + PERSON "אבי לוי") and word extension
# (PERSON "ז'" grown to "ז'אן" over ORGANIZATION "אן-פייר").
SHUFFLE_EXTRA = ["משפחת כהן ומשפחת לוינשטיין נפגשו בבית אבי לוי.",
                 "פגשתי את מוחמד אבו-סאלח ואת ז'אן-פייר לוי."]
SHUFFLE_EXTRA_PERSONS = ["אבי לוי", "ז'אן-פייר לוי"]
# Seed rule: the predict checks fail on this text with the old _dedupe (overlapping spans) and
# pass with the union merge. Seeds 3, 5, 10, 13 and 27 of 0-29 fail on overlap before the fix;
# 5, 10, 13 and 27 then pass, and 5 also passes the end-to-end check for the two review names.
# The other seeds fail for causes
# outside predict's overlap handling: the model misses a name in long context ("אזולאי"), or it
# splits "בבית אבי לוי" into two touching spans. See the task-4 report.
SHUFFLE_SEED = 5
# End-to-end guard seeds (search over seeds 0-99): with the old _dedupe, analyze + sanitize left
# part of a review name in the output; with the union merge the name is fully masked.
# 43: "ז'אן-פייר לוי" lost "פייר" and "לוי"; 90: "אבי לוי" lost "לוי".
E2E_GUARD_SEEDS = (43, 90)
# Task 4b leak seeds: each one left part of a fixture person unmasked on e9a72f4 and passes now.
# 0: "יוסי" (spaCy LOCATION "אברהמי מחברת אורנים" beat PERSON "יוסי אברהמי"; fixed by dropping
# spaCy findings on Hebrew text). 54, 77: "לוי" of "ז'אן-פייר לוי" (two spans with one space
# between, the weak half under the threshold; fixed by the gap merge). 59: "אבי" of "אבי לוי"
# on e9a72f4; with the gap merge alone, PERSON "רחוב הרצל 12 תל אביב נועה גולן ויעל רוזן" lost
# to the street rule (fixed by resolve_keep_hebrew_coverage). Fix round R7 (no cross-type gap
# merge) broke 54, 77 and 59 again: ORGANIZATION "ז'אן-פייר" / LOCATION "בבית" beat the
# propagated copy of the full name; fixed by the coverage give-back for propagated copies.
E2E_LEAK_SEEDS = (0, 54, 77, 59)


def shuffled_long_text(items, seed):
    rng = random.Random(seed)
    sents = [i["text"] for i in items] + SHUFFLE_EXTRA
    rng.shuffle(sents)
    sep = rng.choice([" ", "\n"])
    return sep.join(sents * 2)


def shuffle_persons(items):
    names = {e[0] for i in items for e in i["entities"] if e[1] == "PER"}
    return sorted(names | set(SHUFFLE_EXTRA_PERSONS))


# ---- varied long text (fix round R8): names reappear in other sentences, not verbatim ----
VARIED_TEMPLATES = [
    "אתמול בערב {n} התקשר לשאול על החשבונית.",
    "המסמך נשלח אל {n} לחתימה.",
    "לדברי {n}, הפגישה תתקיים ביום רביעי.",
    "{n} אישר את ההזמנה בטלפון.",
    "בישיבה השתתפו גם {n} ונציג מהספק.",
    "ההעברה בוצעה על שם {n} בשבוע שעבר.",
    "צריך לעדכן את {n} לגבי השינוי בלוח הזמנים.",
    "הכרטיס נפתח לבקשת {n}.",
]
VARIED_SURNAME_TEMPLATES = ["פנינו אל מר {n} בנושא החוזה.", "גם משפחת {n} הגיעה לאירוע."]
VARIED_EN = ["Please send the invoice to John Carter before Friday.",
             "Sarah Mitchell reviewed the firewall logs on Monday."]
VARIED_EN_NO_ENTITY = ["The backup job finished without errors last night.",
                       "Restart the service after you apply the patch."]
# Seeds of varied_long_text that left part of a person unmasked before fix round R8 ("אזולאי"
# in all four, with "גולן", "ישראלי", "לוי" or "וקנין") and pass after it.
VARIED_SEEDS = (3, 12, 15, 20)


def varied_long_text(items, seed):
    """(text, persons, no_entity). The fixture sentences and the two review sentences, 12
    template sentences with a random person (30% only the surname), and 4 English lines,
    shuffled. persons: (name, start, end) of every person occurrence; no_entity: (kind, start,
    end) of the sentences with no entity ("noent-he" or "noent-en")."""
    rng = random.Random(seed)
    sents = [(i["text"], [e[0] for e in i["entities"] if e[1] == "PER"],
              "he" if i["entities"] else "noent-he") for i in items]
    sents += zip(SHUFFLE_EXTRA, (["אבי לוי"], ["מוחמד אבו-סאלח", "ז'אן-פייר לוי"]), ("he", "he"))
    pool = sorted({n for _, ns, _ in sents for n in ns})
    parts = []
    for s, ns, kind in sents:
        occ = [(n, m.start()) for n in ns
               for m in re.finditer(r"(?<!\w)" + re.escape(n) + r"(?!\w)", s)]
        parts.append((s, occ, kind))
    for _ in range(12):
        n = rng.choice(pool)
        if rng.random() < 0.3:
            n = re.split(r"\s", n)[-1]
            t = rng.choice(VARIED_SURNAME_TEMPLATES)
        else:
            t = rng.choice(VARIED_TEMPLATES)
        s = t.format(n=n)
        parts.append((s, [(n, s.index(n))], "he"))
    parts += [(s, [], "en") for s in VARIED_EN] + [(s, [], "noent-en") for s in VARIED_EN_NO_ENTITY]
    rng.shuffle(parts)
    sep = rng.choice([" ", "\n"])
    text, persons, no_entity = "", [], []
    for k, (s, occ, kind) in enumerate(parts):
        if k:
            text += sep
        base = len(text)
        text += s
        persons += [(n, base + o, base + o + len(n)) for n, o in occ]
        if kind.startswith("noent"):
            no_entity.append((kind, base, base + len(s)))
    return text, persons, no_entity


def varied_problems(engine, text, persons):
    """Name parts longer than 1 char (whole words) of a person that no applied finding covers,
    and multi-word person surfaces left in the output."""
    vault = ps.SessionVault()
    out, enabled = ps.sanitize(text, engine.analyze(text, [], vault), vault)
    problems = [("in-output", n) for n in sorted({n for n, _, _ in persons}) if " " in n and n in out]
    for name, s, e in persons:
        for p_start, p_end in _name_parts(text, s, e):
            if not any(f.start <= p_start and p_end <= f.end for f in enabled):
                problems.append(("part-unmasked", name, text[p_start:p_end], p_start))
    return problems


def _occurrences(text, name):
    return [(m.start(), m.end()) for m in re.finditer(r"(?<!\w)" + re.escape(name) + r"(?!\w)", text)]


def _name_parts(text, start, end):
    """(start, end) of each part of a name longer than 1 char (split on spaces and hyphens)."""
    return [(start + m.start(), start + m.end()) for m in re.finditer(r"[^\s\-־]{2,}", text[start:end])]


def predict_problems(model, text, persons):
    """Overlapping predict spans, and person occurrences not covered by one span."""
    problems = []
    spans = model.predict(text)
    for a, b in zip(spans, spans[1:]):
        if a.end > b.start:
            problems.append(("overlap", text[a.start:a.end], a.entity, text[b.start:b.end], b.entity))
    for name in persons:
        for s, e in _occurrences(text, name):
            if not any(sp.start <= s and e <= sp.end for sp in spans):
                problems.append(("predict-not-covered", name, s))
    return problems


def engine_problems(engine, text, persons):
    """Person surfaces, or name parts longer than 1 char, left after analyze + sanitize."""
    problems = []
    vault = ps.SessionVault()
    out, enabled = ps.sanitize(text, engine.analyze(text, [], vault), vault)
    for name in persons:
        if name in out:
            problems.append(("in-output", name))
        for s, e in _occurrences(text, name):
            for p_start, p_end in _name_parts(text, s, e):
                if not any(f.start <= p_start and p_end <= f.end for f in enabled):
                    problems.append(("part-unmasked", name, text[p_start:p_end], p_start))
    return problems


@unittest.skipUnless(_real_model_available(), "Hebrew model or runtime not installed")
class ShuffledLongTextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.items = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.tmp = Path(tempfile.mkdtemp())
        cls.engine = ps.DetectionEngine(ps.AppConfig(cls.tmp / "config.json"), cls.tmp / "rules")
        cls.engine.initialize()
        cls.model = ps.load_hebrew_model(ps.find_hebrew_model())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def test_engine_uses_hebrew_model(self):
        self.assertIsNotNone(getattr(self.engine, "hebrew_status", None))
        self.assertIn("ז'אן-פייר לוי", shuffled_long_text(self.items, SHUFFLE_SEED))
        self.assertIn("בבית אבי לוי.", shuffled_long_text(self.items, SHUFFLE_SEED))

    def test_predict_no_overlap_and_every_person_covered(self):
        text = shuffled_long_text(self.items, SHUFFLE_SEED)
        tokens = len(self.model.tokenizer.encode(text, add_special_tokens=False).ids)
        self.assertGreater(tokens, ps.HEBREW_WINDOW_TOKENS)  # two windows with an overlap zone
        self.assertEqual(predict_problems(self.model, text, shuffle_persons(self.items)), [])

    def test_review_names_fully_masked_end_to_end(self):
        text = shuffled_long_text(self.items, SHUFFLE_SEED)
        self.assertEqual(engine_problems(self.engine, text, SHUFFLE_EXTRA_PERSONS), [])

    def test_review_names_fully_masked_end_to_end_guard_seeds(self):
        for seed in E2E_GUARD_SEEDS:
            with self.subTest(seed=seed):
                text = shuffled_long_text(self.items, seed)
                self.assertEqual(engine_problems(self.engine, text, SHUFFLE_EXTRA_PERSONS), [])

    def test_every_fixture_person_fully_masked_end_to_end(self):
        text = shuffled_long_text(self.items, SHUFFLE_SEED)
        self.assertEqual(engine_problems(self.engine, text, shuffle_persons(self.items)), [])

    def test_varied_text_every_person_fully_masked(self):
        # R8: names reappear in other sentences; the Hebrew model misses "אזולאי" there and a
        # cut spaCy finding keeps it masked
        for seed in VARIED_SEEDS:
            with self.subTest(seed=seed):
                text, persons, _ = varied_long_text(self.items, seed)
                self.assertIn("אזולאי", {n for n, _, _ in persons})
                self.assertEqual(varied_problems(self.engine, text, persons), [])

    def test_every_fixture_person_fully_masked_on_leak_seeds(self):
        # No fixture person surface stays in the output, and every part of a name longer than
        # 1 char (a whole word) sits inside an applied finding. Coverage is checked by offsets:
        # a substring search on the output gives false failures ("אבי" in "תל אביב").
        for seed in E2E_LEAK_SEEDS:
            with self.subTest(seed=seed):
                text = shuffled_long_text(self.items, seed)
                self.assertEqual(engine_problems(self.engine, text, shuffle_persons(self.items)), [])

if __name__ == "__main__":
    unittest.main()


# ---- propagation over Hebrew prefix letters (final review I-4a) ----
# "ישראל ישראלי" found once must also mask "לישראל ישראלי": Hebrew attaches the letters
# ו ב כ ל מ ש ה to the next word. Only the name is masked, not the prefix.
class HebrewPrefixPropagationTests(unittest.TestCase):
    def spans(self, text, value, ci=True):
        return [text[s:e] for s, e in ps.find_propagated(text, value, ci)]

    def test_prefixed_hebrew_occurrence_found(self):
        t = "שלחתי לישראל ישראלי ואחר כך וכשישראל ישראלי חזר. ישראל ישראלי."
        got = list(ps.find_propagated(t, "ישראל ישראלי", True))
        self.assertEqual(len(got), 3)
        self.assertEqual({t[s:e] for s, e in got}, {"ישראל ישראלי"})
        self.assertEqual(got[0][0], t.index("לישראל") + 1)

    def test_at_most_three_prefix_letters(self):
        self.assertEqual(self.spans("ולכשישראל ישראלי", "ישראל ישראלי"), [])

    def test_other_letters_do_not_count_as_prefix(self):
        self.assertEqual(self.spans("אישראל ישראלי", "ישראל ישראלי"), [])
        self.assertEqual(self.spans("לוי ובלוינשטיין", "לוי"), ["לוי"])

    def test_english_propagation_unchanged(self):
        for t, v in (("blJohn Carter and lJohn Carter, John Carter.", "John Carter"),
                     ("ל-John Carter וJohn Carter", "John Carter"),
                     ("x10.1.2.3 10.1.2.3", "10.1.2.3")):
            self.assertEqual(list(ps.find_propagated(t, v, True)), list(ps.find_literal(t, v, True)))

    def test_engine_masks_prefixed_copy(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        eng, _ = make_engine(tmp)
        # a manual exact rule finds the bare name only; NER is off, so only propagation can
        # find the prefixed copy
        text = "דנה כהן נפגשה בחיפה. אחר כך שלחנו לדנה כהן מסמך."
        v = ps.SessionVault()
        fs = eng.analyze(text, [ps.ManualRule("exact", "דנה כהן", "PERSON")], v, skip_ner=True)
        out, _ = ps.sanitize(text, fs, v)
        self.assertNotIn("דנה", out)
        self.assertNotIn("כהן", out)
        s = text.index("לדנה") + 1
        self.assertIn((s, s + len("דנה כהן"), "propagated"),
                      [(f.start, f.end, f.source) for f in fs])


# ---- wanted entity types reach the union (final review M-1) ----
# The union of overlapping spans takes the type of its best part. When that type is not wanted
# (organizations off, or LOCATION/PERSON deselected), the recognizer used to drop the whole union,
# also the wanted part. predict now gets the wanted types and types the union by a wanted part.
class WantedTypesUnionTests(unittest.TestCase):
    T = "פגשתי את ז'אן-פייר לוי היום."

    def raw(self, a_entity, b_entity):
        t = self.T
        z, l = t.index("ז'אן"), t.index("לוי")
        return [ps.HebrewSpan(z, l, a_entity, 0.95), ps.HebrewSpan(z + 5, l + 3, b_entity, 0.9)]

    def test_dedupe_types_by_wanted_part(self):
        spans = self.raw("ORGANIZATION", "PERSON")
        got = ps.HebrewNerModel._dedupe(spans, {"PERSON", "LOCATION"})
        self.assertEqual([(s.entity, s.score) for s in got], [("PERSON", 0.95)])
        spans = self.raw("LOCATION", "PERSON")
        got = ps.HebrewNerModel._dedupe(spans, {"LOCATION", "ORGANIZATION"})
        self.assertEqual([s.entity for s in got], ["LOCATION"])
        # without a wanted set: as before
        self.assertEqual([s.entity for s in ps.HebrewNerModel._dedupe(self.raw("LOCATION", "PERSON"))],
                         ["PERSON"])

    def test_predict_drops_only_unions_without_a_wanted_part(self):
        model, _ = build({})
        raw = self.raw("ORGANIZATION", "ORGANIZATION")
        with mock.patch.object(model, "_predict_group", return_value=raw):
            self.assertEqual(model.predict(self.T, {"PERSON"}), [])
            self.assertEqual(len(model.predict(self.T, {"ORGANIZATION"})), 1)

    def engine_hebrew(self, raw, **kw):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        eng, _ = make_engine(tmp, orgs=kw.pop("orgs", True))
        ents = kw.pop("drop", None)
        if ents:
            eng.config["engine"]["builtin_entities"] = [
                e for e in eng.config["engine"]["builtin_entities"] if e != ents]
        with mock.patch.object(eng.hebrew_model, "_predict_group", return_value=raw):
            fs = eng.analyze(self.T, [], ps.SessionVault())
        return [(f.text, f.entity) for f in fs if f.source == "hebrew_ner"]

    def test_engine_organizations_off_keeps_location_union(self):
        got = self.engine_hebrew(self.raw("ORGANIZATION", "LOCATION"), orgs=False)
        self.assertEqual(got, [("ז'אן-פייר לוי", "LOCATION")])

    def test_engine_location_deselected_keeps_organization_union(self):
        got = self.engine_hebrew(self.raw("LOCATION", "ORGANIZATION"), drop="LOCATION")
        self.assertEqual(got, [("ז'אן-פייר לוי", "ORGANIZATION")])

    def test_recognizer_person_not_requested_keeps_location_union(self):
        # the bundled rules hold PERSON, so the engine always asks for PERSON; the recognizer
        # still must not lose the LOCATION part when a caller leaves PERSON out
        rec = ps.HebrewNerRecognizer(build({})[0])
        with mock.patch.object(rec.model, "_predict_group", return_value=self.raw("LOCATION", "PERSON")):
            res = rec.analyze(self.T, ["LOCATION", "ORGANIZATION"])
        self.assertEqual([(self.T[r.start:r.end], r.entity_type) for r in res],
                         [("ז'אן-פייר לוי", "LOCATION")])


# ---- unreadable model folder (final review I-1) ----
class UnreadableModelFolderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bundle = self.tmp / "bundle"
        self.model = make_model(self.bundle)
        real = Path.is_file
        model = self.model

        def is_file(p):
            if model in Path(p).parents or Path(p) == model:
                raise PermissionError(13, "Permission denied", str(p))
            return real(p)
        self.patches = [mock.patch.object(ps, "bundle_dir", return_value=self.bundle),
                        mock.patch.object(ps, "APP_DIR", self.tmp / "app"),
                        mock.patch.object(Path, "is_file", is_file)]

    def run_patched(self, fn):
        for p in self.patches:
            p.start()
        try:
            return fn()
        finally:
            for p in reversed(self.patches):
                p.stop()

    def test_discovery_returns_none(self):
        self.assertIsNone(self.run_patched(ps.find_hebrew_model))
        self.assertFalse(self.run_patched(ps.is_full_build))

    def test_initialize_succeeds_and_reports_failure(self):
        rules = self.tmp / "rules"
        shutil.copytree(TEMPLATE_RULES, rules / "remote")
        (rules / "local").mkdir()
        eng = ps.DetectionEngine(ps.AppConfig(self.tmp / "config.json"), rules)
        self.run_patched(eng.initialize)
        self.assertNotEqual(eng.hebrew_status, "loaded")
        self.assertTrue(eng.hebrew_status.startswith("failed"), eng.hebrew_status)
        self.assertIsNone(eng.hebrew_model)
        fs = eng.analyze("John Smith logged in from 10.20.30.40", [], ps.SessionVault())
        self.assertIn("INTERNAL_IP", {f.entity for f in fs})

    def test_find_error_never_stops_initialize(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        rules = tmp / "rules"
        shutil.copytree(TEMPLATE_RULES, rules / "remote")
        (rules / "local").mkdir()
        eng = ps.DetectionEngine(ps.AppConfig(tmp / "config.json"), rules)
        with mock.patch.object(ps, "find_hebrew_model", side_effect=OSError("disk gone")):
            eng.initialize()
        self.assertTrue(eng.hebrew_status.startswith("failed"))

    @unittest.skipUnless(ps.QT_OK, "PyQt6 not installed")
    def test_settings_dialog_opens(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        self.app = ps.QtWidgets.QApplication.instance() or ps.QtWidgets.QApplication([])
        cfg = ps.AppConfig(self.tmp / "config.json")
        dlg = self.run_patched(lambda: ps.SettingsDialog(None, cfg, mock.Mock(builtin_supported=[])))
        self.addCleanup(dlg.deleteLater)
        self.assertFalse(dlg.chk_hebrew.isEnabled())


# ---- Hebrew NER state in the engine status label (final review I-3) ----
class EngineStatusLabelTests(unittest.TestCase):
    def test_suffix(self):
        f = ps.hebrew_status_suffix
        self.assertEqual(f("loaded", True), "  ·  Hebrew NER")
        self.assertEqual(f("off", True), "")
        self.assertEqual(f("not installed", False), "")
        self.assertEqual(f("failed: boom", True), "  ·  Hebrew NER: failed (see Log)")
        self.assertEqual(f("failed: denied", False), "  ·  Hebrew NER: failed (see Log)")
        self.assertEqual(f("not installed", True), "  ·  Hebrew NER: failed (see Log)")

    @unittest.skipUnless(ps.QT_OK, "PyQt6 not installed")
    def test_main_window_label(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        self.app = ps.QtWidgets.QApplication.instance() or ps.QtWidgets.QApplication([])
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch.object(ps.MainWindow, "_start_engine"):
            win = ps.MainWindow(ps.AppConfig(tmp / "config.json"))
        self.addCleanup(win.deleteLater)
        cases = [("failed: boom", tmp, "Hebrew NER: failed (see Log)"),
                 ("loaded", tmp, "  ·  Hebrew NER"),
                 ("not installed", None, None)]
        for status, folder, want in cases:
            with self.subTest(status=status):
                win.engine.hebrew_status = status
                win.engine.model_name = "en_core_web_lg"
                win._startup_checked = True
                with mock.patch.object(win, "_run", lambda fn, done, *a, **k: done("presidio+spacy")), \
                     mock.patch.object(ps, "find_hebrew_model", return_value=folder), \
                     mock.patch.object(ps, "is_full_build", return_value=False):
                    win._start_engine()
                text = win.lbl_engine.text()
                self.assertTrue(text.startswith("Engine: Presidio + spaCy en_core_web_lg  ·  offline"))
                if want:
                    self.assertTrue(text.endswith(want), text)
                else:
                    self.assertEqual(text, "Engine: Presidio + spaCy en_core_web_lg  ·  offline")


# ---- Settings checkbox without the runtime (final review M-5) ----
@unittest.skipUnless(ps.QT_OK, "PyQt6 not installed")
class HebrewSettingsRuntimeTests(unittest.TestCase):
    def test_checkbox_disabled_when_runtime_missing(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        self.app = ps.QtWidgets.QApplication.instance() or ps.QtWidgets.QApplication([])
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        cfg = ps.AppConfig(tmp / "config.json")
        cfg["engine"]["hebrew_ner"] = True
        for attr in ("ort", "HfTokenizer"):
            with self.subTest(missing=attr), \
                 mock.patch.object(ps, "find_hebrew_model", return_value=tmp), \
                 mock.patch.object(ps, attr, None):
                dlg = ps.SettingsDialog(None, cfg, mock.Mock(builtin_supported=[]))
                self.addCleanup(dlg.deleteLater)
                self.assertFalse(dlg.chk_hebrew.isEnabled())
                self.assertIn("Hebrew model not installed", dlg.chk_hebrew.text())
                dlg._accept()
                self.assertTrue(cfg.data["engine"]["hebrew_ner"])
