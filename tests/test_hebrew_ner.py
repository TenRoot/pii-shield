"""Hebrew NER tests:  python -m unittest discover -s tests -v"""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
