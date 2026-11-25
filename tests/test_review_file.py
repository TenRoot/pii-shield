"""Save review / Load review: store the analyzed text, findings and session map; restore them
without a new analysis."""
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pii_sanitizer as ps  # noqa: E402

TEXT = "id 123456782 host SRV-DC01 id 123456782 user contoso"


def sample_findings():
    out = []
    for value, ent, tok in (("123456782", "IL_ID", "<IL_ID_1>"), ("SRV-DC01", "HOSTNAME", "<HOSTNAME_1>"),
                            ("contoso", "ORGANIZATION", "<ORGANIZATION_1>")):
        start = 0
        while (i := TEXT.find(value, start)) >= 0:
            out.append(ps.Finding(i, i + len(value), value, ent, 0.9, "custom", "rule", True, tok))
            start = i + 1
    out.sort(key=lambda f: f.start)
    out[-1].enabled = False                     # the user turned "contoso" off
    out[1].token, out[1].token_edited = "<HOST_A>", True
    return out


class ReviewDataTests(unittest.TestCase):
    def test_round_trip(self):
        vault = ps.SessionVault()
        vault.commit("SRV-DC01", "<HOST_A>", "HOSTNAME")
        fs = sample_findings()
        data = ps.review_to_dict(TEXT, fs, vault, 0.7)
        self.assertEqual(data["format"], ps.REVIEW_FORMAT)
        self.assertEqual(data["format_version"], ps.REVIEW_FORMAT_VERSION)
        data = json.loads(json.dumps(data))        # through JSON, as on disk
        text, got, session, threshold = ps.review_from_dict(data)
        self.assertEqual(text, TEXT)
        self.assertEqual(got, fs)
        self.assertEqual([f.token_edited for f in got], [f.token_edited for f in fs])
        self.assertEqual(threshold, 0.7)
        self.assertEqual(session["entries"][0]["token"], "<HOST_A>")

    def test_rejects_other_files(self):
        with self.assertRaises(ValueError):
            ps.review_from_dict({"app": "PII Shield", "entries": []})          # a session map file
        data = ps.review_to_dict(TEXT, sample_findings(), ps.SessionVault(), 0.85)
        data["format_version"] = ps.REVIEW_FORMAT_VERSION + 1
        with self.assertRaises(ValueError):
            ps.review_from_dict(data)

    def test_rejects_findings_that_do_not_match_the_text(self):
        data = ps.review_to_dict(TEXT, sample_findings(), ps.SessionVault(), 0.85)
        data["findings"][0]["start"] += 1
        with self.assertRaises(ValueError):
            ps.review_from_dict(data)
        data = ps.review_to_dict(TEXT, sample_findings(), ps.SessionVault(), 0.85)
        data["findings"][0]["end"] = len(TEXT) + 5
        with self.assertRaises(ValueError):
            ps.review_from_dict(data)


class ReviewFileGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        cls.app = ps.QtWidgets.QApplication.instance() or ps.QtWidgets.QApplication([])

    def make_window(self):
        with mock.patch.object(ps.MainWindow, "_start_engine"):
            w = ps.MainWindow(ps.AppConfig(self.tmp / "config.json"))
        self.addCleanup(w.deleteLater)
        return w

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = self.tmp / "review.json"
        w = self.win = self.make_window()
        w.input.setPlainText(TEXT)
        w.analyzed_text = TEXT
        w.findings = sample_findings()
        w.thr.setValue(0.7)
        w.populate_table()
        w._update_send_button()       # as at the end of a real analysis

    def save(self, w=None, answer=None):
        w = w or self.win
        Yes = ps.QtWidgets.QMessageBox.StandardButton.Yes
        with mock.patch.object(ps.QtWidgets.QMessageBox, "warning", return_value=answer or Yes), \
             mock.patch.object(ps.QtWidgets.QFileDialog, "getSaveFileName", return_value=(str(self.path), "")):
            w.save_review()

    def load(self, w):
        with mock.patch.object(ps.QtWidgets.QFileDialog, "getOpenFileName", return_value=(str(self.path), "")), \
             mock.patch.object(ps.QtWidgets.QMessageBox, "question",
                               return_value=ps.QtWidgets.QMessageBox.StandardButton.Yes), \
             mock.patch.object(ps.QtWidgets.QMessageBox, "warning") as warn:
            w.load_review()
        return warn

    def test_save_writes_private_file(self):
        self.save()
        data = json.loads(self.path.read_text("utf-8"))
        self.assertEqual(data["text"], TEXT)
        self.assertEqual(len(data["findings"]), len(self.win.findings))
        if os.name != "nt":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_save_cancelled_at_warning_writes_nothing(self):
        self.save(answer=ps.QtWidgets.QMessageBox.StandardButton.No)
        self.assertFalse(self.path.exists())

    def test_load_restores_review_without_analysis(self):
        self.save()
        w2 = self.make_window()
        with mock.patch.object(w2, "_run") as run:
            warn = self.load(w2)
        run.assert_not_called()                       # no analysis
        warn.assert_not_called()
        self.assertEqual(w2.input.toPlainText(), TEXT)
        self.assertEqual(w2.analyzed_text, TEXT)
        self.assertEqual(w2.findings, self.win.findings)
        self.assertAlmostEqual(w2.thr.value(), 0.7)
        self.assertGreater(w2.table.rowCount(), 0)
        self.assertTrue(w2.btn_send.isEnabled(), "ready to sanitize")
        out, _ = ps.sanitize(w2.analyzed_text, w2.findings, w2.vault)
        self.assertIn("<HOST_A>", out)
        self.assertIn("contoso", out, "the disabled finding stays disabled")

    def test_load_with_token_clash_changes_nothing(self):
        self.save()
        w2 = self.make_window()
        w2.vault.commit("other-value", "<HOST_A>", "HOSTNAME")   # the same token for another value
        w2.input.setPlainText("keep me")
        warn = self.load(w2)
        warn.assert_called_once()
        self.assertEqual(w2.input.toPlainText(), "keep me")
        self.assertEqual(w2.findings, [])

    def test_load_bad_file_shows_message(self):
        self.path.write_text("{not json", "utf-8")
        w2 = self.make_window()
        warn = self.load(w2)
        warn.assert_called_once()
        self.assertEqual(w2.findings, [])

    def test_save_button_follows_review_state(self):
        self.assertTrue(self.win.btn_save_review.isEnabled())
        w2 = self.make_window()
        self.assertFalse(w2.btn_save_review.isEnabled())


if __name__ == "__main__":
    unittest.main()
