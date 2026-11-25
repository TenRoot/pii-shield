"""Send to Sanitize on a large review runs in the background; a small one stays immediate."""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import pii_sanitizer as ps  # noqa: E402
from test_group_values import TEXT, findings_for  # noqa: E402


class GenerateBackgroundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        cls.app = ps.QtWidgets.QApplication.instance() or ps.QtWidgets.QApplication([])

    def setUp(self):
        # Earlier test files leave queued calls that point at deleted windows. Drop them before
        # these tests call processEvents (as in tests/test_pdf.py _qapp).
        ps.QtCore.QThreadPool.globalInstance().waitForDone(10000)
        ps.QtCore.QCoreApplication.removePostedEvents(None)
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        with mock.patch.object(ps.MainWindow, "_start_engine"):
            self.win = ps.MainWindow(ps.AppConfig(self.tmp / "config.json"))
        self.addCleanup(self.win.deleteLater)
        w = self.win
        w.input.setPlainText(TEXT)
        w.analyzed_text = TEXT
        w.findings = findings_for(TEXT)
        w.populate_table()
        w._update_send_button()

    def wait(self):
        ps.QtCore.QThreadPool.globalInstance().waitForDone(10000)
        self.app.processEvents()

    def test_small_review_is_immediate(self):
        self.win.generate()
        self.assertIn("<IL_ID_1>", self.win.output.toPlainText())
        self.assertNotIn("123456782", self.win.output.toPlainText())

    def test_large_review_runs_in_background(self):
        w = self.win
        with mock.patch.object(ps, "SANITIZE_BACKGROUND_FINDINGS", 0):
            w.generate()
            self.assertFalse(w.btn_generate.isEnabled(), "off while it runs")
            self.assertFalse(w.btn_restore.isEnabled())
            self.assertIn("Sanitizing", w.statusBar().currentMessage())
            self.wait()
        self.assertIn("<IL_ID_1>", w.output.toPlainText())
        self.assertIn("passed", w.lbl_leak.text())
        self.assertTrue(w.btn_generate.isEnabled())
        self.assertTrue(w.btn_restore.isEnabled())
        self.assertEqual(w.tabs.currentIndex(), 1)

    def test_background_token_conflict_shows_message(self):
        w = self.win
        w.vault.commit("other value", "<IL_ID_1>", "IL_ID")      # the token is taken
        with mock.patch.object(ps, "SANITIZE_BACKGROUND_FINDINGS", 0), \
             mock.patch.object(ps.QtWidgets.QMessageBox, "warning") as warn:
            w.generate()
            self.wait()
        warn.assert_called_once()
        self.assertEqual(w.output.toPlainText(), "")
        self.assertTrue(w.btn_generate.isEnabled())

    def test_result_after_close_is_ignored(self):
        w = self.win
        w._closing = True
        w._on_sanitized(("new", [], []))
        self.assertEqual(w.output.toPlainText(), "")


if __name__ == "__main__":
    unittest.main()
