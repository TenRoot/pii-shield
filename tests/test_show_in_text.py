"""Review table: show a finding in its context (tooltip preview, right-click, double-click)."""
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

Qt = ps.Qt
LINES = [f"filler line {i} with some words" for i in range(200)]
LINES[150] = "פנינו אל מר אבו-סאלח בנושא החוזה."
LINES[170] = "again אבו-סאלח here"
TEXT = "\n".join(LINES)


def findings():
    out = []
    start = 0
    while (i := TEXT.find("אבו-סאלח", start)) >= 0:
        out.append(ps.Finding(i, i + len("אבו-סאלח"), "אבו-סאלח", "PERSON", 0.9, "hebrew_ner", "", True, "<PERSON_1>"))
        start = i + 1
    return out


class LineContextTests(unittest.TestCase):
    def test_line_and_context(self):
        s = TEXT.find("אבו-סאלח")
        line, snippet = ps.line_and_context(TEXT, s, s + len("אבו-סאלח"), width=12)
        self.assertEqual(line, 151)
        self.assertIn("[אבו-סאלח]", snippet)
        self.assertIn("אל מר", snippet)
        self.assertTrue(snippet.startswith("…"))

    def test_first_line_and_newlines_shown(self):
        text = "John Smith\nnext line"
        line, snippet = ps.line_and_context(text, 0, 10, width=20)
        self.assertEqual(line, 1)
        self.assertEqual(snippet, "[John Smith]↵next line")

    def test_new_text_is_not_mixed_with_cached_text(self):
        self.assertEqual(ps.line_and_context("a\nb\nc", 4, 5)[0], 3)
        self.assertEqual(ps.line_and_context("abc", 2, 3)[0], 1)


class ShowInTextGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        cls.app = ps.QtWidgets.QApplication.instance() or ps.QtWidgets.QApplication([])

    def setUp(self):
        ps.QtCore.QThreadPool.globalInstance().waitForDone(10000)
        ps.QtCore.QCoreApplication.removePostedEvents(None)
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        with mock.patch.object(ps.MainWindow, "_start_engine"):
            self.win = ps.MainWindow(ps.AppConfig(self.tmp / "config.json"))
        self.addCleanup(self.win.deleteLater)
        w = self.win
        w.resize(1000, 700)
        w.input.setPlainText(TEXT)
        w.analyzed_text = TEXT
        w.findings = findings()
        w.populate_table()

    def test_tooltip_shows_line_and_context(self):
        tip = self.win._context_tooltip(self.win._row_indices(0))
        self.assertIn("Line 151:", tip)
        self.assertIn("[אבו-סאלח]", tip)
        self.assertIn("Line 171:", tip, "a grouped row lists the copies")

    def test_ungrouped_tooltip_shows_one_copy(self):
        self.win.chk_group.setChecked(False)
        tip = self.win._context_tooltip(self.win._row_indices(1))
        self.assertIn("Line 171:", tip)
        self.assertNotIn("Line 151:", tip)

    def test_show_in_text_selects_and_focuses(self):
        w = self.win
        f = w.findings[0]
        w.show()
        w._show_in_text(0)
        cur = w.input.textCursor()
        self.assertEqual((cur.selectionStart(), cur.selectionEnd()), (f.start, f.end))
        self.assertIs(w.focusWidget(), w.input)
        self.assertTrue(any(s.cursor.selectionStart() == f.start for s in w.input.extraSelections()),
                        "a strong highlight marks the finding")

    def test_show_in_text_with_changed_input_shows_message(self):
        w = self.win
        w.input.setPlainText("changed")
        w._show_in_text(0)
        self.assertIn("Re-analyze", w.statusBar().currentMessage())

    def test_double_click_on_start_or_count_shows_in_text(self):
        w = self.win
        with mock.patch.object(w, "_show_in_text") as show:
            w._on_cell_double_clicked(0, ps.C_START)
            w._on_cell_double_clicked(0, ps.C_END)
            w._on_cell_double_clicked(0, ps.C_TEXT)
        self.assertEqual(show.call_count, 2, "only Start and Count/End cells")

    def test_hover_on_original_text_shows_context_tooltip(self):
        w = self.win
        w.show()
        rect = w.table.visualItemRect(w.table.item(0, ps.C_TEXT))
        ev = ps.QtGui.QHelpEvent(ps.QtCore.QEvent.Type.ToolTip, rect.center(), w.table.viewport().mapToGlobal(rect.center()))
        with mock.patch.object(ps.QtWidgets.QToolTip, "showText") as show:
            handled = w.eventFilter(w.table.viewport(), ev)
        self.assertTrue(handled)
        self.assertIn("Line 151:", show.call_args.args[1])

    def test_menu_label_names_the_line(self):
        self.assertEqual(self.win._show_in_text_label(0), "Show in text (line 151)")


if __name__ == "__main__":
    unittest.main()
