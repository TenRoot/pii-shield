"""Review table: enable or disable the selected rows (buttons and the Space key)."""
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

Qt = ps.Qt


class EnableSelectedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        cls.app = ps.QtWidgets.QApplication.instance() or ps.QtWidgets.QApplication([])

    def setUp(self):
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

    def select(self, *values):
        t = self.win.table
        t.clearSelection()
        sm = t.selectionModel()
        flags = ps.QtCore.QItemSelectionModel.SelectionFlag
        for r in range(t.rowCount()):
            if t.item(r, ps.C_TEXT).text() in values:
                sm.select(t.model().index(r, 0), flags.Select | flags.Rows)

    def enabled(self, value):
        return {f.enabled for f in self.win.findings if f.text.casefold() == value.casefold()}

    def test_table_allows_multi_select(self):
        self.assertEqual(self.win.table.selectionMode(),
                         ps.QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)

    def test_disable_and_enable_selected(self):
        self.select("123456782", "contoso")
        self.win._set_enabled_selected(False)
        self.assertEqual(self.enabled("123456782"), {False}, "all 3 copies of a grouped row")
        self.assertEqual(self.enabled("contoso"), {False})
        self.assertEqual(self.enabled("SRV-DC01"), {True}, "unselected rows do not change")
        self.win._set_enabled_selected(True)
        self.assertTrue(all(f.enabled for f in self.win.findings))

    def test_selection_is_kept_after_the_change(self):
        self.select("123456782", "contoso")
        self.win._set_enabled_selected(False)
        rows = sorted({i.row() for i in self.win.table.selectedIndexes()})
        self.assertEqual(sorted(self.win.table.item(r, ps.C_TEXT).text() for r in rows), ["123456782", "contoso"])

    def test_space_toggles_selected(self):
        self.select("123456782", "contoso")
        self.win._toggle_selected()
        self.assertEqual(self.enabled("123456782") | self.enabled("contoso"), {False}, "all on -> all off")
        self.win._toggle_selected()
        self.assertEqual(self.enabled("123456782") | self.enabled("contoso"), {True}, "all off -> all on")
        next(f for f in self.win.findings if f.text == "contoso").enabled = False
        self.win.populate_table()
        self.select("123456782", "contoso")
        self.win._toggle_selected()
        self.assertEqual(self.enabled("123456782") | self.enabled("contoso"), {True}, "mixed -> all on")

    def test_space_shortcut_exists_on_table(self):
        keys = [s.key().toString() for s in self.win.table.findChildren(ps.QtGui.QShortcut)]
        self.assertIn("Space", keys)

    def test_ungrouped_changes_only_selected_copy(self):
        w = self.win
        w.chk_group.setChecked(False)
        first = next(r for r in range(w.table.rowCount()) if w.table.item(r, ps.C_TEXT).text() == "123456782")
        w.table.clearSelection()
        w.table.selectRow(first)
        w._set_enabled_selected(False)
        self.assertEqual(sorted(f.enabled for f in w.findings if f.text == "123456782"), [False, True, True])

    def test_no_selection_shows_message(self):
        self.win.table.clearSelection()
        self.win._set_enabled_selected(False)
        self.assertTrue(all(f.enabled for f in self.win.findings))
        self.assertIn("Select", self.win.statusBar().currentMessage())


if __name__ == "__main__":
    unittest.main()
