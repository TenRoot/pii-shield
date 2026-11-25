"""Review table: "Group same values" shows one row per value, with a Count column."""
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

Qt = ps.Qt
TEXT = "id 123456782 host SRV-DC01 id 123456782 and 123456782 host srv-dc01 user contoso"


def findings_for(text):
    out = []
    for value, ent, tok in (("123456782", "IL_ID", "<IL_ID_1>"), ("SRV-DC01", "HOSTNAME", "<HOSTNAME_1>"),
                            ("srv-dc01", "HOSTNAME", "<HOSTNAME_1>"), ("contoso", "ORGANIZATION", "<ORGANIZATION_1>")):
        start = 0
        while True:
            i = text.find(value, start)
            if i < 0:
                break
            out.append(ps.Finding(i, i + len(value), value, ent, 0.9, "custom", "rule", True, tok))
            start = i + 1
    return sorted(out, key=lambda f: f.start)


class GroupValuesGuiTests(unittest.TestCase):
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

    def row_of(self, value):
        for r in range(self.win.table.rowCount()):
            if self.win.table.item(r, ps.C_TEXT).text() == value:
                return r
        self.fail(f"no row for {value}")

    def test_grouped_by_default_with_count(self):
        w = self.win
        self.assertTrue(w.chk_group.isChecked())
        self.assertTrue(ps.DEFAULT_CONFIG["behavior"]["group_values"])
        # 123456782 x3, SRV-DC01 + srv-dc01 (same value, case-insensitive) x2, contoso x1
        self.assertEqual(w.table.rowCount(), 3)
        self.assertEqual(w.table.horizontalHeaderItem(ps.C_END).text(), "Count")
        r = self.row_of("123456782")
        self.assertEqual(w.table.item(r, ps.C_END).data(Qt.ItemDataRole.DisplayRole), 3)
        self.assertEqual(w.table.item(r, ps.C_START).data(Qt.ItemDataRole.DisplayRole), TEXT.index("123456782"))
        self.assertEqual(len(w._row_indices(r)), 3)

    def test_ungrouped_shows_every_detection(self):
        w = self.win
        w.chk_group.setChecked(False)
        self.assertEqual(w.table.rowCount(), len(w.findings))
        self.assertEqual(w.table.horizontalHeaderItem(ps.C_END).text(), "End")
        self.assertFalse(w.config["behavior"]["group_values"], "the choice is saved")

    def test_unchecking_a_group_disables_all_copies(self):
        w = self.win
        r = self.row_of("123456782")
        w.table.item(r, ps.C_EN).setCheckState(Qt.CheckState.Unchecked)
        self.assertEqual([f.enabled for f in w.findings if f.text == "123456782"], [False] * 3)
        self.assertTrue(all(f.enabled for f in w.findings if f.text != "123456782"))
        r = self.row_of("123456782")
        w.table.item(r, ps.C_EN).setCheckState(Qt.CheckState.Checked)
        self.assertTrue(all(f.enabled for f in w.findings))

    def test_mixed_group_is_partly_checked(self):
        w = self.win
        next(f for f in w.findings if f.text == "123456782").enabled = False
        w.populate_table()
        r = self.row_of("123456782")
        self.assertEqual(w.table.item(r, ps.C_EN).checkState(), Qt.CheckState.PartiallyChecked)

    def test_entity_edit_applies_to_all_copies(self):
        w = self.win
        r = self.row_of("123456782")
        w.table.item(r, ps.C_ENT).setText("NATIONAL_ID")
        self.assertEqual({f.entity for f in w.findings if f.text == "123456782"}, {"NATIONAL_ID"})

    def test_disable_shown_covers_all_copies(self):
        w = self.win
        w.type_filter.setCurrentText("IL_ID")
        w._set_enabled_visible(False)
        self.assertEqual([f.enabled for f in w.findings if f.entity == "IL_ID"], [False] * 3)
        self.assertTrue(all(f.enabled for f in w.findings if f.entity != "IL_ID"))

    def test_type_filter_hides_grouped_rows(self):
        w = self.win
        w.type_filter.setCurrentText("HOSTNAME")
        shown = [w.table.item(r, ps.C_TEXT).text() for r in range(w.table.rowCount()) if not w.table.isRowHidden(r)]
        self.assertEqual(len(shown), 1)
        self.assertEqual(shown[0].casefold(), "srv-dc01")

    def test_selected_indices_include_all_copies(self):
        w = self.win
        w.table.selectRow(self.row_of("123456782"))
        self.assertEqual(sorted(w.findings[i].start for i in w._selected_indices()),
                         sorted(f.start for f in w.findings if f.text == "123456782"))

    def test_click_again_moves_to_next_copy(self):
        w = self.win
        r = self.row_of("123456782")
        starts = [f.start for f in w.findings if f.text == "123456782"]
        w.table.selectRow(r)
        self.assertEqual(w.input.textCursor().selectionStart(), starts[0])
        w._on_row_clicked(r, ps.C_TEXT)
        self.assertEqual(w.input.textCursor().selectionStart(), starts[1])
        w._on_row_clicked(r, ps.C_TEXT)
        w._on_row_clicked(r, ps.C_TEXT)
        self.assertEqual(w.input.textCursor().selectionStart(), starts[0], "wraps around")


if __name__ == "__main__":
    unittest.main()
