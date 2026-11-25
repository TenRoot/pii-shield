"""Split the sanitized output into parts, and export the full output or the parts to .txt."""
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

PARA = "The user <PERSON_1> asked about host <HOSTNAME_1> at <IP_ADDRESS_1>. Please check the logs."


class SplitOutputTests(unittest.TestCase):
    def test_short_text_is_one_part(self):
        self.assertEqual(ps.split_output("short text", 100), ["short text"])

    def test_parts_rejoin_and_respect_size(self):
        text = "\n\n".join([PARA] * 40)
        parts = ps.split_output(text, 500)
        self.assertGreater(len(parts), 1)
        self.assertEqual("".join(parts), text, "no text is lost or added")
        self.assertTrue(all(len(p) <= 500 for p in parts))

    def test_cut_prefers_blank_line(self):
        text = "\n\n".join([PARA] * 40)
        for p in ps.split_output(text, 500)[:-1]:
            self.assertTrue(p.endswith("\n\n"), repr(p[-20:]))

    def test_cut_falls_back_to_line_then_space(self):
        lines = "\n".join([PARA] * 40)
        for p in ps.split_output(lines, 500)[:-1]:
            self.assertTrue(p.endswith("\n"))
        words = " ".join([PARA] * 40)
        for p in ps.split_output(words, 500)[:-1]:
            self.assertTrue(p.endswith(" "))

    def test_token_is_never_cut(self):
        text = "x" * 95 + "<PERSON_12>" + "y" * 200   # no whitespace: a hard cut
        parts = ps.split_output(text, 100)
        self.assertEqual("".join(parts), text)
        for p in parts:
            self.assertEqual(p.count("<"), p.count(">"), p)

    def test_headers(self):
        self.assertEqual(ps.with_part_headers(["a", "b"]),
                         ["--- Part 1 of 2 ---\na", "--- Part 2 of 2 ---\nb"])
        self.assertEqual(ps.with_part_headers(["only"]), ["only"])

    def test_part_file_names(self):
        self.assertEqual(ps.part_file_names(3), ["sanitized_part_1_of_3.txt", "sanitized_part_2_of_3.txt",
                                                 "sanitized_part_3_of_3.txt"])
        self.assertEqual(ps.part_file_names(12)[0], "sanitized_part_01_of_12.txt")

    def test_default_split_size(self):
        self.assertEqual(ps.DEFAULT_CONFIG["behavior"]["split_chars"], 50000)
        self.assertTrue(ps.DEFAULT_CONFIG["behavior"]["split_headers"])


class SplitExportGuiTests(unittest.TestCase):
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
        self.text = "\n\n".join([PARA] * 40)
        self.win.output.setPlainText(self.text)

    def split(self, size=1000, headers=True):
        self.win.spin_split.setValue(size)
        self.win.chk_split_headers.setChecked(headers)
        self.win.split_now()

    def test_split_fills_part_list(self):
        self.split()
        n = len(ps.split_output(self.text, 1000 - 32))   # the header line takes 32 characters of room
        self.assertGreater(n, 1)
        self.assertEqual(self.win.cmb_parts.count(), n)
        self.assertEqual(self.win.cmb_parts.itemText(0), f"1 of {n}")
        self.assertTrue(self.win.btn_copy_part.isEnabled())
        self.assertTrue(self.win.btn_export_parts.isEnabled())

    def test_copy_part_copies_and_moves_to_next(self):
        self.split()
        self.win.copy_part()
        clip = ps.QtWidgets.QApplication.clipboard().text()
        self.assertTrue(clip.startswith("--- Part 1 of "))
        self.assertEqual(self.win.cmb_parts.currentIndex(), 1)

    def test_no_headers_option(self):
        self.split(headers=False)
        self.win.copy_part()
        self.assertFalse(ps.QtWidgets.QApplication.clipboard().text().startswith("--- Part"))

    def test_new_output_clears_parts(self):
        self.split()
        self.win.output.setPlainText("other text")
        self.assertEqual(self.win.cmb_parts.count(), 0)
        self.assertFalse(self.win.btn_copy_part.isEnabled())
        self.assertFalse(self.win.btn_export_parts.isEnabled())

    def test_split_size_is_saved(self):
        self.split(size=1234, headers=False)
        self.assertEqual(self.win.config["behavior"]["split_chars"], 1234)
        self.assertFalse(self.win.config["behavior"]["split_headers"])

    def test_export_full_writes_utf8_file(self):
        self.win.output.setPlainText("שם: <PERSON_1>")
        target = self.tmp / "out.txt"
        with mock.patch.object(ps.QtWidgets.QFileDialog, "getSaveFileName", return_value=(str(target), "")):
            self.win.export_full()
        self.assertEqual(target.read_text("utf-8"), "שם: <PERSON_1>")

    def test_export_full_cancel_writes_nothing(self):
        with mock.patch.object(ps.QtWidgets.QFileDialog, "getSaveFileName", return_value=("", "")):
            self.win.export_full()
        self.assertEqual(list(self.tmp.glob("*.txt")), [])

    def test_export_parts_writes_numbered_files(self):
        self.split()
        n = self.win.cmb_parts.count()
        with mock.patch.object(ps.QtWidgets.QFileDialog, "getExistingDirectory", return_value=str(self.tmp)):
            self.win.export_parts()
        files = sorted(self.tmp.glob("sanitized_part_*.txt"))
        self.assertEqual([f.name for f in files], ps.part_file_names(n))
        self.assertTrue(files[0].read_text("utf-8").startswith(f"--- Part 1 of {n} ---\n"))

    def test_export_parts_asks_before_overwrite(self):
        self.split()
        n = self.win.cmb_parts.count()
        first = self.tmp / ps.part_file_names(n)[0]
        first.write_text("old", "utf-8")
        No = ps.QtWidgets.QMessageBox.StandardButton.No
        with mock.patch.object(ps.QtWidgets.QFileDialog, "getExistingDirectory", return_value=str(self.tmp)), \
             mock.patch.object(ps.QtWidgets.QMessageBox, "question", return_value=No) as ask:
            self.win.export_parts()
        ask.assert_called_once()
        self.assertEqual(first.read_text("utf-8"), "old")
        self.assertEqual(len(list(self.tmp.glob("sanitized_part_*.txt"))), 1)

    def test_buttons_off_without_output(self):
        self.win.output.setPlainText("")
        self.assertFalse(self.win.btn_split.isEnabled())
        self.assertFalse(self.win.btn_export_full.isEnabled())


if __name__ == "__main__":
    unittest.main()
