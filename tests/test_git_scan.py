"""Git branch scan tests:  python -m unittest tests.test_git_scan -v"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pii_sanitizer as ps  # noqa: E402

TEMPLATE_RULES = HERE.parent / "github-repo-template" / "rules"

NORMAL = (
    "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
    "@@ -3,0 +4,2 @@\n+one = 1\n+key = 'AKIAIOSFODNN7EXAMPLE'\r\n"
    "@@ -10 +12 @@\n-old\n+new\n"
    "diff --git a/gone.txt b/gone.txt\ndeleted file mode 100644\n--- a/gone.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    "diff --git a/img.png b/img.png\nBinary files a/img.png and b/img.png differ\n"
    'diff --git "a/dir/a\\tb.txt" "b/dir/a\\tb.txt"\n--- "a/dir/a\\tb.txt"\n+++ "b/dir/a\\tb.txt"\n@@ -0,0 +1 @@\n+t\n'
)

COMBINED = (
    "diff --cc conf.ini\nindex 1,2..3\n--- a/conf.ini\n+++ b/conf.ini\n"
    "@@@ -1,1 -1,1 +1,2 @@@\n- a=1\n -a=2\n++SECRET=hunter2\n+ b=1\n"
)


class ParserTests(unittest.TestCase):
    def test_normal_diff(self):
        chunks, skipped = ps.parse_unified_diff(NORMAL, "uncommitted")
        by = {c.file: c for c in chunks}
        self.assertEqual(by["app.py"].lines, [(4, "one = 1"), (5, "key = 'AKIAIOSFODNN7EXAMPLE'"), (12, "new")])
        self.assertNotIn("gone.txt", by)
        self.assertEqual(skipped, [("img.png", "binary")])
        self.assertEqual(by["dir/a\tb.txt"].lines, [(1, "t")])
        self.assertEqual({c.source for c in chunks}, {"uncommitted"})

    def test_combined_diff(self):
        chunks, _ = ps.parse_unified_diff(COMBINED, "abc1234567")
        self.assertEqual(chunks[0].lines, [(1, "SECRET=hunter2"), (2, "b=1")])

    def test_quoted_octal_path(self):
        diff = ('diff --git "a/na\\303\\257ve.txt" "b/na\\303\\257ve.txt"\n--- /dev/null\n'
                '+++ "b/na\\303\\257ve.txt"\n@@ -0,0 +1 @@\n+x\n')
        chunks, _ = ps.parse_unified_diff(diff, "uncommitted")
        self.assertEqual(chunks[0].file, "naïve.txt")

    def test_git_log_splits_commits_and_messages(self):
        log_text = (
            "\x1ePIISHIELD-COMMIT " + "a" * 40 + "\nFix login\n\ncontact jsmith@contoso.com\n\n\x1fPIISHIELD-END\n"
            + NORMAL
            + "\x1ePIISHIELD-COMMIT " + "b" * 40 + "\nEmpty change\n\x1fPIISHIELD-END\n"
        )
        chunks, skipped, n = ps.parse_git_log(log_text)
        self.assertEqual(n, 2)
        msg = next(c for c in chunks if c.source == "a" * 10 and c.file == ps.COMMIT_MESSAGE_FILE)
        self.assertEqual(msg.lines, [(1, "Fix login"), (2, ""), (3, "contact jsmith@contoso.com")])
        self.assertTrue(any(c.source == "a" * 10 and c.file == "app.py" for c in chunks))
        self.assertEqual(skipped, [("img.png", "binary")])


if __name__ == "__main__":
    unittest.main()
