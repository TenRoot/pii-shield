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


def _git(cwd, *args, check=True, input=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_AUTHOR_NAME="Test User", GIT_AUTHOR_EMAIL="test.user@example.org",
               GIT_COMMITTER_NAME="Test User", GIT_COMMITTER_EMAIL="test.user@example.org")
    r = subprocess.run(["git", "-c", "init.defaultBranch=main", "-c", "core.autocrlf=false", *args],
                       cwd=str(cwd), env=env, capture_output=True, input=input)
    if check and r.returncode != 0:
        raise AssertionError(f"git {args} failed: {r.stderr.decode(errors='replace')}")
    return r.stdout.decode(errors="replace").strip()


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8", newline="")


def _commit(repo, rel, data, msg="change"):
    _write(Path(repo) / rel, data)
    _git(repo, "add", "--", rel)
    _git(repo, "commit", "-q", "-m", msg)
    return _git(repo, "rev-parse", "HEAD")


def _init(path):
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q")
    _git(path, "symbolic-ref", "HEAD", "refs/heads/main")
    _git(path, "config", "core.autocrlf", "false")
    return path


@unittest.skipUnless(shutil.which("git"), "git not installed")
class ScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.etmp = Path(tempfile.mkdtemp())
        rules = cls.etmp / "rules"
        shutil.copytree(TEMPLATE_RULES, rules / "remote")
        (rules / "local").mkdir()
        cls.engine = ps.DetectionEngine(ps.AppConfig(cls.etmp / "config.json"), rules)
        cls.engine.initialize()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.etmp, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        _git(self.tmp, "init", "-q", "--bare", "remote.git")
        _git(self.tmp / "remote.git", "symbolic-ref", "HEAD", "refs/heads/main")
        self.work = _init(self.tmp / "work")
        _git(self.work, "remote", "add", "origin", str(self.tmp / "remote.git"))
        _commit(self.work, "base.txt", "line one\npassword=OldS3cret!\n", "base")
        _git(self.work, "push", "-q", "-u", "origin", "main")

    def scan(self, path=None, **kw):
        return ps.scan_git_repo(Path(path or self.work), self.engine, 0.85, **kw)

    @staticmethod
    def vals(result):
        return {(f.source if f.source in ("uncommitted", "untracked") else "commit", f.file, f.line, f.value)
                for f in result.findings}

    @staticmethod
    def values(result):
        return {f.value for f in result.findings}

    def test_pushed_value_not_found(self):
        r = self.scan()
        self.assertNotIn("OldS3cret!", self.values(r))
        self.assertEqual(r.commits, 0)

    def test_new_commit_found(self):
        _commit(self.work, "app/cfg.py", "a = 1\nb = 2\npassword=Sup3rS3cret!\n")
        with self.assertLogs(ps.APP_ID, "DEBUG") as logs:
            r = self.scan()
        self.assertIn(("commit", "app/cfg.py", 3, "Sup3rS3cret!"), self.vals(r))
        self.assertEqual(r.commits, 1)
        self.assertFalse([m for m in logs.output if "Sup3rS3cret!" in m])
        self.assertTrue([rec for rec in logs.records if rec.getMessage().startswith("Git scan:")])

    def test_add_then_remove_still_found(self):
        a = _commit(self.work, "k.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        _commit(self.work, "k.py", "key = None\n")
        r = self.scan()
        self.assertTrue([f for f in r.findings if f.value == "AKIAIOSFODNN7EXAMPLE" and f.source == a[:10]])

    def test_uncommitted_and_untracked(self):
        _write(self.work / "base.txt", "line one\npassword=OldS3cret!\npassword=Staged1!\n")
        _git(self.work, "add", "base.txt")
        _write(self.work / "base.txt", "line one\npassword=OldS3cret!\npassword=Staged1!\npassword=Unstaged1!\n")
        _write(self.work / "new.txt", "password=Untracked1!\n")
        v = self.vals(self.scan())
        self.assertIn(("uncommitted", "base.txt", 3, "Staged1!"), v)
        self.assertIn(("uncommitted", "base.txt", 4, "Unstaged1!"), v)
        self.assertIn(("untracked", "new.txt", 1, "Untracked1!"), v)

    def test_ignored_file_not_scanned(self):
        _commit(self.work, ".gitignore", "secret.env\n")
        _write(self.work / "secret.env", "password=Ignored1!\n")
        self.assertNotIn("Ignored1!", self.values(self.scan()))

    def test_binary_skipped(self):
        _commit(self.work, "blob.bin", b"\x00\x01password=BinaryS3cret!")
        self.assertIn(("blob.bin", "binary"), self.scan().skipped)

    def test_unpushed_main_commits_on_new_branch(self):
        _commit(self.work, "m.txt", "password=MainOnly1!\n")
        _git(self.work, "switch", "-q", "-c", "feature")
        _commit(self.work, "x.txt", "password=Feature1!\n")
        vals = self.values(self.scan())
        self.assertIn("MainOnly1!", vals)
        self.assertIn("Feature1!", vals)

    def test_no_remote_scans_all(self):
        repo = _init(self.tmp / "solo")
        _commit(repo, "a.txt", "password=Solo1abc!\n")
        _commit(repo, "b.txt", "password=Solo2abc!\n")
        r = self.scan(repo)
        self.assertEqual(r.commits, 2)
        self.assertIn("no remotes", r.range_desc)
        self.assertTrue({"Solo1abc!", "Solo2abc!"} <= self.values(r))

    def test_merge_resolution_found(self):
        _commit(self.work, "conf.ini", "x=0\n")
        _git(self.work, "switch", "-q", "-c", "a")
        _commit(self.work, "conf.ini", "x=1\n")
        _git(self.work, "switch", "-q", "main")
        _git(self.work, "switch", "-q", "-c", "b")
        _commit(self.work, "conf.ini", "x=2\n")
        _git(self.work, "merge", "-q", "a", check=False)          # conflict
        _write(self.work / "conf.ini", "password=Merge1abc!\n")
        _git(self.work, "add", "conf.ini")
        _git(self.work, "commit", "-q", "--no-edit")
        conflict_merge = _git(self.work, "rev-parse", "HEAD")
        _git(self.work, "switch", "-q", "-c", "c", "main")
        _commit(self.work, "other.txt", "plain\n")
        _git(self.work, "switch", "-q", "b")
        _git(self.work, "merge", "-q", "--no-ff", "--no-edit", "c")
        clean_merge = _git(self.work, "rev-parse", "HEAD")
        r = self.scan()
        self.assertTrue([f for f in r.findings if f.value == "Merge1abc!" and f.source == conflict_merge[:10]])
        self.assertFalse([f for f in r.findings if f.source == clean_merge[:10] and f.file != ps.COMMIT_MESSAGE_FILE])

    def test_commit_message_found_author_not(self):
        _commit(self.work, "c.txt", "plain\n", "Subject line\n\npassword=MsgS3cret!\n")
        r = self.scan()
        self.assertIn(("commit", ps.COMMIT_MESSAGE_FILE, 3, "MsgS3cret!"), self.vals(r))
        self.assertFalse([f for f in r.findings if "test.user@example.org" in f.value])

    def test_worktree(self):
        wt = self.tmp / "wt"
        _git(self.work, "worktree", "add", "-q", str(wt), "-b", "wt-branch")
        _commit(wt, "w1.txt", "password=WtCommit1!\n")
        _write(wt / "w2.txt", "password=WtStaged1!\n")
        _git(wt, "add", "w2.txt")
        _write(wt / "w3.txt", "password=WtUntracked1!\n")
        _write(self.work / "base.txt", "line one\npassword=OldS3cret!\npassword=MainTree1!\n")
        vals = self.values(self.scan(wt))
        self.assertTrue({"WtCommit1!", "WtStaged1!", "WtUntracked1!"} <= vals)
        self.assertNotIn("MainTree1!", vals)

    def test_git_dir_env_ignored(self):
        other = _init(self.tmp / "other")
        _commit(other, "o.txt", "password=OtherRepo1!\n")
        _write(other / "u.txt", "password=OtherUntracked1!\n")
        with mock.patch.dict(os.environ, {"GIT_DIR": str(other / ".git"), "GIT_WORK_TREE": str(other)}):
            vals = self.values(self.scan())
        self.assertFalse({"OtherRepo1!", "OtherUntracked1!"} & vals)

    def test_fresh_vault_per_chunk(self):
        _commit(self.work, "f1.txt", "password=Fresh1abc!\n")
        _commit(self.work, "f2.txt", "password=Fresh2abc!\n")
        seen = []
        real = self.engine.analyze

        def spy(text, manual, vault, *a, **kw):
            seen.append((vault, len(vault.active_tokens)))
            return real(text, manual, vault, *a, **kw)
        with mock.patch.object(self.engine, "analyze", side_effect=spy):
            self.scan()
        self.assertGreaterEqual(len(seen), 2)
        self.assertTrue(all(isinstance(v, ps.SessionVault) and n == 0 for v, n in seen))
        self.assertEqual(len({id(v) for v, _ in seen}), len(seen))

    def test_not_a_repo(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        with self.assertRaises(ps.GitScanError) as cm:
            self.scan(empty)
        self.assertTrue(str(cm.exception).startswith("Not a Git working tree"))

    def test_ner_off_by_default(self):
        if self.engine.mode != "presidio+spacy":
            self.skipTest("needs a spaCy model")
        _commit(self.work, "notes.txt", "John Smith approved the change.\n")
        r = self.scan()
        self.assertFalse([f for f in r.findings if f.recognizer in ps.NER_RECOGNIZERS])
        r = self.scan(use_ner=True)
        self.assertTrue([f for f in r.findings if f.entity == "PERSON"])

    def test_path_with_space_and_unicode(self):
        _commit(self.work, "dir with space/naïve.txt", "password=Unicode1!\n")
        r = self.scan()
        self.assertTrue([f for f in r.findings if f.file == "dir with space/naïve.txt" and f.value == "Unicode1!"])

    def test_crlf_file(self):
        _commit(self.work, "w.txt", b"a\r\nb\r\npassword=CrlfS3cret!\r\n")
        self.assertIn(("commit", "w.txt", 3, "CrlfS3cret!"), self.vals(self.scan()))

    def test_unborn_head(self):
        repo = _init(self.tmp / "unborn")
        _write(repo / "s.txt", "password=Unborn1abc!\n")
        _git(repo, "add", "s.txt")
        _write(repo / "u.txt", "password=Unborn2abc!\n")
        r = self.scan(repo)
        self.assertEqual(r.commits, 0)
        v = self.vals(r)
        self.assertIn(("uncommitted", "s.txt", 1, "Unborn1abc!"), v)
        self.assertIn(("untracked", "u.txt", 1, "Unborn2abc!"), v)

    def test_untracked_symlink_skipped(self):
        try:
            os.symlink(self.work / "base.txt", self.work / "link")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available")
        self.assertIn(("link", "symlink"), self.scan().skipped)

    def test_git_missing(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaises(ps.GitScanError) as cm:
                self.scan()
        self.assertIn("git was not found on PATH", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
