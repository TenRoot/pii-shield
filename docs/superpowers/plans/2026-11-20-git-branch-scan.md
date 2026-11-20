# Git Branch Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A **Scan Git Repo...** dialog that reports PII and secrets in everything a push of the current branch sends, plus uncommitted and untracked work, without changing the repo or the session.

**Architecture:** A Qt-free core in a new section of `pii_sanitizer.py` runs the `git` CLI, parses `git log -p --cc` and `git diff HEAD` output into chunks of added lines, and runs each chunk through `DetectionEngine.analyze()` with a throwaway `SessionVault`. A non-modal `GitScanDialog` runs the core in the thread pool and shows the results in a table.

**Tech Stack:** Python 3.12/3.13, `subprocess` + `git` CLI, Presidio/spaCy (existing engine), PyQt6, `unittest`.

**Spec:** `docs/superpowers/specs/2026-11-20-git-branch-scan-design.md`

## Global Constraints

- Work on branch `feature/git-branch-scan`, not on `main`. The first commit includes the spec and this plan.
- All product code goes into `pii_sanitizer.py`. Put the core in a new section `# 6b. Git branch scan` between section 6 (`Sanitize / leak check`) and section 7 (`GitHub rules sync`). The dialog goes in section 8 (GUI).
- No new dependencies. Run `git` only through `subprocess.run` with an argument list, never `shell=True`.
- Every `git` call: `-c core.fsmonitor=false -c core.quotepath=off` before the subcommand; `--no-color --no-ext-diff --no-textconv` on `log`/`diff`; `cwd` = repo root; a timeout; `creationflags=subprocess.CREATE_NO_WINDOW` on Windows (`getattr(subprocess, "CREATE_NO_WINDOW", 0)`).
- Environment for every call: copy `os.environ`, remove `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_COMMON_DIR`, `GIT_OBJECT_DIRECTORY`; set `GIT_TERMINAL_PROMPT=0`, `GIT_OPTIONAL_LOCKS=0`.
- Never test for a `.git` folder. Find the root only with `git rev-parse --show-toplevel`.
- Decode all `git` output and file content as UTF-8 with `errors="replace"`.
- Never write a detected value or a line of scanned text to the logger. One summary line for each scan: range, commits, findings, skipped.
- The scan must not change the session map: always pass a new `SessionVault()` to `analyze()`.
- Size limit: 1 MB (`GIT_SCAN_MAX_BYTES = 1_000_000`) for an untracked file and for one chunk of added text. Binary check: a NUL byte in the first 8 KB (`8192`).
- Run tests with `python -m unittest discover -s tests -v`. CI runs them on `windows-latest`.

## Review Focus

1. **Paths with spaces and non-ASCII names** (`dir with space/naïve.txt`). Git quotes such paths in diff headers, even with `core.quotepath=off`, when they hold a tab, quote or backslash. Expect the right path in the result. Test: Task 3 `test_path_with_space_and_unicode`.
2. **CRLF files.** Expect correct line numbers and values without a trailing `\r`. Test: Task 3 `test_crlf_file`.
3. **A new repo with no commits yet (unborn `HEAD`).** `git log HEAD` and `git diff HEAD` fail there. Expect 0 commits and findings from staged and untracked files, not an error. Test: Task 3 `test_unborn_head`.
4. **An untracked symlink or a file deleted during the scan.** Expect an entry in `skipped`, not a crash. Never follow a symlink. Test: Task 3 `test_untracked_symlink_skipped`.
5. **`git` not on PATH.** Expect `GitScanError` with the text `git was not found on PATH`. Test: Task 3 `test_git_missing`.

---

### Task 1: `analyze()` can drop NER findings on request

**Files:**
- Modify: `pii_sanitizer.py:1715-1732` (`DetectionEngine.analyze`)
- Test: `tests/test_core.py` (class `EngineTests`)

**Interfaces:**
- Produces: `DetectionEngine.analyze(text, manual_rules, vault, threshold=None, skip_ner: bool = False) -> List[Finding]`. When `skip_ner` is true, findings whose recognizer is in `NER_RECOGNIZERS` are dropped at the same point as the existing `skip_ner_on_logs` filter, so they never reach overlap resolution or value propagation. `last_ner_skipped` is unchanged by this flag.

- [ ] **Step 1: Create the branch and commit the spec and plan**

```bash
git switch -c feature/git-branch-scan
git add docs/superpowers/specs/2026-11-20-git-branch-scan-design.md docs/superpowers/plans/2026-11-20-git-branch-scan.md
git commit -m "Docs: Git branch scan design and plan"
```

- [ ] **Step 2: Write the failing test**

```python
    def test_skip_ner_argument_drops_ner_findings(self):
        if self.engine.mode != "presidio+spacy":
            self.skipTest("needs a spaCy model")
        fs = self.engine.analyze(SAMPLE, [], ps.SessionVault(), skip_ner=True)
        self.assertFalse([f for f in fs if f.recognizer in ps.NER_RECOGNIZERS])
        self.assertFalse([f for f in fs if f.text == "John Smith"], "no propagated copy of a dropped NER value")
        self.assertTrue([f for f in fs if f.text == "AKIAIOSFODNN7EXAMPLE"], "rules still run")
```

- [ ] **Step 3: Run it and see it fail**

Run: `python -m unittest tests.test_core.EngineTests.test_skip_ner_argument_drops_ner_findings -v`
Expected: FAIL with `TypeError: ... unexpected keyword argument 'skip_ner'`

- [ ] **Step 4: Add the `skip_ner` keyword** — OR it into the existing `skip_ner` local before the results loop.

- [ ] **Step 5: Run the full suite and see it pass**

Run: `python -m unittest discover -s tests -v`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add pii_sanitizer.py tests/test_core.py
git commit -m "Engine: analyze() takes skip_ner"
```

---

### Task 2: Diff and log parser (pure functions)

**Files:**
- Modify: `pii_sanitizer.py` (new section `6b. Git branch scan`)
- Create: `tests/test_git_scan.py`

**Interfaces:**
- Produces:

```python
GIT_COMMIT_MARK = "\x1ePIISHIELD-COMMIT "   # git format: %x1ePIISHIELD-COMMIT %H
GIT_MSG_END = "\x1fPIISHIELD-END"            # git format: %x1fPIISHIELD-END
GIT_LOG_FORMAT = "--format=%x1ePIISHIELD-COMMIT %H%n%B%x1fPIISHIELD-END"
COMMIT_MESSAGE_FILE = "(commit message)"

@dataclass
class AddedChunk:
    source: str                       # short SHA (10 chars), "uncommitted" or "untracked"
    file: str                         # repo-relative path, or COMMIT_MESSAGE_FILE
    lines: List[Tuple[int, str]]      # (1-based line number in the new file, text without EOL)

def parse_unified_diff(text: str, source: str) -> Tuple[List[AddedChunk], List[Tuple[str, str]]]
def parse_git_log(text: str) -> Tuple[List[AddedChunk], List[Tuple[str, str]], int]
```

`parse_unified_diff` returns `(chunks, skipped)`: one chunk for each file with at least one added line, and `(path, "binary")` for each `Binary files ... differ`. `parse_git_log` splits on `GIT_COMMIT_MARK`, makes one `COMMIT_MESSAGE_FILE` chunk for each non-empty message (line 1 = subject, trailing blank lines dropped), runs `parse_unified_diff` on the rest, and returns `(chunks, skipped, commit_count)`.

Parser rules (from the spec):
- File path comes from `+++ b/<path>`. `+++ /dev/null` means a deleted file: no chunk. Unquote C-style quoted paths (`"b/dir/a\tb.txt"`): strip the quotes, decode the escapes, then strip `b/`. For `Binary files` lines, take the path from the preceding `diff --git` / `diff --cc` header.
- Hunk header `@@ -a,b +c,d @@` (normal) or `@@@ -a,b -c,d +e,f @@@` (combined). The number of parents = number of `@` in the opening run minus 1. The new-file counter starts at the `+` start number.
- A body line has one prefix column for each parent. A line is in the new file when no column is `-`. It is **added** when it is in the new file and at least one column is `+`. Increment the counter for every line in the new file.
- Strip a trailing `\r` from each added line. Ignore `\ No newline at end of file`.

- [ ] **Step 1: Write the failing tests** in `tests/test_git_scan.py`, class `ParserTests`:

```python
NORMAL = (
    "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
    "@@ -3,0 +4,2 @@\n+one = 1\n+key = 'AKIAIOSFODNN7EXAMPLE'\r\n"
    "@@ -10 +12 @@\n-old\n+new\n"
    "diff --git a/gone.txt b/gone.txt\ndeleted file mode 100644\n--- a/gone.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    "diff --git a/img.png b/img.png\nBinary files a/img.png and b/img.png differ\n"
    'diff --git "a/dir/a\\tb.txt" "b/dir/a\\tb.txt"\n--- "a/dir/a\\tb.txt"\n+++ "b/dir/a\\tb.txt"\n@@ -0,0 +1 @@\n+t\n'
)

def test_normal_diff(self):
    chunks, skipped = ps.parse_unified_diff(NORMAL, "uncommitted")
    by = {c.file: c for c in chunks}
    self.assertEqual(by["app.py"].lines, [(4, "one = 1"), (5, "key = 'AKIAIOSFODNN7EXAMPLE'"), (12, "new")])
    self.assertNotIn("gone.txt", by)
    self.assertEqual(skipped, [("img.png", "binary")])
    self.assertEqual(by["dir/a\tb.txt"].lines, [(1, "t")])
    self.assertEqual({c.source for c in chunks}, {"uncommitted"})

COMBINED = (
    "diff --cc conf.ini\nindex 1,2..3\n--- a/conf.ini\n+++ b/conf.ini\n"
    "@@@ -1,1 -1,1 +1,2 @@@\n- a=1\n -a=2\n++SECRET=hunter2\n+ b=1\n"
)

def test_combined_diff(self):
    chunks, _ = ps.parse_unified_diff(COMBINED, "abc1234567")
    self.assertEqual(chunks[0].lines, [(1, "SECRET=hunter2"), (2, "b=1")])

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
```

- [ ] **Step 2: Run them and see them fail**

Run: `python -m unittest tests.test_git_scan.ParserTests -v`
Expected: FAIL with `AttributeError: module 'pii_sanitizer' has no attribute 'parse_unified_diff'`

- [ ] **Step 3: Implement `AddedChunk`, `parse_unified_diff` and `parse_git_log`** with the rules above. Git writes non-ASCII bytes in quoted paths as octal escapes (`\303\257`). Decode the escapes to raw bytes first, then decode those bytes as UTF-8, so `\303\257` becomes `ï`.

- [ ] **Step 4: Run them and see them pass**

Run: `python -m unittest tests.test_git_scan.ParserTests -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pii_sanitizer.py tests/test_git_scan.py
git commit -m "Git scan: unified and combined diff parser"
```

---

### Task 3: `scan_git_repo()` — git calls, untracked files, analysis

**Files:**
- Modify: `pii_sanitizer.py` (section `6b`)
- Test: `tests/test_git_scan.py` (class `ScanTests`)

**Interfaces:**
- Consumes: `AddedChunk`, `parse_unified_diff`, `parse_git_log`, `GIT_LOG_FORMAT` (Task 2); `analyze(..., skip_ner=)` (Task 1).
- Produces:

```python
class GitScanError(Exception): ...

@dataclass
class GitFinding:
    source: str; file: str; line: int; entity: str; value: str; recognizer: str; score: float

@dataclass
class GitScanResult:
    repo: Path
    range_desc: str                   # copy below
    commits: int
    threshold: float
    findings: List[GitFinding]
    skipped: List[Tuple[str, str]]    # (path, "binary" | "too large" | "symlink" | "unreadable")

def run_git(repo: Path, *args: str, timeout: float = 120) -> bytes
def git_repo_root(path: Path) -> Path
def scan_git_repo(repo: Path, engine: DetectionEngine, threshold: float, use_ner: bool = False,
                  progress: Callable[[str], None] = lambda s: None) -> GitScanResult
```

Behavior:
- `run_git` applies the Global Constraints options and environment. `FileNotFoundError` → `GitScanError("git was not found on PATH")`. Non-zero exit → `GitScanError` with the first line of stderr. Timeout → `GitScanError("git timed out")`.
- `git_repo_root` runs `rev-parse --show-toplevel` with `cwd=path`. A missing folder or a failure → `GitScanError("Not a Git working tree: <path>")`.
- Unborn `HEAD` (`git rev-parse --verify -q HEAD` fails): commits = 0, skip `git log`; for uncommitted changes diff against the empty tree with `git diff --cached <empty-tree>` plus `git diff` (unstaged). Get the empty tree ID from `git hash-object -t tree --stdin` with empty input, not a hard-coded SHA, so SHA-256 repos work.
- Normal case: `git log -p --cc --unified=0 -M GIT_LOG_FORMAT HEAD --not --remotes`, then `git diff HEAD --unified=0 -M` with source `"uncommitted"`, then `git ls-files --others --exclude-standard -z`.
- `range_desc`: if `git remote` prints nothing → `"all commits (this repo has no remotes)"`; else → `"commits not on any remote (remote refs as of the last fetch)"`.
- Untracked files: `os.lstat`; a symlink → `"symlink"`; `OSError` → `"unreadable"`; size > `GIT_SCAN_MAX_BYTES` → `"too large"`; NUL in the first 8192 bytes → `"binary"`. Otherwise one chunk, lines numbered from 1.
- Analysis: for each chunk, join the line texts with `"\n"`; if the joined text is larger than `GIT_SCAN_MAX_BYTES` → `(file, "too large")`; else `engine.analyze(text, [], SessionVault(), threshold=threshold, skip_ner=not use_ner)`; map each finding's `start` to a line with `bisect` over line start offsets.
- `progress(...)` once for each phase ("Reading commits...", "Reading uncommitted changes...", "Reading untracked files...", "Analyzing N chunks..."). No values in progress text.
- At the end: `log.info("Git scan: %s; %d commits, %d findings, %d skipped", range_desc, ...)`.

Test fixture (in `ScanTests`; skip the class with `@unittest.skipUnless(shutil.which("git"), "git not installed")`):
- `setUpClass`: engine as in `EngineTests` (copy of template rules, `initialize()`).
- `setUp`: temp dir with a bare `remote.git` and a clone `work`; `git config user.name/user.email` (`Test User` / `test.user@example.org`); `git symbolic-ref HEAD refs/heads/main`; commit `base.txt` containing `password=OldS3cret!`; `git push -u origin main`.
- Helper `self.scan(path=None, **kw)` → `ps.scan_git_repo(path or self.work, self.engine, 0.85, **kw)`.
- Helper `vals(result)` → `{(f.source if f.source in ("uncommitted", "untracked") else "commit", f.file, f.line, f.value) for f in result.findings}`.

- [ ] **Step 1: Write the failing tests**

| Test | Setup | Assertions |
|---|---|---|
| `test_pushed_value_not_found` | none | `"OldS3cret!"` not in any `f.value`; `commits == 0` |
| `test_new_commit_found` | commit `app/cfg.py` with line 3 `password=Sup3rS3cret!`; run the scan inside `self.assertLogs(ps.APP_ID, "DEBUG")` | `("commit", "app/cfg.py", 3, "Sup3rS3cret!") in vals(r)`; `commits == 1`; `"Sup3rS3cret!"` not in any log record; one record starts with `Git scan:` |
| `test_add_then_remove_still_found` | commit A adds `key = AKIAIOSFODNN7EXAMPLE`, commit B removes it | a finding with value `AKIAIOSFODNN7EXAMPLE` and `source` = A's 10-char SHA |
| `test_uncommitted_and_untracked` | stage a change to `base.txt` with `password=Staged1!`, an unstaged change with `password=Unstaged1!`, a new untracked `new.txt` with `password=Untracked1!` | sources `uncommitted`, `uncommitted`, `untracked` for the three values |
| `test_ignored_file_not_scanned` | `.gitignore` with `secret.env`; `secret.env` holds `password=Ignored1!` | no finding with that value |
| `test_binary_skipped` | commit `blob.bin` with bytes `b"\x00\x01password=Bin1!"` | `("blob.bin", "binary") in r.skipped` |
| `test_unpushed_main_commits_on_new_branch` | commit on `main` (not pushed) with `password=MainOnly1!`; `git switch -c feature`, commit `x.txt` | both values found |
| `test_no_remote_scans_all` | fresh repo with no remote, 2 commits | `commits == 2`; `range_desc` contains `no remotes` |
| `test_merge_resolution_found` | branches `a`/`b` change the same line of `conf.ini`; merge with a conflict; resolve the line as `password=Merge1!`; commit. Then merge a branch `c` that touches a different file (clean merge) | `"Merge1!"` found with the conflict merge's SHA; no finding has the clean merge's SHA |
| `test_commit_message_found_author_not` | commit with body `password=MsgS3cret!` | a finding `("commit", "(commit message)", 3, "MsgS3cret!")`; no finding value contains `test.user@example.org` |
| `test_worktree` | `git worktree add ../wt -b wt-branch`; commit, stage and add untracked files there; add an unstaged change in `work` with `password=MainTree1!` | scan of `../wt` finds the worktree values; `"MainTree1!"` not found |
| `test_git_dir_env_ignored` | `mock.patch.dict(os.environ, {"GIT_DIR": str(other_repo / ".git")})`, where `other_repo` has an untracked secret | the scan of `work` does not report it |
| `test_fresh_vault_per_chunk` | two new files with secrets; wrap `engine.analyze` with `mock.patch.object(self.engine, "analyze", wraps=self.engine.analyze)` | every call's third argument is a `SessionVault` with empty `active_tokens` when called, and no two calls share the same vault object |
| `test_not_a_repo` | empty temp folder | `GitScanError` raised, message starts with `Not a Git working tree` |
| `test_ner_off_by_default` | skip unless `engine.mode == "presidio+spacy"`; commit `notes.txt` with `John Smith approved the change.` | no NER-recognizer finding by default; with `use_ner=True` a `PERSON` finding exists |
| `test_path_with_space_and_unicode` | commit `dir with space/naïve.txt` with `password=Uni1!` | finding with `file == "dir with space/naïve.txt"` |
| `test_crlf_file` | commit `w.txt` with bytes `b"a\r\nb\r\npassword=Crlf1!\r\n"` | finding at line 3 with value `Crlf1!` |
| `test_unborn_head` | `git init` with no commits; stage `s.txt` (`password=Unborn1!`); untracked `u.txt` (`password=Unborn2!`) | `commits == 0`; both found, sources `uncommitted` and `untracked` |
| `test_untracked_symlink_skipped` | skip if `os.symlink` raises; untracked symlink `link` to `base.txt` | `("link", "symlink") in r.skipped` |
| `test_git_missing` | `mock.patch("subprocess.run", side_effect=FileNotFoundError)` | `GitScanError` with `git was not found on PATH` |

- [ ] **Step 2: Run them and see them fail**

Run: `python -m unittest tests.test_git_scan.ScanTests -v`
Expected: FAIL with `AttributeError: ... has no attribute 'scan_git_repo'`

- [ ] **Step 3: Implement `GitScanError`, `GitFinding`, `GitScanResult`, `run_git`, `git_repo_root`, `scan_git_repo`** as specified above.

- [ ] **Step 4: Run them and see them pass**

Run: `python -m unittest tests.test_git_scan -v`
Expected: PASS (the NER and symlink tests may show as skipped).

- [ ] **Step 5: Run the full suite**

Run: `python -m unittest discover -s tests -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add pii_sanitizer.py tests/test_git_scan.py
git commit -m "Git scan: scan_git_repo over unpushed commits, uncommitted and untracked files"
```

---

### Task 4: GUI dialog, button, config key and README

**Files:**
- Modify: `pii_sanitizer.py` — `DEFAULT_CONFIG["behavior"]` (`:128-135`), new class `GitScanDialog` in section 8 before `class MainWindow`, `MainWindow` Step 1 button row (`:2883-2893`), `_start_engine.done` (`:3141-3149`) and `_task_error` (`:3132-3136`)
- Modify: `README.md` (new section under **Running the app**)
- Test: `tests/test_git_scan.py` (class `GitScanDialogTests`, `@unittest.skipUnless(ps.QT_OK, ...)`, offscreen setup as in `tests/test_core.py:590-604`)

**Interfaces:**
- Consumes: `scan_git_repo`, `GitScanResult`, `GitFinding`, `GitScanError`, `git_repo_root` (Task 3); `Task`, `_button`, `set_note` (existing).
- Produces:

```python
DEFAULT_CONFIG["behavior"]["git_scan_last_repo"] = ""

class GitScanDialog(QtWidgets.QDialog):
    def __init__(self, config: AppConfig, engine: DetectionEngine,
                 threshold: Callable[[], float], parent=None)
    # widgets: path_edit, btn_browse, chk_ner, btn_scan, lbl_status, lbl_note,
    #          table (6 columns), skipped_box (QGroupBox, checkable, collapsed), skipped_list, btn_copy
    def start_scan(self) -> None
    def show_result(self, result: GitScanResult) -> None
    def results_tsv(self) -> str
MainWindow.btn_git_scan: QtWidgets.QPushButton
MainWindow.open_git_scan(self) -> None
```

Exact copy (from the spec, in STE):
- Button: `Scan Git Repo...`, tooltip `Scan the commits this branch would push, plus uncommitted and untracked files, for PII and secrets`.
- Window title: `Git Scan`. Check box: `Find names with spaCy (more noise)`, clear by default. Buttons: `Browse...`, `Scan` (primary), `Copy Results`.
- Table headers: `Source`, `File`, `Line`, `Entity`, `Value`, `Recognizer`. Sorting on; columns resizable (`QHeaderView.ResizeMode.Interactive`); `Line` sorts as a number.
- `lbl_status`: `f"Range: {r.range_desc} · {r.commits} commits · {len(r.findings)} findings · {len(r.skipped)} skipped · min score {r.threshold:.2f}"`.
- `lbl_note` (via `set_note`):
  - findings > 0 → `f"{n} findings. Fix them before you push."`, kind `leak`;
  - no findings, commits > 0 → `f"No findings in {r.commits} commits and the uncommitted changes."`, kind `okmsg`;
  - no findings, commits == 0 → `"0 commits to push. No findings in the uncommitted changes."`, kind `stale`.
- Skipped group title: `f"Skipped files ({len(r.skipped)})"`; each item `f"{path} — {reason}"`.

Behavior:
- `open_git_scan` keeps one dialog instance (`self._git_scan_dialog`), shows it non-modal and raises it.
- `btn_git_scan` starts disabled. Enable it in `_start_engine.done`. In `_task_error`, set it the same way as `btn_analyze`.
- `start_scan`: empty path → the note `Choose a repo folder.` in `lbl_note` (kind `stale`), no scan. Otherwise save the path to `config["behavior"]["git_scan_last_repo"]` and `config.save()`, disable `btn_scan`, read `threshold()` now, and run `scan_git_repo` in a `Task` with progress shown in `lbl_status`. On error, show the message in `lbl_note` (kind `leak`) and turn `btn_scan` on again.
- Double-click on a row copies `f"{file}:{line}"` to the clipboard.
- `results_tsv()` returns a header line and one line per row, tab-separated, in the current sort order. `Copy Results` puts it on the clipboard.

- [ ] **Step 1: Write the failing tests** (class `GitScanDialogTests`; build `MainWindow` with `_start_engine` patched, as in `tests/test_core.py:599-603`):

```python
def _result(self, findings, commits=2, skipped=()):
    return ps.GitScanResult(Path("/r"), "commits not on any remote (remote refs as of the last fetch)",
                            commits, 0.85, list(findings), list(skipped))

def test_button_waits_for_engine(self):
    self.assertEqual(self.win.btn_git_scan.text(), "Scan Git Repo...")
    self.assertFalse(self.win.btn_git_scan.isEnabled())

def test_show_result_with_findings(self):
    d = ps.GitScanDialog(self.win.config, self.win.engine, lambda: 0.85, self.win)
    f = ps.GitFinding("abc1234567", "app/cfg.py", 3, "SECRET", "Sup3rS3cret!", "Passwords", 0.9)
    d.show_result(self._result([f], skipped=[("blob.bin", "binary")]))
    self.assertEqual(d.table.rowCount(), 1)
    self.assertEqual(d.table.item(0, 1).text(), "app/cfg.py")
    self.assertEqual(d.lbl_note.text(), "1 findings. Fix them before you push.")
    self.assertEqual(d.lbl_note.objectName(), "leak")
    self.assertIn("· 1 findings · 1 skipped · min score 0.85", d.lbl_status.text())
    self.assertEqual(d.results_tsv().splitlines()[1].split("\t"),
                     ["abc1234567", "app/cfg.py", "3", "SECRET", "Sup3rS3cret!", "Passwords"])

def test_show_result_clean_and_zero_commits(self):
    d = ps.GitScanDialog(self.win.config, self.win.engine, lambda: 0.85, self.win)
    d.show_result(self._result([], commits=4))
    self.assertEqual(d.lbl_note.text(), "No findings in 4 commits and the uncommitted changes.")
    self.assertEqual(d.lbl_note.objectName(), "okmsg")
    d.show_result(self._result([], commits=0))
    self.assertEqual(d.lbl_note.text(), "0 commits to push. No findings in the uncommitted changes.")
    self.assertEqual(d.lbl_note.objectName(), "stale")
    self.assertEqual(d.table.rowCount(), 0)

def test_ner_box_clear_and_last_repo_remembered(self):
    self.win.config["behavior"]["git_scan_last_repo"] = str(self.tmp)
    d = ps.GitScanDialog(self.win.config, self.win.engine, lambda: 0.85, self.win)
    self.assertFalse(d.chk_ner.isChecked())
    self.assertEqual(d.path_edit.text(), str(self.tmp))
```

- [ ] **Step 2: Run them and see them fail**

Run: `python -m unittest tests.test_git_scan.GitScanDialogTests -v`
Expected: FAIL with `AttributeError: ... has no attribute 'btn_git_scan'`

- [ ] **Step 3: Add the config key, `GitScanDialog`, `btn_git_scan` (after `btn_load` in the row) and `open_git_scan`** as specified above.

- [ ] **Step 4: Run them and see them pass**

Run: `python -m unittest tests.test_git_scan.GitScanDialogTests -v`
Expected: PASS

- [ ] **Step 5: Add the README section** `### Scan a Git branch` under **Running the app**, in STE. Cover: how to open it; what it reads (added lines of commits not on any remote, merge resolutions, commit messages, staged and unstaged changes, untracked files that Git does not ignore); what it does not read (author and committer names and emails, lines that the branch does not add, ignored files); that it does not run `git fetch`, so the range uses the remote refs from the last fetch; the spaCy check box; the 1 MB limit and the skipped list; that `git` must be on PATH; that it works in linked worktrees.

- [ ] **Step 6: Run the full suite**

Run: `python -m unittest discover -s tests -v`
Expected: all PASS.

- [ ] **Step 7: Check the GUI by hand**

Run: `python pii_sanitizer.py`, wait for the engine, click **Scan Git Repo...**, pick this repo, click **Scan**.
Expected: the status line names the range and counts; the table fills or the green/yellow note shows; the **Log** tab has one `Git scan:` line with no values.

- [ ] **Step 8: Commit**

```bash
git add pii_sanitizer.py tests/test_git_scan.py README.md
git commit -m "UI: Scan Git Repo dialog; README: Scan a Git branch"
```
