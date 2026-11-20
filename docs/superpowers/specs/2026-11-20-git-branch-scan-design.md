# Git branch scan — design

Date: 2026-11-20
Status: draft, for approval

## Intent

The user wants to find PII and secrets in a Git branch before they push it. The branch can
change many files. Loading each file into PII Shield by hand does not work at that size.

The scan is a leak check. It only reports findings. It does not mask text, change files or
block a push. The user reads the results, then fixes the code or pushes it.

## Goals

- From the GUI, the user picks a repo folder and starts one scan.
- The scan covers everything that a push of the current branch sends, plus local work that
  is not committed yet:
  1. each commit in `@{upstream}..HEAD`, one commit at a time;
  2. staged and unstaged changes to tracked files (`git diff HEAD`);
  3. untracked files that Git does not ignore.
- For commits and tracked changes, the scan reads only the **added lines**. For an untracked
  file, every line is an added line.
- The results show where each finding is: source (commit, uncommitted or untracked), file,
  line number, entity type, value and recognizer.
- The scan uses the same rules, allow list and score threshold as the normal analysis.

## Non-goals

- No Git hook. The user starts each scan by hand.
- No masking or rewriting of files or history.
- No CLI option in this change. (The core function is free of Qt, so a CLI can come later.)
- No `git fetch`. The scan uses the remote-tracking refs as they are.
- No scan of lines that the branch does not add. Old content is already on the remote.

## Anti-goals (a failure even if it works)

- The scan writes a detected value to the **Log** tab or to a log file. The README promises
  that the log never contains detected values or prompt text.
- The scan makes a network request, or `git` asks for credentials.
- The scan changes the repo: index, working tree, refs or config.
- The scan changes the session map. A scan must not add tokens to the current session.
- The scan misses a value that a commit adds and a later commit removes. The push still sends
  that commit.

## Constraints

- One file: all code goes into `pii_sanitizer.py`, the same as the rest of the app.
- No new dependencies. The scan runs the `git` CLI through `subprocess`.
- `git` must be on PATH. If it is not, the scan shows a clear error.
- The Windows build has no console. `git` must run with `CREATE_NO_WINDOW`, so no console
  window opens for each call.
- The engine must be loaded before a scan can start. Use the same rule as the **Analyze**
  button.
- The GUI must stay responsive. Run the scan in the thread pool with the existing `Task`
  class and send progress through its `progress` signal.

## Approaches

| Approach | Trade-off | Decision |
|---|---|---|
| **1. Scan each commit separately.** `git log -p` over `base..HEAD`, then `git diff HEAD`, then untracked files. | Finds values that a later commit removes. Gives a commit column. The same value can show more than once. | **Chosen.** This is the only approach that catches every value the push sends. |
| 2. Scan one net diff, `git diff @{upstream}`. | Simpler, one row for each value. Misses add-then-remove values. No commit column. | Rejected. |
| 3. Use a Python Git library (GitPython, dulwich). | New dependency, larger Windows build, no gain over the CLI. | Rejected. |

## Decided by the user

- Case A: a leak check that reports results. The user fixes or pushes by hand.
- No hook. A manual scan from the GUI, with a **Scan Git Repo...** button and a folder picker.
- Compare against the remote. (The user approved `@{upstream}`. The builder check changed it
  to `HEAD --not --remotes`, which covers more. See "Choosing the commits".)
- Read added lines only (option 1).
- Also scan uncommitted changes, staged and unstaged.
- Approach 1.
- Scan commit messages. Do not scan author or committer names or emails.
- Worktrees must work.

## Design

### Core function (no Qt)

```python
def scan_git_repo(repo: Path, engine: DetectionEngine,
                  progress: Callable[[str], None] = lambda s: None) -> GitScanResult
```

`GitScanResult` holds:

- `base`: the ref and the short SHA the scan compared against, and how the scan chose it.
- `commits`: the number of commits scanned.
- `findings`: a list of `GitFinding(source, file, line, entity, value, recognizer, score)`.
  `source` is a short commit SHA, `uncommitted` or `untracked`.
- `skipped`: a list of `(file, reason)`, for example `binary` or `too large`.

Errors (not a repo, no `git`, no base found) raise one exception class with a message the
GUI can show.

### Choosing the commits

The range is every commit reachable from `HEAD` that no remote-tracking ref has:
`git log HEAD --not --remotes`.

- This includes `@{upstream}..HEAD`, which the user approved. It also covers the cases where
  a fallback to `main` would give a false all-clear:
  - **First push of a new repo** (no upstream, no remote refs): `--not --remotes` excludes
    nothing, so the scan reads every commit from the root.
  - **Feature branch with no upstream, and local `main` has unpushed commits:** those `main`
    commits are not on a remote, so the scan reads them. The push sends them too.
- A commit that is already on any remote branch is skipped. That commit is already on the
  server.
- The status line names the range: "commits not on any remote (last fetch: refs as they are
  now)". If the repo has no remotes, it says so.
- If the scan reads 0 commits, the status line says it plainly ("0 commits to push") and
  does not show the green all-clear for commits. The uncommitted and untracked parts still
  run.

*Builder's call (by Claude), from the builder check: `--not --remotes` in place of
`@{upstream}..HEAD` with fallbacks. Reason: the fallbacks could report a clean branch when
the push sends commits that the scan never read.*

### Commit messages

The scan reads the full message (subject and body) of each commit in the range. It does
not read author or committer names or emails. (Decided by the user.)

- The git log format adds the message: for example `--format=<marker>%H%n%B<end-marker>`.
  Use markers that cannot appear in a message by chance.
- A finding in a message has the file value `(commit message)`. The line number counts
  from the subject line, which is line 1.
- The README says that author and committer identity is not scanned.

### Merge commits

`git log -p` prints no patch for a merge commit. A value that the user adds while they
resolve a merge conflict would be missed. The scan uses `git log --cc`:

- A clean merge shows no diff, so it gives no findings.
- A conflict resolution shows only the lines that differ from every parent. The parser
  reads combined hunks: `@@@ -a,b -c,d +e,f @@@` headers, with one prefix column for each
  parent. A line is added when no prefix column is `-` and at least one is `+`. The line
  number comes from the `+e,f` part.
- Commits from a merged-in local branch are in the range by themselves, so the scan reads
  them as normal commits.

*Builder's call (by Claude), from the builder check. `-m --first-parent` was rejected: it
reports all content of the merged-in branch, including content already on the remote.*

### Git calls

Every call:

- uses an argument list, never a shell;
- adds `-c core.fsmonitor=false -c core.quotepath=off` and `--no-color --no-ext-diff
  --no-textconv` where they apply, so repo config cannot run a program and the output is
  stable;
- sets `GIT_TERMINAL_PROMPT=0` and `GIT_OPTIONAL_LOCKS=0` in the environment, and removes
  `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_COMMON_DIR` and `GIT_OBJECT_DIRECTORY`
  from it, so `git` reads the folder the user picked and no other repo;
- runs with `cwd=repo` and a timeout;
- reads bytes and decodes them as UTF-8 with `errors="replace"`.

Commands:

1. `git rev-parse --show-toplevel` — check that the folder is in a repo.
2. `git log -p --cc --unified=0 -M --format=<message format> HEAD --not --remotes` —
   the commits with their messages and merge resolutions. The order does not matter.
3. `git diff HEAD --unified=0 -M` — staged and unstaged changes together.
4. `git ls-files --others --exclude-standard -z` — untracked files.

### Worktrees

The scan must work in a linked worktree (`git worktree add`) as well as in the main one.

- Never test for a `.git` folder. In a linked worktree, `.git` is a file. Use only
  `git rev-parse --show-toplevel` to find the repo root.
- Run every call with `cwd` set to the root that `rev-parse` returns. Each worktree has its
  own `HEAD`, index and working tree, so all three scan parts read the picked worktree.
- `@{upstream}` comes from the shared repo config, so it works in every worktree.
- A bare repo has no working tree. `rev-parse --show-toplevel` fails there, and the scan
  shows the "not a repo" error.

### Reading a diff

Parse the unified diff with `--unified=0`:

- `+++ b/<path>` gives the file. A deleted file (`+++ /dev/null`) has no added lines.
- `@@ -a,b +c,d @@` gives the line number of the first added line.
- Each line that starts with `+` (but not `+++`) is an added line. Count line numbers from
  the hunk header.
- `Binary files ... differ` adds the file to `skipped` with the reason `binary`.

### Analysis

- For each (source, file), join the added lines with `\n`. Keep a map from text offset to
  line number.
- Call `engine.analyze(text, [], SessionVault(), threshold=thr)` with a new, empty vault.
  The session map stays untouched.
- `thr` is the value of the main window's threshold spin box when the scan starts. The
  **Analyze** button uses that value too, and changes to it are not saved to `config.json`.
  Reading it keeps the scan and **Analyze** in step for the same text. The dialog shows the
  threshold it used.
- A chunk larger than 1 MB of added text is not analyzed. Add it to `skipped` with the
  reason `too large`. Reason: spaCy has a text length limit, and the app does not check it.
- Map each finding's start offset to a line number.
- Untracked files: skip a file larger than 1 MB, or a file with a NUL byte in its first
  8 KB (binary). Add each to `skipped`.

*Builder's call (by Claude): the 1 MB limit.*

### NER filter placement

Drop NER findings inside `analyze()`, through a new keyword argument (for example
`skip_ner=True`). `analyze()` already drops NER findings this way for log input (the
`skip_ner_on_logs` path), before it resolves overlaps and propagates values. A filter after
`analyze()` would be too late: a dropped NER value would already have spread to other
places in the text.

### spaCy NER on code

spaCy reads code as prose and tags many identifiers as PERSON or ORGANIZATION. The scan
dialog has a check box **Find names with spaCy (more noise)**. It is clear by default. When
it is clear, the scan drops findings from the NER recognizers (`NER_RECOGNIZERS`). The
rules still run.

*Builder's call (by Claude): the check box and its default. Reason: on code, NER gives more
false positives than real names.*

### GUI

- A **Scan Git Repo...** button in the Step 1 button row, next to **Load File...**. It is
  disabled until the engine is ready.
- The button opens a non-modal **Git Scan** dialog:
  - a folder field with **Browse...**;
  - the spaCy check box;
  - a **Scan** button (primary);
  - a status line: base ref and SHA, commits scanned, number of findings, number of
    skipped files;
  - a results table: Source, File, Line, Entity, Value, Recognizer. Sorting is on. Columns
    can change width.
  - a collapsible **Skipped files** list.
- Double-click on a row copies `file:line` to the clipboard.
- **Copy Results** copies the table as tab-separated text.
- With no findings, the status line shows a green note: *No findings in N commits and the
  uncommitted changes.*
- The dialog remembers the last folder in `config.json`.

### Logging

The **Log** tab gets one summary line for each scan: base ref, number of commits, number of
findings, number of skipped files. It never gets a value or a line of file text.

### Tests

Add tests to `tests/test_core.py` (or a new `tests/test_git_scan.py`). Each test makes a
temporary Git repo with a bare remote, so `@{upstream}` exists:

- a value in a pushed commit is not found;
- a value in a new commit is found, with the right file and line;
- a value that one new commit adds and the next removes is still found;
- staged, unstaged and untracked values are found, each with the right source;
- a binary file is in `skipped`;
- a branch with no upstream, where local `main` has unpushed commits, finds values in those
  `main` commits;
- a repo with no remote scans every commit from the root;
- a value added in a merge conflict resolution is found, and a clean merge gives no findings;
- a value in a commit message body is found as `(commit message)`, and the author email is
  not reported;
- a folder that is not a repo gives the error;
- in a linked worktree on its own branch, new commits, uncommitted changes and untracked
  files are found, and the main worktree's uncommitted changes are not;
- a `GIT_DIR` set in the environment does not change which repo the scan reads;
- the session vault is unchanged after a scan;
- the diff parser gets the right line numbers for multi-hunk diffs and renames.

The tests need `git` on PATH. CI already has it. Skip these tests when `git` is missing.

### README

Add a **Scan a Git branch** section under **Running the app**: what the scan covers, what
it does not cover (no fetch, added lines only) and the spaCy check box.

## Left to the builder

- The exact layout of the dialog and the parser code.
- Whether to cancel a running scan (useful for very large branches, not required).
- Timeouts for each `git` call.
- The order of findings in the table before the user sorts it.
- Parser details: quoted paths, CRLF line ends, joining hunks.
- Whether the tests also run on the Windows CI job.
