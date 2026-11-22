# Rules manager: edit, delete, and override rules from the Rules chip

Date: 2026-11-22
Status: approved 2026-11-22; builder calls added after the review

## Intent

Today the **Rules** chip in the status bar opens a read-only text list of the loaded rules. To
change a rule, the user edits a YAML file under `rules/` and clicks **Reload Local Rules**.

The user wants to do all rule maintenance inside the app:

1. Edit and delete the rules that they saved from the temporary (manual) rules list.
2. Switch off, or change, bundled and synced rules that flag too much, without touching the
   original files.

Why: the user saves rules quickly while they review a text. Some saved rules are too broad
(for example a `*xx*` wildcard that matches every word with those two letters). Some bundled
and synced rules also give false findings. Fixing either one now needs a text editor, a YAML
file, and knowledge of the rule format.

## Goals

- The Rules chip opens a **Rules manager** window: a table with every rule, enabled and
  disabled.
- The user can switch any rule on or off with a checkbox.
- The user can edit and delete their own saved rules.
- The user can disable a bundled or synced rule, or edit a copy of it. The original file never
  changes.
- The user can restore the original of an overridden rule.
- Every change validates before the app writes it, and applies at once (rules reload).

## Non-goals

- Editing the allow list in this window. (Possible later work.)
- Creating a new rule from scratch in this window. The manual rules panel already does this.
- Editing `rules/local/local_rules.yaml` or other hand-written local files from the app.
- Pushing changes to the shared GitHub rules repo.

## Anti-goals (a failure even if it works)

- A GitHub sync or an app update deletes a user's change. (So: never write to `rules/remote/`
  or to bundled rules.)
- The app deletes comments from a hand-written rule file.
- A bad edit breaks rule loading. (So: validate before write, write atomically.)
- A real value from a user's rule ends up in a tracked file, a test, or a commit.

## How it works today (facts the design depends on)

- `load_rules_dir()` loads, in order: bundled rules (`BUNDLED_RULES`, label `bundled/`), then
  `rules/remote/`, then every other file under `rules/`. A later rule with the same `name`
  replaces an earlier one (`_load_rule_files`, `by_name`).
- `parse_rule_document()` skips a recognizer with `enabled: false` before the merge. So a
  disabled local copy does **not** switch off a bundled or remote rule today. This must change.
- `parse_rule_document()` turns `json_keys` / `json_key_contains` into extra entries in
  `RuleDef.patterns`, and reads `wordlist` files into `RuleDef.deny_list`. So a `RuleDef` is not
  a faithful copy of the YAML. A copy for an override must come from the raw YAML mapping.
- "Save to local rules" (`promote_manual_rules`) writes to `rules/local/promoted_rules.yaml`
  through `append_rule_to_file()`, which rewrites the file with `yaml.safe_dump` (no comments).
- `ManualRule.to_rule_yaml()` stores only the generated regex. Since the uncommitted change of
  2026-11-22, the description also holds the original pattern
  (`Promoted from manual wildcard rule: <pattern>`).
- `rule_details()` (uncommitted, same date) gives human-readable lines for a rule. The current
  report window uses it.

## Approaches considered

- **A. Rules manager window with a form editor (picked).** A table of all rules; a form for the
  common fields; overrides of bundled and synced rules go to an app-owned local file. Safe
  against sync and updates, keeps hand-written comments, and needs no YAML knowledge.
- **B. A YAML text box for each rule.** Cheap and covers every field, but it is file editing
  inside a window. The user asked to stop editing files. Rejected.
- **C. Write each change to the file the rule came from.** A sync deletes changes to synced
  rules, and the app deletes comments in hand-written files. Rejected.

The user picked A.

## Design

### Files

| File | Owner | What the app does |
|---|---|---|
| `BUNDLED_RULES` (in the script) | app | read only |
| `rules/remote/**` | GitHub sync | read only |
| `rules/local/promoted_rules.yaml` | app | read and write (the user's saved rules) |
| `rules/local/overrides.yaml` | app (new) | read and write (copies of bundled and remote rules) |
| any other file under `rules/` (for example `local_rules.yaml`) | the user, by hand | read only; shown as "hand-edited" |

`overrides.yaml` loads after `rules/remote/` because it is under `rules/local/`. It must also
load after every other local file, so that an override always wins. The loader sorts it last.

Add `rules/local/overrides.yaml` to `.gitignore` (same reason as `promoted_rules.yaml`: it holds
the user's values).

### Loader changes

1. **Disabled rules are kept, and their errors are only warnings.** A recognizer with
   `enabled: false` is no longer dropped. The parser checks it fully, but its problems do not
   make a file error. A valid disabled rule keeps its patterns, so a marker can switch it on. An
   invalid one gives a warning and is marked `broken`; a marker cannot switch it on. So a broken
   disabled rule never switches off the rest of its file, and the strict sync dry run behaves as
   today. (Builder call: a disabled rule had no checks before, and a new file error would switch
   off every other rule in that file.)
2. **Partial override (marker).** A recognizer that has a `name`, an `enabled` value, and no
   `entity`, `patterns`, `deny_list`, `wordlist`, `json_keys` or `json_key_contains` is a
   marker. In the merge, a marker takes the earlier rule with the same name, copies it, and sets
   only `enabled`. So:
   - `{name: X, enabled: false}` switches off rule X.
   - `{name: X, enabled: true}` switches on rule X when X is off in its own file (for example
     the bundled `HighEntropyBlobs`).
   A marker with no earlier rule of that name adds a warning
   (`marker '<name>' in <file> has no rule to change`) and is otherwise ignored.
3. **A full rule** (has `entity` and content) replaces the earlier rule, as today. If it is
   disabled, it replaces the earlier rule and the result is off.
4. `RuleDef` gets new fields:
   - `enabled: bool = True`
   - `raw: dict` — the recognizer mapping as read from the file (deep copy).
   - `overrides: Optional["RuleDef"]` — the rule this rule replaced, if any. Markers and copies
     keep the original here, so the window can show its entity and matches, and Edit copy can
     start from its `raw`.
   - `is_marker: bool = False`
   - `broken: bool = False` — a disabled rule that failed validation.
5. **`RuleSet.rules` keeps its meaning: active rules only.** Add `RuleSet.all_rules` (active
   and disabled, in load order). (Builder call: about 20 call sites use `rs.rules` for
   detection, counts and the badge. Keeping that name for active rules leaves them all correct
   with no change.)

The existing `rules/local/local_rules.yaml` example (`MyLabHosts`, `enabled: false`) then shows
in the table as a disabled hand-edited rule. Before the change it did not show at all.

### The Rules manager window

The Rules chip opens it. It replaces the text report.

Table columns:

| On | Entity | Name | Source | Matches | Actions |
|---|---|---|---|---|---|

- **On**: checkbox.
- **Source**: `bundled`, `remote`, `saved` (promoted_rules.yaml), `override`, or `hand-edited`.
  An override row also says what it replaces, for example `override of remote`.
- **Matches**: a short summary from `rule_details()`. For a saved manual rule, show the original
  wildcard or exact value, not the regex. Full text in the tooltip.
- **Actions** by source:

| Source | Checkbox | Actions |
|---|---|---|
| saved | sets `enabled` in promoted_rules.yaml | Edit, Delete |
| bundled, remote | writes a marker to overrides.yaml | Edit copy |
| override | sets `enabled` in overrides.yaml | Edit, Restore original |
| hand-edited | disabled (greyed) | none; tooltip says "edit this file by hand" |

Above the table: a filter box (text match on entity, name, and matches) and a source filter.
Below the table: file errors and warnings, as the old report showed them.

Every action writes the file, then reloads rules. The table refreshes from the new `RuleSet`.
The status bar says "Rules changed. Re-analyze to apply them to the current text."

### Switch off, switch on, and restore for bundled and remote rules

- Toggling the checkbox of a bundled or remote rule writes a marker
  `{name: <name>, enabled: <new state>}` to overrides.yaml.
- If an override entry already exists (marker or copy), toggling sets `enabled` on that entry,
  so the user's edits stay.
- If a marker's `enabled` becomes equal to the original's own state, delete the marker. It no
  longer changes anything.
- **Restore original** removes the rule's entry from overrides.yaml. Confirm first: "Delete your
  copy and use the original rule?" If the original no longer exists, the text is: "The original
  rule no longer exists. This deletes the rule."
- **Edit** on a marker row is Edit copy of the original. The copy keeps the marker's `enabled`
  value and replaces the marker.

### Copies whose original changed or went away

Each copy in overrides.yaml stores a fingerprint of the original:

```yaml
metadata:
  original_sha: <first 12 hex chars of sha1 of the original raw mapping, JSON with sorted keys>
```

The Source column shows `override (original changed)` when the current original has another
fingerprint, and `override (original removed)` when no rule with that name loads before
overrides.yaml. Markers need no fingerprint: they always follow the current original.

### Edit form

One dialog for all editable rules.

Fields:

- **Name**: shown, not editable. The name is the link between an override and its original.
- **Entity**: editable combo box (same list as the manual rules panel). UPPER_SNAKE_CASE check.
- **For a saved manual rule**: match type (Exact, Wildcard, Custom Regex) and one pattern. This
  is the same input as the manual rules panel, so the user edits `*xx*`, not the regex.
- **For any other rule**: a list of regex patterns (add, edit, remove a line) and a list of exact
  values (one per line).
- **Score**: number in (0, 1].
- **Case sensitive**: checkbox.
- A live **Test** box: the user types sample text and sees what the rule matches.

Fields the form does not show (`context`, `validator`, `json_keys`, `json_key_contains`,
`description`, per-pattern names and scores) stay in the raw mapping unchanged.

Save builds the new raw mapping, runs `parse_rule_document()` on the whole new file content, and
writes only if that passes. On failure, the dialog shows the problems and stays open.

### Saved manual rules keep their source

`ManualRule.to_rule_yaml()` adds a per-recognizer key:

```yaml
metadata:
  manual: {match_type: wildcard, pattern: "*contoso*"}
```

The parser ignores `metadata` inside a recognizer (check that it does not warn). The edit form
uses it to show the original input. On save, the form regenerates the regex (or `deny_list` for
Exact) from it.

**Saved rules get a new name when their pattern or entity changes.** The name stays
`manual_<entity>_<sha1(pattern)[:8]>`, computed from the new values. If another saved rule
already has that name, the form refuses to save and says so. (Builder call: saved rules are not
override targets, so their name links nothing. A stale name would let a later "Save to local
rules" with the old pattern overwrite the edited rule.)

Older saved rules have no `metadata`. For those, the form reads the pattern from the description
(`Promoted from manual <type> rule: <pattern>`) if it is there. If not, the form treats the rule
like any other rule (regex list).

### Edit copy of a bundled or remote rule

- Copy `RuleDef.raw` to overrides.yaml, then open the edit form on the copy.
- If the original uses `wordlist:`, the copy replaces it with an inline `deny_list` of the loaded
  values, because a wordlist path is relative to the original file and does not resolve from
  `rules/local/`. The form warns: "This copy no longer follows changes to the original word
  list."
- If the user cancels the form, do not write the copy.

### Writing files

- One helper for all writes: read the file, change one recognizer by name, validate the whole
  document with `parse_rule_document()`, write to a temp file in the same folder, then
  `os.replace()`.
- `append_rule_to_file()` moves to the same helper.
- Delete asks for confirmation.

## Tests

- Loader: a disabled local rule switches off a bundled rule and a remote rule with the same name;
  `rules` excludes it; `all_rules` includes it with `overrides` set.
- Loader: a marker switches a bundled rule off, and switches an off-by-default rule on; a
  marker with no original gives a warning; a full enabled rule with no patterns is still an
  error; a disabled rule with a broken regex is not a file error.
- Loader: overrides.yaml wins over another local file with the same rule name.
- Write helper: edit, disable, delete, restore on temp folders; an invalid edit leaves the file
  unchanged.
- Edit copy of a wordlist rule inlines the values.
- Manual rule round trip: save with `metadata.manual`, edit the wildcard, the regex changes.
- Old saved rule without `metadata`: the pattern comes from the description.
- GUI (offscreen, like `MainWindowGuiTests`): the Rules chip opens the window; unchecking a
  bundled rule reloads rules and the active count drops by one.
- Every test uses neutral sample values (for example `contoso`), never real user values.

## Left to the builder

- Widget choice for the table (QTableWidget or a model and view).
- Exact layout of the edit form and the test box.
- Sort order of the table (suggested: source, then entity, then name).
- Whether the window is modal.
