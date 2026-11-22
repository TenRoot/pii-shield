# Rules Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The Rules chip opens a window where the user switches rules on and off, edits and deletes their saved rules, and overrides bundled and synced rules through local copies.

**Architecture:** The loader keeps disabled rules and supports "marker" partial overrides. Pure module-level helpers do every rule-file write (read, change one recognizer, validate, atomic replace). Two Qt dialogs (`RulesManagerDialog`, `RuleEditDialog`) call only those helpers, then reload rules through the existing engine.

**Tech Stack:** Python 3, PyQt6, PyYAML, `unittest` (run with `python -m unittest discover -s tests`). Single-file app: `pii_sanitizer.py`.

**Spec:** `docs/superpowers/specs/2026-11-22-rules-manager-design.md`

## Global Constraints

- The app never writes to `rules/remote/**` or to `BUNDLED_RULES`.
- The app writes only `rules/local/promoted_rules.yaml` and `rules/local/overrides.yaml`. Every other file under `rules/` is read only ("hand-edited").
- `RuleSet.rules` means active rules only. `RuleSet.all_rules` holds active and disabled rules, in load order.
- Every write validates the whole new document with `parse_rule_document()` first, then writes a temp file in the same folder and calls `os.replace()`. On a validation failure, the file stays unchanged and the helper raises `RuleError`.
- File paths come from a `rules_root: Path` parameter (`engine.rules_root` in the GUI), never from the module constants, so tests can use temp folders.
- Tests use neutral sample values (`contoso`, `example`). Never real user values.
- Status bar text after every change: `Rules changed. Re-analyze to apply them to the current text.`
- Fingerprint: first 12 hex chars of `sha1(json.dumps(raw, sort_keys=True, ensure_ascii=False))`, stored as `metadata.original_sha`.
- Saved rule name: `manual_<entity lower>_<sha1(pattern)[:8]>` (same as `ManualRule.to_rule_yaml()` today).

## Review Focus

1. `promoted_rules.yaml` or `overrides.yaml` was broken by hand (bad YAML) when the user clicks an action: the helper refuses, the window shows the error, the file stays as it was. (Test: Task 2.)
2. The user deletes the last saved rule: `promoted_rules.yaml` keeps `recognizers: []`, and it loads with no error. (Test: Task 2.)
3. A rule name with spaces or dots (allowed by `RULE_NAME_RE`): markers and copies match it exactly. (Test: Task 1.)
4. Edit copy of a rule that uses `json_keys`: the copy keeps `json_keys` and does not also get the generated patterns, so the rule does not match twice. (Test: Task 2.)
5. The user opens the window before the engine finishes its first load: the table shows what is loaded, and an action still reloads rules without a crash. (Test: Task 5.)

---

### Task 0: Branch and commit the earlier work

**Files:**
- Already modified, not committed: `pii_sanitizer.py` (`rule_details()`, description with the original pattern), `tests/test_core.py` (`RuleDetailsTests`), `.gitignore`, the spec.

- [ ] **Step 1:** `git switch -c feature/rules-manager`
- [ ] **Step 2:** Confirm `rules/local/promoted_rules.yaml` is not in `git status` (it is ignored).
- [ ] **Step 3:** Run `python -m unittest tests.test_core.RuleDetailsTests -v`. Expected: 2 tests OK.
- [ ] **Step 4:** Commit:

```bash
git add pii_sanitizer.py tests/test_core.py .gitignore docs/superpowers/specs/2026-11-22-rules-manager-design.md docs/superpowers/plans/2026-11-22-rules-manager.md
git commit -m "Rules report: show what each rule matches; spec and plan for the rules manager"
```

Baseline: the full suite already has 4 failures and 1 error on `main` (Presidio and network tests). Every later task must keep that same set and add no new failure.

---

### Task 1: Loader keeps disabled rules and supports markers

**Files:**
- Modify: `pii_sanitizer.py` — `RuleDef`, `RuleSet`, `parse_rule_document()`, `_load_rule_files()`, `load_rules_dir()`; new constant `OVERRIDES_FILE_NAME = "overrides.yaml"`
- Test: `tests/test_core.py` — new class `RuleOverrideLoaderTests`

**Interfaces:**
- Produces:
  - `RuleDef.enabled: bool = True`, `RuleDef.raw: dict` (deep copy of the recognizer mapping), `RuleDef.overrides: Optional[RuleDef] = None`, `RuleDef.is_marker: bool = False`, `RuleDef.broken: bool = False`
  - `RuleSet.all_rules: List[RuleDef]`; `RuleSet.rules` = `[r for r in all_rules if r.enabled]`
  - `is_marker_mapping(r: dict) -> bool` — has `name` and `enabled`, and none of `entity`, `supported_entity`, `patterns`, `deny_list`, `wordlist`, `json_keys`, `json_key_contains`

- [ ] **Step 1: Write the failing tests** (each builds a temp `rules/` with a `remote/` file and `local/` files, then calls `ps.load_rules_dir(root, bundled=False)`):

```python
def test_marker_switches_off_remote_rule(self):
    # remote/r.yaml: {name: "Contoso Hosts.v2", entity: HOSTNAME, patterns: ['\bcontoso-\w+\b']}
    # local/overrides.yaml: {name: "Contoso Hosts.v2", enabled: false}
    rs = ps.load_rules_dir(root)
    self.assertNotIn("Contoso Hosts.v2", [r.name for r in rs.rules])
    r = next(r for r in rs.all_rules if r.name == "Contoso Hosts.v2")
    self.assertEqual((r.enabled, r.is_marker, r.entity), (False, True, "HOSTNAME"))
    self.assertEqual(r.overrides.source_file, "remote/r.yaml")
    self.assertTrue(r.patterns, "marker keeps the original's patterns")

def test_marker_switches_on_rule_that_is_off_in_its_file(self):
    # remote rule with enabled: false and a valid pattern; marker enabled: true
    self.assertIn(name, [r.name for r in rs.rules])

def test_marker_without_original_warns(self):
    self.assertIn("marker 'nothing_here' in local/overrides.yaml has no rule to change", rs.warnings)
    self.assertNotIn("nothing_here", [r.name for r in rs.all_rules])

def test_disabled_rule_with_broken_regex_is_not_a_file_error(self):
    # local/a.yaml: one enabled valid rule + {name: off, entity: X, enabled: false, patterns: ['(']}
    self.assertEqual(rs.errors, [])
    self.assertTrue(next(r for r in rs.all_rules if r.name == "off").broken)
    self.assertIn("valid_one", [r.name for r in rs.rules])

def test_enabled_rule_without_patterns_is_still_an_error(self):
    # {name: n, entity: HOSTNAME}
    self.assertTrue(rs.errors)

def test_overrides_file_loads_after_other_local_files(self):
    # local/zz_hand.yaml and local/overrides.yaml both define "dup" with different entities
    self.assertEqual(next(r for r in rs.rules if r.name == "dup").source_file, "local/overrides.yaml")

def test_full_copy_records_what_it_replaced(self):
    # remote "c" + full copy "c" in overrides.yaml
    self.assertEqual(next(r for r in rs.rules if r.name == "c").overrides.source_file, "remote/c.yaml")
```

- [ ] **Step 2:** Run `python -m unittest tests.test_core.RuleOverrideLoaderTests -v`. Expected: FAIL (`AttributeError: all_rules`).

- [ ] **Step 3: Implement.**
  - `parse_rule_document()`: replace the `enabled is False: continue` line. For a marker mapping, check only the name and return a `RuleDef(name, entity="", enabled=..., is_marker=True, raw=...)`. For a disabled full rule, parse it fully but collect its problems apart from the file's: if it is valid, return it with `enabled=False` and its patterns; if not, add one warning `disabled rule '<name>' in <file> has errors: <problems joined by '; '>` and return it with `enabled=False`, no patterns, and `broken=True`. Set `raw=copy.deepcopy(r)` on every `RuleDef`.
  - `_load_rule_files()`: for a marker, pop the earlier rule; if none, add the warning and skip; if the marker enables a `broken` rule, add the warning `cannot switch on '<name>': the rule has errors` and keep it off; else `merged = dataclasses.replace(old, enabled=marker.enabled, is_marker=True, raw=marker.raw, source_file=marker.source_file, overrides=old)`. For a full rule, set `r.overrides = old`. Keep the existing override warning for full rules only.
  - `load_rules_dir()`: sort key puts `local/overrides.yaml` last: `(0 if remote, 2 if p.name == OVERRIDES_FILE_NAME and p.parent == root / "local", else 1, str(p))`. Set `rs.all_rules = list(by_name.values())`, `rs.rules = [r for r in rs.all_rules if r.enabled]`.

- [ ] **Step 4:** Run the new tests: PASS. Run the full suite: same baseline failures, nothing new.
- [ ] **Step 5:** Commit: `git commit -am "Rule loader: keep disabled rules and support enable/disable markers"`

---

### Task 2: Rule file write helpers

**Files:**
- Modify: `pii_sanitizer.py` — section "Rule files" next to `append_rule_to_file()`
- Test: `tests/test_core.py` — new class `RuleWriteTests`

**Interfaces:**
- Consumes: Task 1 fields.
- Produces:
  - `rule_kind(rule: RuleDef) -> str` — one of `"bundled"`, `"remote"`, `"saved"`, `"override"`, `"hand-edited"`, from `rule.source_file` (`bundled/` prefix; `remote/` prefix; `local/promoted_rules.yaml`; `local/overrides.yaml`; anything else)
  - `raw_fingerprint(raw: dict) -> str` — 12 hex chars (Global Constraints)
  - `override_status(rule: RuleDef) -> Optional[str]` — `None` (not a copy, or original same), `"changed"`, `"removed"`; markers always `None`
  - `update_rule_file(path: Path, rules_root: Path, change: Callable[[List[dict]], List[dict]]) -> None` — reads (missing file = `{"version": 1, "recognizers": []}`), applies `change` to the recognizer list, validates, atomic write. Raises `RuleError` on bad existing YAML or failed validation.
  - `set_rule_enabled(rules_root: Path, rule: RuleDef, enabled: bool) -> None` — saved: set `enabled` in promoted_rules.yaml. override: set `enabled` on the overrides entry; if the entry is a marker and `enabled == rule.overrides.raw.get("enabled", True)`, remove the marker. bundled/remote: add marker `{name, enabled}`. hand-edited: raise `RuleError("hand-edited rule")`.
  - `override_copy(rule: RuleDef) -> dict` — deep copy of the original's `raw` (`rule.overrides.raw` for a marker, else `rule.raw`); if it has `wordlist`, drop it and set `deny_list` to `rule.deny_list` (the loaded values, merged with any inline `deny_list`); set `metadata.original_sha = raw_fingerprint(<original raw>)`; keep the marker's `enabled` if the rule is a marker.
  - `save_rule(rules_root: Path, rule: RuleDef, new_raw: dict) -> None` — saved and override rules: replace the entry named `rule.name` in their own file (a new name is allowed for saved rules; refuse with `RuleError` if the new name already exists in that file). bundled/remote/marker: upsert `new_raw` into overrides.yaml.
  - `delete_rule(rules_root: Path, rule: RuleDef) -> None` — saved only.
  - `restore_original(rules_root: Path, rule: RuleDef) -> None` — override only; removes the entry from overrides.yaml.
  - `append_rule_to_file(path, rule)` keeps its signature and now calls `update_rule_file`.

- [ ] **Step 1: Write the failing tests** (temp root, load with `load_rules_dir`, act, reload, assert):

```python
def test_disable_and_enable_remote_rule_writes_then_removes_marker(self):
    ps.set_rule_enabled(root, rule("remote_one"), False)
    self.assertEqual(recs(root / "local/overrides.yaml"), [{"name": "remote_one", "enabled": False}])
    ps.set_rule_enabled(root, rule("remote_one"), True)   # rule() reloads
    self.assertEqual(recs(root / "local/overrides.yaml"), [])

def test_disable_saved_rule_sets_flag_in_place(self): ...       # enabled: false in promoted_rules.yaml
def test_delete_last_saved_rule_keeps_valid_empty_file(self):
    ps.delete_rule(root, rule("manual_hostname_x"))
    self.assertEqual(recs(root / "local/promoted_rules.yaml"), [])
    self.assertEqual(ps.load_rules_dir(root).errors, [])

def test_invalid_edit_leaves_file_unchanged(self):
    before = path.read_bytes()
    with self.assertRaises(ps.RuleError):
        ps.save_rule(root, r, {**r.raw, "patterns": ["("]})
    self.assertEqual(path.read_bytes(), before)

def test_broken_yaml_file_is_not_overwritten(self):
    path.write_text("recognizers: [", "utf-8")
    with self.assertRaises(ps.RuleError):
        ps.set_rule_enabled(root, r, False)
    self.assertEqual(path.read_text("utf-8"), "recognizers: [")

def test_override_copy_inlines_wordlist(self):
    c = ps.override_copy(rule("remote_wordlist"))       # remote wordlist file: contoso\nexample
    self.assertNotIn("wordlist", c)
    self.assertEqual(sorted(c["deny_list"]), ["contoso", "example"])

def test_override_copy_keeps_json_keys_without_generated_patterns(self):
    c = ps.override_copy(rule("remote_json"))          # json_keys: [password], no patterns
    self.assertEqual((c["json_keys"], c.get("patterns")), (["password"], None))

def test_override_status_changed_and_removed(self):
    # copy saved with original_sha; change the remote rule -> "changed"; delete it -> "removed"

def test_restore_original_removes_copy(self): ...
def test_saved_rule_rename_collision_refused(self): ...
def test_marker_matches_name_with_spaces_and_dots(self):
    ps.set_rule_enabled(root, rule("Contoso Hosts.v2"), False)
    self.assertNotIn("Contoso Hosts.v2", [r.name for r in ps.load_rules_dir(root).rules])
```

- [ ] **Step 2:** Run `python -m unittest tests.test_core.RuleWriteTests -v`. Expected: FAIL (missing names).
- [ ] **Step 3:** Implement the functions above. `update_rule_file` writes with `yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)` to `path.with_suffix(".tmp")`, then `os.replace`. It refuses (`RuleError`) a `path` whose name is not `promoted_rules.yaml` or `overrides.yaml`, or whose parent is not `rules_root / "local"`.
- [ ] **Step 4:** Run the new tests: PASS. Full suite: baseline only.
- [ ] **Step 5:** Commit: `git commit -am "Rule files: validated atomic writes for enable, edit, delete, restore"`

---

### Task 3: Saved manual rules keep their source pattern

**Files:**
- Modify: `pii_sanitizer.py` — `ManualRule.to_rule_yaml()`, new helpers below
- Test: `tests/test_core.py` — extend `RuleDetailsTests`

**Interfaces:**
- Produces:
  - `ManualRule.rule_name -> str` property (the saved name; `to_rule_yaml()` uses it)
  - `to_rule_yaml()` adds `"metadata": {"manual": {"match_type": <type>, "pattern": <pattern>}}`
  - `manual_source(rule: RuleDef) -> Optional[Tuple[str, str]]` — `(match_type, pattern)` from `raw["metadata"]["manual"]`, else parsed from the description `Promoted from manual <type> rule: <pattern>`, else `None`
  - `rule_details()` shows `wildcard: <pattern>` (or `exact:` / `regex:`) instead of the regex when `manual_source()` returns a value

- [ ] **Step 1: Write the failing tests:**

```python
def test_saved_rule_metadata_round_trip(self):
    y = ps.ManualRule("wildcard", "*contoso*", "ORGANIZATION").to_rule_yaml()
    self.assertEqual(y["metadata"], {"manual": {"match_type": "wildcard", "pattern": "*contoso*"}})
    # write with append_rule_to_file to a temp promoted_rules.yaml, load, then:
    self.assertEqual(ps.manual_source(r), ("wildcard", "*contoso*"))
    self.assertEqual(rs.warnings, [])          # recognizer-level metadata does not warn

def test_manual_source_from_old_description(self):
    r = ps.RuleDef("n", "E", description="Promoted from manual exact rule: contoso", raw={})
    self.assertEqual(ps.manual_source(r), ("exact", "contoso"))

def test_details_prefer_the_original_pattern(self):
    self.assertEqual(ps.rule_details(r)[0:2], [<description>, "wildcard: *contoso*"])
```

- [ ] **Step 2:** Run them: FAIL.
- [ ] **Step 3:** Implement. In `rule_details()`, when `manual_source()` returns a value, emit `f"{type}: {pattern}"` and skip the `regex:` and `values:` lines.
- [ ] **Step 4:** Run: PASS; full suite: baseline only. Update the existing test `test_details_show_description_regex_and_values` only if its expected output changes.
- [ ] **Step 5:** Commit: `git commit -am "Saved rules: keep the original manual pattern in metadata"`

---

### Task 4: Rule edit form

**Files:**
- Modify: `pii_sanitizer.py` — pure helper `build_edited_raw()` near the write helpers; `RuleEditDialog` class in the GUI section (next to `SettingsDialog`)
- Test: `tests/test_core.py` — `RuleEditTests` (pure) and GUI tests in a new `RulesManagerGuiTests` class (same fixture as `MainWindowGuiTests`)

**Interfaces:**
- Consumes: `manual_source()`, `ManualRule`, `save_rule()`, `override_copy()`, `rule_kind()`.
- Produces:
  - `build_edited_raw(base_raw: dict, *, entity: str, score: float, case_sensitive: bool, manual: Optional[Tuple[str, str]] = None, patterns: Sequence[str] = (), values: Sequence[str] = ()) -> dict`
    - With `manual`: start from `ManualRule(type, pattern, entity, not case_sensitive).to_rule_yaml()`, keep `base_raw["enabled"]` if present, set `score`. The result has the new name.
    - Without: copy `base_raw`; set `entity`, `score`, `case_sensitive`; set `patterns` to the list of strings, but keep each existing pattern dict (name, score) whose `regex` is unchanged; set `deny_list` to `values` (remove the key when empty). Leave `context`, `validator`, `json_keys`, `json_key_contains`, `description`, `metadata` as they are.
  - `RuleEditDialog(parent, rule: RuleDef, rules_root: Path, entities: Sequence[str])`; `.exec()` returns Accepted only after `save_rule()` succeeded. For bundled, remote and marker rules, the dialog edits `override_copy(rule)`. If the copy dropped a `wordlist`, it shows: `This copy no longer follows changes to the original word list.`
  - Widgets the tests use: `ed_entity` (QComboBox, editable), `ed_score` (QDoubleSpinBox, range 0.01–1.0), `ed_case` (QCheckBox), `ed_type` + `ed_pattern` (manual rules only), `ed_patterns` and `ed_values` (QPlainTextEdit, one per line; other rules), `ed_sample` (QPlainTextEdit) and `ed_result` (QLabel) for the test box, `btn_save`.

- [ ] **Step 1: Write the failing tests:**

```python
def test_build_edited_raw_manual_renames(self):
    base = ps.ManualRule("wildcard", "*contoso*", "ORGANIZATION").to_rule_yaml()
    new = ps.build_edited_raw(base, entity="ORGANIZATION", score=0.95, case_sensitive=False,
                              manual=("wildcard", "*contoso-labs*"))
    self.assertEqual(new["name"], ps.ManualRule("wildcard", "*contoso-labs*", "ORGANIZATION").rule_name)

def test_build_edited_raw_keeps_unshown_fields(self):
    base = {"name": "n", "entity": "HOSTNAME", "context": ["host"], "validator": "luhn",
            "patterns": [{"name": "p1", "regex": r"\bcontoso\b", "score": 0.7}]}
    new = ps.build_edited_raw(base, entity="HOSTNAME", score=0.9, case_sensitive=False,
                              patterns=[r"\bcontoso\b", r"\bexample\b"])
    self.assertEqual(new["context"], ["host"]); self.assertEqual(new["validator"], "luhn")
    self.assertEqual(new["patterns"][0], {"name": "p1", "regex": r"\bcontoso\b", "score": 0.7})

# GUI
def test_edit_dialog_invalid_regex_stays_open(self):   # ed_patterns "(" -> btn_save -> file unchanged, dialog visible
def test_edit_dialog_test_box_shows_matches(self):     # ed_sample "host contoso-01" -> ed_result contains "contoso-01"
def test_cancel_edit_copy_writes_nothing(self):        # remote rule, reject() -> overrides.yaml does not exist
```

- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement. `save_rule()` does all validation. On `RuleError`, show its text in `QMessageBox.warning` and keep the dialog open. Tests patch `QMessageBox.warning`.
- [ ] **Step 4:** Run: PASS; full suite: baseline only.
- [ ] **Step 5:** Commit: `git commit -am "Rules: edit form for saved rules and override copies"`

---

### Task 5: Rules manager window on the Rules chip

**Files:**
- Modify: `pii_sanitizer.py` — new `RulesManagerDialog`; `MainWindow.show_rule_report` opens it; `.gitignore` (add `rules/local/overrides.yaml`); `README.md` section "Rules layout" (one paragraph on the window and `overrides.yaml`)
- Test: `tests/test_core.py` — `RulesManagerGuiTests`

**Interfaces:**
- Consumes: everything above; `MainWindow.reload_rules()`, `MainWindow._update_rules_badge()`, `engine.rules_root`, `engine.ruleset`.
- Produces: `RulesManagerDialog(parent: MainWindow)` with `table` (QTableWidget, columns `On, Entity, Name, Source, Matches, Actions`), `filter_text` (QLineEdit), `filter_source` (QComboBox: `All, saved, override, bundled, remote, hand-edited`), `refresh()`.
  - Source column text: the `rule_kind()`; for overrides `override of <kind of rule.overrides>`, plus ` (original changed)` / ` (original removed)` from `override_status()`.
  - Matches column: first line of `rule_details()` that is not the description; tooltip: all lines.
  - Actions per kind as in the spec table. Hand-edited rows: checkbox disabled, tooltip `Edit this file by hand: <source_file>`.
  - Every action calls the Task 2 helper, then reloads synchronously: `rs = parent.engine.reload_rules()`, `parent._update_rules_badge(rs)`, `self.refresh()`, status bar text from Global Constraints. A `RuleError` shows in `QMessageBox.warning` and changes nothing.
  - Delete and Restore confirm with `QMessageBox.question` (texts from the spec).
  - Below the table: errors and warnings from `rs.errors` / `rs.warnings`, as the old report showed them.

- [ ] **Step 1: Write the failing tests** (engine `rules_root` points at a temp root with a bundled-off fixture: patch `ps.BUNDLED_RULES` with one small rule):

```python
def test_chip_opens_manager(self):         # w.show_rule_report() with exec patched -> RulesManagerDialog built, row count == len(rs.all_rules)
def test_uncheck_bundled_rule_drops_active_count(self):
    before = len(w.engine.ruleset.rules)
    dlg.table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
    self.assertEqual(len(w.engine.ruleset.rules), before - 1)
    self.assertIn("Re-analyze", w.statusBar().currentMessage())
def test_hand_edited_row_is_read_only(self):
def test_delete_saved_rule_after_confirm(self):   # question -> Yes; row gone; file has recognizers: []
def test_filter_by_source(self):
def test_open_before_engine_load(self):          # fresh MainWindow, engine never started: dialog opens; uncheck works
```

- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement. Block the table's `itemChanged` signal while `refresh()` fills rows. Remove the old text-report body of `show_rule_report`.
- [ ] **Step 4:** Run: PASS; full suite: baseline only.
- [ ] **Step 5: Manual check.** Launch the app (`python3 pii_sanitizer.py`), click the Rules chip, switch off one bundled rule, edit one saved rule, restore the bundled rule. Confirm `rules/local/overrides.yaml` appears and then holds `recognizers: []`.
- [ ] **Step 6:** Commit: `git commit -am "Rules chip opens the rules manager window"`
