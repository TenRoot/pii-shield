# PII Shield

PII Shield removes personal and sensitive data from text before you send the text to an LLM.
It replaces each sensitive value with a token, for example `<HOSTNAME_1>`. When the LLM
replies, PII Shield puts the original values back.

All processing is local. PII Shield uses Microsoft Presidio and a local spaCy model. The full
Windows build also uses a local Hebrew name model. The app
makes only two kinds of network requests: GitHub requests (the rules sync and the app version
check) and a Presidio version check on PyPI. All of them run at startup, and you can also
start the rules sync manually. PII Shield never sends prompt text. Offline mode turns off all
network access.

## How detection works

Microsoft Presidio runs all detection. It sends the text to each detector below and collects
the results. All detectors run locally, in the same analysis.

| Detector | Runs on | Finds | Build |
|---|---|---|---|
| **Presidio built-in recognizers** | all text | email, phone, IP address, credit card (with a checksum test), IBAN, URL, US SSN, crypto wallet, MAC address | small and full |
| **spaCy** (`en_core_web_lg`, through Presidio) | all text | person names, organizations and places in English | small and full |
| **DictaBERT NER** (Hebrew model, through Presidio) | only lines with Hebrew letters | person names, organizations and places in Hebrew | full only |
| **PII Shield rules and word lists** | all text | Israeli ID (ת.ז), Hebrew street addresses, host names, user names, keys and secrets, and your own rules | small and full |

To select which Presidio entities to find, open **Settings > Detection**. The review table
shows the source of each finding: Presidio (built-in recognizers and spaCy), Custom rule,
Hebrew NER, Manual, Propagated or Session map.

**English text:** the small build and the full build give the same result. Presidio, spaCy and
the rules find the values.

**Hebrew text, small build:** only the rules, the word lists and the Presidio built-in
recognizers find values. spaCy does not know Hebrew, so its findings on Hebrew text are often
wrong.

**Hebrew text, full build:** the Hebrew model finds the names. spaCy still runs on Hebrew
lines, but its findings there are often wrong and too long. So PII Shield drops each spaCy
finding on Hebrew words that a Hebrew model finding already covers. PII Shield keeps a spaCy
finding on a Hebrew word that no Hebrew model finding covers, because the Hebrew model misses
some surnames.

**Long text:** spaCy cannot read more than 1,000,000 characters at a time. PII Shield analyzes
a long text, for example a large PDF, in parts of 100,000 characters. The parts overlap by 2,000
characters, so PII Shield finds a value that crosses a cut.

**After the detectors:** when two findings overlap, PII Shield keeps one of them, normally the
longer one. Then it finds every other copy of each detected value in the text and masks those
copies too.

## Features

- You review every detection in an editable table before PII Shield masks the text.
- The same value always gets the same token for the full session. `SRV-DC01` and `srv-dc01`
  share one token by default.
- You add custom recognizers as YAML or JSON rule files. Click **Reload Local Rules** to load
  changes without a restart.
- A team can share rules through a private GitHub repo. PII Shield checks the integrity of
  each downloaded file and validates all files before it applies them.

## Setup

CI uses Python 3.12. The local test run uses Python 3.13.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

The spaCy model gives name, location and organization detection. PII Shield never downloads
a model by itself. If `en_core_web_lg` is not installed, PII Shield uses the first installed
model from this list: `en_core_web_trf`, `en_core_web_md`, `en_core_web_sm`. If no model is
installed, PII Shield runs in regex-only mode with no name detection.

spaCy reads log lines as prose, so it tags field names and values such as `arn` or
`COMMAND=/bin/ls` as PERSON or ORGANIZATION. To stop this, set **Settings > Detection > Turn
off spaCy NER when the input looks like log lines** (`engine.skip_ner_on_logs` in
`config.json`). The option is off by default. When it is on and 60% or more of the non-blank
lines look like log lines, PII Shield drops all spaCy findings for that input. A line looks like
a log line when it starts with a timestamp, a syslog priority or a log level, holds a JSON
object, or has two or more `key=value` pairs. The rules still run, so user names and host names
in log fields are still masked. Prose input keeps spaCy NER.

`keyring` is optional. With `keyring`, PII Shield stores the GitHub token in the OS
credential store. Without `keyring`, PII Shield stores the token in plain text in
`config.json`.

## Windows build

Each release on GitHub has two portable Windows builds. Neither needs Python or another install:

- `PII-Shield-<version>-win64.zip`: the standard (small) build.
- `PII-Shield-<version>-win64-full.zip`: the full build. See [Full build](#full-build).

To install a build:

1. Download the zip from the **Releases** page and unzip it to a folder you can write to. Do not
   use `Program Files`.
2. Run `PII-Shield\PII-Shield.exe`. PII Shield stores `config.json`, `rules/` and `backups/`
   next to the exe.

The exe is not code-signed, so Windows SmartScreen can show a warning on first start.

The exe has no console. To see the output of a command-line option, add `--log-file`:

```powershell
.\PII-Shield.exe --self-test --log-file self-test.log
```

To update the Windows build, the app downloads the new release zip of the same build and checks
its SHA-256. It then closes, replaces `PII-Shield.exe` and `_internal\`, and starts again. Your
settings and rules stay.

To build the zips, push a `v<version>` tag. The workflow in `.github/workflows/build-windows.yml`
builds the small and the full build in two parallel jobs. Each job runs the tests, builds with
`packaging/pii_shield.spec`, smoke-tests the exe and uploads its zip. When both jobs succeed, a
publish job creates the release with both zips. If one job fails, the workflow publishes
nothing. The publish job then commits `version.json` at the root of this repo. That file names
the new version, the script SHA-256, and the URL and SHA-256 of each zip, so every install finds
the update.

Before you push the tag, set `__version__` and stamp `github-repo-template/app/version.json`
with the SHA-256 of `pii_sanitizer.py`. A tag build stops if they do not match. A manual run
(**Run workflow**) only shows a warning: it builds both zips and uploads them as artifacts, but
it publishes no release.

### Full build

The full build is the small build with two additions:

- **Hebrew name detection.** A Hebrew model finds person names, organizations and places in
  Hebrew text. PII Shield masks them the same way as English findings. The review table shows
  `Hebrew NER` as their source. To turn the model off, clear **Settings > Detection > Hebrew
  name detection (DictaBERT NER)**. The Hebrew model does not find all names. It misses some
  names, mostly a surname alone. Always check the review table before you send the text.
- **Bundled Tesseract.** The full build reads scanned PDF pages with no separate Tesseract
  install. The bundled Tesseract has Hebrew and English data.

The full zip is approximately 665 MB. The small zip is approximately 471 MB. Both builds run
locally. The Hebrew model and Tesseract make no network calls.

A full install updates only to the full zip of the new version. If a release has no full zip,
the app does not update and shows `No full build is available for this version.` A small
install updates to the small zip.

The Hebrew model is DictaBERT NER (`dicta-il/dictabert-ner`) by Dicta, under the
[CC BY 4.0 license](https://creativecommons.org/licenses/by/4.0/). The full build uses the
8-bit ONNX copy from `onnx-community/dictabert-ner-ONNX` with no changes.
`_internal\models\dictabert-ner\LICENSE.txt` has the credit.
`_internal\THIRD_PARTY_NOTICES.txt` lists the licenses of the model, onnxruntime, tokenizers,
Tesseract and the Tesseract libraries, and holds their full license texts.

To use the Hebrew model from source:

```bash
pip install -r requirements-full.txt
python packaging/fetch_full_assets.py --model-only --install-dev
```

The script downloads the three model files from a fixed revision and checks the SHA-256 of
each file. `--install-dev` copies the model to `models/dictabert-ner/` next to
`pii_sanitizer.py`. From source, OCR uses the Tesseract installed on your computer.

To build the full zip on Windows, run the script without `--model-only`. The script then also
downloads Tesseract into `build-assets/`. Then build with `PII_SHIELD_FLAVOR=full`:

```powershell
python packaging/fetch_full_assets.py --dest build-assets
$env:PII_SHIELD_FLAVOR = 'full'
pyinstaller --noconfirm packaging/pii_shield.spec
```

## Running the app

```bash
python pii_sanitizer.py
```

The GUI has five tabs:

1. **Input & Review** — paste or load text, then click **Analyze PII & Sensitive Data**.
   Enable or disable each finding. Add manual rules for values the engine did not find.
   **Group same values** (on by default) shows one row for each value, with a **Count** column
   in place of **End**. **Start** shows the first copy. A change in a grouped row (enable,
   entity type, token) applies to every copy of the value. A partly checked box means that only
   some copies are enabled. Click a selected row again to go to the next copy in the text. To
   change one copy only, clear **Group same values**.
2. **Sanitize** — click **Generate Sanitized Prompt**, then copy the clean text into your LLM.
   A text that is too long for the LLM can go in parts:
   - Set **Split into parts of** (default 50,000 characters) and click **Split**. A cut falls
     after a blank line, else after a line break, else after a space. A token such as
     `<PERSON_1>` is never cut.
   - **Part headers** starts each part with a line such as `--- Part 2 of 7 ---`.
   - **Copy Part** copies the selected part and then selects the next part.
   - **Export Full Text…** writes the sanitized text to one `.txt` file. **Export Parts…** writes
     `sanitized_part_1_of_7.txt` and the other parts to a folder that you select. The file names
     contain only numbers. The app asks before it overwrites a file.

   Exports contain only the sanitized text. All parts belong to the same session, so the same
   value has the same token in every part, and **Restore** works on replies to any part.
   Use `.txt`, not PDF: a PDF can keep PII in its file properties, and its text extraction can
   break tokens.
3. **Restore** — paste the LLM reply and click **Restore Original Values**.
4. **Session Map** — see the token-to-value map. Export it or import it to continue a
   session later.
5. **Log** — see engine and sync messages. The log never contains detected values or
   prompt text.

### PDF files

**Load file** opens PDF files. The app reads text pages directly. Each page starts with a
header line, for example `--- page 1 ---`. The text is read on your computer only. The app
makes no network call.

The app also reads filled form fields and notes (for example "Fill & Sign" text). It
writes their values under the page text, after a `[form fields and notes]` line, one value
per line. If the app cannot read them, the page line says `(form fields or notes not read)`.

Scanned pages have no text layer. The app sends them to Tesseract (OCR) with Hebrew and
English data. Pages that are mostly an image, or whose text is unreadable, also go to OCR.
The page line then reads `--- page 2 (OCR) ---`.

If Tesseract is not installed, the app skips each scanned page. The page line says why, for
example `--- page 2 (scanned, skipped: Tesseract not installed) ---`. If a scanned page has a
little text, for example a stamp or a page number, the app keeps that text. The page line
then reads `--- page 2 (little text, image text not read: Tesseract not installed) ---`.
If Hebrew or English data is missing, OCR runs with the other language. The page line says
so.

The app looks for Tesseract in this order:

1. the path in **Settings → PDF**;
2. the bundled copy in `_internal\tesseract\` (only the full build has it);
3. `tesseract` on PATH;
4. on Windows, `C:\Program Files\Tesseract-OCR\tesseract.exe`.

To install Tesseract:

- **Windows:** run the UB Mannheim Tesseract installer. Under additional languages, select
  **Hebrew**. The app finds `C:\Program Files\Tesseract-OCR\tesseract.exe`. To use another
  location, set the path in **Settings → PDF**.
- **Debian/Ubuntu:** run `sudo apt install tesseract-ocr tesseract-ocr-heb`.

Tesseract 4.0 or later is needed. The app sends page images to Tesseract through a pipe. It
writes no temporary image files. To turn OCR off, clear **OCR scanned pages (Tesseract)** in
**Settings → PDF**.

Limits:

- The small build finds names and organizations with an English model only. In Hebrew text,
  only rules and word lists find PII. The full build also finds Hebrew names, organizations and
  places (see [Full build](#full-build)).
- The app cannot open password-protected PDFs.

### Scan a Git branch

Use the Git scan to find PII and secrets in a branch before you push it. The scan only reports.
It does not change the repo, and it does not add tokens to the session map.

1. Wait until the engine is loaded, then click **Scan Git Repo...** in tab 1.
2. Choose the repo folder. A linked worktree (`git worktree add`) also works.
3. Click **Scan**.

The scan reads:

- the added lines of every commit that is not on a remote branch yet, including lines that you
  add when you resolve a merge conflict;
- the message of each of those commits;
- staged and unstaged changes;
- untracked files that Git does not ignore.

The scan does not read:

- author and committer names and emails;
- lines that the branch does not add, because those lines are already on the remote;
- files that Git ignores.

The scan does not run `git fetch`. It compares against the remote branches as they were at
your last fetch or pull. If the repo has no remote, the scan reads every commit.

Each finding shows the source (a commit, `uncommitted` or `untracked`), the file, the line,
the entity type and the value. Double-click a row to copy `file:line`. **Copy Results** copies
the table as tab-separated text. The scan uses the **min score** value from tab 1.

To remove a false finding, right-click its row and select **Add to permanent allow-list (never
flag again)**. PII Shield adds the value to `rules/local/allow_list.yaml`. The value then leaves
the list, together with every other row that has the same value. The match ignores case and
spaces at the start and end. The next scan and the main screen do not flag the value again.
You can select many rows before you right-click. The menu can also copy the value or `file:line`.

spaCy reads code as prose and finds many false names, so the scan does not use spaCy by
default. To find names, select **Find names with spaCy (more noise)**. The rules always run.

The scan skips binary files, Git LFS objects and any file or diff part larger than 1 MB. The
**Skipped files** list shows each skipped file and the reason. When the scan skips a file, it
never shows the green "no findings" note. Check skipped files by hand. `git` must be on PATH.

The scan ignores repo settings that change the diff output (for example `diff.noprefix` or
`log.showRoot`) and `-diff` or `binary` in `.gitattributes`. It turns off filter drivers (for
example git-lfs or git-crypt) and signature checks, so the scan runs no program from the repo
config.

### Data folder

PII Shield keeps its data next to `pii_sanitizer.py`. To use a different folder, set
`PII_SHIELD_HOME`. The data folder contains:

| Path | Contents |
|---|---|
| `config.json` | Settings. Open **Settings** in the GUI to change them. |
| `rules/local/` | Your local rules. GitHub sync never changes this folder. |
| `rules/remote/` | Rules from GitHub. Each sync replaces this folder. |
| `backups/` | Backups of the script from app updates. |

Git ignores `config.json`, `backups/` and `rules/remote/`.

## Rules

### Rules layout

PII Shield loads rules in three layers:

1. **Bundled rules.** The script contains a copy of `github-repo-template/rules/`, so a fresh
   install detects hostnames, accounts, secrets and other values with an empty `rules/` folder.
2. **Remote rules** in `rules/remote/`.
3. **Local rules:** every other `.yaml`, `.yml` and `.json` file under `rules/`, including
   files in subfolders.

If two rules have the same `name`, the rule from the later layer is used. A local rule
overrides a remote rule, and both override a bundled rule. `rules/local/overrides.yaml`
(written by the Rules manager) wins over every other rule file with the same rule name.

After you change a file in `github-repo-template/rules/`, run `python tools/bundle_rules.py`
to update the bundled copy. A test fails if the two copies differ.

PII Shield writes these files in `rules/local/` from the GUI:

- `promoted_rules.yaml` — manual rules that you save with **Save to Local Rules**.
- `allow_list.yaml` — values that you add to the allow list.
- `overrides.yaml` — your changes to bundled and remote rules. Git ignores it.

`rules/local/local_rules.yaml` is an example local rule. It is disabled.

Click the Rules chip in the status bar to open the Rules manager window. It lists every rule.
You can switch rules on or off, edit them, and delete your saved rules. A change to a bundled
or remote rule goes into `overrides.yaml`, so a sync or an app update keeps it. "Restore
original" removes your change. Rules in other local files are read only. Edit those files by hand.

### Rule format

```yaml
version: 1
allow_list:            # values that PII Shield never masks (case-insensitive)
  - localhost
recognizers:
  - name: FileServers          # unique name
    entity: HOSTNAME           # UPPER_SNAKE_CASE; gives tokens like <HOSTNAME_1>
    score: 0.9
    patterns:                  # Python regular expressions
      - {name: fs, regex: '\bfs\d{2}\.contoso\.local\b'}
  - name: Customers
    entity: CUSTOMER
    wordlist: wordlists/customers.txt   # one value per line, relative to this file
```

A rule needs at least one of `patterns`, `deny_list`, `wordlist`, `json_keys` or
`json_key_contains`. Other fields are `context`, `case_sensitive`, `validator` and `enabled`.
The header of `github-repo-template/rules/rules.yaml` gives the full schema.

**Mask only the value.** If a pattern has a group named `value`, PII Shield masks only that
group. The rest of the match stays in the text, so the LLM can still read it:

```yaml
    patterns:
      - {name: kv, regex: 'password\s*=\s*(?P<value>\S+)'}   # password=<SECRET_1>
```

Manual rules of the type `regex` also accept a `value` group.

**Mask JSON fields by key name.** `json_keys` masks the value of each listed key in JSON, in
escaped JSON and in Python dicts. `json_key_contains` masks the value of every key that contains
one of the listed texts. Key matching ignores case and the separators `-`, `_`, `.` and space,
so `userName`, `user_name` and `USER-NAME` are the same key. PII Shield masks strings of 2 or
more characters and numbers of 3 or more digits. It never masks `true`, `false`, `null`, `""`
or `"-"`.

```yaml
  - name: JsonUserFields
    entity: USERNAME
    json_keys: [userName, samAccountName, owner]
    json_key_contains: [principalname]
```

**Validators.** A validator checks each match:

| Validator | Keeps a match when |
|---|---|
| `luhn` | the digits pass the Luhn checksum (card numbers) |
| `israeli_id` | the digits pass the Teudat Zehut checksum |
| `ipv4` | the value is a valid IPv4 address |
| `private_ipv4` | the value is a private, loopback or link-local IPv4 address |
| `high_entropy` | the value is a random-looking hex (32+) or base64 (40+) string |
| `not_well_known` | the value is not a built-in name such as `root`, `SYSTEM`, `Public` or `S-1-5-18` |

The bundled rules in `secrets.yaml`, `identity.yaml`, `hosts.yaml` and `json_fields.yaml` find
API tokens, credentials in URLs and command lines, session cookies, Windows SIDs, LDAP and
cloud user names, user names in home paths, and host names in syslog lines. Many of their
patterns come from [logtotal-sanitizer](https://github.com/socprime/logtotal-sanitizer) by
SOC Prime (Apache-2.0). See `NOTICE`.

`HighEntropyBlobs` in `secrets.yaml` is off by default because it also masks file hashes. To
turn it on, copy the rule to `rules/local/` and remove `enabled: false`.

If a rule file has an error, PII Shield skips only that file. The other files still load.

### Shared rules on GitHub

By default, PII Shield syncs the rules from `github-repo-template/rules` in this public repo
(`TenRoot/pii-shield`, branch `main`) and reads `version.json` from the repo root. No token is
needed. Without a token, GitHub allows 60 API requests per hour per IP address, and one sync
uses about 8.

To use your own rules repo, start from `github-repo-template/`:

| Path | Purpose |
|---|---|
| `rules/` | Rule files and wordlists. The app syncs this folder into `rules/remote/`. |
| `app/version.json` | Latest app version and the SHA-256 of the script, for update checks. Each release has a ready `version.json` with the Windows zip fields. |
| `Publish-AppVersion.ps1` | Writes `app/version.json` from `app/pii_sanitizer.py`. |
| `.github/workflows/validate-rules.yml` | CI. Validates the rules and checks the hash in `version.json`. |

To connect the app to your own repo, click **Update Rules** on the toolbar. Enter the contents
API URL of the rules folder, for example `https://api.github.com/repos/org/repo/contents/rules`,
the branch, the version path `app/version.json` and a token. Then click **Check & Pull Updates**.

The sync downloads only `.yaml`, `.yml`, `.json`, `.txt`, `.lst` and `.csv` files. It checks
the git blob SHA of each file and validates all rules in a staging folder. If any check
fails, the sync changes nothing.

### Updates at startup

After the engine loads, PII Shield runs three checks in the background:

- **Rules sync.** PII Shield pulls the rules with the same checks as a
  manual sync. If the pull fails, the app keeps the current rules and writes the error to the
  **Log** tab.
- **App version check.** PII Shield reads `version.json` from the rules repo. If that file
  lists a newer version, PII Shield asks if you want to install it. The download must match the
  SHA-256 in `version.json`. The script version backs up the current script and needs a
  restart. The Windows build installs the new release zip and restarts by itself.
- **Presidio check.** PII Shield asks PyPI for the latest `presidio-analyzer` and
  `presidio-anonymizer` versions. If a newer version exists, the status bar and the **Log** tab
  show the `pip install -U` command to run. PII Shield never installs packages itself.

To turn off the rules sync or the Presidio check, open **Settings → Behavior**. To turn off the
app version check, clear **Also check for a new application version** in the **Update Rules**
dialog. Offline mode turns off all three.

Validate rules before you push them:

```bash
python pii_sanitizer.py --validate-rules github-repo-template/rules
```
