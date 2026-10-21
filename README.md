# PII Shield

PII Shield removes personal and sensitive data from text before you send the text to an LLM.
It replaces each sensitive value with a token, for example `<HOSTNAME_1>`. When the LLM
replies, PII Shield puts the original values back.

All processing is local. PII Shield uses Microsoft Presidio and a local spaCy model. The app
makes only two kinds of network requests: GitHub requests (the rules sync and the app version
check) and a Presidio version check on PyPI. All of them run at startup, and you can also
start the rules sync manually. PII Shield never sends prompt text. Offline mode turns off all
network access.

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

`keyring` is optional. With `keyring`, PII Shield stores the GitHub token in the OS
credential store. Without `keyring`, PII Shield stores the token in plain text in
`config.json`.

## Windows build

Each release on GitHub has a portable Windows build, `PII-Shield-<version>-win64.zip`. It needs
no Python and no other install:

1. Download the zip from the **Releases** page and unzip it to a folder you can write to. Do not
   use `Program Files`.
2. Run `PII-Shield\PII-Shield.exe`. PII Shield stores `config.json`, `rules/` and `backups/`
   next to the exe.

The exe is not code-signed, so Windows SmartScreen can show a warning on first start.

The exe has no console. To see the output of a command-line option, add `--log-file`:

```powershell
.\PII-Shield.exe --self-test --log-file self-test.log
```

To update the Windows build, the app downloads the new release zip and checks its SHA-256. It
then closes, replaces `PII-Shield.exe` and `_internal\`, and starts again. Your settings and
rules stay. For this to work, `app/version.json` in the rules repo must contain
`windows_zip_url` and `windows_zip_sha256`. Each release includes a `version.json` with these
fields, ready to copy.

To build the zip, push a `v<version>` tag. The workflow in `.github/workflows/build-windows.yml`
runs the tests, builds with `packaging/pii_shield.spec`, smoke-tests the exe and publishes the
release.

## Running the app

```bash
python pii_sanitizer.py                          # start the GUI
python pii_sanitizer.py --validate-rules DIR     # validate a rules folder and exit
python pii_sanitizer.py --version
python pii_sanitizer.py --debug                  # verbose logging
python pii_sanitizer.py --self-test              # load the engine, analyze a sample, exit
python pii_sanitizer.py --log-file FILE          # write console output to FILE
```

The GUI has five tabs:

1. **Input & Review** — paste or load text, then click **Analyze PII & Sensitive Data**.
   Enable or disable each finding. Add manual rules for values the engine did not find.
2. **Sanitize** — click **Generate Sanitized Prompt**, then copy the clean text into your LLM.
3. **Restore** — paste the LLM reply and click **Restore Original Values**.
4. **Session Map** — see the token-to-value map. Export it or import it to continue a
   session later.
5. **Log** — see engine and sync messages. The log never contains detected values or
   prompt text.

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
overrides a remote rule, and both override a bundled rule.

After you change a file in `github-repo-template/rules/`, run `python tools/bundle_rules.py`
to update the bundled copy. A test fails if the two copies differ.

PII Shield writes these files in `rules/local/` from the GUI:

- `promoted_rules.yaml` — manual rules that you save with **Save to Local Rules**.
- `allow_list.yaml` — values that you add to the allow list.

`rules/local/local_rules.yaml` is an example local rule. It is disabled.

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

A rule needs at least one of `patterns`, `deny_list` or `wordlist`. Other fields are
`context`, `case_sensitive`, `validator` (`luhn`, `israeli_id`, `ipv4`, `private_ipv4`) and
`enabled`. The header of `github-repo-template/rules/rules.yaml` gives the full schema.

If a rule file has an error, PII Shield skips only that file. The other files still load.

### Shared rules on GitHub

`github-repo-template/` is a starter for the shared rules repo:

| Path | Purpose |
|---|---|
| `rules/` | Rule files and wordlists. The app syncs this folder into `rules/remote/`. |
| `app/version.json` | Latest app version and the SHA-256 of the script, for update checks. |
| `Publish-AppVersion.ps1` | Writes `app/version.json` from `app/pii_sanitizer.py`. |
| `.github/workflows/validate-rules.yml` | CI. Validates the rules and checks the hash in `version.json`. |

To connect the app, click **Update Rules** on the toolbar. Enter the contents API URL of the
rules folder, for example `https://api.github.com/repos/org/repo/contents/rules`, the branch
and a token. Then click **Check & Pull Updates**.

The sync downloads only `.yaml`, `.yml`, `.json`, `.txt`, `.lst` and `.csv` files. It checks
the git blob SHA of each file and validates all rules in a staging folder. If any check
fails, the sync changes nothing.

### Updates at startup

After the engine loads, PII Shield runs three checks in the background:

- **Rules sync.** If a rules repo is set, PII Shield pulls the rules with the same checks as a
  manual sync. If the pull fails, the app keeps the current rules and writes the error to the
  **Log** tab.
- **App version check.** If a rules repo is set, PII Shield reads `app/version.json` from it.
  If that file lists a newer version, PII Shield asks if you want to install it. The download
  must match the SHA-256 in `version.json`, and PII Shield backs up the current script first.
  Restart the app to use the new version.
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
