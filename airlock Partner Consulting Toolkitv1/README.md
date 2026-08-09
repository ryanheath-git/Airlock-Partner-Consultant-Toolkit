# Airlock Partner Consulting Tool Kit

A local, browser-based Python code runner. Write or paste Python in a
browser tab, run it, compile it into a standalone Windows `.exe`, scan
the result on VirusTotal, or run your own Airlock Digital scripts —
all served from a small Flask app running on your own machine.

**This app is designed to run only on localhost, for a single local user.
It is not meant to be exposed to a network or the internet — see
[Security](#security) below.**

## Features

- **Editor tab** — paste Python code, run it, see stdout/stderr/exit
  code in the Output panel.
- **Compile to .exe** — bundles the code with PyInstaller into a
  timestamped standalone executable (`script_YYYYMMDD_HHMMSS.exe`),
  downloadable from the browser.
- **VirusTotal upload** — after a successful compile, upload the `.exe`
  for scanning with one button, then open the results in a new tab
  with a second button once the upload completes.
- **Status panel** — a permanently visible panel at the bottom of the
  Editor and Scripts tabs showing compile/run progress, results, and
  errors, with larger, easier-to-read text than a slim status line.
- **Scripts tab** — run your own local Python scripts with
  command-line arguments (e.g. `report.py --user jdoe --verbose`),
  with autocomplete over the scripts in your configured folder, and a
  configurable execution timeout (default 120s) for longer-running
  scripts.
- **GitHub sync** — optionally sync `.py` files from a GitHub repo into
  your local script folder, automatically on startup or on demand.
- **Custom Widgets tab** — purpose-built tools beyond the code runner.
  The first widget, **Timed Audit Mode**, moves selected Airlock Digital
  agents from one policy group into another (e.g. enforcement → audit)
  for a set duration, then automatically moves them back — even across
  an app restart, since sessions are persisted to disk and any overdue
  revert is caught up on the next launch. Failed reverts are retried
  automatically rather than silently dropped. Sessions can also be
  reverted early from the widget.
- **Settings tab** — a card-based layout (VirusTotal, Airlock Digital,
  Script folder & execution, GitHub sync) so more options are visible
  at once. Store your VirusTotal / Airlock Digital API keys, tenant,
  and port, copy any saved key to the clipboard for use as a script
  argument, set the script folder path and timeout, and configure
  GitHub sync — all stored locally.

## Requirements

- Python 3.9+
- Windows (for the `.exe` compile feature — PyInstaller builds for
  whatever OS it runs on, so compiling only produces a real `.exe` if
  run on Windows)

## Setup

```bash
git clone <your-repo-url>
cd <repo-folder>
pip install -r requirements.txt
python app.py
```

Then open **http://localhost:5000** in your browser.

**After pulling changes or replacing files, fully stop the running
server (Ctrl+C) and start it again** — Flask's dev server does not
hot-reload, so edits won't take effect until it's restarted. If a
server seems "stuck" on old behavior, check for a leftover process
still bound to port 5000 (e.g. `netstat -ano | findstr :5000` on
Windows) and kill it before restarting.

## Configuration

All settings are managed from the **Settings** tab in the app itself
and stored in a local `config.json` file created next to `app.py` on
first save. This file is git-ignored — it never gets committed.

| Setting | Purpose |
|---|---|
| VirusTotal API key | Enables the "Upload to VirusTotal" button after compiling; available to scripts as `VT_API_KEY` |
| Airlock Digital API key | Used by the Timed Audit Mode widget, and available to your scripts as the `AIRLOCK_API_KEY` env var |
| Airlock Digital tenant | Your Airlock server hostname; used to build the API URL (`https://<tenant>:<port>`) and available to scripts as `AIRLOCK_TENANT` |
| Airlock Digital port | REST API port on your Airlock server; defaults to 3129 (Airlock's documented default) if left blank |
| Script folder | Local folder the Scripts tab lists/runs scripts from |
| Script execution timeout | How long (seconds) a script may run before it's stopped; default 120 |
| GitHub sync | Optionally pulls `.py` files from a repo into the script folder |

## Security

This app executes arbitrary Python code and, once compiled,
arbitrary executables — with your full local user permissions. Keep
this in mind:

- Runs bound to `127.0.0.1` only — do **not** change this to `0.0.0.0`
  or expose port 5000 to your network/internet. Anyone who could reach
  it could run arbitrary code on your machine.
- `config.json` stores API keys in **plaintext**. It's git-ignored by
  default; don't commit it, screenshot it, or share it.
- The Settings tab lets you copy a saved key to the clipboard — the
  real key value is sent to your own browser on request for that
  purpose, never anywhere else.
- Files uploaded to VirusTotal become visible to other VirusTotal
  users/vendors once scanned — don't upload anything containing
  secrets or proprietary code you don't want potentially exposed.
- Scripts run from the Scripts tab (local or synced from GitHub) run
  with your full user permissions — only point the script folder /
  GitHub sync at sources you trust.
- Timed Audit Mode moves real endpoints between real Airlock Digital
  policy groups — double-check the source/destination groups and agent
  selection before starting a session. `audit_sessions.json` tracks
  in-progress sessions locally so scheduled reverts survive an app
  restart; it's git-ignored since it's runtime state, not app source.

## Project structure

```
.
├── app.py                 # Flask app — all backend routes
├── requirements.txt
├── templates/
│   └── index.html         # Single-page frontend (editor, scripts, widgets, settings)
├── .gitignore
├── config.json             # created at runtime — git-ignored
├── builds/                 # compiled .exe output — git-ignored
├── api_scripts/            # local/synced scripts folder — git-ignored
└── audit_sessions.json     # Timed Audit Mode session state — git-ignored
```
