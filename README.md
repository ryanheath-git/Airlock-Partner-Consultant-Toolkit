# Airlock Partner Consulting Tool Kit

A local, browser-based Python code runner. Write or paste Python in a
browser tab, run it, compile it into a standalone Windows `.exe`, scan
the result on VirusTotal, or run your own Airlock Digital scripts —
Also a custom widgets tab for added little applets. 
The settings tab allows you to save API keys as well as link to a github repository which you can also synch to a local folder. 
This is needed as some scripts require custom .yaml files or config.json 
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
- **Custom Widgets tab** — purpose-built tools beyond the code runner,
  shown as tiles that expand into a right-hand detail panel when
  clicked. Two widgets so far:
  - **Timed Audit Mode** moves selected Airlock Digital agents from
    one policy group into another (e.g. enforcement → audit) for a
    set duration, then automatically moves them back — even across an
    app restart, since sessions are persisted to disk and any overdue
    revert is caught up on the next launch. Failed reverts are
    retried automatically rather than silently dropped. Sessions can
    also be reverted early from the widget.
  - **ISO 27001 Compliance** assesses every Airlock policy group
    against a set of ISO/IEC 27001:2022 Annex A controls that Airlock's
    policy configuration can provide direct evidence for (currently
    A.8.7, A.8.8, A.8.9, A.8.12, A.8.15, A.8.19 — see `iso_mapping.json`
    for which ones have a real automated rule versus a manual
    placeholder). Shows a live dashboard per group plus an
    endpoint-weighted donut chart (Fully Compliant / Partially
    Compliant / Non-Compliant / Not Assessed, by percentage of managed
    endpoints, not just group count), and can generate a downloadable,
    self-contained HTML report with the same chart for client
    engagements — open it in any browser, and print to PDF from there
    if needed. The control mapping is intentionally editable, not
    hardcoded — see below.
  - **Partner Engagement Report** pulls user activity, agent counts
    (audit vs. enforcement), and license utilization across your
    partner tenants in Airlock Digital's Cloud multi-tenant
    environment — a separate API layer from the regular Airlock
    connections used elsewhere in the app, with its own admin
    credential and per-tenant Tenant ID / Directory ID pairs (each
    partner has a distinct Directory ID, so both are stored together
    per tenant rather than assuming one fixed value). Generates a
    self-contained HTML report — summary table across all tenants plus
    expandable per-tenant detail — that opens directly in a new
    browser tab.
- **Settings tab** — a card-based layout (VirusTotal, Airlock Digital,
  Script folder & execution, GitHub sync) so more options are visible
  at once. Store your VirusTotal API key, save multiple Airlock Digital
  connections (each its own tenant + port + key, switchable without
  re-entering anything), copy any saved key to the clipboard for use as
  a script argument, set the script folder path and timeout, and
  configure GitHub sync — all stored locally.

## Requirements

- Python 3.9+
- Windows (for the `.exe` compile feature — PyInstaller builds for
  whatever OS it runs on, so compiling only produces a real `.exe` if
  run on Windows)

## Setup

### Windows quick start — `run.bat`

The included `run.bat` sets everything up and launches the app in one
step, using an isolated Python virtual environment so this project's
dependencies never conflict with anything else on your machine:

1. Changes into the folder the batch file itself lives in (so it works
   no matter where you clone or move the project — no path to edit).
2. Creates a `venv\` virtual environment folder the first time it's
   run; skips this step on later runs since it already exists.
3. Activates that virtual environment.
4. Installs everything in `requirements.txt` into it via `pip install`.
5. Launches `python app.py` and keeps the window open (`pause`) so you
   can see the server log and any errors.

Just double-click `run.bat` (or run it from a terminal) each time you
want to start the app — steps 2–4 are safe to repeat and only do real
work the first time or after `requirements.txt` changes.

### Manual / cross-platform

```bash
git clone <your-repo-url>
cd <repo-folder>
pip install -r requirements.txt
python app.py
```

Then open **http://localhost:5000** in your browser.

**After pulling changes or replacing files, fully stop the running
server (Ctrl+C, or close the `run.bat` window) and start it again** —
Flask's dev server does not hot-reload, so edits won't take effect
until it's restarted. If a server seems "stuck" on old behavior, check
for a leftover process still bound to port 5000 (e.g.
`netstat -ano | findstr :5000` on Windows) and kill it before
restarting.

## ISO 27001 control mapping (`iso_mapping.json`)

This file defines which controls the ISO 27001 Compliance widget
assesses and how. It's a plain, git-tracked JSON file (not runtime
state) meant to be hand-edited per client engagement — add or remove
controls, change descriptions, or tune rule thresholds without
touching `app.py`.

Each control has an `id`, `title`/`name`, `description`, and a `rule`.
Supported rule types:

| Type | Purpose |
|---|---|
| `field_equals` | Compares one field in the policy response to a pass/partial value (e.g. `auditmode`) |
| `list_any_match` | Checks whether at least N items in a list field match a condition (e.g. an actively-enforced entry in `blocklists`) |
| `all_of` / `any_of` | Combines sub-rules (AND / OR) — used for controls needing more than one signal |
| `manual` | Marks a control as requiring manual attestation rather than automated scoring |

A control's status is always one of `meets`, `partial`, `unmet`, or
`unknown` (the field the rule depends on wasn't present in the API
response — treated distinctly from `unmet` so the report never
silently claims a control failed when the data just wasn't there to
check).

Overall compliance categorization per group (used for the endpoint-
weighted chart) is based only on controls with a real automated rule —
`manual` placeholders are excluded from that roll-up so an unconfirmed
control can't silently drag a group into "non-compliant."

Current scope: A.8.7, A.8.9, and A.8.19 have real automated rules,
confirmed against actual Airlock API responses. A.8.8, A.8.12, and
A.8.15 are `manual` placeholders pending a confirmed field mapping —
extending them, or adding more controls, is expected as this widget
matures.

## Configuration

All settings are managed from the **Settings** tab in the app itself
and stored in a local `config.json` file created next to `app.py` on
first save. This file is git-ignored — it never gets committed.

| Setting | Purpose |
|---|---|
| VirusTotal API key | Enables the "Upload to VirusTotal" button after compiling; available to scripts as `VT_API_KEY` |
| Airlock Digital connections | Multiple saved tenant+port+key combinations — see below; the active one is used by every Airlock-related widget, and is available to scripts as `AIRLOCK_API_KEY`, `AIRLOCK_TENANT`, `AIRLOCK_PORT` |
| Script folder | Local folder the Scripts tab lists/runs scripts from |
| Script execution timeout | How long (seconds) a script may run before it's stopped; default 120 |
| GitHub sync | Optionally pulls `.py` files from a repo into the script folder |

### Airlock Digital connections (multiple tenants)

The Settings tab lets you save more than one Airlock Digital connection
— useful if you work across multiple client tenants. Each connection
bundles a label, tenant, port, and API key together as one saved unit,
so an API key can never accidentally get paired with the wrong
tenant's URL. Only one connection is **active** at a time; every
Airlock-related feature (Timed Audit Mode, ISO 27001 Compliance, the
Scripts tab's env vars) always uses whichever connection is currently
active. Switching the active connection takes effect immediately, with
no restart needed.

If you're upgrading from an older version of this app that only
supported a single tenant/key, that setup is automatically migrated
into your first saved connection (labeled "Default") the next time you
start `app.py` — nothing is lost.

### Partner Engagement Report (Cloud multi-tenant API)

This widget talks to a completely different API surface than the rest
of the app — Airlock Digital's Cloud/MSP multi-tenant management
layer, not a single on-prem server. It has its own separate connection
config (Cloud base domain + admin API key, set inside the widget
itself, not the Settings tab) plus a list of partner tenants you
maintain, each with its own Tenant ID **and** Directory ID — both vary
per partner, so both are stored together per entry rather than
assuming one fixed value.

A few things worth knowing if you're extending this widget:

- Auth uses a `UserApiKey` header (not `X-ApiKey` like the on-prem
  API), plus per-call `tenantID` and `Directoryid` headers.
- Endpoints are split across at least four modules
  (`https://<base_domain>/<module>/v1/<endpoint>`) — `willard`,
  `webfe`, `policy`, and `directory` were all needed for the four data
  points this widget pulls today. There's no reliable rule for which
  module or HTTP method (GET vs. POST) a given endpoint needs — each
  one was confirmed individually against real API responses, and a
  couple of assumptions from before actual field-testing turned out
  wrong. If you add a new call, test it directly rather than pattern-
  matching from a similar-looking endpoint.
- `cloud_api_request()` in `app.py` logs every call (URL, method,
  status, response body) to the terminal — the fastest way to diagnose
  a new integration issue is to reproduce it and read that log.
- Each of the four data points (users, agent counts, audit/enforce
  split, license allocation) is collected independently — a failure in
  one shows as "Unavailable" for that piece specifically rather than
  blanking out the whole tenant's report.

## Security

This app executes arbitrary Python code and, once compiled,
arbitrary executables — with your full local user permissions. Keep
this in mind:

- Runs bound to `127.0.0.1` only — do **not** change this to `0.0.0.0`
  or expose port 5000 to your network/internet. Anyone who could reach
  it could run arbitrary code on your machine.
- `config.json` stores API keys in **plaintext**. It's git-ignored by
  default; don't commit it, screenshot it, or share it.
- The Cloud admin API key used by the Partner Engagement Report widget
  can see across **every** partner tenant it has access to — treat it
  with at least as much care as your other credentials, since it's not
  scoped to a single client the way your regular Airlock connections
  are.
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
├── run.bat                 # Windows one-step setup + launch script
├── requirements.txt
├── iso_mapping.json         # editable ISO 27001 <-> Airlock control mapping
├── templates/
│   └── index.html         # Single-page frontend (editor, scripts, widgets, settings)
├── .gitignore
├── venv/                   # created by run.bat — git-ignored
├── config.json             # created at runtime — git-ignored
├── builds/                 # compiled .exe output — git-ignored
├── api_scripts/            # local/synced scripts folder — git-ignored
└── audit_sessions.json     # Timed Audit Mode session state — git-ignored
```
