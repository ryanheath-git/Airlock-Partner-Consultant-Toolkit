# Airlock Partner Consulting Toolkit — Project Summary

Read this first in a new conversation to get up to speed quickly. It covers what's
built, why it's built the way it is, and mistakes already made once — no need to
repeat them.

## What this is

A local Flask app (`app.py` + `templates/index.html`, single-page frontend) for an
Airlock Digital partner/consultant. Runs on `127.0.0.1:5000` only, single user,
plaintext local config files (deliberate — this is a personal tool, not multi-user
or internet-facing).

Lives at `Documents\airlock-partner-consulting-toolkit` (moved up one level from an
old `airlock-partner-consulting-toolkit_Migrate\airlock-partner-consulting-toolkit`
nesting on 2026-09-04 — just a folder rename/move, no code changes involved).

## Tabs / features, in the order they were built

1. **Editor** — run/compile Python snippets, upload compiled .exe to VirusTotal.
2. **Scripts** — run local Airlock Digital scripts with env vars
   (`AIRLOCK_API_KEY`/`TENANT`/`PORT`, `VT_API_KEY`) injected from the active
   connection. Auto-detects an output file from a script's own stdout
   (`HTML report:`, `Saved:`, etc.) and offers to open it.
3. **Custom Widgets** tab, tile-list-and-detail-panel UI (click a tile on the left,
   its content opens on the right):
   - **Timed Audit Mode** — move Airlock agents to an audit group temporarily,
     auto-revert on a timer (persists across app restarts).
   - **ISO 27001 Compliance** — evaluates policy groups against a small,
     *editable* set of ISO 27001 controls (`iso_mapping.json`), some with real
     automated rules, others explicitly marked `manual` (honest placeholders,
     not guessed logic). Produces a live dashboard plus a downloadable,
     self-contained HTML report with an endpoint-weighted SVG donut chart
     (weighted by agent count, not just group count).
   - **NFR Tracking** (originally "Partner Engagement Report") — pulls user
     activity, agent counts, audit/enforce split, and license utilization
     across partner tenants in Airlock's **Cloud multi-tenant API** — a
     completely different, undocumented API surface from the on-prem REST API
     the rest of the app uses. See "Cloud API reverse-engineering" below.
     The partner tenant list is collapsible (`<details>`, collapsed by
     default) with a live summary line (e.g. "12 tenants — 8 selected") so you
     don't have to scroll a long tenant list just to generate a report;
     Select all/none and the add-tenant form stay outside it. The generated
     report uses the app's own dark color palette (`--bg`/`--panel`/`--accent`
     etc., same values as `templates/index.html`) instead of plain white/black,
     with a light-theme override for `@media print` so it doesn't waste ink.
     Alongside "Generate report" (opens the HTML report in a new tab), two
     export buttons pull the same data as **Excel** (`.xlsx` — a Summary sheet
     across all tenants plus one sheet per tenant listing its users) or
     **XML** (`.xml` — a `<PartnerEngagementReport>` document with per-tenant
     `<Users>` and explicit `<Errors>` elements, so a failed data pull for one
     tenant is called out rather than silently dropped). All three formats are
     built from `run_cloud_partner_report()` in `app.py`, so they can never
     drift out of sync with each other.
4. **Settings** tab — same tile-list-and-detail-panel UI as Custom Widgets
   (deliberately restructured to match it). Cards: VirusTotal API, Airlock API
   Settings (multi-connection manager), Script folder & execution, GitHub sync,
   **Publish to GitHub**, Logging.
   - **Publish to GitHub** is the opposite direction from GitHub sync — it
     pushes this app's own source files *out* to a repo of your choice
     (same repo as sync, or a different one) instead of pulling scripts in.
     Uses a fixed, hand-maintained file list (`GITHUB_PUBLISH_FILES` in
     `app.py`: `app.py`, `templates/index.html`, `iso_mapping.json`,
     `README.md`, `PROJECT_SUMMARY.md`, `requirements.txt`, `run.bat`,
     `.gitignore`) rather than a real `.gitignore` parser, so a secret or
     runtime file can never end up on it by accident — `config.json`,
     `cloud_config.json`, `venv/`, `builds/`, `api_scripts/`, and
     `audit_sessions.json` are structurally excluded, not just skipped by
     convention. Builds one commit for all files via GitHub's Git Data API
     (blobs → tree → commit → ref) instead of one commit per file, and
     handles both an existing branch (fast-forward) and a brand-new
     repo/branch (no parent commit) the first time you publish into one.
     Needs a token with **write** access (classic `repo` scope, or
     fine-grained `Contents: Read and write`) — a stricter requirement
     than GitHub sync's read-only, optional-for-public-repos token.

## Key design decisions

- **Multiple Airlock connections, not one.** Each saved connection bundles
  label + tenant + port + API key as one unit, so a key can never get paired
  with the wrong tenant. One is "active" at a time; switching it takes effect
  immediately across every widget, no restart. Switching from *either*
  Settings or the Scripts tab keeps both in sync, and notifies any
  already-opened widget (Timed Audit Mode, ISO) to refresh stale
  connection-dependent data rather than silently showing data from the
  previous connection.
- **Per-feature config files, not one shared blob.** `config.json` (core
  settings + Airlock connections), `cloud_config.json` (NFR Tracking's admin
  credential + tenant list — deliberately separated after a real persistence
  issue, see Pitfalls), `iso_mapping.json` (ISO control rules, git-tracked,
  meant to be hand-edited), `audit_sessions.json` (Timed Audit Mode runtime
  state). All the *.json config files are pretty-printed (`indent=2`) so they're
  actually readable if someone opens them by hand.
- **Rule engine for ISO controls, not hardcoded logic.** `iso_mapping.json`
  defines controls declaratively (`field_equals`, `list_any_match`, `all_of`,
  `manual`); a control with no confirmed field mapping is `manual`, and shows
  as "unknown" rather than a fabricated pass/fail. Manual controls are
  excluded from the compliance-category rollup so an unscored control can't
  silently drag a group into "non-compliant."
- **Reports are self-contained HTML**, not PDF/Word — open in any browser,
  print-to-PDF if needed, no extra dependencies. ISO report downloads; NFR
  Tracking report opens directly in a new tab once data is ready (see
  Pitfalls — this was originally wrong). NFR Tracking additionally offers
  Excel and XML export of the same underlying data, for people who want to
  pivot/filter it or feed it into something else rather than just read it.
- **Logging is toggleable and dual-destination** — Settings → Logging turns
  terminal + rotating `app.log` (5MB, 3 backups) on/off together, live, no
  restart. On by default.

## Cloud API reverse-engineering (NFR Tracking widget)

This was the hardest part of the project — Airlock's Cloud multi-tenant
management API has essentially no public documentation. Found by manually
capturing browser Network tab traffic (Thunder Client for testing, HAR
export for bulk documentation) while using the actual web console.

**What was learned, for reference:**
- Auth: `UserApiKey` header (not `X-ApiKey`, that's the on-prem API), plus
  per-call `tenantID` and `Directoryid` headers. Directory ID is **not fixed**
  — it genuinely varies per partner tenant, confirmed on two different real
  tenants.
- URL shape: `https://<base_domain>/<module>/v1/<endpoint>`. At least four
  modules exist (`willard`, `webfe`, `policy`, `directory`), each hosting
  different endpoints — **the module isn't guessable from the endpoint name**.
  `directory-licence-allocation-list`'s module (`directory`) was wrongly
  assumed to be `webfe` initially and caused a real 404 bug in production use.
- **HTTP method is not consistent across endpoints** — some need GET, some
  need POST (even ones with no meaningful request body). Wrong-method calls
  return 405, which is easy to conflate with an auth problem if you're not
  looking closely.
- Sending more than one item in a batch-shaped request
  (`tenant-policy-clients-in-scope-list` with multiple `TenantPolicyGroupList`
  entries) triggered a `500 Internal Server Error` — the backend doesn't
  handle it, despite the payload accepting an array. Stick to one item per
  call unless multi-item support is explicitly confirmed working.
- A tool (`document_api_from_har.py`, delivered separately from the toolkit
  zip — meant to live in the user's Script Folder) turns a HAR capture into
  an interactive, Swagger-style HTML reference: sidebar grouped by module,
  sample curl command per endpoint, secrets redacted to placeholders. Runs
  incrementally — merges new captures into the same file, filling gaps
  without erasing or duplicating what's already documented.

## Pitfalls hit and already fixed — avoid repeating these

1. **`dict.get(key, default)` doesn't catch an explicit `null`.** Bit us
   twice with real Airlock/Cloud API responses that returned `"agents": null`
   instead of omitting the key or using `[]`. Fix: `(data.get(x) or [])`, not
   `data.get(x, [])`, for any field sourced from a third-party API.
2. **Folder/process mixups look exactly like data-loss bugs.** More than
   once, what looked like a persistence bug was actually the running
   `app.py` and the config file being inspected living in different folders,
   or an old server process still running on port 5000. Fix applied: the app
   now prints its exact working directory and config file paths at startup —
   check that first before assuming a save is broken.
3. **Don't guess API method/module from a sibling endpoint.** Every wrong
   guess in the Cloud API integration came from assuming a new endpoint would
   behave like one already confirmed. Test each one for real.
4. **A report that opens a browser tab before the data is ready is a bug,
   not a nice-to-have fix.** Originally opened the tab immediately then
   filled it in async — user stared at a blank page for minutes on a slow
   multi-tenant pull. Fixed: fetch first, open the tab (via blob URL) only
   once the response is actually in hand; falls back to a clickable link if
   the browser's popup blocker catches the delayed `window.open()`. The
   Excel/XML export buttons follow the same pattern — data is fetched fully
   before a download is triggered.
5. **When two tabs share the same CSS classes for visual consistency, scope
   their JS event handlers independently.** Settings and Custom Widgets both
   use `.widget-tile`/`.widget-detail-panel` for identical styling — their
   click handlers are scoped to `#tab-settings` / `#tab-widgets`
   respectively so opening one never collapses the other.
6. **Terminal log output is the single most effective debugging tool in this
   project.** Every real bug (the null-vs-missing crash, the wrong HTTP
   method, the wrong module) was found by adding a log line and asking for
   the terminal output — not by guessing from symptoms alone.
7. **Flask's dev server doesn't hot-reload.** After any `app.py` or
   `templates/index.html` edit, fully stop the running server and restart it
   (`run.bat` again, or `python app.py`) — otherwise you'll be staring at old
   behavior and wondering why a fix "didn't work."

## Where things stand

Fully working, tested against real Airlock environments (not just synthetic
data) at every step. No known open bugs as of this summary.

Session 2026-09-04 added to NFR Tracking: a collapsible partner tenant list
with a live selected-count summary, a report re-themed to match the app's own
dark palette (with a light print override), and Excel/XML export alongside
the existing HTML report — all three built from the same
`run_cloud_partner_report()` data so they stay in sync. Also moved the
project folder up a level, from `Documents\airlock-partner-consulting-toolkit_Migrate\airlock-partner-consulting-toolkit`
to just `Documents\airlock-partner-consulting-toolkit` (folder move only, no
code changes).

Session 2026-09-08 added the **Publish to GitHub** Settings card — pushes
this app's own source files to a GitHub repo as a single commit via the Git
Data API, using a fixed file list so secrets/runtime files can't end up in
it by accident. See the Settings tab bullet above for details. Verified with
the Flask test client and mocked GitHub API responses covering: pushing to
an existing branch, publishing into a brand-new repo/branch with no prior
commits, a missing-token error, and a malformed repo string — plus a full
template render to confirm the new card doesn't break page load.

Natural next steps, if picked up again: extend `iso_mapping.json` with more
automated controls (several are still `manual` pending confirmed field
mappings), and possibly extend NFR Tracking with more Cloud API data points
now that the auth/module/method pattern is understood.
