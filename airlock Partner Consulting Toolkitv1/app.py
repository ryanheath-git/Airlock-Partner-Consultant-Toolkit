"""
Local browser-based Python code runner.

Run with:
    python app.py

Then open http://localhost:5000 in your browser.

SECURITY NOTE:
This runs whatever Python code is submitted, on your own machine,
with your own user permissions. It is intended for LOCAL, PERSONAL
use only (e.g. testing snippets on your own laptop). Do NOT expose
this server to the network or the internet — anyone who can reach
it can run arbitrary code on your computer.
"""

import subprocess
import sys
import tempfile
import os
import uuid
import json
import shlex
import time
import threading
import logging
from datetime import datetime, timezone, timedelta

import requests
from flask import Flask, request, jsonify, render_template, send_from_directory

app = Flask(__name__)

# Logs to the terminal running `python app.py` — most useful for
# diagnosing third-party API calls (Airlock Digital, VirusTotal, GitHub)
# where the request succeeded but the response shape wasn't what the
# app expected. Not written to a file; this is a local single-user tool
# and the terminal window itself is the log.
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("app")

# Max time (seconds) a submitted script is allowed to run before being killed.
EXECUTION_TIMEOUT = 10

# Max time (seconds) a compile job is allowed to run before being killed.
# PyInstaller can be slow, especially on the first run.
COMPILE_TIMEOUT = 180

# Where compiled executables are saved. Created next to this file.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BUILDS_DIR = os.path.join(BASE_DIR, "builds")
os.makedirs(BUILDS_DIR, exist_ok=True)

# Local config file storing the VirusTotal API key.
# NOTE: stored in plaintext. Fine for a single-user local tool, but
# don't commit this file or share it — it grants access to your
# VirusTotal account/quota.
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

# Persisted Timed Audit Mode sessions, so scheduled reverts survive an
# app restart. Local file next to app.py; not sensitive on its own
# (agent IDs and group IDs only, no secrets) but still git-ignored.
AUDIT_SESSIONS_PATH = os.path.join(BASE_DIR, "audit_sessions.json")

VT_FILES_URL = "https://www.virustotal.com/api/v3/files"
VT_UPLOAD_URL_ENDPOINT = "https://www.virustotal.com/api/v3/files/upload_url"
VT_LARGE_FILE_THRESHOLD = 32 * 1024 * 1024  # VT requires the special upload URL above 32MB

# Max time (seconds) an API-calls script is allowed to run before being killed.
DEFAULT_API_SCRIPT_TIMEOUT = 120

# Default folder for your Airlock Digital script repository, used when
# api_scripts_dir isn't set in config.json. You can point this at your
# existing repo instead via the Settings tab. Scripts always run from
# this local folder — GitHub, when enabled, is a sync source that copies
# .py files into this folder, not a separate execution location.
DEFAULT_API_SCRIPTS_DIR = os.path.join(BASE_DIR, "api_scripts")

# File types the app will offer to open after an API-calls script runs.
OUTPUT_FILE_EXTENSIONS = (".xlsx", ".xml", ".html", ".htm")


def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_config(config):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f)


# Guards audit_sessions.json against concurrent access between HTTP
# request handlers and the background revert-scheduler thread.
AUDIT_SESSIONS_LOCK = threading.Lock()


def load_audit_sessions():
    with AUDIT_SESSIONS_LOCK:
        if os.path.exists(AUDIT_SESSIONS_PATH):
            try:
                with open(AUDIT_SESSIONS_PATH, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return []
        return []


def save_audit_sessions(sessions):
    with AUDIT_SESSIONS_LOCK:
        with open(AUDIT_SESSIONS_PATH, "w") as f:
            json.dump(sessions, f)


def get_scripts_dir():
    configured = load_config().get("api_scripts_dir", "").strip()
    scripts_dir = configured if configured else DEFAULT_API_SCRIPTS_DIR
    os.makedirs(scripts_dir, exist_ok=True)
    return scripts_dir


def get_script_timeout():
    configured = load_config().get("api_script_timeout", "").strip()
    if configured.isdigit() and int(configured) > 0:
        return int(configured)
    return DEFAULT_API_SCRIPT_TIMEOUT


# Default port for the Airlock Digital REST API, per Airlock's own docs.
DEFAULT_AIRLOCK_PORT = 3129


def get_airlock_base_url():
    """Returns (base_url, error) — base_url is None if not configured."""
    config = load_config()
    tenant = config.get("airlock_tenant", "").strip()
    if not tenant:
        return None, "No Airlock Digital tenant configured. Add one in Settings."
    port = config.get("airlock_port", "").strip() or str(DEFAULT_AIRLOCK_PORT)
    # Allow the tenant field to already include a port (tenant:port) without
    # doubling up, in case someone pastes it in that form.
    host = tenant.split(":")[0]
    return f"https://{host}:{port}", None


def airlock_request(path, payload=None):
    """POSTs to the Airlock Digital REST API and returns (data, error).
    data is the parsed 'response' object on success; error is a plain,
    display-ready message on any failure (config, network, auth, or API-
    level error)."""
    base_url, err = get_airlock_base_url()
    if err:
        return None, err

    config = load_config()
    api_key = config.get("airlock_api_key", "").strip()
    if not api_key:
        return None, "No Airlock Digital API key configured. Add one in Settings."

    try:
        resp = requests.post(
            f"{base_url}{path}",
            json=payload or {},
            headers={"X-ApiKey": api_key, "Content-Type": "application/json"},
            timeout=20,
        )
    except requests.exceptions.SSLError as e:
        return None, f"SSL certificate error connecting to {base_url}: {e}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Couldn't connect to {base_url}: {e}"
    except requests.exceptions.Timeout:
        return None, f"Request to {base_url}{path} timed out."
    except requests.exceptions.RequestException as e:
        return None, f"Request failed: {e}"

    if resp.status_code == 401 or resp.status_code == 403:
        try:
            detail = resp.json()
        except ValueError:
            detail = resp.text.strip()
        # Airlock's own error body usually distinguishes an invalid key
        # from a key that's valid but missing a required REST API role
        # for this endpoint — surface it rather than a generic message.
        return None, f"Airlock Digital rejected the request (status {resp.status_code}): {detail}"

    log.info("Airlock %s -> %s: %s", path, resp.status_code, resp.text[:2000])

    try:
        data = resp.json()
    except ValueError:
        return None, f"Airlock Digital returned a non-JSON response (status {resp.status_code})."

    if not resp.ok:
        return None, f"Airlock Digital API error (status {resp.status_code}): {data}"

    error_field = data.get("error")
    if error_field is not None and str(error_field).strip().lower() != "success":
        return None, f"Airlock Digital API error: {error_field}"

    return data.get("response", {}), None


def airlock_move_agents(dest_groupid, agent_ids):
    """Moves the given agent IDs to dest_groupid. Returns (ok, error)."""
    if not agent_ids:
        return True, None
    _, err = airlock_request("/v1/agent/move", {"groupid": dest_groupid, "agentid": agent_ids})
    return err is None, err


def parse_github_repo(value):
    """Accepts 'owner/repo' or a full https://github.com/owner/repo URL."""
    value = value.strip()
    if value.endswith(".git"):
        value = value[: -len(".git")]
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    value = value.strip("/")
    parts = value.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError("Repo must be in 'owner/repo' form, or a full GitHub URL.")
    return parts[0], parts[1]


def sync_github_scripts():
    """Downloads .py files from the configured GitHub repo into the local
    scripts folder. Only touches .py files it manages — any other files
    already sitting in the scripts folder (notes, configs, etc.) are left
    alone. Returns a dict describing the outcome; never raises.
    """
    config = load_config()
    if (config.get("github_sync_enabled", "") or "").strip().lower() != "true":
        return {"synced": False, "reason": "disabled"}

    repo = config.get("github_repo", "").strip()
    if not repo:
        return {"synced": False, "reason": "no repo configured"}

    branch = config.get("github_branch", "").strip() or "main"
    subdir = config.get("github_subdir", "").strip().strip("/")
    token = config.get("github_token", "").strip()

    try:
        owner, name = parse_github_repo(repo)
    except ValueError as e:
        return {"synced": False, "reason": str(e)}

    api_url = f"https://api.github.com/repos/{owner}/{name}/contents/{subdir}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        resp = requests.get(api_url, headers=headers, params={"ref": branch}, timeout=15)
    except requests.exceptions.RequestException as e:
        return {"synced": False, "reason": f"GitHub request failed: {e}"}

    if not resp.ok:
        return {"synced": False, "reason": f"GitHub API error: {resp.status_code}"}

    items = resp.json()
    if not isinstance(items, list):
        return {"synced": False, "reason": "Configured path isn't a folder in this repo."}

    py_files = [item for item in items if item.get("type") == "file" and item["name"].endswith(".py")]

    scripts_dir = get_scripts_dir()
    downloaded = []
    errors = []
    for item in py_files:
        raw_url = item.get("download_url")
        if not raw_url:
            continue
        try:
            file_resp = requests.get(raw_url, headers=headers, timeout=15)
            file_resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            errors.append(f"{item['name']}: {e}")
            continue
        with open(os.path.join(scripts_dir, item["name"]), "wb") as f:
            f.write(file_resp.content)
        downloaded.append(item["name"])

    return {
        "synced": True,
        "downloaded": downloaded,
        "errors": errors,
        "location": f"{owner}/{name}@{branch}" + (f"/{subdir}" if subdir else ""),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/run", methods=["POST"])
def run_code():
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")

    if not isinstance(code, str) or not code.strip():
        return jsonify({"error": "No code provided."}), 400

    # Write the submitted code to a temporary file and run it as a
    # separate process, so it can't crash or hang the server itself.
    tmp_dir = tempfile.gettempdir()
    filename = os.path.join(tmp_dir, f"snippet_{uuid.uuid4().hex}.py")

    try:
        with open(filename, "w") as f:
            f.write(code)

        try:
            result = subprocess.run(
                [sys.executable, filename],
                capture_output=True,
                text=True,
                timeout=EXECUTION_TIMEOUT,
            )
            return jsonify(
                {
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.returncode,
                    "timed_out": False,
                }
            )
        except subprocess.TimeoutExpired as e:
            return jsonify(
                {
                    "stdout": e.stdout or "",
                    "stderr": (e.stderr or "") + f"\n[Execution stopped: exceeded {EXECUTION_TIMEOUT}s time limit]",
                    "exit_code": None,
                    "timed_out": True,
                }
            )
    finally:
        if os.path.exists(filename):
            os.remove(filename)


@app.route("/compile", methods=["POST"])
def compile_code():
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")

    if not isinstance(code, str) or not code.strip():
        return jsonify({"success": False, "error": "No code provided."}), 400

    # Name the output using today's date and time, e.g. script_20260714_143205.exe
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    exe_basename = f"script_{timestamp}"

    with tempfile.TemporaryDirectory() as work_dir:
        script_path = os.path.join(work_dir, "source.py")
        with open(script_path, "w") as f:
            f.write(code)

        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--noconfirm",
            "--distpath", BUILDS_DIR,
            "--workpath", work_dir,
            "--specpath", work_dir,
            "--name", exe_basename,
            script_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=COMPILE_TIMEOUT,
            )
        except FileNotFoundError:
            return jsonify(
                {
                    "success": False,
                    "error": "PyInstaller isn't installed. Run: pip install pyinstaller",
                }
            ), 500
        except subprocess.TimeoutExpired:
            return jsonify(
                {
                    "success": False,
                    "error": f"Compilation timed out after {COMPILE_TIMEOUT}s.",
                }
            ), 500

        # PyInstaller only appends .exe automatically on Windows.
        produced_name = exe_basename + (".exe" if os.name == "nt" else "")
        produced_path = os.path.join(BUILDS_DIR, produced_name)
        built_ok = result.returncode == 0 and os.path.exists(produced_path)

        return jsonify(
            {
                "success": built_ok,
                "filename": produced_name if built_ok else None,
                "download_url": f"/download/{produced_name}" if built_ok else None,
                # Keep logs short — PyInstaller output can be very long.
                "stdout": result.stdout[-3000:],
                "stderr": result.stderr[-3000:],
                "exit_code": result.returncode,
            }
        )


@app.route("/download/<path:filename>")
def download(filename):
    return send_from_directory(BUILDS_DIR, filename, as_attachment=True)


def key_preview(value):
    return ("•" * 8 + value[-4:]) if value else ""


@app.route("/config", methods=["GET"])
def get_config():
    config = load_config()
    vt_key = config.get("vt_api_key", "")
    airlock_key = config.get("airlock_api_key", "")
    github_token = config.get("github_token", "")
    return jsonify(
        {
            "vt_api_key": {"has_key": bool(vt_key), "key_preview": key_preview(vt_key)},
            "airlock_api_key": {"has_key": bool(airlock_key), "key_preview": key_preview(airlock_key)},
            "airlock_tenant": config.get("airlock_tenant", ""),
            "airlock_port": config.get("airlock_port", ""),
            "api_scripts_dir": config.get("api_scripts_dir", ""),
            "api_scripts_dir_resolved": get_scripts_dir(),
            "api_script_timeout": config.get("api_script_timeout", ""),
            "api_script_timeout_resolved": get_script_timeout(),
            "github_sync_enabled": (config.get("github_sync_enabled", "") or "").strip().lower() == "true",
            "github_repo": config.get("github_repo", ""),
            "github_branch": config.get("github_branch", ""),
            "github_subdir": config.get("github_subdir", ""),
            "github_token": {"has_key": bool(github_token), "key_preview": key_preview(github_token)},
        }
    )


VALID_CONFIG_FIELDS = {
    "vt_api_key", "airlock_api_key", "airlock_tenant", "airlock_port", "api_scripts_dir", "api_script_timeout",
    "github_sync_enabled", "github_repo", "github_branch", "github_subdir", "github_token",
}
SECRET_CONFIG_FIELDS = {"vt_api_key", "airlock_api_key", "github_token"}


@app.route("/config", methods=["POST"])
def set_config():
    data = request.get_json(silent=True) or {}

    # Supports either a single {"field": ..., "value": ...} update, or a
    # batch {"fields": {"a": "...", "b": "..."}} update in one request.
    if "fields" in data and isinstance(data["fields"], dict):
        updates = data["fields"]
    elif "field" in data:
        updates = {data.get("field"): data.get("value", "")}
    else:
        return jsonify({"error": "No fields provided."}), 400

    if not updates:
        return jsonify({"error": "No fields provided."}), 400

    for field, value in updates.items():
        if field not in VALID_CONFIG_FIELDS:
            return jsonify({"error": f"Unknown field '{field}'."}), 400
        if not isinstance(value, str):
            return jsonify({"error": f"Value for '{field}' must be a string."}), 400

    if "github_sync_enabled" in updates and updates["github_sync_enabled"].strip().lower() not in ("true", "false"):
        return jsonify({"error": "github_sync_enabled must be 'true' or 'false'."}), 400

    if "api_script_timeout" in updates:
        timeout_val = updates["api_script_timeout"].strip()
        if timeout_val and not (timeout_val.isdigit() and int(timeout_val) > 0):
            return jsonify({"error": "api_script_timeout must be a whole number of seconds greater than 0."}), 400

    if "airlock_port" in updates:
        port_val = updates["airlock_port"].strip()
        if port_val and not (port_val.isdigit() and 1 <= int(port_val) <= 65535):
            return jsonify({"error": "airlock_port must be a whole number between 1 and 65535."}), 400

    config = load_config()
    for field, value in updates.items():
        config[field] = value.strip()
    save_config(config)

    response = {"saved": True}
    if len(updates) == 1:
        only_field = next(iter(updates))
        response["field"] = only_field
        if only_field in SECRET_CONFIG_FIELDS:
            response["key_preview"] = key_preview(config[only_field])
        if only_field == "api_scripts_dir":
            response["api_scripts_dir_resolved"] = get_scripts_dir()
        if only_field == "api_script_timeout":
            response["api_script_timeout_resolved"] = get_script_timeout()
    else:
        response["fields"] = list(updates.keys())
        secret_updates = {f: key_preview(config[f]) for f in updates if f in SECRET_CONFIG_FIELDS}
        if secret_updates:
            response["key_previews"] = secret_updates
        if "api_scripts_dir" in updates:
            response["api_scripts_dir_resolved"] = get_scripts_dir()
        if "api_script_timeout" in updates:
            response["api_script_timeout_resolved"] = get_script_timeout()

    return jsonify(response)


@app.route("/config/reveal", methods=["POST"])
def reveal_config_value():
    # Returns a saved secret's real value so the Settings tab can copy it
    # to the clipboard. Only ever called by an explicit user click on a
    # Copy button — never included in the regular masked /config GET.
    data = request.get_json(silent=True) or {}
    field = data.get("field", "")

    if field not in SECRET_CONFIG_FIELDS:
        return jsonify({"error": "Invalid field."}), 400

    config = load_config()
    value = config.get(field, "")
    if not value:
        return jsonify({"error": "No key saved."}), 404

    return jsonify({"value": value})


@app.route("/api_scripts", methods=["GET"])
def list_api_scripts():
    scripts_dir = get_scripts_dir()
    try:
        scripts = sorted(
            f for f in os.listdir(scripts_dir)
            if f.endswith(".py") and os.path.isfile(os.path.join(scripts_dir, f))
        )
    except OSError as e:
        return jsonify({"error": f"Couldn't read scripts folder: {e}", "scripts": [], "location": scripts_dir}), 500
    return jsonify({"scripts": scripts, "location": scripts_dir})


@app.route("/sync", methods=["POST"])
def sync_now():
    result = sync_github_scripts()
    if not result["synced"]:
        return jsonify({"success": False, "error": result.get("reason", "Sync failed.")}), 400
    return jsonify(
        {
            "success": True,
            "downloaded": result["downloaded"],
            "errors": result["errors"],
            "location": result["location"],
        }
    )


@app.route("/api_scripts/run", methods=["POST"])
def run_api_script():
    data = request.get_json(silent=True) or {}
    # "script" holds the script name optionally followed by command-line
    # arguments, e.g. "report.py --user jdoe --verbose".
    raw_input_str = data.get("script", "")

    if not isinstance(raw_input_str, str) or not raw_input_str.strip():
        return jsonify({"error": "No script selected."}), 400

    try:
        tokens = shlex.split(raw_input_str.strip())
    except ValueError as e:
        return jsonify({"error": f"Couldn't parse arguments: {e}"}), 400

    if not tokens:
        return jsonify({"error": "No script selected."}), 400

    script_name, script_args = tokens[0], tokens[1:]

    safe_name = os.path.basename(script_name)
    if not safe_name.endswith(".py"):
        return jsonify({"error": "Invalid script name."}), 400

    exec_dir = get_scripts_dir()
    script_path = os.path.join(exec_dir, safe_name)
    if not os.path.isfile(script_path):
        return jsonify({"error": f"Script not found: {safe_name}"}), 404

    config = load_config()
    env = os.environ.copy()
    env["AIRLOCK_API_KEY"] = config.get("airlock_api_key", "")
    env["AIRLOCK_TENANT"] = config.get("airlock_tenant", "")
    env["VT_API_KEY"] = config.get("vt_api_key", "")

    # Snapshot existing xlsx/xml/html files beforehand so we can tell
    # which one the script produced or updated.
    before_mtimes = {}
    try:
        for f in os.listdir(exec_dir):
            if f.lower().endswith(OUTPUT_FILE_EXTENSIONS):
                fp = os.path.join(exec_dir, f)
                before_mtimes[fp] = os.path.getmtime(fp)
    except OSError:
        pass

    run_start = time.time()
    script_timeout = get_script_timeout()

    try:
        result = subprocess.run(
            [sys.executable, script_path, *script_args],
            capture_output=True,
            text=True,
            timeout=script_timeout,
            cwd=exec_dir,
            env=env,
        )
        response = {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        response = {
            "stdout": e.stdout or "",
            "stderr": (e.stderr or "") + f"\n[Execution stopped: exceeded {script_timeout}s time limit]",
            "exit_code": None,
            "timed_out": True,
        }

    # Detect a new or freshly-modified output file (xlsx/xml/html) from this run.
    output_file = None
    try:
        candidates = []
        for f in os.listdir(exec_dir):
            if f.lower().endswith(OUTPUT_FILE_EXTENSIONS):
                fp = os.path.join(exec_dir, f)
                mtime = os.path.getmtime(fp)
                is_new_or_updated = fp not in before_mtimes or mtime > before_mtimes[fp]
                if is_new_or_updated and mtime >= run_start - 1:
                    candidates.append((mtime, fp))
        if candidates:
            candidates.sort(reverse=True)
            output_file = candidates[0][1]
    except OSError:
        pass

    if output_file:
        response["output_file"] = output_file
        response["output_filename"] = os.path.basename(output_file)

    return jsonify(response)


@app.route("/open_file", methods=["POST"])
def open_file():
    data = request.get_json(silent=True) or {}
    path = data.get("path", "")

    if not isinstance(path, str) or not path.strip():
        return jsonify({"success": False, "error": "No path provided."}), 400

    real_path = os.path.realpath(path)
    allowed_roots = [os.path.realpath(get_scripts_dir())]
    if not any(real_path == root or real_path.startswith(root + os.sep) for root in allowed_roots):
        return jsonify({"success": False, "error": "That file is outside the allowed scripts/output folders."}), 403

    if not os.path.isfile(real_path):
        return jsonify({"success": False, "error": "File not found."}), 404

    try:
        if os.name == "nt":
            os.startfile(real_path)  # noqa: os.startfile only exists on Windows
        elif sys.platform == "darwin":
            subprocess.run(["open", real_path], check=False)
        else:
            subprocess.run(["xdg-open", real_path], check=False)
        return jsonify({"success": True})
    except OSError as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/virustotal/upload", methods=["POST"])
def virustotal_upload():
    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "")

    if not isinstance(filename, str) or not filename.strip():
        return jsonify({"success": False, "error": "No filename provided."}), 400

    # Prevent path traversal — only allow files that actually live in BUILDS_DIR.
    safe_name = os.path.basename(filename)
    file_path = os.path.join(BUILDS_DIR, safe_name)
    if not os.path.exists(file_path):
        return jsonify({"success": False, "error": f"File not found: {safe_name}"}), 404

    api_key = load_config().get("vt_api_key", "")
    if not api_key:
        return jsonify(
            {"success": False, "error": "No VirusTotal API key configured. Add one in the Settings tab."}
        ), 400

    headers = {"x-apikey": api_key}
    file_size = os.path.getsize(file_path)

    try:
        if file_size > VT_LARGE_FILE_THRESHOLD:
            # Files over 32MB need a dedicated upload URL first.
            resp = requests.get(VT_UPLOAD_URL_ENDPOINT, headers=headers, timeout=30)
            resp.raise_for_status()
            upload_url = resp.json()["data"]
        else:
            upload_url = VT_FILES_URL

        with open(file_path, "rb") as f:
            resp = requests.post(
                upload_url,
                headers=headers,
                files={"file": (safe_name, f, "application/octet-stream")},
                timeout=120,
            )

        if resp.status_code == 401:
            return jsonify({"success": False, "error": "VirusTotal rejected the API key (unauthorized)."}), 401
        if resp.status_code == 429:
            return jsonify({"success": False, "error": "VirusTotal rate limit / quota exceeded."}), 429
        resp.raise_for_status()

        analysis_id = resp.json()["data"]["id"]
        vt_url = f"https://www.virustotal.com/gui/file-analysis/{analysis_id}"

        return jsonify({"success": True, "analysis_id": analysis_id, "vt_url": vt_url})

    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": f"VirusTotal request failed: {e}"}), 502


# --- Custom Widgets: Timed Audit Mode ---

@app.route("/airlock/groups", methods=["GET"])
def airlock_groups():
    data, err = airlock_request("/v1/group")
    if err:
        return jsonify({"error": err, "groups": []}), 400

    # Be defensive about the exact response shape — normally it's
    # {"groups": [...]}, but fall back to finding any list in the
    # response, or treating the response itself as the list.
    if isinstance(data, dict):
        groups = data.get("groups")
        if groups is None:
            groups = next((v for v in data.values() if isinstance(v, list)), [])
    elif isinstance(data, list):
        groups = data
    else:
        groups = []

    result = []
    for g in groups:
        if not isinstance(g, dict):
            continue
        groupid = g.get("groupid") or g.get("id") or g.get("group_id")
        if not groupid:
            continue
        name = (
            g.get("name") or g.get("groupname") or g.get("group_name") or g.get("title")
            or f"(unnamed — {groupid[:8]})"
        )
        result.append({"groupid": groupid, "name": name})
    result.sort(key=lambda g: g["name"].lower())

    response = {"groups": result}
    if not result and groups:
        # Airlock returned data but nothing matched the fields we expect —
        # echo a raw sample so the mismatch is visible right in the widget
        # rather than requiring a look at the server's terminal log.
        first = groups[0]
        response["raw_sample"] = first if isinstance(first, dict) else str(first)
        log.warning("Airlock /v1/group returned data but no groups parsed. Raw sample: %s", first)

    return jsonify(response)


@app.route("/airlock/agents", methods=["POST"])
def airlock_agents():
    data_in = request.get_json(silent=True) or {}
    groupid = data_in.get("groupid", "").strip()
    if not groupid:
        return jsonify({"error": "No groupid provided.", "agents": []}), 400

    data, err = airlock_request("/v1/agent/find", {"groupid": groupid})
    if err:
        return jsonify({"error": err, "agents": []}), 400

    if isinstance(data, dict):
        agents = data.get("agents")
        if agents is None:
            agents = next((v for v in data.values() if isinstance(v, list)), [])
    elif isinstance(data, list):
        agents = data
    else:
        agents = []

    result = []
    for a in agents:
        if not isinstance(a, dict):
            continue
        agentid = a.get("agentid") or a.get("id")
        if not agentid:
            continue
        # Defensive filter: only include agents actually in the requested
        # group, in case the API doesn't filter server-side on this field.
        agent_groupid = a.get("groupid")
        if agent_groupid and agent_groupid != groupid:
            continue
        result.append(
            {
                "agentid": agentid,
                "hostname": a.get("hostname") or agentid,
                "username": a.get("username", ""),
                "os": a.get("os", ""),
            }
        )
    result.sort(key=lambda a: a["hostname"].lower())

    response = {"agents": result}
    if not result and agents:
        first = agents[0]
        response["raw_sample"] = first if isinstance(first, dict) else str(first)
        log.warning("Airlock /v1/agent/find returned data but no agents parsed. Raw sample: %s", first)

    return jsonify(response)


def process_due_audit_sessions():
    """Reverts any Timed Audit Mode session whose timer has expired.
    Also retries sessions stuck in 'revert_failed' from a prior attempt —
    a failed revert should keep being retried, not silently give up,
    since that would leave endpoints in audit mode indefinitely."""
    sessions = load_audit_sessions()
    now = datetime.now(timezone.utc)
    changed = False

    for s in sessions:
        if s.get("status") not in ("active", "revert_failed"):
            continue
        try:
            expires_at = datetime.fromisoformat(s["expires_at"])
        except (KeyError, ValueError, TypeError):
            continue
        if expires_at > now:
            continue

        ok, err = airlock_move_agents(s["source_groupid"], s["agent_ids"])
        changed = True
        if ok:
            s["status"] = "reverted"
            s["reverted_at"] = now.isoformat()
            s["revert_error"] = None
        else:
            s["status"] = "revert_failed"
            s["revert_error"] = err

    if changed:
        save_audit_sessions(sessions)


def audit_scheduler_loop():
    while True:
        try:
            process_due_audit_sessions()
        except Exception as e:  # noqa: broad except — this loop must never die
            print(f"[audit scheduler] error: {e}")
        time.sleep(20)


@app.route("/audit/sessions", methods=["GET"])
def audit_sessions_list():
    return jsonify({"sessions": load_audit_sessions()})


@app.route("/audit/start", methods=["POST"])
def audit_start():
    data_in = request.get_json(silent=True) or {}
    source_groupid = (data_in.get("source_groupid") or "").strip()
    source_group_name = (data_in.get("source_group_name") or "").strip() or source_groupid
    dest_groupid = (data_in.get("dest_groupid") or "").strip()
    dest_group_name = (data_in.get("dest_group_name") or "").strip() or dest_groupid
    agent_ids = data_in.get("agent_ids") or []
    agent_labels = data_in.get("agent_labels") or []
    duration_seconds = data_in.get("duration_seconds")

    if not source_groupid or not dest_groupid:
        return jsonify({"error": "Source and destination groups are required."}), 400
    if source_groupid == dest_groupid:
        return jsonify({"error": "Source and destination groups must be different."}), 400
    if not isinstance(agent_ids, list) or not agent_ids or not all(isinstance(a, str) and a for a in agent_ids):
        return jsonify({"error": "Select at least one agent to move."}), 400
    if not isinstance(duration_seconds, (int, float)) or duration_seconds <= 0:
        return jsonify({"error": "duration_seconds must be a positive number."}), 400

    ok, err = airlock_move_agents(dest_groupid, agent_ids)
    if not ok:
        return jsonify({"error": f"Move to '{dest_group_name}' failed: {err}"}), 502

    now = datetime.now(timezone.utc)
    session = {
        "id": str(uuid.uuid4()),
        "source_groupid": source_groupid,
        "source_group_name": source_group_name,
        "dest_groupid": dest_groupid,
        "dest_group_name": dest_group_name,
        "agent_ids": agent_ids,
        "agent_labels": agent_labels if len(agent_labels) == len(agent_ids) else agent_ids,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=duration_seconds)).isoformat(),
        "status": "active",
        "revert_error": None,
        "reverted_at": None,
    }

    sessions = load_audit_sessions()
    sessions.append(session)
    save_audit_sessions(sessions)

    return jsonify({"success": True, "session": session})


@app.route("/audit/cancel", methods=["POST"])
def audit_cancel():
    data_in = request.get_json(silent=True) or {}
    session_id = (data_in.get("id") or "").strip()
    if not session_id:
        return jsonify({"error": "No session id provided."}), 400

    sessions = load_audit_sessions()
    session = next((s for s in sessions if s.get("id") == session_id), None)
    if not session:
        return jsonify({"error": "Session not found."}), 404
    if session.get("status") not in ("active", "revert_failed"):
        return jsonify({"error": f"Session is already '{session.get('status')}'."}), 400

    ok, err = airlock_move_agents(session["source_groupid"], session["agent_ids"])
    if not ok:
        session["status"] = "revert_failed"
        session["revert_error"] = err
        save_audit_sessions(sessions)
        return jsonify({"error": f"Revert failed: {err}"}), 502

    session["status"] = "reverted"
    session["reverted_at"] = datetime.now(timezone.utc).isoformat()
    session["revert_error"] = None
    save_audit_sessions(sessions)

    return jsonify({"success": True, "session": session})


if __name__ == "__main__":
    # If GitHub sync is enabled, pull the latest scripts down before serving
    # so the API Calls tab reflects the current repo state on startup.
    startup_sync = sync_github_scripts()
    if startup_sync.get("synced"):
        print(f"[startup sync] Pulled {len(startup_sync['downloaded'])} script(s) from {startup_sync['location']}")
    elif startup_sync.get("reason") not in ("disabled", "no repo configured"):
        print(f"[startup sync] Skipped: {startup_sync.get('reason')}")

    # Catch up on any Timed Audit Mode sessions that expired while the app
    # wasn't running, then start the background thread that watches for
    # future expirations.
    process_due_audit_sessions()
    threading.Thread(target=audit_scheduler_loop, daemon=True).start()

    # host="127.0.0.1" keeps this reachable only from your own machine.
    app.run(host="127.0.0.1", port=5000, debug=False)
