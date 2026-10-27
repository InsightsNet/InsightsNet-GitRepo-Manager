import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel, simpledialog
from tkinter import ttk
from tkinter import scrolledtext
from PIL import Image, ImageTk
import shutil
import subprocess
import os
import sys
import ctypes
import threading
import datetime
import re
import shlex
import queue
import tempfile
import webbrowser
import hashlib
import colorsys
import pathlib
import json
import urllib.request
import urllib.error
from urllib.parse import urlparse
from git import Repo

repo = None
branch_dropdown = None
selected_files = []
file_entries = {}
app_closing = False
graph_refresh_in_progress = False
_PUSH_SECTION_GRID = {"row": 3, "column": 0, "columnspan": 3, "padx": 10, "pady": 10, "sticky": "we"}
_ui_queue = queue.Queue()

def _post_ui(fn):
    """Enqueue a UI callback to run on the Tk main thread."""
    _ui_queue.put(fn)

# ---- Route git's credential / SSH host-key prompts to a GUI dialog instead of
# the terminal (this app has no terminal for the user to type into once launched
# from a GUI). git and ssh each support an external "askpass" program: they spawn
# it as its own process with the prompt text as argv[1] and read the typed answer
# back from its stdout, so the helper below is a standalone script (it can't
# reuse this process's Tk mainloop) that pops a small dialog and prints the
# result. This covers both HTTPS username/password prompts and SSH "yes/no" host
# key confirmation prompts, since both are just "show this text, read one line
# back" from git/ssh's point of view.
def _setup_git_gui_credential_prompts():
    try:
        app_dir = os.path.dirname(os.path.abspath(__file__))
        helper_py = os.path.join(app_dir, "_git_askpass_gui.py")
        helper_src = '''#!/usr/bin/env python3
import sys
import os
import tempfile
import time
import tkinter as tk
from tkinter import simpledialog

# ssh tries several auth mechanisms per connection (a passphrase prompt per
# candidate identity key, then password auth), each spawning this script as a
# separate process with no shared memory. Without this, cancelling once still
# leaves the remaining mechanisms popping the same dialog again. Remember a
# recent cancel via a short-lived marker file so the whole operation gives up
# after a single cancel, while an unrelated LATER operation still prompts fresh.
CANCEL_FLAG = os.path.join(tempfile.gettempdir(), "igrm_git_askpass_cancel.flag")
CANCEL_TTL = 20  # seconds


def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else "Enter value:"

    try:
        if os.path.exists(CANCEL_FLAG) and (time.time() - os.path.getmtime(CANCEL_FLAG)) < CANCEL_TTL:
            sys.exit(1)
    except OSError:
        pass

    root = tk.Tk()
    root.withdraw()
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass
    answer = simpledialog.askstring(
        "Git",
        prompt,
        show="*" if "password" in prompt.lower() else None,
        parent=root,
    )
    root.destroy()

    if answer is None:
        try:
            with open(CANCEL_FLAG, "w") as f:
                f.write("")
        except OSError:
            pass
        sys.exit(1)

    try:
        os.remove(CANCEL_FLAG)
    except OSError:
        pass
    print(answer)


if __name__ == "__main__":
    main()
'''
        with open(helper_py, "w", encoding="utf-8") as f:
            f.write(helper_src)

        if os.name == "nt":
            helper_bat = os.path.join(app_dir, "_git_askpass_gui.bat")
            pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
            if not os.path.exists(pyw):
                pyw = sys.executable
            with open(helper_bat, "w", encoding="utf-8") as f:
                f.write(f'@echo off\r\n"{pyw}" "{helper_py}" %*\r\n')
            askpass_cmd = helper_bat
        else:
            os.chmod(helper_py, 0o755)
            askpass_cmd = helper_py

        os.environ["GIT_ASKPASS"] = askpass_cmd
        os.environ["SSH_ASKPASS"] = askpass_cmd
        # Force ssh to use SSH_ASKPASS even though this terminal has a TTY
        # (OpenSSH otherwise prefers prompting the controlling terminal directly).
        os.environ["SSH_ASKPASS_REQUIRE"] = "force"
        # Don't let git fall back to prompting this terminal either.
        os.environ["GIT_TERMINAL_PROMPT"] = "0"
        # ssh's default NumberOfPasswordPrompts is 3: cancelling (or a wrong
        # password) once still leaves it re-invoking SSH_ASKPASS two more times,
        # popping the same dialog again. Cap it at 1 so cancel/close means cancel.
        ssh_opts = ["-o NumberOfPasswordPrompts=1"]

        # Unlike HTTPS, ssh has no credential.helper equivalent — password-based
        # ssh auth (as opposed to a passphrase-protected key) has no built-in way
        # to be "remembered" at all, so an action like Clone (which immediately
        # fetches again to populate branches) would otherwise re-prompt right
        # after a successful entry. ControlMaster/ControlPersist works around
        # this the same way ssh's own connection sharing does: the first
        # connection to a host stays open in the background (over a local Unix
        # socket) and later ssh invocations to the same host reuse it instead of
        # authenticating again. Not set on Windows: OpenSSH's Windows port
        # doesn't reliably support Unix domain sockets for this.
        if os.name != "nt":
            control_dir = os.path.join(tempfile.gettempdir(), "igrm_ssh_control")
            try:
                os.makedirs(control_dir, exist_ok=True)
                ssh_opts.append("-o ControlMaster=auto")
                ssh_opts.append("-o ControlPersist=3600")
                ssh_opts.append(f"-o ControlPath={os.path.join(control_dir, '%C')}")
            except OSError:
                pass

        existing_ssh_cmd = os.environ.get("GIT_SSH_COMMAND")
        if not existing_ssh_cmd:
            os.environ["GIT_SSH_COMMAND"] = "ssh " + " ".join(ssh_opts)

        # HTTPS credentials aren't remembered between separate git invocations by
        # default, so an action like Clone (which immediately fetches again to
        # populate branches) re-prompts right after a successful entry. Cache
        # entered credentials in memory for this session via git's built-in
        # credential-cache daemon (never touches disk, expires after an hour) —
        # applied as an environment-scoped git config override so it doesn't
        # touch the user's ~/.gitconfig. Not set on Windows: credential-cache
        # relies on a Unix domain socket that isn't reliably available there.
        if os.name != "nt":
            os.environ["GIT_CONFIG_COUNT"] = "1"
            os.environ["GIT_CONFIG_KEY_0"] = "credential.helper"
            os.environ["GIT_CONFIG_VALUE_0"] = "cache --timeout=3600"
    except Exception:
        pass

_setup_git_gui_credential_prompts()

# ---- Tk cleanup guard to avoid noisy shutdown warnings ----
try:
    if not hasattr(ImageTk.PhotoImage, "_orig_del"):
        ImageTk.PhotoImage._orig_del = ImageTk.PhotoImage.__del__
        def _safe_photoimage_del(self):
            try:
                ImageTk.PhotoImage._orig_del(self)
            except RuntimeError:
                # Happens on shutdown when Tk mainloop is gone
                pass
        ImageTk.PhotoImage.__del__ = _safe_photoimage_del
except Exception:
    pass

try:
    if not hasattr(tk.Image, "_orig_del"):
        tk.Image._orig_del = tk.Image.__del__
        def _safe_image_del(self):
            try:
                tk.Image._orig_del(self)
            except RuntimeError:
                # Happens on shutdown when Tk mainloop is gone
                pass
        tk.Image.__del__ = _safe_image_del
except Exception:
    pass

try:
    if not hasattr(tk.Variable, "_orig_del"):
        tk.Variable._orig_del = tk.Variable.__del__
        def _safe_variable_del(self):
            try:
                tk.Variable._orig_del(self)
            except RuntimeError:
                # Happens on shutdown when Tk mainloop is gone
                pass
        tk.Variable.__del__ = _safe_variable_del
except Exception:
    pass

# =============== Git AuthN helpers ===============

def _read_identity_from_repo(r: Repo):
    """Return (name, email) from repo-local config, or (None, None)."""
    name = email = None
    try:
        with r.config_reader() as cr:
            try:
                name = cr.get_value('user', 'name')
            except Exception:
                pass
            try:
                email = cr.get_value('user', 'email')
            except Exception:
                pass
    except Exception:
        pass
    return name, email

def _git_global_get(key: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "config", "--global", "--get", key],
            capture_output=True, text=True, check=False,
            startupinfo=_win_startupinfo(),
        )
        v = (out.stdout or "").strip()
        return v or None
    except Exception:
        return None

def _git_global_set(key: str, value: str) -> bool:
    try:
        subprocess.run(["git", "config", "--global", key, value],
                       capture_output=True, text=True, check=True,
                       startupinfo=_win_startupinfo())
        return True
    except Exception:
        return False

def _prompt_identity_dialog() -> bool:
    """Modal: capture name/email + scope, write it, and return True so the caller
    can continue the commit in one step (instead of bouncing to another tab)."""
    global repo
    if not repo:
        return False

    # Prefill from the AuthN tab, then global config, then the OS user name.
    pre_name = pre_email = ""
    if 'auth_name_var' in globals():
        pre_name = auth_name_var.get().strip()
        pre_email = auth_email_var.get().strip()
    pre_name = pre_name or _git_global_get("user.name") or \
        os.environ.get("USERNAME") or os.environ.get("USER") or ""
    pre_email = pre_email or _git_global_get("user.email") or ""

    win = Toplevel(root)
    win.title("Git identity needed")
    win.transient(root)
    win.resizable(False, False)
    win.grab_set()

    result = {"ok": False}
    frm = tk.Frame(win, padx=18, pady=16)
    frm.pack(fill="both", expand=True)

    tk.Label(frm, text="Commits need an author name and email.",
             font=("Arial", 10)).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

    name_var = tk.StringVar(value=pre_name)
    email_var = tk.StringVar(value=pre_email)

    tk.Label(frm, text="Name:", anchor="e", width=8).grid(row=1, column=0, sticky="e", pady=3)
    name_entry = tk.Entry(frm, textvariable=name_var, width=36)
    name_entry.grid(row=1, column=1, sticky="w", pady=3)
    tk.Label(frm, text="Email:", anchor="e", width=8).grid(row=2, column=0, sticky="e", pady=3)
    tk.Entry(frm, textvariable=email_var, width=36).grid(row=2, column=1, sticky="w", pady=3)

    scope_var = tk.StringVar(value="global")
    scope_frame = tk.Frame(frm)
    scope_frame.grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 0))
    tk.Radiobutton(scope_frame, text="All repositories on this machine (global)",
                   variable=scope_var, value="global").pack(anchor="w")
    tk.Radiobutton(scope_frame, text="This repository only",
                   variable=scope_var, value="repo").pack(anchor="w")

    tk.Label(frm, text="Tip: use an email registered on your GitLab / GitHub account.",
             font=("Arial", 8), fg="#777").grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 0))
    err = tk.Label(frm, text="", font=("Arial", 8), fg="#c00")
    err.grid(row=5, column=0, columnspan=2, sticky="w")

    def _save_and_continue():
        n = name_var.get().strip()
        e = email_var.get().strip()
        if not n or not e:
            err.config(text="Enter both a name and an email.")
            return
        if "@" not in e or "." not in e.rsplit("@", 1)[-1]:
            err.config(text="That doesn't look like an email address.")
            return
        try:
            if scope_var.get() == "global":
                if not (_git_global_set("user.name", n) and _git_global_set("user.email", e)):
                    err.config(text="Could not write global Git config.")
                    return
            else:
                with repo.config_writer() as cw:
                    cw.set_value('user', 'name', n)
                    cw.set_value('user', 'email', e)
        except Exception as ex:
            err.config(text=f"Could not save identity: {ex}")
            return
        try:
            if 'auth_name_var' in globals():
                auth_name_var.set(n)
                auth_email_var.set(e)
        except Exception:
            pass
        result["ok"] = True
        win.destroy()

    btns = tk.Frame(frm)
    btns.grid(row=6, column=0, columnspan=2, pady=(14, 0))
    tk.Button(btns, text="Save & Commit", command=_save_and_continue, width=14).pack(side="left", padx=6)
    tk.Button(btns, text="Cancel", command=win.destroy, width=10).pack(side="left", padx=6)

    name_entry.focus_set()
    win.wait_window()
    return result["ok"]


def _ensure_identity_before_commit() -> bool:
    """Ensure git can resolve an author identity before committing.

    A repo-local OR global identity is fine (config_reader() merges both). Only
    when neither exists do we prompt - inline, so the commit continues in one step.
    """
    global repo, auth_name_var, auth_email_var
    if not repo:
        return False

    name, email = _read_identity_from_repo(repo)
    if name and email:
        return True

    return _prompt_identity_dialog()

def _apply_identity_repo():
    """Save name/email from AuthN tab into THIS repo's .git/config."""
    global repo, auth_name_var, auth_email_var
    if not repo:
        messagebox.showwarning("Git AuthN", "No repository loaded into Local Clone Directory.")
        return
    name = auth_name_var.get().strip()
    email = auth_email_var.get().strip()
    if not name or not email:
        messagebox.showwarning("Git AuthN", "Please enter both name and email.")
        return
    try:
        with repo.config_writer() as cw:
            cw.set_value('user', 'name', name)
            cw.set_value('user', 'email', email)
        messagebox.showinfo("Git AuthN", "Saved author identity to this repository.")
    except Exception as e:
        messagebox.showerror("Git AuthN", f"Failed to save identity:\n{e}")

def _apply_identity_global():
    """Save name/email from AuthN tab to global ~/.gitconfig."""
    global auth_name_var, auth_email_var
    name = auth_name_var.get().strip()
    email = auth_email_var.get().strip()
    if not name or not email:
        messagebox.showwarning("Git AuthN", "Please enter both name and email.")
        return
    ok1 = _git_global_set("user.name", name)
    ok2 = _git_global_set("user.email", email)
    if ok1 and ok2:
        messagebox.showinfo("Git AuthN", "Saved author identity to your global Git config.")
    else:
        messagebox.showerror("Git AuthN", "Failed to save global identity.")

def _show_effective_identity():
    """Show identity Git will use (repo-local and global)."""
    global repo
    parts = []
    if repo:
        rn, re_ = _read_identity_from_repo(repo)
        parts.append(
            "Repo identity:\n"
            f"  user.name  = {rn or '(unset)'}\n"
            f"  user.email = {re_ or '(unset)'}"
        )
    gn = _git_global_get("user.name")
    ge = _git_global_get("user.email")
    parts.append(
        "Global identity:\n"
        f"  user.name  = {gn or '(unset)'}\n"
        f"  user.email = {ge or '(unset)'}"
    )
    messagebox.showinfo("Git AuthN", "\n\n".join(parts))

def _prefill_auth_fields():
    """Prefill AuthN tab fields from repo-local or global config."""
    if 'auth_name_var' not in globals():
        return
    name = email = ""
    if repo:
        rn, re_ = _read_identity_from_repo(repo)
        name = rn or ""
        email = re_ or ""
    if not name:
        name = _git_global_get("user.name") or ""
    if not email:
        email = _git_global_get("user.email") or ""
    auth_name_var.set(name)
    auth_email_var.set(email)

# =============== HTTPS Personal Access Token (native credential helper) ===============
# git invokes credential.helper automatically for every https:// transfer, so once
# a token is "approved" into the OS-native store (Git Credential Manager on Windows,
# osxkeychain on macOS, libsecret on Linux) clone/fetch/push authenticate with no
# prompt and Repo.clone_from needs no special handling. The secret is only ever
# piped to git over stdin (never argv, where it would show in the process list) and
# is never written by us to any git config or repo file.

CRED_CMD_TIMEOUT = 20  # seconds; a hung helper shouldn't freeze the GUI thread


def _run_git_credential(verb: str, host: str, username: str = "", password: str = "",
                        protocol: str = "https", interactive: bool = False):
    """Pipe a credential description to `git credential <verb>` over stdin.

    verb is 'fill', 'approve' or 'reject'. When interactive is False (the default)
    git is told not to prompt (no terminal, no askpass) so a missing credential
    fails cleanly instead of popping the GUI askpass dialog.
    Returns (returncode, stdout, stderr).
    """
    lines = [f"protocol={protocol}", f"host={host}"]
    if username:
        lines.append(f"username={username}")
    if password:
        lines.append(f"password={password}")
    stdin = "\n".join(lines) + "\n\n"

    cmd = ["git", "credential", verb]
    env = os.environ.copy()
    if not interactive:
        # No terminal prompt, no GUI askpass, and stop Git Credential Manager from
        # popping its own auth window when it has nothing stored for the host.
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GCM_INTERACTIVE"] = "never"
        env.pop("GIT_ASKPASS", None)
        env.pop("SSH_ASKPASS", None)
        cmd = ["git", "-c", "credential.interactive=false", "credential", verb]
    try:
        res = subprocess.run(
            cmd,
            input=stdin, text=True, capture_output=True,
            startupinfo=_win_startupinfo(), env=env, timeout=CRED_CMD_TIMEOUT,
        )
        return res.returncode, (res.stdout or ""), (res.stderr or "")
    except FileNotFoundError:
        return 127, "", "git executable not found."
    except subprocess.TimeoutExpired:
        return 124, "", "git credential timed out."
    except Exception as e:  # pragma: no cover - defensive
        return 1, "", str(e)


def _parse_credential_output(text: str):
    """Pull (username, password) out of `git credential fill` stdout."""
    user = pw = None
    for line in text.splitlines():
        if line.startswith("username="):
            user = line[len("username="):]
        elif line.startswith("password="):
            pw = line[len("password="):]
    return user, pw


def _configured_cred_helpers() -> list[str]:
    """Every credential.helper value git currently sees (any scope)."""
    try:
        res = subprocess.run(
            ["git", "config", "--get-all", "credential.helper"],
            text=True, capture_output=True, startupinfo=_win_startupinfo(), check=False,
        )
        return [l.strip() for l in (res.stdout or "").splitlines() if l.strip()]
    except Exception:
        return []


def _persistent_cred_helper_present() -> bool:
    """True if a *storing* helper is configured.

    The app itself injects `credential.helper=cache` via GIT_CONFIG_* on non-Windows
    (in-memory, expires in an hour), so a lone `cache` does not count as somewhere a
    PAT can actually be kept.
    """
    for h in _configured_cred_helpers():
        first = h.split()[0] if h else ""
        base = first.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if base and base not in ("cache", "cache--timeout"):
            return True
    return False


def _git_core_dir() -> str:
    try:
        res = subprocess.run(["git", "--exec-path"], text=True, capture_output=True,
                             startupinfo=_win_startupinfo(), check=False)
        return (res.stdout or "").strip()
    except Exception:
        return ""


def _has_credential_backend(name: str) -> bool:
    """Is a `git-credential-<name>` helper actually installed?"""
    if shutil.which(f"git-credential-{name}"):
        return True
    core = _git_core_dir()
    if core:
        exe = f"git-credential-{name}" + (".exe" if sys.platform.startswith("win") else "")
        if os.path.isfile(os.path.join(core, exe)):
            return True
    return False


def _default_credential_helper() -> str:
    """Best native credential store for this platform."""
    if sys.platform.startswith("win"):
        # Git for Windows renamed the helper 'manager-core' -> 'manager' in 2.39;
        # pick whichever this install actually ships.
        for h in ("manager", "manager-core"):
            if _has_credential_backend(h):
                return h
        return "manager"
    if sys.platform == "darwin":
        return "osxkeychain"
    if _has_credential_backend("libsecret"):
        return "libsecret"
    for p in ("/usr/lib/git-core/git-credential-libsecret",
              "/usr/libexec/git-core/git-credential-libsecret"):
        if os.path.isfile(p):
            return "libsecret"
    return "store"  # plaintext ~/.git-credentials - callers warn about this


def _https_token_stored(host: str):
    """Non-interactive lookup: returns (username, password) or (None, None)."""
    if not host:
        return None, None
    rc, out, _ = _run_git_credential("fill", host, interactive=False)
    if rc != 0:
        return None, None
    return _parse_credential_output(out)


def _probe_token_api(host: str, token: str):
    """Hit the provider's /user endpoint.

    Returns (ok, who, detail, meta). meta may carry 'scopes' (list[str], possibly
    empty for a fine-grained token) and 'expires' (ISO date string).
    """
    h = (host or "").lower()
    is_github = (h == "github.com")
    is_bitbucket = (h == "bitbucket.org")
    if is_github:
        url, keys = "https://api.github.com/user", ("login",)
    elif is_bitbucket:
        url, keys = "https://api.bitbucket.org/2.0/user", ("username", "nickname")
    else:  # gitlab.com or self-hosted GitLab
        url, keys = f"https://{host}/api/v4/user", ("username",)

    def _get(u, timeout=15):
        req = urllib.request.Request(u, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "InsightsNet-GitRepo-Manager",
        })
        return urllib.request.urlopen(req, timeout=timeout)

    meta = {}
    try:
        with _get(url) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            if is_github:
                sc = resp.headers.get("X-OAuth-Scopes")
                if sc is not None:
                    meta["scopes"] = [s.strip() for s in sc.split(",") if s.strip()]
                exp = resp.headers.get("github-authentication-token-expiration")
                if exp:
                    meta["expires"] = exp.strip().split(" ")[0]
        who = next((str(data[k]) for k in keys if data.get(k)), None) or \
            data.get("name") or "(unknown)"
    except urllib.error.HTTPError as e:
        hint = {401: "invalid or expired token",
                403: "token lacks the required scope, or SSO is not authorised"}.get(e.code, "")
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        return False, "", f"HTTP {e.code} {hint}".strip() + (f"\n{body}" if body else ""), {}
    except Exception as e:
        return False, "", str(e), {}

    # GitLab exposes the current token's own scopes/expiry via a second endpoint.
    if not is_github and not is_bitbucket:
        try:
            with _get(f"https://{host}/api/v4/personal_access_tokens/self", timeout=10) as r2:
                t = json.loads(r2.read().decode("utf-8", "replace"))
            if isinstance(t, dict):
                if t.get("scopes"):
                    meta["scopes"] = list(t["scopes"])
                if t.get("expires_at"):
                    meta["expires"] = str(t["expires_at"])[:10]
        except Exception:
            pass

    return True, who, "", meta


def _days_until(iso_date: str):
    """Whole days from today to an ISO date/datetime, or None if unparseable."""
    for parse in (
        lambda s: datetime.datetime.fromisoformat(s.replace("Z", "+00:00")),
        lambda s: datetime.datetime.strptime(s[:10], "%Y-%m-%d"),
    ):
        try:
            return (parse(iso_date).date() - datetime.date.today()).days
        except Exception:
            continue
    return None


def _format_token_meta(meta: dict) -> str:
    """One-liner-per-fact summary of scopes / expiry for a token, or ''."""
    if not meta:
        return ""
    bits = []
    if "scopes" in meta:
        bits.append("Scopes: " + (", ".join(meta["scopes"]) if meta["scopes"]
                                  else "(none listed - fine-grained or scope-less token)"))
    exp = meta.get("expires")
    if exp:
        days = _days_until(exp)
        if days is None:
            bits.append(f"Expires: {exp}")
        elif days < 0:
            bits.append(f"Expires: {exp}  (EXPIRED)")
        else:
            bits.append(f"Expires: {exp}  ({days} day(s) left)")
    return "\n".join(bits)


# ---- Registry of hosts we've saved a token for (hostnames only, no secrets) ----

def _pat_registry_path() -> str:
    return os.path.join(os.path.expanduser("~"),
                        ".insightsnet_gitrepo_manager", "https_hosts.json")


def _pat_registry_load() -> list[str]:
    try:
        with open(_pat_registry_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return [str(x) for x in data.get("hosts", [])] if isinstance(data, dict) else []
    except Exception:
        return []


def _pat_registry_save(hosts) -> None:
    try:
        p = _pat_registry_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump({"hosts": sorted({h for h in hosts if h})}, fh, indent=2)
    except Exception:
        pass


def _pat_registry_add(host: str) -> None:
    if host:
        _pat_registry_save(_pat_registry_load() + [host])


def _pat_registry_remove(host: str) -> None:
    _pat_registry_save([h for h in _pat_registry_load() if h != host])


def _git_credentials_file_hosts() -> list:
    """(host, username) pairs from the plaintext 'store' helper files."""
    out = []
    for p in (os.path.join(os.path.expanduser("~"), ".git-credentials"),
              os.path.join(os.path.expanduser("~"), ".config", "git", "credentials")):
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if "://" not in line:
                        continue
                    try:
                        u = urlparse(line)
                    except ValueError:
                        continue
                    if u.hostname:
                        out.append((u.hostname, u.username or ""))
        except OSError:
            pass
    return out


def _windows_cred_hosts() -> list:
    """Hosts with a 'git:https://...' entry in Windows Credential Manager."""
    if not sys.platform.startswith("win"):
        return []
    try:
        res = subprocess.run(["cmdkey", "/list"], text=True, capture_output=True,
                             startupinfo=_win_startupinfo(), check=False)
    except Exception:
        return []
    return re.findall(r'git:https?://([^\s/]+)', res.stdout or "")


def _list_stored_https_credentials() -> list:
    """Best-effort inventory of hosts that have an HTTPS token on this machine."""
    seen = {}

    def _touch(host, source):
        host = (host or "").strip().lower()
        if not host:
            return None
        d = seen.setdefault(host, {"host": host, "username": "",
                                   "source": set(), "status": ""})
        d["source"].add(source)
        return d

    for hst in _pat_registry_load():
        _touch(hst, "app")
    for hst, usr in _git_credentials_file_hosts():
        d = _touch(hst, "git-credentials")
        if d and usr and not d["username"]:
            d["username"] = usr
    for hst in _windows_cred_hosts():
        _touch(hst, "credential-manager")

    rows = []
    for host, d in sorted(seen.items()):
        usr, pw = _https_token_stored(host)
        if pw:
            d["status"] = "valid"
            if usr:
                d["username"] = usr
        else:
            d["status"] = "not found"
        d["source"] = " + ".join(sorted(d["source"]))
        rows.append(d)
    return rows


def _pat_default_username(host: str) -> str:
    """Username that reliably pairs with a PAT for the given host."""
    h = (host or "").lower()
    if "gitlab" in h:
        return "oauth2"
    if h == "bitbucket.org":
        return ""  # Bitbucket needs the real account name; make the user supply it
    return "x-access-token"  # GitHub ignores the username with a PAT


def _save_https_token():
    """Store the PAT from the AuthN tab into the native git credential helper."""
    global auth_pat_host_var, auth_pat_user_var, auth_pat_token_var, auth_pat_status_var
    host = auth_pat_host_var.get().strip()
    user = auth_pat_user_var.get().strip()
    token = auth_pat_token_var.get().strip()
    if not host or not token:
        messagebox.showwarning("HTTPS Token", "Enter at least a host and a token.")
        return
    if "/" in host or " " in host:
        messagebox.showwarning("HTTPS Token", f"'{host}' is not a bare hostname.")
        return
    if not user:
        user = _pat_default_username(host)
        if not user:
            messagebox.showwarning(
                "HTTPS Token",
                "Enter the account username for this host (Bitbucket needs your "
                "real username, not an email).")
            return
        auth_pat_user_var.set(user)

    if not _persistent_cred_helper_present():
        helper = _default_credential_helper()
        extra = ("\n\nNOTE: no system keyring helper was found, so the token would "
                 "be saved in PLAINTEXT at ~/.git-credentials."
                 if helper == "store" else "")
        if not messagebox.askyesno(
            "HTTPS Token",
            "Git has no credential helper configured, so there is nowhere to keep "
            f"the token.\n\nConfigure '{helper}' in your global Git config now?{extra}"):
            return
        if not _git_global_set("credential.helper", helper):
            messagebox.showerror("HTTPS Token",
                                 "Failed to set credential.helper in global Git config.")
            return

    rc, out, err = _run_git_credential("approve", host, user, token)
    if rc != 0:
        messagebox.showerror("HTTPS Token",
                             f"git credential approve failed:\n{(err or out).strip()}")
        return
    _pat_registry_add(host)
    auth_pat_token_var.set("")  # don't leave the secret sitting in the widget
    auth_pat_status_var.set(f"Token stored for {user}@{host}.")
    messagebox.showinfo(
        "HTTPS Token",
        f"Token stored for {user}@{host} via your Git credential helper.\n\n"
        "HTTPS clone / fetch / push will now authenticate automatically.\n"
        'Use "Test Token" to verify it against the server.')


def _test_https_token():
    """Verify the stored (or typed) token really authenticates to the host."""
    global auth_pat_host_var, auth_pat_user_var, auth_pat_token_var, auth_pat_status_var
    host = auth_pat_host_var.get().strip()
    if not host:
        messagebox.showwarning("HTTPS Token", "Enter a host to test.")
        return
    user, token = _https_token_stored(host)
    from_store = bool(token)
    if not token:
        token = auth_pat_token_var.get().strip()
        user = user or auth_pat_user_var.get().strip()
    if not token:
        messagebox.showinfo(
            "HTTPS Token",
            f"No token is stored for {host}, and none is typed above.")
        return

    # If the token is already in the helper, the most honest check is a real git
    # operation against the loaded repo (when it lives on this host). A token that
    # is only typed (not yet saved) can't be exercised that way, so probe the API.
    origin_url = get_origin_url()
    oh, _ = _parse_origin_host_and_path()
    if from_store and repo and oh == host and origin_url.startswith(("http://", "https://")):
        try:
            repo.git.ls_remote(origin_url)
        except Exception as e:
            messagebox.showerror("HTTPS Token", f"ls-remote against origin failed:\n{e}")
            return
        _, _, _, meta = _probe_token_api(host, token)   # best-effort scope/expiry info
        extra = _format_token_meta(meta)
        status_extra = "  " + extra.replace("\n", "  ") if extra else ""
        auth_pat_status_var.set(f"Token OK for {host} (ls-remote succeeded).{status_extra}")
        messagebox.showinfo(
            "HTTPS Token",
            f"Success: authenticated to {host} and listed refs for the loaded repo."
            + (f"\n\n{extra}" if extra else ""))
        return

    ok, who, detail, meta = _probe_token_api(host, token)
    if ok:
        extra = _format_token_meta(meta)
        status_extra = "  " + extra.replace("\n", "  ") if extra else ""
        auth_pat_status_var.set(f"Token OK for {host} (as {who}).{status_extra}")
        messagebox.showinfo("HTTPS Token",
                            f"Success: authenticated to {host} as {who}."
                            + (f"\n\n{extra}" if extra else ""))
    else:
        messagebox.showerror("HTTPS Token", f"Token check failed for {host}:\n{detail}")


def _remove_https_token():
    """Drop the stored token for the host from the credential helper."""
    global auth_pat_host_var, auth_pat_user_var, auth_pat_status_var
    host = auth_pat_host_var.get().strip()
    if not host:
        messagebox.showwarning("HTTPS Token", "Enter the host whose token to remove.")
        return
    user, _ = _https_token_stored(host)
    user = user or auth_pat_user_var.get().strip()
    if not messagebox.askyesno("HTTPS Token",
                               f"Remove the stored HTTPS token for {host}?"):
        return
    rc, out, err = _run_git_credential("reject", host, user)
    if rc != 0:
        messagebox.showerror("HTTPS Token",
                             f"git credential reject failed:\n{(err or out).strip()}")
        return
    _pat_registry_remove(host)
    auth_pat_status_var.set(f"No token stored for {host}.")
    messagebox.showinfo("HTTPS Token", f"Removed the stored token for {host}.")


def _prefill_pat_fields():
    """Set the token host from the loaded repo's origin and report stored state."""
    if 'auth_pat_host_var' not in globals():
        return
    host, _ = _parse_origin_host_and_path()
    origin_url = get_origin_url()
    if not host or not origin_url.startswith(("http://", "https://")):
        if host:
            auth_pat_host_var.set(host)
        auth_pat_status_var.set("")
        return
    auth_pat_host_var.set(host)
    user, token = _https_token_stored(host)
    if token:
        if user:
            auth_pat_user_var.set(user)
        auth_pat_status_var.set(f"A token is already stored for {user or '?'}@{host}.")
    else:
        if not auth_pat_user_var.get().strip():
            auth_pat_user_var.set(_pat_default_username(host))
        auth_pat_status_var.set(f"No token stored for {host} yet.")


# =============== AuthN: HTTPS / SSH configuration windows ===============
# The Git AuthN tab shows only two buttons; each opens its method's full
# configuration in a separate window so the tab itself stays uncluttered.

_auth_child_windows = {}  # key -> Toplevel; each method opens at most one window


def _singleton_auth_window(key: str, title: str, geometry: str):
    """Return a fresh Toplevel for `key`, or None if one is already open (raised)."""
    w = _auth_child_windows.get(key)
    if w is not None:
        try:
            if w.winfo_exists():
                w.deiconify()
                w.lift()
                w.focus_set()
                return None
        except tk.TclError:
            pass
    w = Toplevel(root)
    w.title(title)
    w.transient(root)
    w.geometry(geometry)
    _auth_child_windows[key] = w
    return w


def open_stored_tokens_window():
    """Best-effort table of every host that has an HTTPS token on this machine."""
    win = _singleton_auth_window("https_stored", "Stored HTTPS Tokens", "660x360")
    if win is None:
        return

    frm = tk.Frame(win, padx=14, pady=12)
    frm.pack(fill="both", expand=True)
    tk.Label(frm, text="HTTPS tokens saved on this machine",
             font=("Arial", 11, "bold")).pack(anchor="w")
    tk.Label(frm, text="Collected from this app's own record, ~/.git-credentials, and "
             "(on Windows) Credential Manager. Passwords/tokens are never shown.",
             font=("Arial", 8), fg="#666", justify="left").pack(anchor="w", pady=(0, 8))

    table_wrap = tk.Frame(frm)
    table_wrap.pack(fill="both", expand=True)
    cols = ("host", "username", "source", "status")
    tree = ttk.Treeview(table_wrap, columns=cols, show="headings", selectmode="browse")
    for c, t, w in (("host", "Host", 210), ("username", "Username", 130),
                    ("source", "Source", 170), ("status", "Status", 90)):
        tree.heading(c, text=t)
        tree.column(c, width=w, anchor="w")
    vb = ttk.Scrollbar(table_wrap, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vb.set)
    tree.pack(side="left", fill="both", expand=True)
    vb.pack(side="right", fill="y")

    empty_lbl = tk.Label(frm, text="", font=("Arial", 9), fg="#a60")
    empty_lbl.pack(anchor="w", pady=(6, 0))

    def _refresh():
        # Enumeration spawns a `git credential fill` per host; do it off the UI thread.
        tree.delete(*tree.get_children())
        empty_lbl.config(text="Loading…")

        def work():
            try:
                rows = _list_stored_https_credentials()
            except Exception:
                rows = []

            def apply_rows():
                if not tree.winfo_exists():
                    return
                tree.delete(*tree.get_children())
                for d in rows:
                    tree.insert("", "end", iid=d["host"],
                                values=(d["host"], d["username"] or "-",
                                        d["source"], d["status"]))
                empty_lbl.config(text="" if rows else
                                 "No stored HTTPS tokens found. Save one from the HTTPS window.")

            _post_ui(apply_rows)

        threading.Thread(target=work, daemon=True).start()

    def _selected():
        sel = tree.selection()
        return sel[0] if sel else ""

    def _use():
        host = _selected()
        if not host:
            return
        auth_pat_host_var.set(host)
        usr, _ = _https_token_stored(host)
        auth_pat_user_var.set(usr or _pat_default_username(host))
        auth_pat_status_var.set(f"A token is stored for {usr or '?'}@{host}.")
        win.destroy()

    def _remove():
        host = _selected()
        if not host:
            return
        if not messagebox.askyesno("Stored HTTPS Tokens",
                                   f"Remove the stored token for {host}?", parent=win):
            return
        usr, _ = _https_token_stored(host)
        _run_git_credential("reject", host, usr or "")
        _pat_registry_remove(host)
        _refresh()

    btns = tk.Frame(frm)
    btns.pack(pady=(10, 0))
    tk.Button(btns, text="Use in form", command=_use, width=13).grid(row=0, column=0, padx=5)
    tk.Button(btns, text="Remove", command=_remove, width=11).grid(row=0, column=1, padx=5)
    tk.Button(btns, text="Refresh", command=_refresh, width=11).grid(row=0, column=2, padx=5)
    tk.Button(btns, text="Close", command=win.destroy, width=10).grid(row=0, column=3, padx=5)

    _refresh()
    win.focus_set()


def open_https_auth_window():
    """HTTPS Personal Access Token configuration in its own window."""
    win = _singleton_auth_window("https", "HTTPS Authentication", "560x470")
    if win is None:
        return

    frm = tk.Frame(win, padx=20, pady=18)
    frm.pack(fill="both", expand=True)

    tk.Label(frm, text="HTTPS Access Token", font=("Arial", 13, "bold")).pack(pady=(0, 4))
    tk.Label(
        frm,
        text="Saved in your OS credential helper (Git Credential Manager / Keychain / "
             "libsecret).\nOnce saved, HTTPS clone / fetch / push authenticate "
             "automatically.\n\n"
             "GitLab username: oauth2       GitHub username: x-access-token (any value works)\n"
             "Bitbucket: your real account username.",
        font=("Arial", 8), justify="center", fg="#555").pack(pady=(0, 12))

    host_frame = tk.Frame(frm); host_frame.pack(pady=4)
    tk.Label(host_frame, text="Host:", width=10, anchor="e").grid(row=0, column=0, padx=5)
    tk.Entry(host_frame, textvariable=auth_pat_host_var, width=38).grid(row=0, column=1)

    user_frame = tk.Frame(frm); user_frame.pack(pady=4)
    tk.Label(user_frame, text="Username:", width=10, anchor="e").grid(row=0, column=0, padx=5)
    tk.Entry(user_frame, textvariable=auth_pat_user_var, width=38).grid(row=0, column=1)

    token_frame = tk.Frame(frm); token_frame.pack(pady=4)
    tk.Label(token_frame, text="Token:", width=10, anchor="e").grid(row=0, column=0, padx=5)
    token_entry = tk.Entry(token_frame, textvariable=auth_pat_token_var, width=38, show="*")
    token_entry.grid(row=0, column=1)
    show_var = tk.BooleanVar(value=False)
    tk.Checkbutton(
        token_frame, text="show", variable=show_var,
        command=lambda: token_entry.config(show="" if show_var.get() else "*"),
    ).grid(row=0, column=2, padx=4)

    btn_frame = tk.Frame(frm); btn_frame.pack(pady=(14, 4))
    tk.Button(btn_frame, text="Save Token", command=_save_https_token, width=14).grid(row=0, column=0, padx=6)
    tk.Button(btn_frame, text="Test Token", command=_test_https_token, width=14).grid(row=0, column=1, padx=6)
    tk.Button(btn_frame, text="Remove Token", command=_remove_https_token, width=14).grid(row=0, column=2, padx=6)

    tk.Label(frm, textvariable=auth_pat_status_var, font=("Arial", 8), fg="#0a6",
             wraplength=480, justify="center").pack(pady=(6, 0))

    tk.Button(frm, text="Show stored tokens…", command=open_stored_tokens_window).pack(pady=(12, 0))
    tk.Button(frm, text="Close", command=win.destroy).pack(pady=(8, 0))

    _prefill_pat_fields()
    win.focus_set()


def open_ssh_auth_window():
    """SSH key management and the guided repo-connection steps in their own window."""
    win = _singleton_auth_window("ssh", "SSH Authentication", "620x470")
    if win is None:
        return

    frm = tk.Frame(win, padx=20, pady=18)
    frm.pack(fill="both", expand=True)

    tk.Label(frm, text="SSH keys", font=("Arial", 12, "bold")).pack(pady=(0, 4))
    key_row = tk.Frame(frm); key_row.pack(pady=(0, 12))
    tk.Button(key_row, text="Show Public Key", command=show_public_keys, width=20).grid(row=0, column=0, padx=8, pady=3)
    tk.Button(key_row, text="Generate SSH Key", command=generate_ssh_key_help, width=20).grid(row=0, column=1, padx=8, pady=3)
    tk.Button(key_row, text="Manage Server Keys", command=manage_server_keys, width=20).grid(row=1, column=0, padx=8, pady=3)

    tk.Label(frm, text="Repository SSH connection  (run in order)",
             font=("Arial", 12, "bold")).pack(pady=(8, 4))
    conn = tk.Frame(frm); conn.pack(pady=(0, 4))
    tk.Button(conn, text="1. Show Remote URLs", command=show_remote_urls, width=24).grid(row=0, column=0, padx=6, pady=3)
    tk.Button(conn, text="2. Convert Origin to SSH", command=convert_origin_to_ssh, width=24).grid(row=0, column=1, padx=6, pady=3)
    tk.Button(conn, text="3. Trust Server Host Key", command=trust_origin_host, width=24).grid(row=1, column=0, padx=6, pady=3)
    tk.Button(conn, text="4. Test SSH to Server", command=test_origin_ssh_guided, width=24).grid(row=1, column=1, padx=6, pady=3)
    tk.Button(conn, text="5. Verify with Fetch", command=verify_with_fetch, width=24).grid(row=2, column=0, padx=6, pady=3)

    tk.Label(frm, text="Diagnostics", font=("Arial", 12, "bold")).pack(pady=(10, 4))
    diag = tk.Frame(frm); diag.pack(pady=(0, 4))
    tk.Button(diag, text="Show Active Key for This Repo", command=show_active_key_for_repo, width=28).grid(row=0, column=0, padx=6, pady=3)
    tk.Button(diag, text="Check Git SSH Client", command=check_git_ssh_client, width=24).grid(row=0, column=1, padx=6, pady=3)

    tk.Button(frm, text="Close", command=win.destroy).pack(pady=(16, 0))
    win.focus_set()

# --- helpers: current branch + origin URL + SSH/remote tools ---

def _current_branch_name():
    """Return the active branch name or '' if detached."""
    try:
        return repo.active_branch.name
    except Exception:
        try:
            name = repo.git.rev_parse('--abbrev-ref', 'HEAD').strip()
            return '' if name == 'HEAD' else name
        except Exception:
            return ''

def _get_primary_remote():
    """
    Prefer a remote named 'origin'; otherwise return the first remote.
    Returns a git.Remote or None.
    """
    try:
        if not repo or not repo.remotes:
            return None
        for r in repo.remotes:
            if r.name == "origin":
                return r
        return repo.remotes[0]
    except Exception:
        return None

def _has_remote_origin():
    """Back-compat stub (kept so other code doesn't crash)."""
    return bool(_get_primary_remote())

def get_origin_url():
    """Return URL of the primary remote (origin preferred), or ''."""
    r = _get_primary_remote()
    try:
        return r.url if r else ""
    except Exception:
        return ""

# ---- origin parsing + SSH tools (GitHub/GitLab/self-hosted) ----

ORIGIN_PARSE_RE = re.compile(
    r"""
    (?:
        (?P<ssh_user>[^@]+)@(?P<ssh_host>[^:]+):(?P<ssh_path>.+)   # git@host:group/repo(.git)
      | https?://(?P<http_host>[^/]+)/(?P<http_path>.+)           # http(s)://host/group/repo(.git)
    )
    """,
    re.X | re.I
)

def _parse_origin_host_and_path():
    """Return (host, path_without_.git) from the primary remote URL."""
    url = get_origin_url()
    if not url:
        return "", ""
    m = ORIGIN_PARSE_RE.match(url)
    if not m:
        return "", ""
    if m.group("ssh_host"):
        host = m.group("ssh_host")
        path = m.group("ssh_path")
    else:
        host = m.group("http_host")
        path = m.group("http_path")
    if path.endswith(".git"):
        path = path[:-4]
    return host, path

def _ssh_test_to_host(host: str):
    """Common ssh -T tester with accept-new fallback and trust prompt.

    `host` may be a managed profile alias (ssh then reads its HostName / User /
    IdentityFile), a bare hostname, or an explicit 'user@host'. With no explicit
    user we use the login mapped for that server in ~/.ssh/config (default 'git').
    """
    _prof = next((h for h in _managed_hosts() if h["host"] == host), None)
    if _prof:
        target = _prof["host"]        # the alias; ssh_config supplies the rest
        host = _profile_server(_prof)
    else:
        user, host = _split_user_host(host)
        login = user or _login_for_host(host)
        target = f"{login}@{host}"
    startupinfo = None
    if sys.platform.startswith("win"):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    def run_ssh(args, feed_stdin=None):
        try:
            res = subprocess.run(
                args,
                input=feed_stdin,
                text=True,
                capture_output=True,
                startupinfo=startupinfo,
            )
            msg = (res.stdout or "") + (res.stderr or "")
            return res.returncode, msg.strip()
        except Exception as e:
            return 255, f"Failed to run ssh: {e}"

    # First try with StrictHostKeyChecking=accept-new (newer OpenSSH)
    rc, msg = run_ssh(["ssh", "-T", "-o", "StrictHostKeyChecking=accept-new", target])
    if rc != 255 or "unknown option -- o" not in msg.lower():
        messagebox.showinfo(f"SSH Test ({target})", msg or "(no output)")
        return

    # Fallback for older ssh: plain ssh -T
    rc2, msg2 = run_ssh(["ssh", "-T", target])
    lower = msg2.lower()
    if "continue connecting (yes/no" in lower or "authenticity of host" in lower:
        trust = messagebox.askyesno(
            f"Trust {host} host key?",
            f"The authenticity of host '{host}' can't be established.\n\n"
            "Do you want to trust this host key and continue?"
        )
        if trust:
            rc3, msg3 = run_ssh(["ssh", "-T", target], feed_stdin="yes\n")
            messagebox.showinfo(f"SSH Test ({target})", msg3 or "(no output)")
        else:
            messagebox.showinfo(f"SSH Test ({target})", "Aborted by user.")
        return

    messagebox.showinfo(f"SSH Test ({target})", msg2 or "(no output)")

def _default_ssh_dir() -> str:
    """Default per-user SSH directory (~/.ssh) on Windows, macOS and Linux."""
    return os.path.join(os.path.expanduser("~"), ".ssh")


def show_public_keys():
    """List every *.pub key in the user's default ~/.ssh directory in a table."""
    ssh_dir = _default_ssh_dir()

    pub_files = []
    if os.path.isdir(ssh_dir):
        try:
            for name in sorted(os.listdir(ssh_dir)):
                full = os.path.join(ssh_dir, name)
                if name.lower().endswith(".pub") and os.path.isfile(full):
                    try:
                        with open(full, "r", encoding="utf-8", errors="replace") as fh:
                            content = fh.read().strip()
                    except Exception as e:
                        content = f"(could not read: {e})"
                    pub_files.append((name, content))
        except Exception as e:
            messagebox.showerror("Public Keys", f"Could not read SSH directory:\n{ssh_dir}\n\n{e}")
            return

    if not pub_files:
        want = messagebox.askyesno(
            "Public Keys",
            "There is no public/private key in this system.\n\n"
            f"Looked in: {ssh_dir}"
            + ("" if os.path.isdir(ssh_dir) else "\n(directory does not exist)")
            + "\n\nTo generate a new key, use the \"Generate SSH Key\" button.\n"
            "Open those instructions now?",
        )
        if want:
            generate_ssh_key_help()
        return

    popup = Toplevel(root)
    popup.title("SSH Public Keys")
    popup.geometry("900x420")
    popup.minsize(600, 300)
    popup.transient(root)

    popup.grid_rowconfigure(2, weight=1)
    popup.grid_columnconfigure(0, weight=1)

    tk.Label(popup, text="SSH Public Keys", font=("Arial", 12, "bold")).grid(
        row=0, column=0, sticky="w", padx=10, pady=(10, 2)
    )
    tk.Label(popup, text=f".ssh directory:  {ssh_dir}", font=("Arial", 9)).grid(
        row=1, column=0, sticky="w", padx=10, pady=(0, 6)
    )

    table_wrap = tk.Frame(popup)
    table_wrap.grid(row=2, column=0, sticky="nsew", padx=10, pady=0)
    table_wrap.grid_rowconfigure(0, weight=1)
    table_wrap.grid_columnconfigure(0, weight=1)

    cols = ("file_name", "public_key")
    tree = ttk.Treeview(table_wrap, columns=cols, show="headings")
    tree.heading("file_name", text="file_name")
    tree.heading("public_key", text="public_key")
    tree.column("file_name", width=160, minwidth=120, stretch=False, anchor="w")
    tree.column("public_key", width=1400, minwidth=300, stretch=False, anchor="w")

    vbar = ttk.Scrollbar(table_wrap, orient="vertical", command=tree.yview)
    hbar = ttk.Scrollbar(table_wrap, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vbar.grid(row=0, column=1, sticky="ns")
    hbar.grid(row=1, column=0, sticky="ew")

    for name, content in pub_files:
        tree.insert("", "end", values=(name, content.replace("\n", " ")))

    def _copy_selected():
        sel = tree.selection()
        if not sel:
            return
        key_text = tree.item(sel[0], "values")[1]
        popup.clipboard_clear()
        popup.clipboard_append(key_text)

    btn_row = tk.Frame(popup)
    btn_row.grid(row=3, column=0, sticky="e", padx=10, pady=8)
    tk.Button(btn_row, text="Copy selected key", command=_copy_selected).pack(side="left", padx=4)
    tk.Button(btn_row, text="Close", command=popup.destroy).pack(side="left", padx=4)


def _best_identity_email() -> str:
    """Best guess at the user's email for the ssh-keygen -C comment."""
    try:
        v = auth_email_var.get().strip()
        if v:
            return v
    except Exception:
        pass
    try:
        v = _git_global_get("user.email")
        if v:
            return v.strip()
    except Exception:
        pass
    return "YOUR_EMAIL_ADDRESS"


def generate_ssh_key_help():
    """Show the ssh-keygen command (copyable) plus step-by-step instructions."""
    ssh_dir = _default_ssh_dir()

    popup = Toplevel(root)
    popup.title("Generate SSH Key")
    popup.geometry("680x520")
    popup.minsize(560, 440)
    popup.transient(root)
    popup.grid_columnconfigure(0, weight=1)
    popup.grid_rowconfigure(4, weight=1)

    tk.Label(popup, text="Generate a new SSH key", font=("Arial", 12, "bold")).grid(
        row=0, column=0, sticky="w", padx=12, pady=(12, 2)
    )

    # --- Comment (-C) field: the user's preferred label for the key ---
    # Only letters, digits and @ . - _ are allowed. This keeps the value safe
    # inside the -C "..." shell argument (no quotes, spaces, slashes, commas).
    _allowed_comment_re = re.compile(r"^[A-Za-z0-9@._-]*$")

    def _sanitize_comment(s: str) -> str:
        return re.sub(r"[^A-Za-z0-9@._-]", "", s or "")

    comment_var = tk.StringVar(value=_sanitize_comment(_best_identity_email()))
    cmt_row = tk.Frame(popup)
    cmt_row.grid(row=1, column=0, sticky="ew", padx=12, pady=(4, 2))
    cmt_row.grid_columnconfigure(1, weight=1)
    tk.Label(cmt_row, text="Your preferred comment:", font=("Arial", 9)).grid(
        row=0, column=0, sticky="w"
    )

    def _validate_comment(proposed: str) -> bool:
        if _allowed_comment_re.match(proposed):
            cmt_hint.configure(
                text="This goes after -C in the command below (usually your email; "
                     "it is just a label and can be changed later).",
                fg="#555",
            )
            return True
        cmt_hint.configure(
            text="Only letters, digits and  @ . - _  are allowed "
                 "(no spaces, quotes, commas or slashes).",
            fg="#b00020",
        )
        cmt_row.after(1800, lambda: cmt_hint.configure(
            text="This goes after -C in the command below (usually your email; "
                 "it is just a label and can be changed later).",
            fg="#555"))
        return False

    cmt_hint = tk.Label(
        cmt_row,
        text="This goes after -C in the command below (usually your email; "
             "it is just a label and can be changed later).",
        font=("Arial", 8), fg="#555", wraplength=620, justify="left",
    )
    cmt_hint.grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))

    _vcmd = (cmt_row.register(_validate_comment), "%P")
    cmt_entry = tk.Entry(cmt_row, textvariable=comment_var, font=("Consolas", 10),
                         validate="key", validatecommand=_vcmd)
    cmt_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), ipady=2)

    tk.Label(popup, text="Run this command in your terminal:", font=("Arial", 9)).grid(
        row=2, column=0, sticky="w", padx=12, pady=(6, 2)
    )

    cmd_row = tk.Frame(popup)
    cmd_row.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 6))
    cmd_row.grid_columnconfigure(0, weight=1)
    cmd_entry = tk.Entry(cmd_row, font=("Consolas", 10))
    cmd_entry.grid(row=0, column=0, sticky="ew", ipady=4)

    def _current_command() -> str:
        c = _sanitize_comment(comment_var.get().strip())
        return f'ssh-keygen -t ed25519 -C "{c}"' if c else "ssh-keygen -t ed25519"

    def _refresh_cmd(*_):
        cmd_entry.configure(state="normal")
        cmd_entry.delete(0, tk.END)
        cmd_entry.insert(0, _current_command())
        cmd_entry.configure(state="readonly")

    _refresh_cmd()
    comment_var.trace_add("write", _refresh_cmd)

    def _copy_cmd():
        popup.clipboard_clear()
        popup.clipboard_append(_current_command())
        copy_btn.configure(text="Copied!")
        popup.after(1200, lambda: copy_btn.configure(text="Copy command"))

    copy_btn = tk.Button(cmd_row, text="Copy command", command=_copy_cmd)
    copy_btn.grid(row=0, column=1, padx=(8, 0))

    steps_before = (
        "Steps\n"
        "1. Open your default terminal.\n"
        "   - On Windows, PowerShell is preferred (from our side).\n"
        "   - On macOS / Linux, use the Terminal app.\n"
        "2. Do NOT change any directory or path - just leave the terminal\n"
        "   where it opens (your home folder).\n"
        "3. In the \"Your preferred comment\" field above, type the label you\n"
        "   want for this key (usually your email). It is placed after -C in\n"
        "   the command.\n"
        "4. Paste and run the command above.\n"
        "5. Press Enter at every prompt to accept the defaults\n"
        "   (default file location, and an empty passphrase if you prefer).\n"
        "6. The key pair is created in:\n   "
    )
    steps_after = (
        "\n   (private key: id_ed25519   |   public key: id_ed25519.pub)\n"
        "7. Come back here and click \"Show Public Key\" - your new public\n"
        "   key will be listed there, ready to copy into GitHub / GitLab.\n\n"
        "Note: the -C value is just a label (the comment you set above, usually\n"
        "your email). It does not have to match anything and can be changed later."
    )
    txt = scrolledtext.ScrolledText(popup, wrap="word", font=("Arial", 9), height=12)
    txt.grid(row=4, column=0, sticky="nsew", padx=12, pady=(4, 6))
    txt.tag_configure(
        "sshpath",
        font=("Consolas", 9, "bold"),
        background="#fff3b0",
        foreground="#000000",
    )
    txt.insert("1.0", steps_before)
    txt.insert("end", ssh_dir, "sshpath")
    txt.insert("end", steps_after)
    txt.configure(state="disabled")

    tk.Button(popup, text="Close", command=popup.destroy).grid(
        row=5, column=0, sticky="e", padx=12, pady=(0, 12)
    )


# =============== SSH config (~/.ssh/config) management ===============
# The app owns ONLY the fenced region below. Anything outside the fence is
# the user's and is never rewritten. Each managed Host block maps one GitLab
# server to one private key, with IdentitiesOnly so SSH uses exactly that key.

SSH_CFG_FENCE_START = "# >>> insightsnet-gitrepo-manager >>>"
SSH_CFG_FENCE_END = "# <<< insightsnet-gitrepo-manager <<<"


def _ssh_config_path() -> str:
    return os.path.join(_default_ssh_dir(), "config")


def _ensure_ssh_dir() -> str:
    """Create ~/.ssh (0700 on POSIX) if missing; return its path."""
    d = _default_ssh_dir()
    try:
        os.makedirs(d, exist_ok=True)
        if not sys.platform.startswith("win"):
            os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def _read_ssh_config_parts():
    """Split ~/.ssh/config into (before, managed_body, after) around the fence.

    managed_body is the text between the two fence markers (markers excluded).
    No file, or a missing/broken fence -> ("<all text>", "", "").
    """
    path = _ssh_config_path()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return "", "", ""

    start = text.find(SSH_CFG_FENCE_START)
    if start == -1:
        return text, "", ""
    end = text.find(SSH_CFG_FENCE_END, start)
    if end == -1:
        return text, "", ""
    before = text[:start]
    managed = text[start + len(SSH_CFG_FENCE_START):end]
    after = text[end + len(SSH_CFG_FENCE_END):]
    return before, managed.strip("\n"), after


def _parse_host_blocks(body: str) -> list[dict]:
    """Parse `Host` blocks out of SSH-config text."""
    hosts: list[dict] = []
    cur = None
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, val = line.partition(" ")
        val = val.strip()
        if val.startswith("="):
            val = val[1:].strip()
        kl = key.lower()
        if kl == "host":
            if cur:
                hosts.append(cur)
            cur = {"host": val, "hostname": "", "user": "",
                   "identityfile": "", "identitiesonly": ""}
        elif cur is not None:
            if kl in cur:
                cur[kl] = val
    if cur:
        hosts.append(cur)
    return hosts


def _managed_hosts() -> list[dict]:
    """Host blocks inside the app-managed fence."""
    _, body, _ = _read_ssh_config_parts()
    return _parse_host_blocks(body)


def _unmanaged_host_conflict(host: str) -> bool:
    """True if `host` has a Host block OUTSIDE the managed fence."""
    before, _, after = _read_ssh_config_parts()
    outside = _parse_host_blocks(before + "\n" + after)
    return any(h["host"] == host for h in outside)


def _identity_for_host(host: str) -> str:
    """IdentityFile of the canonical managed profile for `host`, or ''."""
    ps = _profiles_for_host(host)
    return ps[0].get("identityfile", "") if ps else ""


def _render_host_block(h: dict) -> str:
    return "\n".join([
        f"Host {h['host']}",
        f"    HostName {h.get('hostname') or h['host']}",
        f"    User {h.get('user') or 'git'}",
        f"    IdentityFile {h['identityfile']}",
        "    IdentitiesOnly yes",
    ])


def _render_managed_block(hosts: list[dict]) -> str:
    inner = "\n\n".join(_render_host_block(h) for h in hosts)
    return (
        f"{SSH_CFG_FENCE_START}\n"
        "# Managed automatically by InsightsNet GitRepo Manager.\n"
        "# Edit these entries from the app's SSH keys section, not by hand.\n"
        + (inner + "\n" if inner else "")
        + f"{SSH_CFG_FENCE_END}\n"
    )


def _backup_ssh_config() -> str | None:
    """Copy config -> config.bak-<timestamp>; return backup path or None."""
    path = _ssh_config_path()
    if not os.path.isfile(path):
        return None
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = f"{path}.bak-{stamp}"
    n = 1
    while os.path.exists(dst):
        dst = f"{path}.bak-{stamp}-{n}"
        n += 1
    try:
        shutil.copyfile(path, dst)
        return dst
    except OSError:
        return None


def _write_managed_hosts(hosts: list[dict]) -> str | None:
    """Rewrite the managed fence with `hosts` (backup first). Returns backup path."""
    _ensure_ssh_dir()
    before, _, after = _read_ssh_config_parts()
    backup = _backup_ssh_config()

    before = before.rstrip("\n")
    after = after.lstrip("\n")
    chunks = []
    if before:
        chunks.append(before + "\n\n")
    chunks.append(_render_managed_block(hosts))
    if after:
        chunks.append("\n" + after)
    new_text = "".join(chunks)
    if not new_text.endswith("\n"):
        new_text += "\n"

    path = _ssh_config_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(new_text)
    os.replace(tmp, path)
    if not sys.platform.startswith("win"):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return backup


def _profile_server(h: dict) -> str:
    """The real GitLab hostname a managed block points at (HostName, else alias)."""
    return h.get("hostname") or h.get("host", "")


def _profiles_for_host(host: str) -> list[dict]:
    """Every managed profile whose server (or alias) is `host`, canonical first.

    Multiple profiles per server are allowed; the one whose alias equals the
    hostname (the plain-'git@host' default) is returned first.
    """
    if not host:
        return []
    out = [h for h in _managed_hosts()
           if h.get("host") == host or _profile_server(h) == host]
    out.sort(key=lambda h: 0 if h.get("host") == _profile_server(h) else 1)
    return out


def _profile_alias(hostname: str, user: str, taken) -> str:
    """A unique managed 'Host' alias for one (hostname, login) profile."""
    user = user or "git"
    base = hostname if user == "git" else f"{hostname}-{user}"
    if base not in taken:
        return base
    n = 2
    while f"{base}-{n}" in taken:
        n += 1
    return f"{base}-{n}"


def _upsert_profile(hostname: str, identity_path: str, user: str,
                    alias: str | None = None) -> str | None:
    """Add a managed SSH profile, or update the one named `alias`. Returns backup.

    Servers may have several profiles (different logins / keys). When editing
    (`alias` given) that profile is updated. When adding, an identical profile
    (same server + login + key) is left as-is; anything else becomes a new entry
    with its own alias — an existing profile is never silently overwritten.
    """
    user = user or "git"
    hosts = _managed_hosts()
    taken = {h["host"] for h in hosts}

    target = None
    if alias:
        target = next((h for h in hosts if h["host"] == alias), None)
    if target is None:
        target = next((h for h in hosts
                       if _profile_server(h) == hostname
                       and (h.get("user") or "git") == user
                       and h.get("identityfile") == identity_path), None)

    if target is not None:
        target["hostname"] = hostname
        target["user"] = user
        target["identityfile"] = identity_path
    else:
        hosts.append({"host": _profile_alias(hostname, user, taken),
                      "hostname": hostname, "user": user,
                      "identityfile": identity_path, "identitiesonly": "yes"})
    return _write_managed_hosts(hosts)


def _remove_host_identity(alias: str) -> str | None:
    """Drop the managed profile named `alias`; returns backup path."""
    hosts = [h for h in _managed_hosts() if h["host"] != alias]
    return _write_managed_hosts(hosts)


def _repair_managed_ssh_config() -> bool:
    """Fix malformed managed Host blocks written by older versions.

    Those glued the login onto the alias ('Host ccl@git.example.com') instead of
    'Host git.example.com' + 'User ccl'. Rewrite each such block into a proper
    profile (bare hostname as HostName, 'user@' moved to the User line, a unique
    alias), keeping it as its own entry so nothing is silently merged away.
    Returns True if anything changed.
    """
    hosts = _managed_hosts()
    if not any("@" in h.get("host", "") or "@" in h.get("hostname", "") for h in hosts):
        return False

    fixed: list[dict] = []
    taken: set = set()
    for h in hosts:
        alias = h.get("host", "")
        user = h.get("user") or ""
        hn = h.get("hostname") or alias
        if "@" in alias:
            u, _, bare = alias.partition("@")
            if u and (not user or user == "git"):
                user = u
            alias = bare or alias
        if "@" in hn:
            hn = hn.split("@", 1)[1]
        hn = hn or alias
        user = user or "git"
        # drop an exact duplicate of one we already kept
        if any(f.get("hostname") == hn and (f.get("user") or "git") == user
               and f.get("identityfile") == h.get("identityfile") for f in fixed):
            continue
        new_alias = alias if alias and alias not in taken else \
            _profile_alias(hn, user, taken)
        taken.add(new_alias)
        fixed.append({**h, "host": new_alias, "hostname": hn, "user": user})

    _write_managed_hosts(fixed)
    return True


def _list_private_keys() -> list[str]:
    """Basenames in ~/.ssh that have a matching .pub sibling (i.e. real key pairs)."""
    d = _default_ssh_dir()
    out = []
    if os.path.isdir(d):
        for name in sorted(os.listdir(d)):
            if name.endswith(".pub"):
                base = name[:-4]
                if os.path.isfile(os.path.join(d, base)):
                    out.append(base)
    return out


def _suggest_key_name(host: str) -> str:
    """gitlab.dlr.de -> id_ed25519_dlr ; gitlab.uni-rostock.de -> id_ed25519_uni_rostock."""
    parts = [p for p in host.split(".") if p and p not in ("gitlab", "www")]
    slug = parts[0] if parts else host
    slug = re.sub(r"[^A-Za-z0-9]+", "_", slug).strip("_").lower() or "key"
    return f"id_ed25519_{slug}"


def _tilde_path(abspath: str) -> str:
    """Rewrite a path under the home dir back to ~/... (forward slashes) for config."""
    home = os.path.expanduser("~")
    try:
        if os.path.commonpath([os.path.abspath(abspath), home]) == home:
            rel = os.path.relpath(os.path.abspath(abspath), home).replace("\\", "/")
            return f"~/{rel}"
    except ValueError:
        pass
    return abspath.replace("\\", "/")


def _win_startupinfo():
    if sys.platform.startswith("win"):
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return si
    return None


def _expand_key_path(p: str) -> str:
    """Expand ~ and env vars in a config IdentityFile value to an absolute path."""
    return os.path.abspath(os.path.expanduser(os.path.expandvars(p or "")))


def _run_ssh_keygen(key_path: str, email: str):
    """Create an ed25519 key pair non-interactively. Returns (ok, message)."""
    try:
        res = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", "", "-C", email or ""],
            text=True, capture_output=True, startupinfo=_win_startupinfo(),
        )
        return res.returncode == 0, ((res.stdout or "") + (res.stderr or "")).strip()
    except FileNotFoundError:
        return False, "ssh-keygen not found. Install the OpenSSH client and retry."
    except Exception as e:
        return False, f"Failed to run ssh-keygen: {e}"


def _read_pub_for_identity(identityfile: str) -> str:
    """Return the contents of <identityfile>.pub, or '' if not readable."""
    p = _expand_key_path(identityfile) + ".pub"
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _origin_host_or_blank() -> str:
    host, _ = _parse_origin_host_and_path()
    return host or ""


def manage_server_keys():
    """View / edit the per-GitLab-server SSH identity mappings in ~/.ssh/config."""
    try:
        _repair_managed_ssh_config()
    except Exception:
        pass
    popup = Toplevel(root)
    popup.title("Manage Server Keys")
    popup.geometry("820x460")
    popup.minsize(680, 360)
    popup.transient(root)
    popup.grid_columnconfigure(0, weight=1)
    popup.grid_rowconfigure(2, weight=1)

    tk.Label(popup, text="Per-server SSH identities", font=("Arial", 12, "bold")).grid(
        row=0, column=0, sticky="w", padx=12, pady=(12, 2)
    )
    path_lbl = tk.Label(popup, text="", font=("Arial", 9), fg="#444")
    path_lbl.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 6))

    table_wrap = tk.Frame(popup)
    table_wrap.grid(row=2, column=0, sticky="nsew", padx=12)
    table_wrap.grid_rowconfigure(0, weight=1)
    table_wrap.grid_columnconfigure(0, weight=1)

    cols = ("host", "login", "key", "pub", "status")
    tree = ttk.Treeview(table_wrap, columns=cols, show="headings", selectmode="browse")
    for c, t, w in (("host", "GitLab server", 210), ("login", "SSH login", 90),
                    ("key", "Key file", 220),
                    ("pub", ".pub?", 60), ("status", "Status", 170)):
        tree.heading(c, text=t)
        tree.column(c, width=w, anchor="w", stretch=(c == "status"))
    vbar = ttk.Scrollbar(table_wrap, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vbar.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vbar.grid(row=0, column=1, sticky="ns")

    active_lbl = tk.Label(popup, text="", font=("Arial", 9), justify="left")
    active_lbl.grid(row=3, column=0, sticky="w", padx=12, pady=(8, 2))

    def _refresh():
        tree.delete(*tree.get_children())
        path_lbl.config(text=f"~/.ssh/config :  {_ssh_config_path()}")
        for h in _managed_hosts():
            ident = h.get("identityfile", "")
            has_pub = os.path.isfile(_expand_key_path(ident) + ".pub") if ident else False
            has_priv = os.path.isfile(_expand_key_path(ident)) if ident else False
            if not ident:
                status = "no key set"
            elif not has_priv:
                status = "private key missing"
            elif not has_pub:
                status = "key present, .pub missing"
            else:
                status = "OK"
            tree.insert("", "end", iid=h["host"],
                        values=(_profile_server(h), h.get("user") or "git",
                                os.path.basename(ident) or "(none)",
                                "yes" if has_pub else "no", status))
        oh = _origin_host_or_blank()
        if oh:
            profs = _profiles_for_host(oh)
            if profs:
                names = ", ".join(f"{p.get('user') or 'git'} ({os.path.basename(p.get('identityfile',''))})"
                                  for p in profs)
                active_lbl.config(
                    text=f"Loaded repo host: {oh}\nProfile(s): {names}", fg="#0a0")
                first_alias = profs[0]["host"]
                if first_alias in tree.get_children():
                    tree.selection_set(first_alias)
            else:
                active_lbl.config(
                    text=f"Loaded repo host: {oh}\nNo key mapped for this server yet "
                         f"— use Add mapping to set one.", fg="#a60")
        else:
            active_lbl.config(text="No repo loaded (or remote is not recognised).", fg="#666")

    def _selected_host():
        sel = tree.selection()
        return sel[0] if sel else ""

    def _selected_profile():
        a = _selected_host()
        return next((h for h in _managed_hosts() if h["host"] == a), None)

    def _open_editor(host_prefill="", edit_alias=None):
        if edit_alias:
            prof = next((h for h in _managed_hosts() if h["host"] == edit_alias), None)
            if not prof:
                return
            hn = _profile_server(prof)
            u = prof.get("user") or "git"
            host_prefill = f"{u}@{hn}" if u != "git" else hn
        _key_mapping_editor(popup, host_prefill, _refresh, edit_alias)

    def _edit_selected():
        a = _selected_host()
        if a:
            _open_editor(edit_alias=a)

    def _remove():
        prof = _selected_profile()
        if not prof:
            return
        label = f"{prof.get('user') or 'git'}@{_profile_server(prof)}"
        if not messagebox.askyesno(
            "Remove mapping",
            f"Remove this managed SSH profile?\n\n{label}\n"
            f"key: {os.path.basename(prof.get('identityfile',''))}\n\n"
            "The key files on disk are NOT deleted.", parent=popup):
            return
        try:
            bak = _remove_host_identity(prof["host"])
            _refresh()
            messagebox.showinfo("Removed", f"Removed {label}."
                                + (f"\nBackup: {bak}" if bak else ""), parent=popup)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=popup)

    def _test():
        a = _selected_host()
        if a:
            _ssh_test_to_host(a)

    def _show_pub():
        prof = _selected_profile()
        if not prof:
            return
        server = _profile_server(prof)
        ident = prof.get("identityfile", "")
        pub = _read_pub_for_identity(ident)
        if not pub:
            messagebox.showinfo("Public key", f"No .pub found for:\n{ident}", parent=popup)
            return
        w = Toplevel(popup)
        w.title(f"{server} — public key")
        w.geometry("760x200")
        w.transient(popup)
        tk.Label(w, text=f"{os.path.basename(ident)}.pub  —  paste into "
                 f"https://{server}/-/user_settings/ssh_keys", font=("Arial", 9)).pack(
            anchor="w", padx=10, pady=(10, 4))
        t = scrolledtext.ScrolledText(w, wrap="word", height=5, font=("Consolas", 9))
        t.pack(fill="both", expand=True, padx=10, pady=4)
        t.insert("1.0", pub)
        t.configure(state="disabled")
        def _copy():
            w.clipboard_clear(); w.clipboard_append(pub)
        tk.Button(w, text="Copy", command=_copy).pack(side="left", padx=10, pady=8)
        tk.Button(w, text="Close", command=w.destroy).pack(side="left", pady=8)

    btn_row = tk.Frame(popup)
    btn_row.grid(row=4, column=0, sticky="w", padx=12, pady=10)
    tk.Button(btn_row, text="Add mapping", command=lambda: _open_editor(_origin_host_or_blank())).pack(side="left", padx=4)
    tk.Button(btn_row, text="Edit selected", command=_edit_selected).pack(side="left", padx=4)
    tk.Button(btn_row, text="Remove", command=_remove).pack(side="left", padx=4)
    tk.Button(btn_row, text="Test selected", command=_test).pack(side="left", padx=4)
    tk.Button(btn_row, text="Show .pub", command=_show_pub).pack(side="left", padx=4)
    tk.Button(btn_row, text="Close", command=popup.destroy).pack(side="left", padx=4)

    _refresh()


def _key_mapping_editor(parent, host_prefill, on_done, edit_alias=None):
    """Sub-dialog: choose (or generate) the key for one GitLab-server SSH profile.

    `edit_alias` is the managed Host alias being edited; None means add a new
    profile (a server may have several, one per login / key).
    """
    win = Toplevel(parent)
    win.title("Edit SSH profile" if edit_alias else "Add SSH profile")
    win.geometry("560x360")
    win.transient(parent)
    win.grab_set()
    win.grid_columnconfigure(0, weight=1)

    tk.Label(win, text="GitLab server — hostname or any URL from it.\n"
             "Prefix with 'user@' only if the server needs a non-'git' login "
             "(e.g. ccl@git.linglit.tu-darmstadt.de).\n"
             "You can add more than one profile per server.", font=("Arial", 9),
             justify="left").grid(row=0, column=0, sticky="w", padx=12, pady=(14, 2))
    _pf_user, _pf_host = _split_user_host(host_prefill or "")
    host_var = tk.StringVar(value=f"{_pf_user}@{_pf_host}" if _pf_user else (_pf_host or ""))
    host_entry = tk.Entry(win, textvariable=host_var, font=("Consolas", 10))
    host_entry.grid(row=1, column=0, sticky="ew", padx=12)

    def _normalize_host(*_):
        raw = host_var.get()
        user, h = _split_user_host(raw)
        norm = f"{user}@{h}" if user else h
        if h and norm != raw:
            host_var.set(norm)
    host_entry.bind("<FocusOut>", _normalize_host)

    tk.Label(win, text="Key to use for this server:", font=("Arial", 9)).grid(
        row=2, column=0, sticky="w", padx=12, pady=(14, 2))

    keys = _list_private_keys()
    if edit_alias:
        _ep = next((h for h in _managed_hosts() if h["host"] == edit_alias), None)
        existing = _ep.get("identityfile", "") if _ep else ""
    else:
        existing = ""
    existing_base = os.path.basename(existing) if existing else ""
    key_var = tk.StringVar(value=existing_base if existing_base in keys
                           else (keys[0] if keys else "__new__"))

    radio_wrap = tk.Frame(win)
    radio_wrap.grid(row=3, column=0, sticky="w", padx=12)

    def _sync_newname_enabled(*_):
        state = "normal" if key_var.get() == "__new__" else "disabled"
        newname_entry.config(state=state)
        newname_lbl.config(fg="#000" if state == "normal" else "#999")

    for k in keys:
        tk.Radiobutton(radio_wrap, text=k, value=k, variable=key_var,
                       command=_sync_newname_enabled).pack(anchor="w")
    tk.Radiobutton(radio_wrap, text="Generate a new key…", value="__new__",
                   variable=key_var, command=_sync_newname_enabled).pack(anchor="w")

    newname_frame = tk.Frame(win)
    newname_frame.grid(row=4, column=0, sticky="ew", padx=12, pady=(6, 0))
    newname_lbl = tk.Label(newname_frame, text="New key file name:", font=("Arial", 9))
    newname_lbl.pack(side="left")
    newname_var = tk.StringVar(value=_suggest_key_name(_pf_host) if _pf_host else "id_ed25519_key")
    newname_entry = tk.Entry(newname_frame, textvariable=newname_var, font=("Consolas", 10), width=28)
    newname_entry.pack(side="left", padx=6)

    _newname_touched = {"v": False}
    def _mark_touched(*_):
        _newname_touched["v"] = True
    newname_entry.bind("<KeyRelease>", _mark_touched)

    def _sync_newname(*_):
        if not _newname_touched["v"]:
            h = _host_from_any(host_var.get())
            if h:
                newname_var.set(_suggest_key_name(h))
    host_var.trace_add("write", _sync_newname)
    _sync_newname_enabled()

    status = tk.Label(win, text="", font=("Arial", 9), fg="#a60", wraplength=520, justify="left")
    status.grid(row=5, column=0, sticky="w", padx=12, pady=(10, 0))

    def _save():
        user, host = _split_user_host(host_var.get())
        host_var.set(f"{user}@{host}" if user else host)
        if not host or " " in host or "/" in host or "." not in host:
            status.config(text="Enter a hostname or a URL, e.g. gitlab.dlr.de "
                               "(optionally 'user@host').")
            return
        if _unmanaged_host_conflict(host):
            status.config(text=f"'{host}' is already configured manually in ~/.ssh/config "
                               "(outside the managed section). Resolve that entry first.")
            return

        choice = key_var.get()
        ssh_dir = _default_ssh_dir()
        if choice == "__new__":
            name = newname_var.get().strip()
            if not name:
                status.config(text="Enter a file name for the new key.")
                return
            key_path = os.path.join(ssh_dir, name)
            if os.path.exists(key_path) or os.path.exists(key_path + ".pub"):
                status.config(text=f"{name} already exists in ~/.ssh — pick another name.")
                return
            _ensure_ssh_dir()
            ok, msg = _run_ssh_keygen(key_path, _best_identity_email())
            if not ok:
                messagebox.showerror("ssh-keygen failed", msg, parent=win)
                return
            identity = _tilde_path(key_path)
        else:
            key_path = os.path.join(ssh_dir, choice)
            identity = _tilde_path(key_path)

        try:
            # The editor always shows the current login as a 'user@' prefix, so
            # an empty prefix here is an explicit choice of the default 'git'.
            bak = _upsert_profile(host, identity, user or "git", alias=edit_alias)
        except Exception as e:
            messagebox.showerror("Error", f"Could not write ~/.ssh/config:\n{e}", parent=win)
            return

        pub = _read_pub_for_identity(identity)
        login = user or "git"
        win.destroy()
        on_done()
        info = (f"Mapped {login}@{host}  →  {identity}\n"
                + (f"Backup: {bak}\n" if bak else "")
                + ("\nAdd this public key to the server "
                   f"(https://{host}/-/user_settings/ssh_keys):\n\n{pub}" if pub else ""))
        messagebox.showinfo("Mapping saved", info, parent=parent)

    btns = tk.Frame(win)
    btns.grid(row=6, column=0, sticky="e", padx=12, pady=14)
    tk.Button(btns, text="Cancel", command=win.destroy).pack(side="right", padx=4)
    tk.Button(btns, text="Save", command=_save).pack(side="right", padx=4)


# =============== SSH host-key trust (fingerprint prompt in the GUI) ===============

def _host_from_any(text: str) -> str:
    """Pull a bare hostname out of a URL, an ssh remote, or a plain host string."""
    t = (text or "").strip()
    if not t:
        return ""
    m = re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', t)
    if m:
        try:
            return (urlparse(t).hostname or "").strip()
        except ValueError:
            return ""
    m = re.match(r'^(?:[^@/\s]+@)?(?P<host>[^:/\s]+)[:/]', t)
    if m:
        return m.group("host")
    return t.split("/")[0].split(":")[0].split("@")[-1]


def _split_user_host(text: str):
    """Split an optional explicit 'user@' prefix from a host string / URL.

    Returns (user, host). `user` is '' when the text carries no explicit user,
    so callers fall back to the 'git' default. Something like
    'ccl@git.linglit.tu-darmstadt.de' -> ('ccl', 'git.linglit.tu-darmstadt.de');
    a plain 'gitlab.dlr.de' -> ('', 'gitlab.dlr.de').
    """
    t = (text or "").strip()
    if not t:
        return "", ""
    # scheme URL: ssh://user@host/..., https://host/...
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', t):
        try:
            p = urlparse(t)
            return (p.username or ""), (p.hostname or "")
        except ValueError:
            return "", ""
    user = ""
    m = re.match(r'^(?P<user>[^@/\s:]+)@(?P<rest>\S+)$', t)
    if m:
        user, t = m.group("user"), m.group("rest")
    return user, _host_from_any(t)


def _login_for_host(host: str) -> str:
    """SSH login mapped to `host` in the managed ~/.ssh/config fence.

    Defaults to 'git'; some GitLab installs (e.g. git.linglit.tu-darmstadt.de)
    require a different account name. When a server has several profiles this
    returns the canonical one's login.
    """
    ps = _profiles_for_host(host)
    return (ps[0].get("user") or "git") if ps else "git"


def _is_ssh_url(url: str) -> bool:
    """True for ssh:// URLs and scp-like 'user@host:path' remotes (any user)."""
    u = (url or "").strip()
    return bool(u) and (u.startswith("ssh://")
                        or re.match(r'^[^@/\s]+@[^/\s:]+:', u) is not None)


def _repo_dirname_from_url(url: str) -> str:
    """Local folder name git would use for `url`: the last path component, minus
    a trailing '.git'. Unlike os.path.basename this understands scp-like SSH URLs
    ('user@host:group/repo.git') and never returns something with ':' or '@' in
    it, which Windows can't use as a directory name.
    """
    u = (url or "").strip().rstrip("/")
    if not u:
        return "repo"
    if "://" in u:
        path = urlparse(u).path
    elif _is_ssh_url(u):                       # scp-like: user@host:path
        path = u.split(":", 1)[1]
    else:
        path = u.replace("\\", "/")
    name = path.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    name = re.sub(r'[<>:"/\\|?*@]+', "", name).strip()
    return name or "repo"


def _rewrite_url_user(url: str, login: str) -> str:
    """Return `url` with its SSH login set to `login` (ssh:// or scp-like form)."""
    if not login or not url:
        return url
    if url.startswith("ssh://"):
        rest = url[len("ssh://"):].split("@", 1)[-1]
        return f"ssh://{login}@{rest}"
    if "://" in url:                                   # http(s)/git/etc. — leave alone
        return url
    m = re.match(r'^[^@/\s]+@(?P<rest>.+)$', url)      # already has 'user@'
    if m:
        return f"{login}@{m.group('rest')}"
    if re.match(r'^[^/\s:]+:', url):                   # 'host:path', no user
        return f"{login}@{url}"
    return url


def _ssh_cmd_for_key(key_path: str) -> str:
    """A `core.sshCommand` / GIT_SSH_COMMAND value that forces exactly one key."""
    p = os.path.abspath(os.path.expanduser(key_path)).replace("\\", "/")
    return f'ssh -i "{p}" -o IdentitiesOnly=yes'


def _known_hosts_path() -> str:
    return os.path.join(_default_ssh_dir(), "known_hosts")


def _host_in_known_hosts(host: str) -> bool:
    try:
        res = subprocess.run(
            ["ssh-keygen", "-F", host],
            text=True, capture_output=True, startupinfo=_win_startupinfo(),
        )
        return res.returncode == 0 and bool(res.stdout.strip())
    except Exception:
        return False


def _scan_host_keys(host: str):
    """Return (keyscan_lines, fingerprint_text) for `host`, or ('', '') on failure."""
    try:
        scan = subprocess.run(
            ["ssh-keyscan", "-T", "10", "-t", "ed25519,rsa,ecdsa", host],
            text=True, capture_output=True, startupinfo=_win_startupinfo(),
        )
    except FileNotFoundError:
        return "", "(ssh-keyscan not found)"
    except Exception as e:
        return "", f"(ssh-keyscan failed: {e})"

    lines = "\n".join(l for l in (scan.stdout or "").splitlines() if l and not l.startswith("#"))
    if not lines:
        return "", "(no host key returned)"

    try:
        fp = subprocess.run(
            ["ssh-keygen", "-l", "-f", "-"],
            input=lines + "\n", text=True, capture_output=True,
            startupinfo=_win_startupinfo(),
        )
        return lines, (fp.stdout or "").strip() or "(could not compute fingerprint)"
    except Exception as e:
        return lines, f"(could not compute fingerprint: {e})"


def _ensure_host_key_trusted(host: str, parent=None) -> bool:
    """If `host` is not in known_hosts, show its fingerprint and ask to trust it.

    Returns True if the host is trusted (already, or after the user accepts),
    False if it could not be fetched or the user declined.
    """
    host = _host_from_any(host)
    if not host:
        return False
    if _host_in_known_hosts(host):
        return True

    lines, fp = _scan_host_keys(host)
    if not lines:
        messagebox.showerror(
            "Host key", f"Could not retrieve the host key for {host}.\n\n{fp}",
            parent=parent or root)
        return False

    trust = messagebox.askyesno(
        f"Unknown host key — {host}",
        f"The authenticity of host '{host}' can't be established.\n\n"
        f"Fingerprint(s):\n{fp}\n\n"
        f"Verify this matches the value published by your GitLab admin\n"
        f"( https://{host}/help/instance_configuration ).\n\n"
        "Trust this host and add it to ~/.ssh/known_hosts?",
        parent=parent or root,
    )
    if not trust:
        return False

    try:
        _ensure_ssh_dir()
        kh = _known_hosts_path()
        existing = ""
        if os.path.isfile(kh):
            with open(kh, "r", encoding="utf-8", errors="replace") as fh:
                existing = fh.read()
        with open(kh, "a", encoding="utf-8", newline="\n") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write(lines + "\n")
        if not sys.platform.startswith("win"):
            try:
                os.chmod(kh, 0o600)
            except OSError:
                pass
    except OSError as e:
        messagebox.showerror("Host key", f"Could not write known_hosts:\n{e}",
                             parent=parent or root)
        return False
    return True


# =============== Repository SSH connection strip (one action per button) ===============

def _ssh_auth_probe(host: str):
    """Non-interactive `ssh -T <login>@host`. Returns (authenticated, message).

    `login` is the account mapped for the host in ~/.ssh/config (default 'git').
    """
    user, host = _split_user_host(host)
    login = user or _login_for_host(host)
    try:
        res = subprocess.run(
            ["ssh", "-T", "-o", "StrictHostKeyChecking=accept-new",
             "-o", "BatchMode=yes", f"{login}@{host}"],
            text=True, capture_output=True, startupinfo=_win_startupinfo(),
        )
        msg = ((res.stdout or "") + (res.stderr or "")).strip()
        low = msg.lower()
        ok = ("welcome to gitlab" in low
              or "successfully authenticated" in low
              or "does not provide shell access" in low)
        return ok, msg or "(no output)"
    except FileNotFoundError:
        return False, "ssh not found. Install the OpenSSH client."
    except Exception as e:
        return False, f"Failed to run ssh: {e}"


def show_remote_urls():
    """Step 1: git remote -v, plus a verdict on what to do next."""
    if not repo:
        messagebox.showinfo("Remote URLs", "No repository loaded.")
        return
    try:
        out = repo.git.remote("-v").strip()
    except Exception as e:
        messagebox.showerror("Remote URLs", f"git remote -v failed:\n{e}")
        return
    if not out:
        messagebox.showinfo("Remote URLs",
                            "This repository has no remotes — nothing to connect over SSH.")
        return
    r = _get_primary_remote()
    url = r.url if r else ""
    if _is_ssh_url(url):
        verdict = 'origin is already SSH.\nNext: click "Trust Server Host Key".'
    elif url.startswith("http://") or url.startswith("https://"):
        verdict = 'origin is HTTPS.\nNext: click "Convert Origin to SSH".'
    else:
        verdict = "Could not classify the origin URL."
    messagebox.showinfo("git remote -v", f"{out}\n\n{'-' * 44}\n{verdict}")


def convert_origin_to_ssh():
    """Step 2: rewrite ONLY the primary remote from HTTPS to git@host:path."""
    r = _get_primary_remote()
    if not r:
        messagebox.showerror("Convert Origin to SSH",
                             "No remote found. Load a repository with a remote first.")
        return
    url = r.url
    if _is_ssh_url(url):
        messagebox.showinfo("Convert Origin to SSH",
                            f"'{r.name}' is already SSH:\n{url}\n\n"
                            'Nothing to do.\nNext: click "Trust Server Host Key".')
        return
    host, path = _parse_origin_host_and_path()
    if not host or not path:
        messagebox.showerror("Convert Origin to SSH", f"Cannot parse the URL:\n{url}")
        return
    ssh_url = f"{_login_for_host(host)}@{host}:{path}.git"
    if not messagebox.askyesno(
        "Convert Origin to SSH",
        f"Change the '{r.name}' remote URL\n\nfrom:  {url}\nto:    {ssh_url}\n\nProceed?"):
        return
    try:
        r.set_url(ssh_url)
    except Exception as e:
        messagebox.showerror("Convert Origin to SSH", f"Failed:\n{e}")
        return
    messagebox.showinfo("Convert Origin to SSH",
                        f"'{r.name}' is now SSH:\n{ssh_url}\n\n"
                        'Next: click "Trust Server Host Key".')


def trust_origin_host():
    """Step 3: add the origin host's key to known_hosts (fingerprint prompt in-app)."""
    host, _ = _parse_origin_host_and_path()
    if not host:
        messagebox.showerror("Trust Server Host Key",
                             "No repository / remote host found.")
        return
    if _host_in_known_hosts(host):
        messagebox.showinfo("Trust Server Host Key",
                            f"{host} is already in ~/.ssh/known_hosts.\n\n"
                            'Next: click "Test SSH to Server".')
        return
    if _ensure_host_key_trusted(host):
        messagebox.showinfo("Trust Server Host Key",
                            f"{host} added to ~/.ssh/known_hosts.\n\n"
                            'Next: click "Test SSH to Server".')


def test_origin_ssh_guided():
    """Step 4: ssh -T to the origin host, with a verdict and next step."""
    host, _ = _parse_origin_host_and_path()
    if not host:
        messagebox.showerror("Test SSH to Server", "No repository / remote host found.")
        return
    if not _ensure_host_key_trusted(host):
        return
    ok, msg = _ssh_auth_probe(host)
    if ok:
        messagebox.showinfo("Test SSH to Server",
                            f"{msg}\n\n{'-' * 44}\nAuthentication works.\n"
                            'Next: click "Verify with Fetch".')
    else:
        ident = _identity_for_host(host) or "(no key mapped)"
        messagebox.showwarning(
            "Test SSH to Server",
            f"{msg}\n\n{'-' * 44}\nSSH did not authenticate.\n\n"
            f"Key mapped for {host}:  {ident}\n\n"
            "Check:\n"
            f"  - the .pub is added at https://{host}/-/user_settings/ssh_keys\n"
            '  - the right key is mapped (open "Manage Server Keys")')


def verify_with_fetch():
    """Step 5: git fetch on the primary remote to confirm end-to-end."""
    r = _get_primary_remote()
    if not r or not repo:
        messagebox.showerror("Verify with Fetch", "No remote found.")
        return
    host, _ = _parse_origin_host_and_path()
    if host and not _ensure_host_key_trusted(host):
        return
    try:
        repo.git.fetch(r.name)
    except Exception as e:
        messagebox.showerror("Verify with Fetch",
                             f"git fetch {r.name} failed:\n\n{e}\n\n"
                             'If this is an auth error, re-check "Test SSH to Server".')
        return
    messagebox.showinfo("Verify with Fetch",
                        f"git fetch {r.name} succeeded.\n\n"
                        "SSH is fully working for this repository. Done.")


def show_active_key_for_repo():
    """Diagnostic: which managed key will SSH use for the loaded repo's host."""
    host, _ = _parse_origin_host_and_path()
    if not host:
        messagebox.showinfo("Active Key for This Repo",
                            "No repository / remote host found.")
        return
    ident = _identity_for_host(host)
    if not ident:
        messagebox.showinfo(
            "Active Key for This Repo",
            f"Remote host:  {host}\n\n"
            "No key mapped in the managed section of ~/.ssh/config.\n"
            'Open "Manage Server Keys" to set one.')
        return
    pub_ok = os.path.isfile(_expand_key_path(ident) + ".pub")
    messagebox.showinfo(
        "Active Key for This Repo",
        f"Remote host:   {host}\n"
        f"IdentityFile:  {ident}\n"
        f".pub present:  {'yes' if pub_ok else 'no'}")


def check_git_ssh_client():
    """Diagnostic: is Git using OpenSSH (reads ~/.ssh/config) or plink (does not)."""
    gs = os.environ.get("GIT_SSH", "")
    gsc = os.environ.get("GIT_SSH_COMMAND", "")
    try:
        cfg = repo.git.config("--get", "core.sshCommand").strip() if repo else ""
    except Exception:
        cfg = ""
    effective = gsc or cfg or gs or "ssh (default OpenSSH)"
    low = effective.lower()
    if "plink" in low or "putty" in low:
        verdict = ("PuTTY/plink detected. plink does NOT read ~/.ssh/config, so the\n"
                   "per-server key mappings will be ignored.\n"
                   "Switch Git to OpenSSH:  set GIT_SSH_COMMAND=ssh  (or clear GIT_SSH).")
    else:
        verdict = "Looks like OpenSSH — ~/.ssh/config is used. Good."
    messagebox.showinfo(
        "Git SSH Client",
        f"GIT_SSH          = {gs or '(unset)'}\n"
        f"GIT_SSH_COMMAND  = {gsc or '(unset)'}\n"
        f"core.sshCommand  = {cfg or '(unset)'}\n\n"
        f"Effective:  {effective}\n\n{verdict}")


def _parse_ssh_user_host(url: str):
    """Return (user, host, port) for SSH URLs; ("", "", None) if not SSH."""
    if not url:
        return "", "", None
    if url.startswith("ssh://"):
        p = urlparse(url)
        return (p.username or "git"), (p.hostname or ""), p.port
    m = re.match(r'(?P<user>[^@]+)@(?P<host>[^:]+):', url)
    if m:
        return m.group("user"), m.group("host"), None
    return "", "", None

def _ask_yes_no(title: str, msg: str) -> bool:
    """Thread-safe yes/no prompt."""
    if app_closing or not root.winfo_exists():
        return False
    if threading.current_thread() is threading.main_thread():
        return messagebox.askyesno(title, msg)
    result = {"value": False}
    done = threading.Event()
    def _prompt():
        result["value"] = messagebox.askyesno(title, msg)
        done.set()
    _post_ui(_prompt)
    done.wait()
    return result["value"]

def _set_status(_msg: str):
    """No-op: status popup removed."""
    return

def _ensure_gitignore(repo_path: str) -> bool:
    """Ensure a .gitignore exists in repo_path and includes .venv."""
    try:
        if not repo_path:
            return False
        gitignore_path = os.path.join(repo_path, ".gitignore")
        if not os.path.exists(gitignore_path):
            with open(gitignore_path, "w", encoding="utf-8") as f:
                f.write(".venv\n")
            return True

        try:
            with open(gitignore_path, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
        except UnicodeDecodeError:
            with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()

        if ".venv" not in lines:
            with open(gitignore_path, "a", encoding="utf-8") as f:
                if lines and lines[-1] != "":
                    f.write("\n")
                f.write(".venv\n")
        return True
    except Exception:
        return False

def _extract_ssh_fingerprint(msg: str) -> str:
    """Extract SHA256 fingerprint from ssh output if present."""
    m = re.search(r"SHA256:[A-Za-z0-9+/=]+", msg or "")
    return m.group(0) if m else ""

def _ensure_ssh_host_trusted(repo_url: str) -> bool:
    """Prompt to trust SSH host key for first-time clones."""
    user, host, port = _parse_ssh_user_host(repo_url)
    if not host:
        return True

    startupinfo = None
    if sys.platform.startswith("win"):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    def run_ssh(extra_args=None, feed_stdin=None):
        args = ["ssh"]
        if port:
            args += ["-p", str(port)]
        if extra_args:
            args += extra_args
        args += [f"{user}@{host}"]
        try:
            res = subprocess.run(
                args,
                input=feed_stdin,
                text=True,
                capture_output=True,
                startupinfo=startupinfo,
            )
            msg = (res.stdout or "") + (res.stderr or "")
            return res.returncode, msg
        except Exception as e:
            return 255, f"Failed to run ssh: {e}"

    rc, msg = run_ssh(["-T", "-o", "StrictHostKeyChecking=accept-new"])
    lower = msg.lower()
    if "unknown option -- o" in lower:
        rc, msg = run_ssh(["-T"])
        lower = msg.lower()

    if "authenticity of host" in lower or "continue connecting (yes/no" in lower:
        fp = _extract_ssh_fingerprint(msg)
        fp_line = f"\n\nFingerprint: {fp}" if fp else ""
        trust = _ask_yes_no(
            f"Trust {host} host key?",
            f"The authenticity of host '{host}' can't be established.\n\n"
            "Do you want to trust this host key and continue?"
            f"{fp_line}"
        )
        if not trust:
            return False
        rc2, msg2 = run_ssh(["-T"], feed_stdin="yes\n")
        if "host key verification failed" in msg2.lower():
            return False
        return True

    if "host key verification failed" in lower:
        return False

    return True

# =============== Repo / Branch / Commit logic ===============

def browse_folder():
    folder = filedialog.askdirectory()
    if folder:
        clone_dir_entry.delete(0, tk.END)
        clone_dir_entry.insert(0, folder)

def _pick_clone_ssh_identity(repo_url: str):
    """Before an SSH clone, make sure a key profile exists and let the user pick one.

    A managed Server Key profile mapped to the clone host is REQUIRED and the user
    must pick one explicitly — there is no "let SSH decide" / auto fallback and no
    borrowing another server's profile.

    Returns (proceed, ssh_command, effective_url):
      proceed        False  -> abort the clone (no profile for this host, or cancelled)
      ssh_command    'ssh…' -> force this key for the clone AND persist it as the
                               cloned repo's core.sshCommand
      effective_url         -> repo_url, with its SSH login rewritten to match the
                               chosen profile when they differ
    """
    try:
        _repair_managed_ssh_config()
    except Exception:
        pass
    user_in, host = _split_user_host(repo_url)
    mappings = _managed_hosts()
    match_aliases = {m["host"] for m in _profiles_for_host(host)}
    host_matches = [m for m in mappings if m["host"] in match_aliases]

    if not host_matches:
        messagebox.showwarning(
            "Server Key profile required",
            f"No Server Key profile is mapped to “{host or repo_url}”.\n\n"
            "An SSH clone requires a key set up for this server. Opening "
            "“Manage Server Keys” — add a profile for this server (set the SSH "
            "login it expects — e.g. git or ccl — and pick or generate a key), "
            "then start the clone again.")
        manage_server_keys()
        return False, "", repo_url

    win = Toplevel(root)
    win.title("Choose Server Key profile for clone")
    win.transient(root)
    win.grab_set()
    win.grid_columnconfigure(0, weight=1)

    tk.Label(win, text=f"Cloning:  {repo_url}", font=("Arial", 9),
             wraplength=540, justify="left").grid(row=0, column=0, sticky="w",
                                                  padx=14, pady=(14, 2))
    tk.Label(win, text=f"Select the Server Key profile to use for {host}. "
             "A mapped profile is required — there is no automatic fallback.",
             font=("Arial", 8), fg="#0a0", wraplength=540,
             justify="left").grid(row=1, column=0, sticky="w", padx=14, pady=(0, 8))

    choice = tk.StringVar()
    box = tk.Frame(win)
    box.grid(row=2, column=0, sticky="w", padx=14)

    for m in host_matches:
        login = m.get("user") or "git"
        ident = m.get("identityfile", "")
        key_ok = bool(ident) and os.path.isfile(_expand_key_path(ident))
        kb = os.path.basename(_expand_key_path(ident)) if ident else "(no key)"
        tk.Radiobutton(
            box, variable=choice, value=m["host"], anchor="w",
            text=f"{login}@{_profile_server(m)}   ·   {kb}"
                 + ("" if key_ok else "   — key file missing"),
        ).pack(anchor="w")

    # preselect: a host profile whose login matches the URL's 'user@', else the
    # first (canonical) host profile
    default_val = next(
        (m["host"] for m in host_matches
         if user_in and (m.get("user") or "git") == user_in),
        host_matches[0]["host"])
    choice.set(default_val)

    out = {"proceed": False, "cmd": "", "url": repo_url}

    def _do():
        v = choice.get()
        m = next((x for x in host_matches if x["host"] == v), None)
        if not m:
            messagebox.showerror(
                "Server Key profile",
                "Select a Server Key profile mapped to this server to continue.",
                parent=win)
            return
        ident = m.get("identityfile", "")
        if not ident or not os.path.isfile(_expand_key_path(ident)):
            messagebox.showerror(
                "SSH profile",
                "That profile has no usable private key.\nFix it in "
                "“Manage Server Keys” first.", parent=win)
            return
        login = m.get("user") or "git"
        out.update(proceed=True,
                   cmd=_ssh_cmd_for_key(_expand_key_path(ident)),
                   url=_rewrite_url_user(repo_url, login))
        win.destroy()

    def _manage():
        win.destroy()
        manage_server_keys()

    btns = tk.Frame(win)
    btns.grid(row=3, column=0, sticky="e", padx=14, pady=14)
    tk.Button(btns, text="Manage profiles…", command=_manage).pack(side="left", padx=4)
    tk.Button(btns, text="Cancel", command=win.destroy).pack(side="left", padx=4)
    tk.Button(btns, text="Clone", command=_do).pack(side="left", padx=4)

    win.wait_window()
    return out["proceed"], out["cmd"], out["url"]


def clone_repo():
    """Clone or load an existing repo based on inputs, with thread-safe UI updates."""
    repo_url = repo_entry.get().strip()
    base_dir = clone_dir_entry.get().strip()

    if not repo_url and not base_dir:
        messagebox.showwarning("Input Error", "Please provide a repo URL or a local repo path.")
        return

    download_button.config(state=tk.DISABLED)

    def task():
        global repo
        result = {
            "ok": False,
            "kind": "",
            "path": None,
            "error": None,
        }

        try:
            # Case 1: Load existing repo directly from base_dir if no repo_url
            if not repo_url and os.path.isdir(base_dir) and os.path.isdir(os.path.join(base_dir, ".git")):
                repo = Repo(base_dir)
                _ensure_gitignore(repo.working_dir)
                result["ok"] = True
                result["kind"] = "loaded_direct"
                result["path"] = base_dir
            else:
                if not os.path.exists(base_dir):
                    os.makedirs(base_dir, exist_ok=True)

                repo_name = _repo_dirname_from_url(repo_url)
                full_clone_path = os.path.join(base_dir, repo_name)

                # Case 2: Repo already cloned at full_clone_path
                if os.path.isdir(full_clone_path) and os.path.isdir(os.path.join(full_clone_path, ".git")):
                    repo = Repo(full_clone_path)
                    _ensure_gitignore(repo.working_dir)
                    result["ok"] = True
                    result["kind"] = "loaded_existing_clone"
                    result["path"] = full_clone_path
                else:
                    # Case 3: Fresh clone
                    clone_url = repo_url
                    ssh_cmd = ""
                    if _is_ssh_url(repo_url):
                        if not _ensure_ssh_host_trusted(repo_url):
                            raise Exception("SSH host key not trusted; clone canceled.")
                        proceed, ssh_cmd, clone_url = _pick_clone_ssh_identity(repo_url)
                        if not proceed:
                            raise Exception(
                                "Clone canceled — set up or choose an SSH profile in "
                                "“Manage Server Keys”, then clone again.")
                    # Force the chosen key via GIT_SSH_COMMAND for the clone, then
                    # persist it as the repo's core.sshCommand so later fetch/push
                    # reuse it. (GitPython refuses `--config` in multi_options.)
                    clone_env = {"GIT_SSH_COMMAND": ssh_cmd} if ssh_cmd else None
                    repo = Repo.clone_from(clone_url, full_clone_path, env=clone_env)
                    if ssh_cmd:
                        try:
                            repo.git.config("core.sshCommand", ssh_cmd)
                        except Exception:
                            pass
                    _ensure_gitignore(repo.working_dir)
                    result["ok"] = True
                    result["kind"] = "cloned"
                    result["path"] = full_clone_path

        except Exception as e:
            result["error"] = e

        def ui_update():
            if app_closing or not root.winfo_exists():
                return
            download_button.config(state=tk.NORMAL)
            if not result["ok"]:
                err_text = str(result["error"])
                low = err_text.lower()
                hint = ""
                if repo_url.startswith(("http://", "https://")) and any(
                    s in low for s in ("authentication failed", "could not read username",
                                       "could not read password", "invalid username or password",
                                       "http 403", "403 forbidden", "terminal prompts disabled")):
                    hint = ("\n\nThis looks like an HTTPS authentication failure. Open the "
                            "'Git AuthN' tab -> HTTPS Access Token, save a Personal Access "
                            "Token for this host, then clone again.")
                elif _is_ssh_url(repo_url) and any(
                    s in low for s in ("permission denied", "publickey",
                                       "could not read from remote repository",
                                       "authentication failed", "access denied")):
                    _h, _ = _split_user_host(repo_url)
                    hint = ("\n\nThis looks like an SSH key problem for "
                            f"“{_h or 'this server'}”. Open 'Git AuthN' -> SSH -> "
                            "'Manage Server Keys' and set up a profile for this "
                            "server (the SSH login it expects — e.g. git or ccl — "
                            "and a key whose .pub is added on the server), then "
                            "clone again.")
                messagebox.showerror("Error", f"Failed to clone/load repo:\n{err_text}{hint}")
                return

            path = result["path"]
            if result["kind"] == "loaded_direct":
                title = "Loaded"
                msg = f"Loaded existing repository:\n{path}"
            elif result["kind"] == "loaded_existing_clone":
                title = "Loaded"
                msg = f"Loaded existing repository at:\n{path}"
            else:
                title = "Success"
                msg = f"Repository cloned to:\n{path}"

            _reset_commit_ui(clear_add_all=True, hide_push=True)
            _clear_workflow_ui()
            messagebox.showinfo(title, msg)
            list_branches(path)
            _prefill_auth_fields()
            _prefill_pat_fields()
            _update_terminal_prompt()
            refresh_workflow_graph()

        _post_ui(ui_update)

    # Run synchronously to avoid Tk thread issues during repo switching.
    task()

def list_branches(repo_path=None):
    """Populate branch dropdown with local + remote branches (any remote).

    The dropdown is filled at once from what is already known locally, then a
    fetch --prune runs in the background and the list is rebuilt when it ends,
    so the window never freezes on a slow network."""
    global repo

    repo_path = repo_path or clone_dir_entry.get()
    if not repo_path or not os.path.exists(repo_path):
        messagebox.showwarning("Error", "Please provide a valid cloned repository path.")
        return

    try:
        repo = Repo(repo_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to list branches:\n{e}")
        _update_terminal_prompt()
        return

    _populate_branch_dropdown()
    _update_terminal_prompt()

    r = _get_primary_remote()
    if not r or _git_op_busy:
        return  # nothing to fetch, or another operation is using the network
    rp = repo

    def work():
        rp.git.fetch("--prune", r.name)

    def done(_res, err):
        if repo is not rp:
            return  # a different repository was loaded meanwhile
        if err:
            # Offline / auth problems: keep the list built from local data.
            git_ops_status_label.config(text="Could not reach the remote - branch list may be outdated.")
            return
        _populate_branch_dropdown(quiet=True)

    _run_git_op("Fetching branches", work, done)

def _populate_branch_dropdown(quiet=False):
    """(Re)build the branch dropdown from local branches + cached remote refs."""
    global branch_dropdown
    try:
        local = {str(h) for h in getattr(repo, "branches", [])}

        # Remote branches (strip '<remote>/' prefix), ignore HEAD
        remote = set()
        try:
            r = _get_primary_remote()
            if r:
                for rf in r.refs:
                    name = rf.name
                    if name.startswith(f"{r.name}/"):
                        n = name[len(r.name)+1:]
                    else:
                        n = name
                    if n != "HEAD":
                        remote.add(n)
        except Exception:
            pass

        all_names = sorted(local | remote)
        if not all_names:
            if not quiet:
                messagebox.showwarning("Branches", "No branches found (local or remote).")
            return

        try:
            current_branch = str(repo.active_branch)
        except Exception:
            current_branch = "main" if "main" in all_names else all_names[0]

        if current_branch not in all_names:
            all_names.insert(0, current_branch)

        branch_var.set(current_branch)
        current_branch_label.config(text=f"Current branch: {current_branch}")

        if branch_dropdown is not None:
            branch_dropdown.destroy()

        branch_dropdown = tk.OptionMenu(branch_section, branch_var, *all_names)
        branch_dropdown.grid(row=3, column=1, padx=10, pady=5, sticky="w")

        def _on_branch_change(*_):
            switch_branch()

        try:
            branch_var.trace_remove("write", getattr(branch_var, "_trace_id", None))
        except Exception:
            pass
        branch_var._trace_id = branch_var.trace_add("write", _on_branch_change)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to list branches:\n{e}")

def switch_branch():
    """Checkout local branch, or create tracking branch from <remote>/<name> if missing."""
    global repo
    target = branch_var.get().strip()
    if not target:
        return
    try:
        local_names = {str(h) for h in getattr(repo, "branches", [])}
        if target in local_names:
            repo.git.checkout(target)
        else:
            r = _get_primary_remote()
            if not r:
                raise Exception("No remote available; cannot create tracking branch.")
            remote_full = f"{r.name}/{target}"
            remote_heads = [ref.name for ref in r.refs]
            if remote_full in remote_heads:
                repo.git.checkout("-b", target, "--track", remote_full)
            else:
                raise Exception(f"Remote branch '{remote_full}' not found.")

        current_branch_label.config(text=f"Current branch: {target}")
        file_frame.grid()
        _prefill_auth_fields()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to switch branch:\n{e}")
        # Put the dropdown back on the branch that is really checked out, so
        # Pull / View Log never act on a branch we failed to switch to.
        current = _current_branch_name()
        if current and current != target:
            branch_var.set(current)

def refresh_branches():
    list_branches()

# ---- Background runner for the Git Operations buttons ----
# Fetch / pull / push talk to the server and can take a while (e.g. on VPN), so
# they run off the UI thread. Only one runs at a time; the buttons are disabled
# and a "Working..." line is shown until it finishes.
_git_op_buttons = []
_git_op_busy = False

def _set_git_ops_busy(label):
    state = "disabled" if label else "normal"
    for b in _git_op_buttons:
        try:
            b.config(state=state)
        except Exception:
            pass
    try:
        git_ops_status_label.config(text=f"{label}..." if label else "")
    except Exception:
        pass

def _run_git_op(label, work, done):
    """Run work() in a thread (no Tk calls inside!), then done(result, error)
    on the UI thread."""
    global _git_op_busy
    if _git_op_busy:
        messagebox.showinfo("Busy", "Another Git operation is still running. Please wait.")
        return
    _git_op_busy = True
    _set_git_ops_busy(label)

    def task():
        try:
            result, err = work(), None
        except Exception as e:
            result, err = None, e

        def finish():
            global _git_op_busy
            _git_op_busy = False
            _set_git_ops_busy(None)
            if app_closing or not root.winfo_exists():
                return
            done(result, err)

        _post_ui(finish)

    threading.Thread(target=task, daemon=True).start()

def _current_branch_and_remote():
    """Checks shared by Pull / Push / Incoming-Outgoing.
    Returns (remote, branch), or (None, None) after telling the user why."""
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return None, None
    r = _get_primary_remote()
    if not r:
        messagebox.showwarning("Error", "No remote configured.")
        return None, None
    branch = _current_branch_name()
    if not branch:
        messagebox.showwarning("Error", "You are not on a branch (detached HEAD). Pick a branch first.")
        return None, None
    return r, branch

def _upstream_ref(rp, r, branch):
    """The remote branch the checked-out branch syncs with: its tracking branch
    if set, else <remote>/<branch>. Returns '' if neither exists."""
    try:
        tracking = rp.active_branch.tracking_branch()
    except Exception:
        tracking = None
    candidates = ([str(tracking)] if tracking else []) + [f"{r.name}/{branch}"]
    for ref in candidates:
        try:
            rp.git.rev_parse("--verify", "--quiet", ref)
            return ref
        except Exception:
            continue
    return ""

_GIT_LOG_FMT = "%h\x1f%an\x1f%ad\x1f%s"

def _parse_log_rows(log_text):
    """Split `git log --pretty=format:_GIT_LOG_FMT` output into 4-tuples."""
    rows = []
    for line in (log_text or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("\x1f")
        while len(parts) < 4:
            parts.append("")
        rows.append(tuple(parts[:4]))
    return rows

def _short_list(paths, limit=15):
    shown = [f"  • {p}" for p in paths[:limit]]
    if len(paths) > limit:
        shown.append(f"  ...and {len(paths) - limit} more")
    return "\n".join(shown)

def _show_text_result(title, header, body):
    """Small scrollable popup for command results."""
    popup = Toplevel(root)
    popup.title(title)
    popup.geometry("640x400")
    popup.minsize(420, 240)
    popup.transient(root)
    tk.Label(popup, text=header, font=("Arial", 11, "bold"), justify="left",
             wraplength=600).pack(anchor="w", padx=12, pady=(12, 6))
    t = scrolledtext.ScrolledText(popup, wrap="none", font=("Consolas", 9), height=14)
    t.pack(fill="both", expand=True, padx=12)
    t.insert("1.0", body or "(no output)")
    t.configure(state="disabled")
    tk.Button(popup, text="Close", command=popup.destroy).pack(anchor="e", padx=12, pady=10)
    popup.bind("<Escape>", lambda _e: popup.destroy())

def git_fetch_status():
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    rp = repo
    r = _get_primary_remote()

    def work():
        if r:
            rp.git.fetch(r.name)
        raw = rp.git.status()
        try:
            porc = rp.git.status("--porcelain=v2", "--branch")
        except Exception:
            porc = ""
        return raw, porc

    def done(res, err):
        if err:
            messagebox.showerror("Error", f"Git fetch/status failed:\n{err}")
            return
        _show_git_status(*res)

    _run_git_op("Fetching status", work, done)

# ---- Incoming / Outgoing ----

def git_incoming_outgoing():
    """Show commits a Pull would bring in and commits a Push would send."""
    r, branch = _current_branch_and_remote()
    if not r:
        return
    rp = repo

    def work():
        rp.git.fetch(r.name)
        upstream = _upstream_ref(rp, r, branch)
        fmt = f"--pretty=format:{_GIT_LOG_FMT}"
        if upstream:
            incoming = _parse_log_rows(rp.git.log(fmt, "--date=short", f"HEAD..{upstream}"))
            outgoing = _parse_log_rows(rp.git.log(fmt, "--date=short", f"{upstream}..HEAD"))
        else:
            # Never pushed: everything not on any remote branch is outgoing.
            incoming = []
            outgoing = _parse_log_rows(rp.git.log(fmt, "--date=short", "HEAD", "--not", "--remotes"))
        return upstream, incoming, outgoing

    def done(res, err):
        if err:
            messagebox.showerror("Incoming / Outgoing", f"Could not compare with the remote:\n{err}")
            return
        _show_incoming_outgoing(branch, r.name, *res)

    _run_git_op("Comparing with remote", work, done)

def _show_incoming_outgoing(branch, remote_name, upstream, incoming, outgoing):
    popup = Toplevel(root)
    popup.title(f"Incoming / Outgoing - {branch}")
    popup.geometry("820x560")
    popup.minsize(520, 360)
    popup.transient(root)
    popup.grid_columnconfigure(0, weight=1)

    def section(row, title, hint, rows, empty_text):
        tk.Label(popup, text=title, font=("Arial", 12, "bold")).grid(
            row=row, column=0, sticky="w", padx=10, pady=(10, 0))
        tk.Label(popup, text=hint, font=("Arial", 9), fg="#555555").grid(
            row=row + 1, column=0, sticky="w", padx=10)
        wrap = tk.Frame(popup)
        wrap.grid(row=row + 2, column=0, sticky="nsew", padx=10, pady=(4, 0))
        popup.grid_rowconfigure(row + 2, weight=1)
        wrap.grid_rowconfigure(0, weight=1)
        wrap.grid_columnconfigure(0, weight=1)
        tree = ttk.Treeview(wrap, columns=("hash", "author", "date", "subject"),
                            show="headings", height=7)
        for c, txt, w, stretch in (("hash", "Hash", 90, False), ("author", "Author", 140, False),
                                   ("date", "Date", 100, False), ("subject", "Subject", 440, True)):
            tree.heading(c, text=txt)
            tree.column(c, width=w, minwidth=60, stretch=stretch, anchor="w")
        vbar = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vbar.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        for rw in rows:
            tree.insert("", "end", values=rw)
        if not rows:
            tree.insert("", "end", values=("", "", "", empty_text))

    if upstream:
        in_hint = f"Commits on '{upstream}' that Pull will bring into '{branch}'."
        out_hint = f"Commits on '{branch}' that Push will send to '{upstream}'."
    else:
        in_hint = f"'{branch}' does not exist on '{remote_name}' yet, so there is nothing to pull."
        out_hint = f"Local-only commits. Push will create '{remote_name}/{branch}' with them."

    section(0, f"Incoming  ({len(incoming)})", in_hint, incoming, "Nothing to pull - up to date")
    section(3, f"Outgoing  ({len(outgoing)})", out_hint, outgoing, "Nothing to push")
    tk.Button(popup, text="Close", command=popup.destroy).grid(
        row=6, column=0, sticky="e", padx=10, pady=10)
    popup.bind("<Escape>", lambda _e: popup.destroy())

# ---- Stash ----

def git_stash_save():
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    if _git_op_busy:
        messagebox.showinfo("Busy", "Another Git operation is still running. Please wait.")
        return
    if not repo.is_dirty(untracked_files=True):
        messagebox.showinfo("Stash", "There are no local changes to stash.")
        return
    note = simpledialog.askstring("Stash changes",
                                  "Optional note for this stash (what were you working on?):",
                                  parent=root)
    if note is None:
        return
    args = ["push", "--include-untracked"] + (["-m", note.strip()] if note.strip() else [])
    try:
        repo.git.stash(*args)
    except Exception as e:
        messagebox.showerror("Stash", f"Git stash failed:\n{e}")
        return
    messagebox.showinfo("Stash", "Your changes are saved in the stash and the working folder is clean.\n\n"
                                 "Use Stash > Apply latest stash to bring them back.")

def git_stash_pop(ref="stash@{0}", parent=None):
    """Re-apply a stash and remove it. Returns True on success."""
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.", parent=parent)
        return False
    if _git_op_busy:
        messagebox.showinfo("Busy", "Another Git operation is still running. Please wait.", parent=parent)
        return False
    try:
        if not repo.git.stash("list").strip():
            messagebox.showinfo("Stash", "The stash is empty.", parent=parent)
            return False
        repo.git.stash("pop", ref)
    except Exception as e:
        messagebox.showerror(
            "Stash",
            f"Could not fully apply {ref}:\n{e}\n\n"
            "If it reports conflicts, fix the conflicted files; the stash is kept "
            "until you drop it from Stash > View stashes.",
            parent=parent)
        return False
    messagebox.showinfo("Stash", f"Applied and removed {ref}.", parent=parent)
    return True

def git_stash_list():
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    try:
        out = repo.git.stash("list", "--pretty=format:%gd\x1f%cr\x1f%gs")
    except Exception as e:
        messagebox.showerror("Stash", f"Could not read the stash:\n{e}")
        return

    popup = Toplevel(root)
    popup.title("Stashes")
    popup.geometry("680x340")
    popup.minsize(440, 220)
    popup.transient(root)
    popup.grid_rowconfigure(1, weight=1)
    popup.grid_columnconfigure(0, weight=1)
    tk.Label(popup, text="Saved stashes (newest first)", font=("Arial", 12, "bold")).grid(
        row=0, column=0, sticky="w", padx=10, pady=(10, 6))

    tree = ttk.Treeview(popup, columns=("ref", "when", "message"), show="headings", selectmode="browse")
    for c, txt, w, stretch in (("ref", "Stash", 90, False), ("when", "When", 110, False),
                               ("message", "Message", 420, True)):
        tree.heading(c, text=txt)
        tree.column(c, width=w, minwidth=60, stretch=stretch, anchor="w")
    tree.grid(row=1, column=0, sticky="nsew", padx=10)

    def _fill(text):
        tree.delete(*tree.get_children())
        for line in (text or "").splitlines():
            parts = (line.split("\x1f") + ["", ""])[:3]
            tree.insert("", "end", iid=parts[0], values=parts)

    _fill(out)

    def _reload():
        try:
            _fill(repo.git.stash("list", "--pretty=format:%gd\x1f%cr\x1f%gs"))
        except Exception:
            pass

    def _selected():
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("Stash", "Select a stash first.", parent=popup)
        return sel[0] if sel else ""

    def _apply():
        ref = _selected()
        if ref and git_stash_pop(ref, parent=popup):
            _reload()

    def _drop():
        ref = _selected()
        if not ref:
            return
        if not messagebox.askyesno("Drop stash", f"Permanently delete {ref}?\nThose changes will be lost.",
                                   parent=popup):
            return
        try:
            repo.git.stash("drop", ref)
        except Exception as e:
            messagebox.showerror("Stash", f"Drop failed:\n{e}", parent=popup)
        _reload()

    btns = tk.Frame(popup)
    btns.grid(row=2, column=0, sticky="e", padx=10, pady=10)
    tk.Button(btns, text="Apply & remove", command=_apply).pack(side="left", padx=4)
    tk.Button(btns, text="Drop", command=_drop).pack(side="left", padx=4)
    tk.Button(btns, text="Close", command=popup.destroy).pack(side="left", padx=4)
    popup.bind("<Escape>", lambda _e: popup.destroy())


_GIT_XY_DESC = {
    "M": "modified", "T": "type changed", "A": "added", "D": "deleted",
    "R": "renamed", "C": "copied", "U": "unmerged",
}


def _describe_xy(xy):
    """Turn a porcelain-v2 <XY> code into a human phrase + staged/unstaged hint."""
    staged = xy[0] if xy and xy[0] != "." else ""
    work = xy[1] if len(xy) > 1 and xy[1] != "." else ""
    parts = []
    if staged:
        parts.append(f"staged: {_GIT_XY_DESC.get(staged, staged)}")
    if work:
        parts.append(f"unstaged: {_GIT_XY_DESC.get(work, work)}")
    return ", ".join(parts) or "changed"


def _show_git_status(raw, porc):
    branch = upstream = None
    ahead = behind = 0
    files = []  # (state, path)
    for line in (porc or "").splitlines():
        if line.startswith("# branch.head"):
            branch = line.split(" ", 2)[2].strip()
        elif line.startswith("# branch.upstream"):
            upstream = line.split(" ", 2)[2].strip()
        elif line.startswith("# branch.ab"):
            try:
                a, b = line.split(" ")[2:4]
                ahead, behind = int(a.lstrip("+")), int(b.lstrip("-"))
            except Exception:
                pass
        elif line[:2] in ("1 ", "2 "):
            fields = line.split(" ", 8)
            xy = fields[1]
            rest = fields[8] if len(fields) > 8 else ""
            if line.startswith("2 "):
                # "<rename-score> <newpath>\t<oldpath>"
                rest = rest.split(" ", 1)[1] if " " in rest else rest
                if "\t" in rest:
                    new_p, old_p = rest.split("\t", 1)
                    rest = f"{old_p}  →  {new_p}"
            files.append((_describe_xy(xy), rest))
        elif line.startswith("? "):
            files.append(("untracked", line[2:]))
        elif line.startswith("! "):
            files.append(("ignored", line[2:]))

    popup = Toplevel(root)
    popup.title("Git Status")
    popup.geometry("640x460")
    popup.minsize(460, 300)
    popup.transient(root)
    popup.grid_rowconfigure(2, weight=1)
    popup.grid_columnconfigure(0, weight=1)

    tk.Label(popup, text="Git Status", font=("Segoe UI", 14, "bold")).grid(
        row=0, column=0, sticky="w", padx=14, pady=(12, 4))

    if upstream:
        if ahead == 0 and behind == 0:
            sync = f"up to date with '{upstream}'"
        else:
            bits = []
            if ahead:
                bits.append(f"{ahead} ahead")
            if behind:
                bits.append(f"{behind} behind")
            sync = f"{', '.join(bits)} vs '{upstream}'"
    else:
        sync = "no upstream tracking branch"
    clean = " — working tree clean" if not files else f" — {len(files)} changed path(s)"
    tk.Label(popup, text=f"On branch {branch or '?'}   ·   {sync}{clean}",
             font=("Segoe UI", 10)).grid(row=1, column=0, sticky="w", padx=14, pady=(0, 8))

    wrap = tk.Frame(popup)
    wrap.grid(row=2, column=0, sticky="nsew", padx=14)
    wrap.grid_rowconfigure(0, weight=1)
    wrap.grid_columnconfigure(0, weight=1)

    tree = ttk.Treeview(wrap, columns=("state", "path"), show="headings", selectmode="extended")
    tree.heading("state", text="State")
    tree.heading("path", text="File")
    tree.column("state", width=180, minwidth=100, stretch=False, anchor="w")
    tree.column("path", width=400, minwidth=200, stretch=True, anchor="w")
    vbar = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
    hbar = ttk.Scrollbar(wrap, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vbar.grid(row=0, column=1, sticky="ns")
    hbar.grid(row=1, column=0, sticky="ew")

    if files:
        for state, path in files:
            tree.insert("", "end", values=(state, path))
    else:
        tree.insert("", "end", values=("clean", "nothing to commit"))

    def _copy_list():
        popup.clipboard_clear()
        popup.clipboard_append("\n".join(
            "\t".join(tree.item(i, "values")) for i in tree.get_children()))

    def _copy_raw():
        popup.clipboard_clear()
        popup.clipboard_append(raw or "")

    def _show_raw():
        w = Toplevel(popup)
        w.title("git status (raw)")
        w.geometry("620x420")
        w.transient(popup)
        t = scrolledtext.ScrolledText(w, wrap="none", font=("Consolas", 9))
        t.pack(fill="both", expand=True)
        t.insert("1.0", raw or "(no output)")
        t.configure(state="disabled")

    btn_row = tk.Frame(popup)
    btn_row.grid(row=3, column=0, sticky="e", padx=14, pady=10)
    tk.Button(btn_row, text="Copy list", command=_copy_list).pack(side="left", padx=4)
    tk.Button(btn_row, text="Copy raw", command=_copy_raw).pack(side="left", padx=4)
    tk.Button(btn_row, text="Raw output", command=_show_raw).pack(side="left", padx=4)
    tk.Button(btn_row, text="Close", command=popup.destroy).pack(side="left", padx=4)
    popup.bind("<Escape>", lambda _e: popup.destroy())

def git_log_branch():
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    # The checked-out branch, not the dropdown (it can differ if a switch failed).
    branch_name = _current_branch_name() or branch_var.get()
    fmt = f"--pretty=format:{_GIT_LOG_FMT}"
    try:
        try:
            log = repo.git.log(branch_name, fmt, "--date=short", "--max-count=500")
        except Exception:
            r = _get_primary_remote()
            rb = f"{r.name}/{branch_name}" if r else branch_name
            log = repo.git.log(rb, fmt, "--date=short", "--max-count=500")
    except Exception as e:
        messagebox.showerror("Error", f"Git log failed:\n{e}")
        return

    rows = _parse_log_rows(log)

    if not rows:
        messagebox.showinfo(f"Git Log - {branch_name}", "No commits found.")
        return

    _show_git_log_table(branch_name, rows)


def _show_git_log_table(branch_name, rows):
    """Show git log rows in a copyable table."""
    popup = Toplevel(root)
    popup.title(f"Git Log - {branch_name}")
    popup.geometry("820x460")
    popup.minsize(520, 260)
    popup.transient(root)

    popup.grid_rowconfigure(1, weight=1)
    popup.grid_columnconfigure(0, weight=1)

    tk.Label(popup, text=f"Git Log - {branch_name}   ({len(rows)} commits)",
             font=("Arial", 12, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 6))

    table_wrap = tk.Frame(popup)
    table_wrap.grid(row=1, column=0, sticky="nsew", padx=10, pady=0)
    table_wrap.grid_rowconfigure(0, weight=1)
    table_wrap.grid_columnconfigure(0, weight=1)

    cols = ("hash", "author", "date", "subject")
    tree = ttk.Treeview(table_wrap, columns=cols, show="headings", selectmode="extended")
    for c, txt, w, stretch in (
        ("hash", "Hash", 90, False),
        ("author", "Author", 140, False),
        ("date", "Date", 100, False),
        ("subject", "Subject", 460, True),
    ):
        tree.heading(c, text=txt)
        tree.column(c, width=w, minwidth=60, stretch=stretch, anchor="w")

    vbar = ttk.Scrollbar(table_wrap, orient="vertical", command=tree.yview)
    hbar = ttk.Scrollbar(table_wrap, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vbar.grid(row=0, column=1, sticky="ns")
    hbar.grid(row=1, column=0, sticky="ew")

    for r in rows:
        tree.insert("", "end", values=r)

    def _rows_to_text(items):
        return "\n".join("\t".join(tree.item(i, "values")) for i in items)

    def _copy_selected(_evt=None):
        sel = tree.selection()
        if not sel:
            return
        popup.clipboard_clear()
        popup.clipboard_append(_rows_to_text(sel))

    def _copy_hash(_evt=None):
        sel = tree.selection()
        if not sel:
            return
        popup.clipboard_clear()
        popup.clipboard_append(" ".join(tree.item(i, "values")[0] for i in sel))

    def _copy_all():
        popup.clipboard_clear()
        popup.clipboard_append(_rows_to_text(tree.get_children()))

    def _download_txt():
        default_name = f"git-log-{branch_name}.txt".replace("/", "-")
        path = filedialog.asksaveasfilename(
            parent=popup,
            title="Save git log as text",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            header = "\t".join(("Hash", "Author", "Date", "Subject"))
            body = _rows_to_text(tree.get_children())
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(header + "\n" + body + "\n")
        except Exception as e:
            messagebox.showerror("Save failed", str(e), parent=popup)
            return
        messagebox.showinfo("Saved", f"Log written to:\n{path}", parent=popup)

    tree.bind("<Double-1>", _copy_hash)
    tree.bind("<Control-c>", _copy_selected)

    btn_row = tk.Frame(popup)
    btn_row.grid(row=2, column=0, sticky="e", padx=10, pady=8)
    tk.Button(btn_row, text="Copy row(s)", command=_copy_selected).pack(side="left", padx=4)
    tk.Button(btn_row, text="Copy hash", command=_copy_hash).pack(side="left", padx=4)
    tk.Button(btn_row, text="Copy all", command=_copy_all).pack(side="left", padx=4)
    tk.Button(btn_row, text="Download as .txt", command=_download_txt).pack(side="left", padx=4)
    tk.Button(btn_row, text="Close", command=popup.destroy).pack(side="left", padx=4)

# ---- Pull ----
# Always merge explicitly: without pull.rebase configured, newer git refuses to
# pull when local and remote have both moved on ("divergent branches").
_PULL_STRATEGY = "--no-rebase"

def _porcelain_paths(rp):
    """(untracked, changed) path sets from `git status`, NUL-separated so
    paths with spaces / non-ASCII come through unquoted."""
    untracked, changed = set(), set()
    entries = rp.git.status("--porcelain", "-z", "--untracked-files=all").split("\0")
    i = 0
    while i < len(entries):
        e = entries[i]
        i += 1
        if len(e) < 4:
            continue
        xy, path = e[:2], e[3:]
        if xy == "??":
            untracked.add(path)
        else:
            changed.add(path)
            if xy[0] in "RC":
                i += 1  # the next entry is the rename/copy source path
    return untracked, changed

def _free_backup_path(src):
    dst = f"{src}.local-backup"
    n = 1
    while os.path.exists(dst):
        dst = f"{src}.local-backup{n}"
        n += 1
    return dst

def git_pull_branch():
    """Pull the checked-out branch: check first, clear blockers with the
    user's OK, then pull and show what changed."""
    r, branch = _current_branch_and_remote()
    if not r:
        return
    rp = repo

    def check():
        rp.git.fetch(r.name)
        upstream = _upstream_ref(rp, r, branch)
        if not upstream:
            return {"upstream": ""}
        ahead, behind = (int(n) for n in
                         rp.git.rev_list("--left-right", "--count", f"HEAD...{upstream}").split())
        info = {"upstream": upstream, "ahead": ahead, "behind": behind,
                "untracked_clash": [], "changed_clash": []}
        if behind:
            incoming = set(p for p in rp.git.diff("--name-only", "-z", f"HEAD...{upstream}").split("\0") if p)
            untracked, changed = _porcelain_paths(rp)
            info["untracked_clash"] = sorted(untracked & incoming)
            info["changed_clash"] = sorted(changed & incoming)
        return info

    _run_git_op("Checking remote", check,
                lambda info, err: _pull_after_check(rp, r, branch, info, err))

def _pull_after_check(rp, r, branch, info, err):
    if err:
        messagebox.showerror("Pull", f"Could not check the remote:\n{err}")
        return
    upstream = info["upstream"]
    if not upstream:
        messagebox.showinfo("Pull", f"Branch '{branch}' does not exist on '{r.name}' yet, "
                                    "so there is nothing to pull.\n\nUse Push to publish it first.")
        return
    if info["behind"] == 0:
        msg = f"Already up to date with '{upstream}'."
        if info["ahead"]:
            msg += f"\n\nYou have {info['ahead']} local commit(s) not pushed yet - use Push."
        messagebox.showinfo("Pull", msg)
        return

    rename = info["untracked_clash"]
    if rename and not messagebox.askyesno(
            "Pull - untracked files in the way",
            "These files exist on your PC but were never committed, and the remote "
            "now has files with the same names:\n\n"
            f"{_short_list(rename)}\n\n"
            "Git cannot pull while they are in the way.\n\n"
            "Rename them to '<name>.local-backup' and continue?\n"
            "(Compare with the pulled version afterwards and delete the backup.)"):
        return

    stash = bool(info["changed_clash"])
    if stash and not messagebox.askyesno(
            "Pull - local changes in the way",
            "You have uncommitted changes in files that the pull also changes:\n\n"
            f"{_short_list(info['changed_clash'])}\n\n"
            "Stash them (save aside), pull, then restore them automatically?\n\n"
            "If both sides changed the same lines you will get conflicts to resolve."):
        return

    remote_name, remote_head = upstream.split("/", 1)
    behind = info["behind"]

    def work():
        notes = []
        for p in rename:
            src = os.path.join(rp.working_dir, p)
            dst = _free_backup_path(src)
            os.rename(src, dst)
            notes.append(f"Renamed {p}  ->  {os.path.relpath(dst, rp.working_dir)}")
        stashed = False
        if stash:
            out = rp.git.stash("push", "-m", f"autostash: before pull of {upstream}")
            stashed = "No local changes to save" not in (out or "")
        before = rp.head.commit.hexsha
        try:
            out = rp.git.pull(_PULL_STRATEGY, remote_name, remote_head)
        except Exception as e:
            try:
                conflicts = [p for p in rp.git.diff("--name-only", "--diff-filter=U").splitlines() if p]
            except Exception:
                conflicts = []
            # Leave any stash in place so the user's changes are never lost.
            return {"notes": notes, "pull_error": e, "conflicts": conflicts, "stashed": stashed}
        pop_error = None
        if stashed:
            try:
                rp.git.stash("pop")
            except Exception as e:
                pop_error = e
        after = rp.head.commit.hexsha
        stat = rp.git.diff("--stat", before, after) if before != after else ""
        return {"notes": notes, "out": out, "stat": stat, "pop_error": pop_error}

    _run_git_op("Pulling", work,
                lambda res, err2: _show_pull_result(upstream, behind, res, err2))

def _show_pull_result(upstream, behind, res, err):
    if err:
        messagebox.showerror("Pull failed", f"Git pull failed:\n{err}")
        return
    refresh_workflow_graph()
    notes = "\n".join(res["notes"])

    if res.get("pull_error"):
        if res["conflicts"]:
            msg = ("The pull stopped with merge conflicts in:\n\n"
                   f"{_short_list(res['conflicts'])}\n\n"
                   "Open these files, fix the <<<<<<< / >>>>>>> sections, then commit.\n"
                   "To cancel the merge instead, run 'git merge --abort' in the Terminal tab.")
        else:
            msg = f"Git pull failed:\n{res['pull_error']}"
        if res["stashed"]:
            msg += "\n\nYour local changes are safe in the stash (Stash > Apply latest stash)."
        if notes:
            msg += f"\n\n{notes}"
        messagebox.showerror("Pull", msg)
        return

    header = f"Pulled {behind} commit(s) from '{upstream}'."
    if res["pop_error"]:
        header += ("  Your stashed changes were restored with conflicts - fix them; "
                   "the stash is kept until you drop it (Stash > View stashes).")
    body = "\n\n".join(part for part in (notes, res["stat"], res["out"]) if part)
    _show_text_result("Pull", header, body)

# ---- Push ----

def git_push(on_success=None, success_note=""):
    r, branch = _current_branch_and_remote()
    if not r:
        return
    rp = repo

    def work():
        try:
            tracking = rp.active_branch.tracking_branch()
        except Exception:
            tracking = None
        if tracking is None:
            # First push of this branch: create it on the remote and track it.
            return rp.git.push("--set-upstream", r.name, branch), True
        return rp.git.push(r.name, branch), False

    def done(res, err):
        if err:
            text = str(err)
            if "[rejected]" in text or "non-fast-forward" in text or "fetch first" in text:
                messagebox.showerror(
                    "Git Push",
                    "The remote has commits you don't have yet, so it refused the push.\n\n"
                    "Click Pull first, then Push again.\n\n"
                    f"Details:\n{text}")
            elif "403" in text or "Permission" in text:
                messagebox.showerror(
                    "Git Push (auth)",
                    f"{text}\n\nRemote: {r.name}\nURL: {get_origin_url()}\n\n"
                    "Fix:\n"
                    "• If remote is HTTPS, use a Personal Access Token or switch to SSH.\n"
                    "• If remote is SSH, ensure your key is added and 'ssh -T git@HOST' succeeds.\n"
                    "Both can be set up in the Git AuthN tab.")
            else:
                messagebox.showerror("Git Push", f"Git push failed:\n{text}")
            return
        out, new_upstream = res
        msg = out or f"Pushed '{branch}' to '{r.name}'."
        if success_note:
            msg += f"\n{success_note}"
        if new_upstream:
            msg += f"\n\n'{branch}' now tracks '{r.name}/{branch}'."
        if on_success:
            on_success()
        messagebox.showinfo("Git Push", msg)
        refresh_workflow_graph()

    _run_git_op("Pushing", work, done)

# =============== Commit Section ===============

def _set_commit_msg_visibility(show: bool):
    """Show/hide the single commit message + description rows (selected files
    carry their own message and description instead)."""
    if show:
        commit_msg_label.grid(row=2, column=0, sticky="w", padx=5, pady=5)
        commit_msg_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5)
        commit_desc_label.grid(row=3, column=0, sticky="nw", padx=5, pady=5)
        commit_desc_text.grid(row=3, column=1, columnspan=2, padx=5, pady=5)
    else:
        commit_msg_label.grid_remove()
        commit_msg_entry.grid_remove()
        commit_desc_label.grid_remove()
        commit_desc_text.grid_remove()

def _refresh_commit_msg_visibility():
    """Hide the 'all files' message if selecting specific files."""
    if add_all_var.get():
        _set_commit_msg_visibility(True)
        return
    _set_commit_msg_visibility(False if selected_files else True)

def toggle_add_all():
    if add_all_var.get():
        choose_button.grid_remove()
        clear_selected_files()
    else:
        choose_button.grid(row=0, column=1, padx=5, pady=(0, 5))
    _refresh_commit_msg_visibility()

def clear_selected_files():
    global selected_files, file_entries
    selected_files.clear()
    for widget in file_messages_frame.winfo_children():
        widget.destroy()
    file_entries.clear()
    try:
        if add_all_var.get():
            choose_button.grid_remove()
        else:
            add_all_checkbox.grid(row=0, column=0, sticky="w", padx=5, pady=(0, 5))
            choose_button.grid(row=0, column=1, padx=5, pady=(0, 5))
    except Exception:
        pass
    _refresh_commit_msg_visibility()

def choose_files():
    """Allow choosing files only from inside the repo working dir."""
    global selected_files, file_entries, repo
    if not repo:
        messagebox.showwarning("Error", "Load a repository first.")
        return
    files = filedialog.askopenfilenames(initialdir=repo.working_dir)
    if files:
        added_any = False
        repo_root = os.path.abspath(repo.working_dir)
        for f in files:
            absf = os.path.abspath(f)
            try:
                if os.path.commonpath([repo_root, absf]) != repo_root:
                    messagebox.showwarning("Skip", f"{os.path.basename(f)} is outside this repository.")
                    continue
            except Exception:
                pass
            if absf not in selected_files:
                selected_files.append(absf)
                add_file_entry(absf)
                added_any = True
        if added_any:
            add_all_checkbox.grid_remove()
        else:
            add_all_checkbox.grid(row=0, column=0, sticky="w", padx=5, pady=(0, 5))
        _refresh_commit_msg_visibility()

def add_file_entry(f):
    """One block per selected file: its own commit message and description."""
    global file_entries
    box = tk.Frame(file_messages_frame)
    box.pack(fill="x", anchor="w", pady=(0, 10))

    tk.Label(box, text=os.path.basename(f), font=("Arial", 10, "bold"))\
      .grid(row=0, column=0, columnspan=2, sticky="w", padx=10)
    tk.Button(box, text="X", fg="red", command=lambda file=f: remove_file(file))\
      .grid(row=0, column=2, padx=5)

    tk.Label(box, text="Commit message:").grid(row=1, column=0, sticky="w", padx=(10, 5))
    entry = tk.Entry(box, width=50)
    entry.grid(row=1, column=1, sticky="w", pady=2)

    tk.Label(box, text="Description (optional):").grid(row=2, column=0, sticky="nw", padx=(10, 5))
    desc = tk.Text(box, width=50, height=3, wrap="word")
    desc.grid(row=2, column=1, sticky="w", pady=2)

    file_entries[f] = (box, entry, desc)

def remove_file(f):
    global selected_files, file_entries
    if f in selected_files:
        selected_files.remove(f)
        file_entries[f][0].destroy()
        del file_entries[f]

    if not selected_files:
        add_all_checkbox.grid(row=0, column=0, sticky="w", padx=5, pady=(0, 5))
    _refresh_commit_msg_visibility()

def _show_push_section():
    try:
        if 'push_section' in globals() and push_section is not None:
            push_section.grid(**_PUSH_SECTION_GRID)
    except Exception:
        pass

def _hide_push_section():
    try:
        if 'push_section' in globals() and push_section is not None:
            push_section.grid_remove()
    except Exception:
        pass

def _clear_workflow_ui():
    try:
        ascii_text.config(state="normal")
        ascii_text.delete("1.0", "end")
        ascii_text.insert("1.0", "No repository loaded.\n")
        ascii_text.config(state="disabled")
    except Exception:
        pass

    try:
        for table in (merges_table, commits_table):
            for row in table.get_children():
                table.delete(row)
    except Exception:
        pass

def _reset_commit_ui(clear_add_all: bool = False, hide_push: bool = True):
    try:
        if clear_add_all:
            add_all_var.set(False)
    except Exception:
        pass
    try:
        commit_msg_entry.delete(0, "end")
    except Exception:
        pass
    try:
        commit_desc_text.delete("1.0", "end")
    except Exception:
        pass
    clear_selected_files()
    if hide_push:
        _hide_push_section()

def _format_status_lines(status_lines: list[str], limit: int = 15) -> str:
    if not status_lines:
        return "(no local changes)"
    shown = status_lines[:limit]
    suffix = f"\n...and {len(status_lines) - limit} more" if len(status_lines) > limit else ""
    return "\n".join(shown) + suffix

def _format_log_lines(log_text: str, limit: int = 10) -> str:
    lines = [ln for ln in (log_text or "").splitlines() if ln.strip()]
    if not lines:
        return "(no remote commits)"
    shown = lines[:limit]
    suffix = f"\n...and {len(lines) - limit} more" if len(lines) > limit else ""
    return "\n".join(shown) + suffix

def _show_pre_commit_summary(remote_summary: str, local_summary: str, final_summary: str) -> bool:
    popup = Toplevel(root)
    popup.title("Pre-Commit Sync Check")
    popup.geometry("780x620")
    popup.minsize(520, 420)
    popup.grid_rowconfigure(1, weight=1)
    popup.grid_columnconfigure(0, weight=1)

    tk.Label(popup, text="Remote vs Local Summary", font=("Arial", 11, "bold"))\
      .grid(row=0, column=0, sticky="w", padx=10, pady=(10, 6))
    tk.Label(
        popup,
        text="Legend: M = Modified, A = Added (staged new file), ?? = Untracked",
        font=("Arial", 9),
        fg="#444444",
    ).grid(row=0, column=0, sticky="e", padx=10, pady=(10, 6))

    txt = scrolledtext.ScrolledText(popup, wrap="word")
    txt.grid(row=1, column=0, sticky="nsew", padx=10, pady=0)

    # Color tags for clarity
    txt.tag_configure("hdr_remote", foreground="#1f5fbf", font=("Arial", 9, "bold"))
    txt.tag_configure("hdr_local", foreground="#1b7f3a", font=("Arial", 9, "bold"))
    txt.tag_configure("hdr_final", foreground="#6a3dbf", font=("Arial", 9, "bold"))
    txt.tag_configure("body_remote", foreground="#0f2f66")
    txt.tag_configure("body_local", foreground="#0f4a23")
    txt.tag_configure("body_final", foreground="#3a1c66")
    txt.tag_configure("rule", foreground="#777777")

    def _ins(header, rule, body, tag_hdr, tag_body):
        txt.insert("end", header + "\n", tag_hdr)
        txt.insert("end", rule + "\n", "rule")
        txt.insert("end", body + "\n\n", tag_body)

    _ins(
        "REMOTE (incoming changes)",
        "-------------------------",
        remote_summary,
        "hdr_remote",
        "body_remote",
    )
    _ins(
        "LOCAL (your working changes)",
        "-----------------------------",
        local_summary,
        "hdr_local",
        "body_local",
    )
    _ins(
        "FINAL (after stash + pull + reapply)",
        "-------------------------------------",
        final_summary,
        "hdr_final",
        "body_final",
    )
    txt.configure(state="disabled")

    btns = tk.Frame(popup)
    btns.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
    btns.grid_columnconfigure(0, weight=1)
    btns.grid_columnconfigure(1, weight=1)
    btns.grid_columnconfigure(2, weight=1)

    result = {"ok": False}

    def _preview_final_diff():
        try:
            popup.grab_release()
        except Exception:
            pass
        _show_final_diff_popup(parent=popup)
        try:
            popup.grab_set()
        except Exception:
            pass

    def _ok():
        result["ok"] = True
        popup.destroy()

    def _cancel():
        result["ok"] = False
        popup.destroy()

    tk.Button(btns, text="Preview Final Diff", command=_preview_final_diff)\
      .grid(row=0, column=0, sticky="e", padx=5)
    tk.Button(btns, text="OK (Stash, Pull, Reapply)", command=_ok)\
      .grid(row=0, column=1, sticky="e", padx=5)
    tk.Button(btns, text="Cancel", command=_cancel)\
      .grid(row=0, column=2, sticky="w", padx=5)

    popup.grab_set()
    root.wait_window(popup)
    return result["ok"]

def _split_diff_by_file(diff_text: str) -> list[tuple[str, str]]:
    """Split a multi-file unified diff into (path, chunk) pairs, one per 'diff --git' header."""
    chunks = []
    path, lines = None, []
    for line in (diff_text or "").splitlines(keepends=True):
        if line.startswith("diff --git "):
            if lines:
                chunks.append((path or "", "".join(lines)))
            header = line[len("diff --git "):].strip()
            path = header.rsplit(" b/", 1)[-1].strip('"') if " b/" in header else header
            lines = [line]
        else:
            lines.append(line)
    if lines:
        chunks.append((path or "", "".join(lines)))
    return chunks

def _open_simple_diff_window(title: str, subtitle: str, diff_text: str, parent=None):
    popup = Toplevel(parent or root)
    popup.title(title)
    popup.geometry("1100x700")
    popup.minsize(700, 420)
    if parent:
        try:
            popup.transient(parent)
        except Exception:
            pass

    popup.grid_rowconfigure(1, weight=1)
    popup.grid_columnconfigure(0, weight=1)

    tk.Label(popup, text=title, font=("Arial", 11, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 2))
    if subtitle:
        tk.Label(popup, text=subtitle, font=("Arial", 9)).grid(row=0, column=0, sticky="e", padx=10, pady=(10, 2))

    notebook = ttk.Notebook(popup)
    notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _add_diff_tab(tab_title: str, content: str, path_label: str = ""):
        tab = tk.Frame(notebook)
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        if path_label:
            tk.Label(tab, text=path_label, font=("Arial", 9, "bold")).grid(
                row=0, column=0, sticky="w", padx=4, pady=(4, 2)
            )
        txt = scrolledtext.ScrolledText(tab, wrap="none")
        txt.grid(row=1, column=0, sticky="nsew", padx=4, pady=0)
        hbar = tk.Scrollbar(tab, orient="horizontal", command=txt.xview)
        hbar.grid(row=2, column=0, sticky="ew", padx=4, pady=(0, 4))
        txt.configure(xscrollcommand=hbar.set)
        _colorize_diff_text(txt, content or "(no changes)")
        txt.configure(state="disabled")
        notebook.add(tab, text=tab_title)

    file_chunks = _split_diff_by_file(diff_text)
    if len(file_chunks) > 1:
        _add_diff_tab(f"All ({len(file_chunks)})", diff_text)
    for path, chunk in file_chunks:
        _add_diff_tab(os.path.basename(path) or "File", chunk, path)
    if not file_chunks:
        _add_diff_tab("All", diff_text)

    try:
        popup.grab_set()
    except Exception:
        pass
    popup.wait_window(popup)

def _show_final_diff_popup(parent=None):
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    r = _get_primary_remote()
    if not r:
        messagebox.showwarning("Error", "No remote configured.")
        return

    branch_name = _current_branch_name() or branch_var.get().strip()
    if not branch_name:
        messagebox.showwarning("Error", "No branch selected.")
        return

    tracking = None
    try:
        tracking = repo.active_branch.tracking_branch()
    except Exception:
        tracking = None

    upstream = str(tracking) if tracking else f"{r.name}/{branch_name}"

    def _diff_no_index(old_path: str, new_path: str) -> str:
        """Return git diff for no-index; accept return codes 0/1."""
        cmd = ["git", "diff", "--no-index", "--binary", "--", old_path, new_path]
        res = subprocess.run(cmd, cwd=repo.working_dir, capture_output=True, text=True)
        if res.returncode in (0, 1):
            return res.stdout
        raise RuntimeError((res.stderr or res.stdout or "").strip() or "git diff --no-index failed")

    def _diff_untracked_file(rel_path: str) -> str:
        # Try OS null device first; fall back to /dev/null for Git behavior.
        for null_path in (os.devnull, "/dev/null"):
            try:
                return _diff_no_index(null_path, rel_path)
            except Exception:
                continue
        return ""

    try:
        # Diff working tree against upstream (final view after pull+reapply).
        diff_parts = []
        diff_base = repo.git.diff(upstream)
        if diff_base.strip():
            diff_parts.append(diff_base)

        # Include untracked files so "?? file" appears in preview.
        for rel in (repo.untracked_files or []):
            abs_path = os.path.join(repo.working_dir, rel)
            if not os.path.isfile(abs_path):
                continue
            ut_diff = _diff_untracked_file(rel)
            if ut_diff.strip():
                diff_parts.append(ut_diff)

        diff_text = "\n".join(diff_parts).strip()
    except Exception as e:
        messagebox.showerror("Preview failed", f"Could not generate diff:\n{e}")
        return

    subtitle = f"Diff: working tree vs {upstream}"
    _open_simple_diff_window("Preview Final Diff", subtitle, diff_text, parent=parent)

def _pre_commit_sync_if_needed() -> bool:
    """If remote is ahead and local has changes, show summary and auto stash/pull/pop."""
    global repo
    try:
        r = _get_primary_remote()
        if not repo or not r:
            return True

        branch_name = _current_branch_name() or branch_var.get().strip()
        if not branch_name:
            return True

        try:
            r.fetch()
        except Exception:
            pass

        tracking = None
        try:
            tracking = repo.active_branch.tracking_branch()
        except Exception:
            tracking = None

        upstream = str(tracking) if tracking else f"{r.name}/{branch_name}"

        try:
            counts = repo.git.rev_list("--left-right", "--count", f"{branch_name}...{upstream}").strip()
            _ahead_str, behind_str = (counts.split() + ["0", "0"])[:2]
            behind = int(behind_str)
        except Exception:
            behind = 0

        dirty = repo.is_dirty(untracked_files=True)

        remote_log = ""
        try:
            remote_log = repo.git.log("--oneline", f"{branch_name}..{upstream}")
        except Exception:
            remote_log = ""

        status_lines = []
        try:
            status_lines = repo.git.status("--porcelain").splitlines()
        except Exception:
            status_lines = []

        remote_summary = _format_log_lines(remote_log, limit=12)
        local_summary = _format_status_lines(status_lines, limit=20)
        if behind > 0 and dirty:
            final_summary = (
                f"Remote is ahead by {behind} commit(s). "
                "Your local changes will be stashed, pulled, and then reapplied. "
                "If conflicts happen during reapply, you will need to resolve them before committing."
            )
        elif behind > 0:
            final_summary = (
                f"Remote is ahead by {behind} commit(s). "
                "No local changes detected, so only a pull is needed."
            )
        elif dirty:
            final_summary = (
                "Remote is not ahead. Your local changes will be committed without a pull."
            )
        else:
            final_summary = "No remote changes and no local changes detected."

        if not _show_pre_commit_summary(remote_summary, local_summary, final_summary):
            return False

        if behind > 0 and dirty:
            stash_created = False
            try:
                out = repo.git.stash("push", "-u", "-m", "autostash: pre-commit")
                if "No local changes to save" not in (out or ""):
                    stash_created = True
            except Exception as e:
                messagebox.showerror("Stash failed", f"Git stash failed:\n{e}")
                return False

            try:
                repo.git.pull(_PULL_STRATEGY, r.name, branch_name)
            except Exception as e:
                messagebox.showerror("Pull failed", f"Git pull failed:\n{e}")
                return False

            if stash_created:
                try:
                    repo.git.stash("pop")
                except Exception as e:
                    messagebox.showerror(
                        "Stash apply failed",
                        f"Git stash pop failed (possible conflicts):\n{e}\n\n"
                        "Resolve conflicts, then try commit again."
                    )
                    return False
        elif behind > 0 and not dirty:
            try:
                repo.git.pull(_PULL_STRATEGY, r.name, branch_name)
            except Exception as e:
                messagebox.showerror("Pull failed", f"Git pull failed:\n{e}")
                return False

        return True
    except Exception as e:
        messagebox.showerror("Sync check failed", f"{e}")
        return False

def _full_commit_message(summary: str, desc_widget=None) -> str:
    """Join the summary with the optional description (blank line between),
    the same layout `git commit -m <summary> -m <description>` produces.
    desc_widget defaults to the shared description box."""
    desc = (desc_widget or commit_desc_text).get("1.0", "end").strip()
    return f"{summary}\n\n{desc}" if desc else summary

def commit_changes():
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    if not _ensure_identity_before_commit():
        return

    committed_files = []

    try:
        if not _pre_commit_sync_if_needed():
            return

        if add_all_var.get():
            msg = commit_msg_entry.get().strip()
            if not msg:
                messagebox.showwarning("Error", "Please enter a commit message for all files.")
                return

            repo.git.add(A=True)
            staged = repo.git.diff("--name-only", "--cached").splitlines()
            if not staged:
                messagebox.showinfo("Nothing to commit", "No changes are staged.")
                return

            repo.index.commit(_full_commit_message(msg))
            committed_files = [(os.path.basename(p), msg) for p in staged]

        else:
            if not selected_files:
                messagebox.showwarning("Error", "No files selected.")
                return

            for f in selected_files:
                per_msg = file_entries[f][1].get().strip()
                if not per_msg:
                    messagebox.showwarning("Error", f"Please enter a commit message for {os.path.basename(f)}")
                    return

            for f in selected_files:
                per_msg = file_entries[f][1].get().strip()
                try:
                    rel = os.path.relpath(f, repo.working_dir)
                except Exception:
                    rel = f
                rel_git = rel.replace("\\", "/")

                has_changes = repo.git.status("--porcelain", "--", rel_git).strip()
                if not has_changes:
                    continue

                repo.git.add("--", rel_git)
                repo.index.commit(_full_commit_message(per_msg, file_entries[f][2]))
                committed_files.append((os.path.basename(f), per_msg))

            if not committed_files:
                messagebox.showinfo("Nothing to commit", "No changes detected for the selected files.")
                return

        show_commit_summary(committed_files)
        _show_push_section()
        _reset_commit_ui(clear_add_all=False, hide_push=False)
        refresh_workflow_graph()

    except Exception as e:
        messagebox.showerror("Error", f"Commit failed:\n{e}")

def _normalize_relpath(path: str) -> str:
    try:
        rel = os.path.relpath(path, repo.working_dir)
    except Exception:
        rel = path
    return rel.replace("\\", "/")

def _colorize_diff_text(widget: tk.Text, diff_text: str):
    widget.tag_configure("add", foreground="green")
    widget.tag_configure("del", foreground="red")
    widget.tag_configure("ctx", foreground="black")

    if not diff_text:
        widget.insert("end", "(no changes)", "ctx")
        return

    for line in diff_text.splitlines(keepends=True):
        if line.startswith("+") and not line.startswith("+++"):
            widget.insert("end", line, "add")
        elif line.startswith("-") and not line.startswith("---"):
            widget.insert("end", line, "del")
        else:
            widget.insert("end", line, "ctx")

def _open_diff_window(title: str, subtitle: str, before_text: str, after_text: str):
    popup = Toplevel(root)
    popup.title(title)
    popup.geometry("1100x700")
    popup.minsize(700, 420)

    popup.grid_rowconfigure(1, weight=1)
    popup.grid_columnconfigure(0, weight=1)

    tk.Label(popup, text=title, font=("Arial", 11, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 2))
    if subtitle:
        tk.Label(popup, text=subtitle, font=("Arial", 9)).grid(row=0, column=0, sticky="e", padx=10, pady=(10, 2))

    panes = ttk.Panedwindow(popup, orient="horizontal")
    panes.grid(row=1, column=0, sticky="nsew", padx=10, pady=0)

    left = tk.Frame(panes)
    right = tk.Frame(panes)
    panes.add(left, weight=1)
    panes.add(right, weight=1)

    tk.Label(left, text="Before Commit (unstaged + staged)", font=("Arial", 9, "bold"))\
      .grid(row=0, column=0, sticky="w", padx=4, pady=(4, 2))
    tk.Label(right, text="Last Commit (vs parent)", font=("Arial", 9, "bold"))\
      .grid(row=0, column=0, sticky="w", padx=4, pady=(4, 2))

    for frame, content in ((left, before_text), (right, after_text)):
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        txt = scrolledtext.ScrolledText(frame, wrap="none")
        txt.grid(row=1, column=0, sticky="nsew", padx=4, pady=(0, 4))
        hbar = tk.Scrollbar(frame, orient="horizontal", command=txt.xview)
        hbar.grid(row=2, column=0, sticky="ew", padx=4, pady=(0, 4))
        txt.configure(xscrollcommand=hbar.set)
        _colorize_diff_text(txt, content)
        txt.configure(state="disabled")

def _open_diff_tabs_window(title: str, items: list[dict]):
    """Open a single popup with a tab per file diff."""
    popup = Toplevel(root)
    popup.title(title)
    popup.geometry("1100x700")
    popup.minsize(700, 420)

    popup.grid_rowconfigure(1, weight=1)
    popup.grid_columnconfigure(0, weight=1)

    tk.Label(popup, text=title, font=("Arial", 11, "bold")).grid(
        row=0, column=0, sticky="w", padx=10, pady=(10, 2)
    )

    notebook = ttk.Notebook(popup)
    notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

    for item in items:
        path = item.get("path", "")
        before_text = item.get("before", "")
        after_text = item.get("after", "")
        subtitle = item.get("subtitle", "")

        tab = tk.Frame(notebook)
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        if subtitle:
            tk.Label(tab, text=subtitle, font=("Arial", 9)).grid(
                row=0, column=0, sticky="w", padx=6, pady=(6, 4)
            )

        panes = ttk.Panedwindow(tab, orient="horizontal")
        panes.grid(row=1, column=0, sticky="nsew", padx=4, pady=0)

        left = tk.Frame(panes)
        right = tk.Frame(panes)
        panes.add(left, weight=1)
        panes.add(right, weight=1)

        tk.Label(left, text="Before Commit (unstaged + staged)", font=("Arial", 9, "bold"))\
          .grid(row=0, column=0, sticky="w", padx=4, pady=(4, 2))
        tk.Label(right, text="Last Commit (vs parent)", font=("Arial", 9, "bold"))\
          .grid(row=0, column=0, sticky="w", padx=4, pady=(4, 2))

        for frame, content in ((left, before_text), (right, after_text)):
            frame.grid_rowconfigure(1, weight=1)
            frame.grid_columnconfigure(0, weight=1)
            txt = scrolledtext.ScrolledText(frame, wrap="none")
            txt.grid(row=1, column=0, sticky="nsew", padx=4, pady=(0, 4))
            hbar = tk.Scrollbar(frame, orient="horizontal", command=txt.xview)
            hbar.grid(row=2, column=0, sticky="ew", padx=4, pady=(0, 4))
            txt.configure(xscrollcommand=hbar.set)
            _colorize_diff_text(txt, content)
            txt.configure(state="disabled")

        tab_title = os.path.basename(path) if path else "File"
        notebook.add(tab, text=tab_title)

def _collect_changed_files_for_preview():
    if add_all_var.get():
        return None  # signal: all changes
    if selected_files:
        return [_normalize_relpath(f) for f in selected_files]
    return []

def _is_preview_allowed(path: str) -> bool:
    """Return False for binary/office/image formats that should not be previewed."""
    ext = os.path.splitext(path)[1].lower()
    blocked = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg",
        ".ico",
        ".pdf",
        ".doc", ".docx",
        ".ppt", ".pptx",
    }
    return ext not in blocked

def _branch_context_label():
    local = _current_branch_name() or branch_var.get().strip() or "(detached)"
    remote = "(no upstream)"
    try:
        if repo and repo.active_branch:
            tracking = repo.active_branch.tracking_branch()
            if tracking:
                remote = str(tracking)
    except Exception:
        pass
    return f"Local: {local} | Remote: {remote}"

def preview_changes():
    """Show per-file diffs: before commit vs last commit."""
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return

    paths = _collect_changed_files_for_preview()
    if paths == []:
        messagebox.showwarning("Error", "No files selected. Choose files or enable 'Add all files'.")
        return

    try:
        untracked = set(repo.untracked_files or [])
        if paths is None:
            files = repo.git.diff("--name-only").splitlines()
            files += repo.git.diff("--name-only", "--cached").splitlines()
            files = sorted({f for f in files if f})
            files += sorted({f for f in untracked if f})
            files = sorted({f for f in files if f})
        else:
            files = paths

        if not files:
            messagebox.showinfo("No changes", "No unstaged or staged changes to preview.")
            return

        files = [f for f in files if _is_preview_allowed(f)]
        if not files:
            messagebox.showinfo(
                "No previewable files",
                "No previewable files found. Image/PDF/Office/Icon formats are excluded."
            )
            return

        preview_items = []
        for f in files:
            is_untracked = f in untracked
            unstaged = repo.git.diff("--", f)
            staged = repo.git.diff("--cached", "--", f)
            combined = ""
            if is_untracked:
                combined += f"*** NEW FILE (untracked): {f} ***\n"
                file_abs = os.path.join(repo.working_dir, f)
                try:
                    with open(file_abs, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                    if content:
                        combined += "diff --git a/{0} b/{0}\n".format(f)
                        combined += "new file mode 100644\n"
                        combined += "--- /dev/null\n"
                        combined += f"+++ b/{f}\n"
                        for line in content.splitlines():
                            combined += f"+{line}\n"
                    else:
                        combined += "(empty file)\n"
                except Exception as e:
                    combined += f"(could not read file: {e})\n"
            if unstaged:
                combined += f"--- Unstaged diff for {f} ---\n{unstaged}\n"
            if staged:
                combined += f"--- Staged diff for {f} ---\n{staged}\n"
            if not combined:
                combined = ""

            after_text = ""
            try:
                if repo.head.is_valid():
                    head = repo.head.commit
                    if head.parents:
                        after_text = repo.git.show("--pretty=format:", "HEAD", "--", f)
                    else:
                        after_text = repo.git.show("--pretty=format:", "HEAD", "--", f)
                else:
                    after_text = "*** No commits yet in this repository ***"
            except Exception:
                after_text = ""

            if not after_text:
                after_text = f"*** Not in last commit: {f} ***"

            subtitle = f"{f}    |    {_branch_context_label()}"
            preview_items.append({
                "path": f,
                "before": combined,
                "after": after_text,
                "subtitle": subtitle,
            })

        if preview_items:
            _open_diff_tabs_window("Preview Changes", preview_items)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to preview changes:\n{e}")

def show_commit_summary(committed_files):
    popup = Toplevel(root)
    popup.title("Commit Summary")
    popup.geometry("600x600")
    popup.minsize(420, 360)

    # Grid layout
    popup.grid_rowconfigure(1, weight=1)
    popup.grid_columnconfigure(0, weight=1)

    tk.Label(popup, text="Files committed:").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 6))

    # ScrolledText (vertical scrollbar built-in)
    txt = scrolledtext.ScrolledText(popup, wrap="none")
    txt.grid(row=1, column=0, sticky="nsew", padx=10, pady=0)

    # Horizontal scrollbar
    hbar = tk.Scrollbar(popup, orient="horizontal", command=txt.xview)
    hbar.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
    txt.configure(xscrollcommand=hbar.set)

    # Fill file list
    for f, msg in committed_files:
        txt.insert("end", f"{f}  --->  {msg}\n")

    txt.configure(state="disabled")

    # Buttons row (Git Push + Close)
    btns = tk.Frame(popup)
    btns.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
    btns.grid_columnconfigure(0, weight=1)
    btns.grid_columnconfigure(1, weight=1)

    tk.Button(btns, text="Git Push",
              command=lambda: push_changes(popup, committed_files)).grid(row=0, column=0, sticky="e", padx=5)
    tk.Button(btns, text="Close", command=popup.destroy).grid(row=0, column=1, sticky="w", padx=5)

def push_changes(popup, committed_files):
    """Git Push from the Commit Summary popup: same background push as the
    Push button; the popup closes once the push succeeds."""
    def _close_popup():
        if popup.winfo_exists():
            popup.destroy()

    git_push(on_success=_close_popup,
             success_note=f"{len(committed_files)} committed file(s) pushed.")

# =============== Workflow Graph helpers (ASCII) ===============

MERGE_RE = re.compile(r"Merge (?:branch '([^']+)'(?: into ([^ ]+))?|pull request #\d+.*)", re.IGNORECASE)

def _name_rev_safe(repo, sha):
    try:
        name = repo.git.name_rev('--name-only', sha).strip()
        return '' if name == 'undefined' else name
    except Exception:
        return ''

def _guess_merge_from_into(repo, merge_commit):
    parents = merge_commit.parents
    if len(parents) < 2:
        return ("", "")

    into_name = _name_rev_safe(repo, parents[0].hexsha)
    from_name = _name_rev_safe(repo, parents[1].hexsha)

    decorations = repo.git.log("-1", "--pretty=%D", merge_commit.hexsha).strip()
    if "HEAD ->" in decorations:
        into_name = decorations.split("HEAD ->")[1].split(",")[0].strip()

    return (from_name, into_name)

def _branch_hint_for_commit(repo, sha: str) -> str:
    """
    Return a short branch-ish name for this commit, using `git name-rev`.
    Examples of raw output: 'main', 'dev~3', 'main^0', 'dev tags/v1.0'.
    We keep only the first token and strip trailing ~... or ^... or {...}.
    """
    try:
        s = repo.git.name_rev('--name-only', sha).strip()
    except Exception:
        return ""
    if not s or s == "undefined":
        return ""
    token = s.split()[0]  # e.g. 'dev~3' or 'main^0'
    m = re.match(r'([^~^{}]+)', token)
    return m.group(1) if m else token

def _collect_workflow_data(r: Repo):
    # --- Build commit list once (for tables + coloring) ---
    commits = list(r.iter_commits("--all", max_count=300))

    # Classify commits for coloring
    merge_shas = set()
    copy_like_shas = set()
    branch_tip_shas = set()

    # NEW rule: match 'copy' or 'restore' anywhere in the commit message (case-insensitive)
    word_re = re.compile(r"(copy|restore)", re.IGNORECASE)

    for c in commits:
        if len(c.parents) >= 2:
            merge_shas.add(c.hexsha)
        msg = c.message or ""
        if word_re.search(msg):
            copy_like_shas.add(c.hexsha)

    # Branch tips (local + remote refs)
    try:
        for ref in r.refs:
            try:
                branch_tip_shas.add(ref.commit.hexsha)
            except Exception:
                pass
    except Exception:
        pass

    # Map short SHA -> kind (normal / merge / branch_tip / copy)
    short_kind = {}
    for c in commits:
        short = c.hexsha[:7]  # git %h is usually 7 chars

        is_merge = c.hexsha in merge_shas
        is_copy  = c.hexsha in copy_like_shas
        is_tip   = c.hexsha in branch_tip_shas

        # Priority: merge > copy/restore > branch tip > normal
        if is_merge:
            kind = "merge"
        elif is_copy:
            kind = "copy"
        elif is_tip:
            kind = "branch_tip"
        else:
            kind = "normal"

        short_kind[short] = kind

    # --- ASCII graph on the left (WITHOUT date/author) ---
    try:
        ascii_graph = r.git.log(
            "--graph", "--decorate", "--all",
            "--pretty=format:%h %d %s",   # no %ad %an here
            max_count="300"
        )
    except Exception as e:
        ascii_graph = f"Failed to render git graph: {e}"

    # --- Build Recent Commits rows ---
    commits_rows = []
    for c in commits:
        short_sha = c.hexsha[:8]
        when = datetime.datetime.fromtimestamp(c.committed_date).strftime("%Y-%m-%d")
        author = c.author.name if c.author else "Unknown"
        summary, desc = _split_commit_message(c.message)
        # Table cells are single-line, so flatten the description there
        desc_flat = " ".join(desc.split())
        branch = _branch_hint_for_commit(r, c.hexsha) or ""
        try:
            changed = list(c.stats.files or {})
        except Exception:
            changed = []
        file_names = ", ".join(os.path.basename(str(p)) for p in changed)
        commits_rows.append((short_sha, when, author, branch, len(changed), file_names,
                             summary, desc_flat))

    # --- Build Merges rows ---
    try:
        raw = r.git.log(
            "--all", "--merges", "--date=short",
            "--pretty=format:%H%x00%ad%x00%an%x00%s"
        )
        merge_lines = [ln for ln in raw.split("\n") if ln] if raw else []
    except Exception:
        merge_lines = []

    merges_rows = []
    for ln in merge_lines:
        try:
            sha, ad, au, msg = ln.split("\x00", 3)
        except ValueError:
            continue
        try:
            mc = r.commit(sha)
        except Exception:
            mc = None
        from_name = into_name = ''
        if mc and len(mc.parents) >= 2:
            from_name, into_name = _guess_merge_from_into(r, mc)
        merges_rows.append((sha[:8], ad, au, from_name, into_name, msg))

    return {
        "short_kind": short_kind,
        "ascii_graph": ascii_graph,
        "commits_rows": commits_rows,
        "merges_rows": merges_rows,
    }

def _apply_workflow_data(data: dict):
    short_kind = data.get("short_kind", {})
    ascii_graph = data.get("ascii_graph", "")
    commits_rows = data.get("commits_rows", [])
    merges_rows = data.get("merges_rows", [])

    ascii_text.config(state="normal")
    ascii_text.delete("1.0", "end")

    lines = ascii_graph.splitlines() if ascii_graph else []
    for line in lines:
        start = ascii_text.index("end-1c")
        ascii_text.insert("end", line + "\n")
        end = ascii_text.index("end-1c")

        # Allow graph chars (| / \ and spaces) between "*" and the SHA
        m = re.search(r"\* [|\\/ ]*([0-9a-f]{7,})", line)
        if m:
            short = m.group(1)
            kind = short_kind.get(short, "normal")
            tag = f"kind_{kind}"
        else:
            tag = "kind_normal"

        ascii_text.tag_add(tag, start, end)

    if not lines:
        ascii_text.insert("1.0", "No history found.\n")

    ascii_text.config(state="disabled")

    # --- Clear the tables on the right ---
    for table in (merges_table, commits_table):
        for row in table.get_children():
            table.delete(row)

    # --- Fill Recent Commits table (with BRANCH column) ---
    for row in commits_rows:
        commits_table.insert("", "end", values=row)

    # --- Fill Merges table ---
    if not merges_rows:
        merges_table.insert("", "end", values=("", "", "", "", "", "No merge commits found"))
    else:
        for row in merges_rows:
            merges_table.insert("", "end", values=row)

def refresh_workflow_graph_async():
    global repo, graph_refresh_in_progress
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return

    if graph_refresh_in_progress:
        return

    graph_refresh_in_progress = True
    repo_snapshot = repo

    try:
        ascii_text.config(state="normal")
        ascii_text.delete("1.0", "end")
        ascii_text.insert("1.0", "Loading history...\n")
        ascii_text.config(state="disabled")
    except Exception:
        pass

    def task():
        try:
            data = _collect_workflow_data(repo_snapshot)
            err = None
        except Exception as e:
            data = None
            err = e

        def ui_update():
            global graph_refresh_in_progress
            graph_refresh_in_progress = False
            if app_closing or not root.winfo_exists():
                return
            if repo_snapshot is not repo:
                return
            if err:
                messagebox.showerror("Error", f"Failed to read commits:\n{err}")
                return
            _apply_workflow_data(data)

        _post_ui(ui_update)

    threading.Thread(target=task, daemon=True).start()

def refresh_workflow_graph():
    # Backwards-compatible entry point (use async to keep UI responsive)
    refresh_workflow_graph_async()

def _split_commit_message(message: str):
    """Split a commit message into (summary, description): the first line,
    then everything after it (Git puts a blank line between the two)."""
    lines = (message or "").strip().splitlines()
    if not lines:
        return "", ""
    return lines[0].strip(), "\n".join(lines[1:]).strip()

def _commit_file_rows(r: Repo, c):
    """Return (status, path, +lines, -lines) for every file a commit touched.

    Diffs against the first parent (same basis as the FILES count), or
    against the empty tree for a root commit."""
    args = ["-r", "--no-commit-id", "-M", "--name-status"]
    if c.parents:
        out = r.git.diff_tree(*args, c.parents[0].hexsha, c.hexsha)
    else:
        out = r.git.diff_tree("--root", *args, c.hexsha)
    try:
        stats = c.stats.files or {}
    except Exception:
        stats = {}

    rows = []
    for line in (out or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        code = parts[0][:1]
        status = _GIT_XY_DESC.get(code, code)
        if code in ("R", "C") and len(parts) >= 3:
            path = f"{parts[1]} -> {parts[2]}"
            st = stats.get(parts[2]) or stats.get(f"{parts[1]} => {parts[2]}") or {}
        else:
            path = parts[1]
            st = stats.get(path) or {}
        rows.append((status, path, st.get("insertions", ""), st.get("deletions", "")))
    return rows

def show_commit_files(_evt=None):
    """Popup listing the files changed in the selected Recent Commits row."""
    if not repo:
        return
    sel = commits_table.selection()
    if not sel:
        return
    values = commits_table.item(sel[0], "values")
    if not values:
        return
    short_sha = values[0]
    try:
        c = repo.commit(short_sha)
        summary, desc = _split_commit_message(c.message)
        rows = _commit_file_rows(repo, c)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read files for {short_sha}:\n{e}")
        return

    popup = Toplevel(root)
    popup.title(f"Files in commit {short_sha}")
    popup.geometry("760x520")
    popup.minsize(480, 300)
    popup.transient(root)
    popup.grid_rowconfigure(2, weight=1)
    popup.grid_columnconfigure(0, weight=1)

    tk.Label(popup, text=f"Commit {short_sha}   ({len(rows)} file(s))",
             font=("Arial", 12, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 2))

    info = tk.Frame(popup)
    info.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 6))
    info.grid_columnconfigure(1, weight=1)
    tk.Label(info, text="Commit:", font=("Arial", 10, "bold"))\
      .grid(row=0, column=0, sticky="nw", padx=(0, 6))
    tk.Label(info, text=summary or "(no summary)", anchor="w", justify="left", wraplength=640)\
      .grid(row=0, column=1, sticky="w")
    tk.Label(info, text="Description:", font=("Arial", 10, "bold"))\
      .grid(row=1, column=0, sticky="nw", padx=(0, 6), pady=(4, 0))
    desc_box = scrolledtext.ScrolledText(info, wrap="word", height=4, font=("Segoe UI", 9))
    desc_box.insert("1.0", desc or "(no description)")
    desc_box.config(state="disabled")
    desc_box.grid(row=1, column=1, sticky="ew", pady=(4, 0))

    table_wrap = tk.Frame(popup)
    table_wrap.grid(row=2, column=0, sticky="nsew", padx=10)
    table_wrap.grid_rowconfigure(0, weight=1)
    table_wrap.grid_columnconfigure(0, weight=1)

    cols = ("status", "file", "added", "removed")
    tree = ttk.Treeview(table_wrap, columns=cols, show="headings", selectmode="extended")
    for col, txt, w, stretch in (
        ("status", "Status", 100, False),
        ("file", "File", 480, True),
        ("added", "+Lines", 70, False),
        ("removed", "-Lines", 70, False),
    ):
        tree.heading(col, text=txt)
        tree.column(col, width=w, minwidth=50, stretch=stretch, anchor="w")

    vbar = ttk.Scrollbar(table_wrap, orient="vertical", command=tree.yview)
    hbar = ttk.Scrollbar(table_wrap, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vbar.grid(row=0, column=1, sticky="ns")
    hbar.grid(row=1, column=0, sticky="ew")

    if rows:
        for row in rows:
            tree.insert("", "end", values=row)
    else:
        tree.insert("", "end", values=("", "No file changes in this commit", "", ""))

    def _copy_paths(_evt=None):
        items = tree.selection() or tree.get_children()
        paths = [tree.item(i, "values")[1] for i in items]
        popup.clipboard_clear()
        popup.clipboard_append("\n".join(paths))

    tree.bind("<Control-c>", _copy_paths)
    btns = tk.Frame(popup)
    btns.grid(row=3, column=0, sticky="e", padx=10, pady=10)
    tk.Button(btns, text="Copy file names", command=_copy_paths).pack(side="left", padx=5)
    tk.Button(btns, text="Close", command=popup.destroy).pack(side="left", padx=5)

def show_graph_help():
    """Popup explaining how to read the ASCII workflow graph."""
    popup = Toplevel(root)
    popup.title("Workflow Graph Help")
    popup.geometry("620x600")
    popup.minsize(460, 400)
    popup.transient(root)
    popup.grid_rowconfigure(0, weight=1)
    popup.grid_columnconfigure(0, weight=1)

    txt = scrolledtext.ScrolledText(popup, wrap="word", font=("Segoe UI", 10),
                                    padx=16, pady=14, relief="flat",
                                    background="#ffffff", cursor="arrow")
    txt.grid(row=0, column=0, sticky="nsew")

    txt.tag_configure("h1", font=("Segoe UI", 15, "bold"), spacing3=10)
    txt.tag_configure("h2", font=("Segoe UI", 11, "bold"),
                      spacing1=14, spacing3=6, foreground="#1a4d7a")
    txt.tag_configure("body", spacing3=4, lmargin1=8, lmargin2=8)
    txt.tag_configure("bullet", spacing3=4, lmargin1=18, lmargin2=34)
    txt.tag_configure("mono", font=("Consolas", 10), foreground="#444444")
    for name, col in (("sw_black", "#000000"), ("sw_red", "#c0392b"),
                      ("sw_blue", "#2670c4"), ("sw_orange", "#d98014")):
        txt.tag_configure(name, foreground=col, font=("Segoe UI", 10, "bold"))

    def h1(s):     txt.insert("end", s + "\n", "h1")
    def h2(s):     txt.insert("end", s + "\n", "h2")
    def bullet(*segs):
        txt.insert("end", "•  ", "bullet")
        for seg in segs:
            if isinstance(seg, tuple):
                txt.insert("end", seg[0], (seg[1], "bullet"))
            else:
                txt.insert("end", seg, "bullet")
        txt.insert("end", "\n")

    h1("Workflow Graph Help")

    h2("Reading order")
    bullet("The graph reads top to bottom: ", ("top = newest", "mono"),
           " commits, ", ("bottom = oldest", "mono"), ".")

    h2("What you see on the left (ASCII graph)")
    bullet(("*", "mono"), "  is a commit.")
    bullet(("|", "mono"), "  vertical lines show branch history continuing.")
    bullet(("/", "mono"), " and ", ("\\", "mono"),
           "  are just connectors: they move branch lines left/right so Git can "
           "draw splits and merges without overlapping.")
    bullet("Rows with only ", ("| / \\", "mono"),
           " and no ", ("*", "mono"),
           "  are connector rows (no commit there) — the 'gaps' between commits.")

    h2("Colors")
    bullet(("Black", "sw_black"), "  — normal commits.")
    bullet(("Red", "sw_red"), "  — merge commits (two branches joined here).")
    bullet(("Blue", "sw_blue"), "  — branch tips (where a branch currently points).")
    bullet(("Orange", "sw_orange"),
           "  — commits whose message mentions 'copy' or 'restore'.")

    h2("Right-hand tables")
    bullet(("Merges", "mono"), " table: who merged what, and into which branch.")
    bullet(("Recent Commits", "mono"),
           " table: the last few hundred commits with file counts and a "
           "best-guess branch name for each commit.")

    txt.configure(state="disabled")

    btn_row = tk.Frame(popup)
    btn_row.grid(row=1, column=0, sticky="e", padx=12, pady=10)
    tk.Button(btn_row, text="Close", width=10, command=popup.destroy).pack()

    popup.bind("<Escape>", lambda _e: popup.destroy())

def _find_chromium_browser():
    """Return a path to a Chromium-based browser (Edge preferred, then Chrome/
    Chromium), used to open the graph in an app-mode popup window. Returns
    None if nothing Chromium-based is found (e.g. a Firefox-only Linux box) —
    the caller falls back to the OS default browser in that case.
    """
    candidates = []
    path_names = []

    if sys.platform == "win32":
        program_dirs = [
            os.environ.get("PROGRAMFILES", r"C:\Program Files"),
            os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            os.environ.get("LOCALAPPDATA", ""),
        ]
        for pf in program_dirs:
            if not pf:
                continue
            candidates.append(os.path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"))
            candidates.append(os.path.join(pf, "Google", "Chrome", "Application", "chrome.exe"))
        path_names = ["msedge", "chrome", "google-chrome"]
    elif sys.platform == "darwin":
        candidates = [
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            os.path.expanduser("~/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            os.path.expanduser("~/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        ]
        path_names = ["microsoft-edge", "google-chrome", "chromium"]
    else:
        # Linux/BSD: no fixed install path convention, so rely on PATH — these
        # are the common package/binary names across distros and Chrome's own
        # .deb/.rpm installer.
        path_names = [
            "microsoft-edge", "microsoft-edge-stable",
            "google-chrome", "google-chrome-stable",
            "chromium-browser", "chromium",
        ]

    for path in candidates:
        if path and os.path.isfile(path):
            return path
    for name in path_names:
        found = shutil.which(name)
        if found:
            return found
    return None

def _open_html_as_popup(file_path: str, width: int = 1300, height: int = 850):
    """Open an HTML file in a chromeless "app mode" window (no tabs/address bar),
    so it reads as a popup rather than a normal browser tab. Falls back to the
    default browser if a Chromium-based one can't be located.
    """
    file_url = pathlib.Path(file_path).as_uri()
    browser = _find_chromium_browser()
    if browser:
        try:
            subprocess.Popen([
                browser,
                f"--app={file_url}",
                f"--window-size={width},{height}",
            ])
            return
        except Exception:
            pass
    webbrowser.open(file_url)

def show_plotly_graph():
    """Plot an interactive Plotly git graph (opens in the default browser)."""
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    try:
        import plotly.graph_objects as go
    except Exception as e:
        messagebox.showerror(
            "Plotly missing",
            f"Plotly is required to plot the graph.\n\nError: {e}\n\n"
            "Install it with: pip install plotly"
        )
        return

    try:
        raw = repo.git.log(
            "--all", "--topo-order",
            "--pretty=format:%H%x00%P%x00%an%x00%ad%x00%s",
            "--date=short",
            "--max-count", "300",
        )
        lines = [ln for ln in raw.split("\n") if ln] if raw else []
    except Exception as e:
        messagebox.showerror("Graph", f"Failed to read git log:\n{e}")
        return

    if not lines:
        messagebox.showinfo("Graph", "No commits found to plot.")
        return

    commits = []
    for ln in lines:
        parts = ln.split("\x00", 4)
        if len(parts) != 5:
            continue
        sha, parents_str, author, date, msg = parts
        parents = parents_str.split() if parents_str else []
        commits.append((sha, parents, author, date, msg))

    y_of = {cid: i for i, (cid, *_) in enumerate(commits)}

    lane_of = {}
    lane_used = set()

    def alloc_lane():
        l = 0
        while l in lane_used:
            l += 1
        lane_used.add(l)
        return l

    for cid, ps, *_ in commits:
        if cid not in lane_of:
            lane_of[cid] = alloc_lane()
        if ps:
            p0 = ps[0]
            if p0 not in lane_of:
                lane_of[p0] = lane_of[cid]
            for p in ps[1:]:
                if p not in lane_of:
                    lane_of[p] = alloc_lane()

    surface = "#fcfcfb"
    text_ink = "#52514e"
    gridline = "#e1e0d9"

    all_lanes = sorted(set(lane_of.values()))
    max_lane = all_lanes[-1] if all_lanes else 0
    n_commits = len(commits)
    text_x = max_lane + 1.3

    # Branch/remote tips per lane, for legend labels.
    lane_labels = {}
    for br in repo.branches:
        tip = br.commit.hexsha
        if tip in lane_of:
            lane_labels.setdefault(lane_of[tip], {"local": set(), "remote": set()})
            lane_labels[lane_of[tip]]["local"].add(br.name)
    for r in repo.remotes:
        for ref in r.refs:
            tip = ref.commit.hexsha
            if tip in lane_of:
                lane_labels.setdefault(lane_of[tip], {"local": set(), "remote": set()})
                lane_labels[lane_of[tip]]["remote"].add(str(ref))

    def label_for_lane(lane):
        groups = lane_labels.get(lane)
        if not groups:
            return f"Lane {lane}"
        local_names = sorted(n for n in groups["local"] if not n.endswith("/HEAD"))
        remote_names = sorted(n for n in groups["remote"] if not n.endswith("/HEAD"))
        parts = []
        if local_names:
            parts.append(f"L: {', '.join(local_names)}")
        if remote_names:
            parts.append(f"R: {', '.join(remote_names)}")
        return " | ".join(parts) if parts else f"Lane {lane}"

    # Color policy: main/master is always red. The next few branches get a
    # fixed, requested color order; anything beyond that gets a color derived
    # from a hash of its label, so it's stable across replots (not reshuffled
    # every time you open the graph) without needing to extend the fixed list.
    MAIN_COLOR = "#e34948"
    FIXED_SEQUENCE = ["#008300", "#2a78d6", "#8c564b", "#eb6834", "#e87ba4"]  # green, blue, brown, orange, pink

    def _is_main_like(lane):
        groups = lane_labels.get(lane)
        if not groups:
            return False
        names = list(groups["local"]) + list(groups["remote"])
        return any(n.rsplit("/", 1)[-1].lower() in ("main", "master") for n in names)

    def _stable_fallback_color(label):
        # Hash-derived hue, kept out of red's wedge (reserved for main/master).
        digest = int(hashlib.md5(label.encode("utf-8")).hexdigest(), 16)
        hue = ((digest % 300) + 30) / 360.0  # 30..330 degrees, skipping ~330-30 (red)
        r, g, b = colorsys.hls_to_rgb(hue, 0.45, 0.55)
        return "#{:02x}{:02x}{:02x}".format(int(r * 255), int(g * 255), int(b * 255))

    lane_color = {}
    _fixed_iter = iter(FIXED_SEQUENCE)
    for lane in all_lanes:
        if _is_main_like(lane):
            lane_color[lane] = MAIN_COLOR
            continue
        nxt = next(_fixed_iter, None)
        lane_color[lane] = nxt if nxt else _stable_fallback_color(label_for_lane(lane))

    def color_for_lane(l):
        return lane_color.get(l, MAIN_COLOR)

    commits_by_lane = {lane: [] for lane in all_lanes}
    for sha, ps, author, date, msg in commits:
        commits_by_lane[lane_of.get(sha, 0)].append((sha, ps, author, date, msg))

    fig = go.Figure()

    # Faint vertical guide line per lane, recessive (gridline-gray, hairline),
    # so lanes stay readable as columns even before any hover/click.
    for lane in all_lanes:
        fig.add_trace(go.Scatter(
            x=[lane, lane], y=[-1, n_commits + 1],
            mode="lines", line=dict(color=gridline, width=1),
            hoverinfo="skip", showlegend=False,
            legendgroup=f"lane{lane}", meta=["guide"],
        ))

    # Everything below is grouped per lane (edges, nodes, message labels) via
    # legendgroup + groupclick="togglegroup", so clicking a lane's legend entry
    # hides that whole lane from the graph, not just its swatch.
    for lane in all_lanes:
        group = f"lane{lane}"
        color = color_for_lane(lane)

        edge_x, edge_y = [], []
        for sha, ps, *_ in commits_by_lane[lane]:
            if sha not in y_of:
                continue
            x0, y0 = lane_of.get(sha, 0), y_of[sha]
            for p in ps:
                if p not in y_of or p not in lane_of:
                    continue
                x1, y1 = lane_of[p], y_of[p]
                bend_y = y0 + 0.4
                edge_x += [x0, x0, x1, x1, None]
                edge_y += [y0, bend_y, bend_y, y1, None]
        if edge_x:
            fig.add_trace(go.Scatter(
                x=edge_x, y=edge_y,
                mode="lines", line=dict(color=color, width=2),
                hoverinfo="skip", showlegend=False, legendgroup=group,
                meta=["edge"],
            ))

        xs, ys, customdata, msg_texts = [], [], [], []
        for sha, ps, author, date, msg in commits_by_lane[lane]:
            hover_msg = msg if len(msg) <= 200 else msg[:197] + "..."
            label_msg = msg if len(msg) <= 70 else msg[:67] + "..."
            xs.append(lane)
            ys.append(y_of[sha])
            customdata.append([sha[:7], date, author, hover_msg])
            msg_texts.append(label_msg)

        # Node markers carry the lane color and are this lane's one legend
        # entry; a surface-colored ring keeps them legible where lines cross.
        fig.add_trace(go.Scatter(
            x=xs, y=ys, mode="markers",
            marker=dict(size=12, color=color, line=dict(width=2, color=surface)),
            customdata=customdata,
            hovertemplate=(
                "<b>%{customdata[0]}</b><br>"
                "Date: %{customdata[1]}<br>"
                "Author: %{customdata[2]}<br>"
                "%{customdata[3]}"
                "<extra></extra>"
            ),
            name=label_for_lane(lane),
            legendgroup=group,
            showlegend=True,
            meta=["node"],
        ))

        # Commit message, in text ink (never the series color) so identity
        # still reads from the colored dot beside it, not the label itself.
        fig.add_trace(go.Scatter(
            x=[text_x] * len(xs), y=ys, mode="text",
            text=msg_texts, textposition="middle right",
            textfont=dict(size=12, color=text_ink),
            hoverinfo="skip", showlegend=False, legendgroup=group,
            meta=["text"],
        ))

    fig.update_layout(
        title=dict(
            text="IGRM Git Workflow Tree",
            font=dict(color="#0b0b0b"),
            subtitle=dict(
                text="Click a legend entry to show/hide a branch · double-click to recolor it",
                font=dict(size=11, color=text_ink),
            ),
        ),
        template="plotly_white",
        font=dict(color=text_ink),
        paper_bgcolor=surface,
        plot_bgcolor=surface,
        xaxis=dict(visible=False, range=[-0.7, text_x + 10]),
        yaxis=dict(visible=False, autorange="reversed"),
        legend=dict(
            title=dict(text="Legend (L=Local, R=Remote)", font=dict(color=text_ink)),
            font=dict(color=text_ink),
            groupclick="togglegroup",
            x=1.02, y=1, xanchor="left",
        ),
        autosize=True,
        height=max(500, 28 * n_commits + 150),
        margin=dict(l=20, r=220, t=60, b=20),
    )

    # Lets a user pick their own color per branch: double-clicking a legend
    # entry opens a native color picker instead of Plotly's default "isolate
    # this trace" behavior, then restyles every edge/node trace in that lane's
    # legendgroup (identified via each trace's `meta` tag — the neutral guide
    # line and commit-message text are deliberately left untouched).
    recolor_script = """
    var gd = document.getElementById('igrm-graph-div');
    if (gd) {
      var _igrmPickers = {};
      function _igrmGetPicker(group, initial) {
        if (_igrmPickers[group]) return _igrmPickers[group];
        var inp = document.createElement('input');
        inp.type = 'color';
        inp.value = initial;
        inp.style.position = 'fixed';
        inp.style.left = '-9999px';
        inp.style.top = '-9999px';
        document.body.appendChild(inp);
        inp.addEventListener('input', function () {
          var newColor = inp.value;
          gd.data.forEach(function (tr, i) {
            if (tr.legendgroup !== group) return;
            var kind = tr.meta && tr.meta[0];
            if (kind === 'node') Plotly.restyle(gd, {'marker.color': newColor}, [i]);
            if (kind === 'edge') Plotly.restyle(gd, {'line.color': newColor}, [i]);
          });
        });
        _igrmPickers[group] = inp;
        return inp;
      }
      gd.on('plotly_legenddoubleclick', function (evt) {
        var tr = gd.data[evt.curveNumber];
        var group = tr.legendgroup;
        if (!group) return false;
        var current = (tr.marker && tr.marker.color) || '#000000';
        _igrmGetPicker(group, current).click();
        return false;
      });
    }
    """

    try:
        out_path = os.path.join(tempfile.gettempdir(), "igrm_workflow_graph.html")
        fig.write_html(
            out_path, auto_open=False, config={"responsive": True},
            div_id="igrm-graph-div", post_script=recolor_script,
        )
        _open_html_as_popup(out_path)
    except Exception as e:
        messagebox.showerror("Graph", f"Failed to open graph in browser:\n{e}")

# =============== Terminal Tab ===============

def _ensure_repo_loaded_for_terminal():
    if not repo:
        messagebox.showwarning("Terminal", "No repository loaded.")
        return False
    return True

def _append_terminal_output(text: str):
    terminal_output.config(state="normal")
    terminal_output.insert("end", text)
    terminal_output.see("end")
    terminal_output.config(state="disabled")

def _append_terminal_command(text: str):
    terminal_output.config(state="normal")
    terminal_output.insert("end", text, "cmd")
    terminal_output.see("end")
    terminal_output.config(state="disabled")

# Characters that let a shell chain / redirect / substitute a second command.
# `git status; ls`, `git log | curl ...`, `git status && calc`, `git status $(whoami)`,
# backtick substitution and newlines all belong here.
_SHELL_METACHARS = (";", "&", "|", "`", "$", ">", "<", "\n", "\r", "(", ")")

def _parse_single_git_command(cmd: str):
    """Validate `cmd` is exactly one git invocation and return its arg list.

    Raises ValueError with a user-facing message otherwise. The returned list is
    run with shell=False, so even a metacharacter that slipped past the explicit
    check below is handed to git as a literal argument, never to a shell.
    """
    hit = next((ch for ch in _SHELL_METACHARS if ch in cmd), None)
    if hit is not None:
        shown = {"\n": "\\n", "\r": "\\r"}.get(hit, hit)
        raise ValueError(
            f"'{shown}' is not allowed here. Only a single git command can be run "
            "(no ';', '&&', '|', redirection or command substitution)."
        )
    try:
        # posix=False so Windows backslash paths aren't mangled; strip the
        # surrounding quotes it leaves on quoted args (e.g. a commit message)
        # ourselves.
        parts = shlex.split(cmd, posix=False)
    except ValueError as e:
        raise ValueError(f"Could not parse command: {e}")
    cleaned = []
    for p in parts:
        if len(p) >= 2 and p[0] == p[-1] and p[0] in ("'", '"'):
            p = p[1:-1]
        cleaned.append(p)
    if not cleaned or cleaned[0].lower() != "git":
        raise ValueError("Only git commands are allowed.")
    return cleaned

def run_git_command():
    if not _ensure_repo_loaded_for_terminal():
        return
    cmd = terminal_entry.get().strip()
    if not cmd:
        return
    try:
        argv = _parse_single_git_command(cmd)
    except ValueError as e:
        messagebox.showwarning("Terminal", str(e))
        return
    if shutil.which("git") is None:
        msg = "Git is not installed in the system. Install it from:\nhttps://git-scm.com/"
        messagebox.showwarning("Terminal", msg)
        _append_terminal_output(msg + "\n")
        return
    terminal_entry.delete(0, "end")
    _append_terminal_command(f"> {cmd}\n")
    try:
        proc = subprocess.run(
            argv,
            cwd=repo.working_dir,
            shell=False,
            text=True,
            capture_output=True
        )
        if proc.stdout:
            _append_terminal_output(proc.stdout)
        if proc.stderr:
            _append_terminal_output(proc.stderr)
        if not proc.stdout and not proc.stderr:
            _append_terminal_output("(no output)\n")
    except Exception as e:
        _append_terminal_output(f"Error: {e}\n")

def _update_terminal_prompt():
    try:
        path = repo.working_dir if repo else "(no repo)"
    except Exception:
        path = "(no repo)"
    try:
        terminal_prompt_var.set(f"{path} >>> ")
    except Exception:
        pass


# =============== UI ===============

# Taskbar grouping on Windows (safe no-op elsewhere)
try:
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("InsightsNet.GitRepoManager")
except Exception:
    pass

def _on_app_close():
    global app_closing
    app_closing = True
    try:
        root.quit()
        root.update_idletasks()
    except Exception:
        pass
    try:
        root.destroy()
    except Exception:
        pass

root = tk.Tk(className="Insightsnetgitrepomanager")
root.title("InsightsNet GitRepo Manager")
root.protocol("WM_DELETE_WINDOW", _on_app_close)

def _drain_ui_queue():
    if app_closing or not root.winfo_exists():
        return
    try:
        while True:
            fn = _ui_queue.get_nowait()
            try:
                fn()
            except Exception:
                pass
    except queue.Empty:
        pass
    root.after(50, _drain_ui_queue)

def resource_path(rel_path: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel_path)

# Window icon
# insightsnet_logo.ico only embeds a single 256x256 image; Windows needs a
# 16x16/32x32 variant inside the .ico to render the title-bar/taskbar icon,
# so it silently fell back to Tk's default feather icon. insightsnet_logo_taskbar.ico
# carries the small sizes needed for that.
try:
    root.iconbitmap(resource_path("insightsnet_logo_taskbar.ico"))
except Exception:
    pass
try:
    _icon_img = ImageTk.PhotoImage(Image.open(resource_path("insightsnet_logo.png")))
    root.iconphoto(True, _icon_img)
except Exception:
    pass

# iconphoto() above only sets the window's own icon. On Ubuntu/GNOME, the
# Dock/taskbar icon for a running app is instead looked up from an installed
# .desktop file matched by the window's WM_CLASS (set via className= above) —
# launching straight from a terminal (python3 app26.py) has no such file, so
# GNOME shows a generic fallback icon there. Registering one (with
# StartupWMClass matching our className) fixes the Dock icon too. No effect on
# Windows/macOS, which don't use .desktop files at all.
if sys.platform.startswith("linux"):
    try:
        _icon_png_path = resource_path("insightsnet_logo.png")
        if os.path.exists(_icon_png_path):
            _apps_dir = os.path.join(os.path.expanduser("~"), ".local", "share", "applications")
            os.makedirs(_apps_dir, exist_ok=True)
            _desktop_path = os.path.join(_apps_dir, "insightsnet-gitrepo-manager.desktop")
            _desktop_content = (
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=InsightsNet GitRepo Manager\n"
                f'Exec="{sys.executable}" "{os.path.abspath(__file__)}"\n'
                f"Icon={_icon_png_path}\n"
                f"StartupWMClass={root.winfo_class()}\n"
                "Terminal=false\n"
                "Categories=Development;\n"
            )
            with open(_desktop_path, "w", encoding="utf-8") as f:
                f.write(_desktop_content)
            os.chmod(_desktop_path, 0o755)
    except Exception:
        pass

root.geometry("980x780")
branch_var = tk.StringVar(root)

# ---- Shared "Developed by Team InsightsNet" credit + hyperlink helpers ----
INSIGHTSNET_URL = "https://insightsnet.org/"

def _open_url(url):
    try:
        webbrowser.open(url)
    except Exception:
        pass

def _hyperlink(parent, text, url, size=9):
    lbl = tk.Label(parent, text=text, font=("Arial", size, "underline"),
                   fg="#1a56db", cursor="hand2")
    lbl.bind("<Button-1>", lambda _e: _open_url(url))
    return lbl

def _insightsnet_credit(parent, size=8, fg="#666"):
    """A row: 'Developed by Team ' + clickable 'InsightsNet'."""
    fr = tk.Frame(parent)
    tk.Label(fr, text="Developed by Team ", font=("Arial", size), fg=fg).pack(side="left")
    _hyperlink(fr, "InsightsNet", INSIGHTSNET_URL, size=size).pack(side="left")
    return fr

# Tabs
notebook = ttk.Notebook(root)
main_tab  = ttk.Frame(notebook)
graph_tab = ttk.Frame(notebook)
terminal_tab = ttk.Frame(notebook)
about_tab = ttk.Frame(notebook)
auth_tab  = ttk.Frame(notebook)
notebook.add(auth_tab,  text="Git AuthN")
notebook.add(main_tab,  text="Main")
notebook.add(graph_tab, text="Workflow Graph")
notebook.add(terminal_tab, text="Terminal")
notebook.add(about_tab, text="About")

# Global footer, shown under every tab (packed before the notebook so it keeps
# its strip at the bottom of the window).
_footer = tk.Frame(root)
_footer.pack(side="bottom", fill="x")
tk.Frame(_footer, height=1, bg="#cccccc").pack(fill="x")
_insightsnet_credit(_footer, size=8).pack(pady=3)

notebook.pack(fill="both", expand=True)

# --- Scrollable container (Main)
main_frame = tk.Frame(main_tab)
main_frame.pack(fill="both", expand=True)

canvas = tk.Canvas(main_frame)
scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
scrollable_frame = tk.Frame(canvas)

scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

# Wheel events are bound app-wide (bind_all), so a single handler routes the
# scroll to whichever tab's canvas is currently shown. Each scrollable tab
# registers its canvas here keyed by the tab's widget path.
_tab_canvases = {str(main_tab): canvas}

def _on_mousewheel(event):
    target = _tab_canvases.get(notebook.select())
    if target is None:
        return
    # bind_all fires for the whole app, including pop-up windows layered over the
    # tab. Only scroll when the pointer is actually over the target canvas (or a
    # widget inside it), so wheeling inside a Toplevel doesn't move the tab behind.
    try:
        w = root.winfo_containing(event.x_root, event.y_root)
    except Exception:
        w = None
    if w is None or (w is not target and str(target) not in str(w)):
        return
    if event.num == 5 or event.delta < 0:
        target.yview_scroll(1, "units")
    elif event.num == 4 or event.delta > 0:
        target.yview_scroll(-1, "units")

canvas.bind_all("<MouseWheel>", _on_mousewheel)
canvas.bind_all("<Button-4>", _on_mousewheel)
canvas.bind_all("<Button-5>", _on_mousewheel)

canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

# ---- Main tab sections
clone_section = tk.LabelFrame(scrollable_frame, text="Clone / Load Repository",
                              padx=10, pady=10, relief="groove", font=("Arial", 12, "bold"))
clone_section.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="we")

tk.Label(clone_section,
         text="Enter a Git URL + directory (to clone) OR paste a local repo path in 'Local Clone Directory' to load.",
         font=("Arial", 10)).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
tk.Label(clone_section, text="Git Repository URL:").grid(row=1, column=0, sticky="w")
repo_entry = tk.Entry(clone_section, width=55)
repo_entry.grid(row=1, column=1, columnspan=2)
tk.Label(clone_section, text="Local Clone Directory (or path to existing repo):").grid(row=2, column=0, sticky="w")
clone_dir_entry = tk.Entry(clone_section, width=42)
clone_dir_entry.grid(row=2, column=1)
browse_button = tk.Button(clone_section, text="Browse", command=browse_folder)
browse_button.grid(row=2, column=2, padx=5)
download_button = tk.Button(clone_section, text="Clone/Load Repository", command=clone_repo)
download_button.grid(row=3, column=0, columnspan=3, pady=10)

branch_section = tk.LabelFrame(scrollable_frame, text="Branch Management",
                               padx=10, pady=10, relief="groove", font=("Arial", 12, "bold"))
branch_section.grid(row=1, column=0, columnspan=3, padx=10, pady=10, sticky="we")
tk.Label(branch_section, text="Manage your Git branches.", font=("Arial", 10))\
  .grid(row=0, column=0, columnspan=4, sticky="w")

tk.Button(branch_section, text="Refresh Branches", command=refresh_branches)\
  .grid(row=1, column=0, padx=5, pady=5, sticky="w")
current_branch_label = tk.Label(branch_section, text="Current branch: N/A")
current_branch_label.grid(row=2, column=0, sticky="w")
branch_dropdown = None

git_check_section = tk.LabelFrame(branch_section, text="Git Operations on Current Branch",
                                  padx=10, pady=10, relief="ridge", font=("Arial", 10, "bold"))
git_check_section.grid(row=4, column=0, columnspan=3, pady=10, sticky="we")
for _i, (_text, _cmd) in enumerate((
        ("Status", git_fetch_status),
        ("View Log", git_log_branch),
        ("Incoming / Outgoing", git_incoming_outgoing),
        ("Pull", git_pull_branch),
        ("Push", git_push))):
    _b = tk.Button(git_check_section, text=_text, command=_cmd)
    _b.grid(row=0, column=_i, padx=5, pady=5)
    _git_op_buttons.append(_b)

stash_button = tk.Menubutton(git_check_section, text="Stash ▾", relief="raised", padx=6, pady=3)
stash_menu = tk.Menu(stash_button, tearoff=0)
stash_menu.add_command(label="Stash changes (save aside)", command=git_stash_save)
stash_menu.add_command(label="Apply latest stash", command=git_stash_pop)
stash_menu.add_separator()
stash_menu.add_command(label="View stashes...", command=git_stash_list)
stash_button.config(menu=stash_menu)
stash_button.grid(row=0, column=5, padx=5, pady=5)
_git_op_buttons.append(stash_button)

git_ops_status_label = tk.Label(git_check_section, text="", fg="#555555", font=("Arial", 9, "italic"))
git_ops_status_label.grid(row=1, column=0, columnspan=6, sticky="w", padx=5)

commit_section = tk.LabelFrame(scrollable_frame, text="Commit Changes",
                               padx=10, pady=10, relief="groove", font=("Arial", 12, "bold"))
commit_section.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="we")

add_all_var = tk.BooleanVar()
add_all_checkbox = tk.Checkbutton(commit_section, text="Add all files",
                                  variable=add_all_var, command=toggle_add_all)
add_all_checkbox.grid(row=0, column=0, sticky="w", padx=5, pady=(0, 5))
choose_button = tk.Button(commit_section, text="Choose Files", command=choose_files)
choose_button.grid(row=0, column=1, padx=5, pady=(0, 5))

file_frame = tk.LabelFrame(commit_section, text="Selected Files",
                           padx=10, pady=10, relief="groove", font=("Arial", 12, "bold"))
file_frame.grid(row=1, column=0, columnspan=3, padx=10, pady=(0, 10), sticky="we")
file_messages_frame = tk.Frame(file_frame)
file_messages_frame.pack(fill="both", expand=True)

commit_msg_label = tk.Label(commit_section, text="Commit message (for all files):")
commit_msg_label.grid(row=2, column=0, sticky="w", padx=5, pady=5)
commit_msg_entry = tk.Entry(commit_section, width=55)
commit_msg_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5)

# Optional description (commit body) for the "all files" commit; selected
# files each get their own. Git stores it after a blank line below the summary.
commit_desc_label = tk.Label(commit_section, text="Description (optional):")
commit_desc_label.grid(row=3, column=0, sticky="nw", padx=5, pady=5)
commit_desc_text = tk.Text(commit_section, width=55, height=4, wrap="word")
commit_desc_text.grid(row=3, column=1, columnspan=2, padx=5, pady=5)

tk.Button(commit_section, text="Commit Changes", command=commit_changes)\
  .grid(row=4, column=0, columnspan=3, pady=10)

preview_row = tk.Frame(commit_section)
preview_row.grid(row=5, column=0, columnspan=3, pady=(0, 10))
tk.Button(preview_row, text="Preview Changes", command=preview_changes)\
  .grid(row=0, column=0, padx=6)
_refresh_commit_msg_visibility()

push_section = tk.LabelFrame(scrollable_frame, text="Push to Remote Repository",
                             padx=10, pady=10, relief="groove", font=("Arial", 12, "bold"))
push_section.grid(**_PUSH_SECTION_GRID)
push_section.grid_remove()

tk.Label(
    push_section,
    text="Use manual push if your local branch is ahead or the commit section didn't push.",
    font=("Arial", 10)
).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

tk.Button(push_section, text="Git Push", command=git_push).grid(row=1, column=0, padx=5, pady=5)

# ---- Static "Git Basics" guide, in the empty column to the right of the sections
guide_section = tk.LabelFrame(scrollable_frame, text="Git Basics - How It Works",
                              padx=10, pady=10, relief="groove", font=("Arial", 12, "bold"))
guide_section.grid(row=0, column=3, rowspan=4, padx=10, pady=10, sticky="nw")

_GUIDE_WRAP = 380

tk.Label(guide_section, font=("Courier New", 9), justify="left", fg="#333333",
         text="Working folder --add--> Staging --commit--> Local repo\n"
              "Local repo  --push--> Remote (GitLab/GitHub)\n"
              "Remote      --pull--> Local repo + Working folder\n"
              "Working folder <--stash / apply--> Stash (saved aside)")\
  .pack(anchor="w", pady=(0, 10))

_GUIDE_STEPS = [
    ("1. Clone / Load",
     "Clone copies a remote repository to your PC (git clone). "
     "Load opens a folder that is already a repository."),
    ("2. Choose a branch",
     "A branch is a separate line of work. Pick it in the dropdown to switch "
     "(git checkout). Refresh Branches shows local branches at once, then "
     "fetches new / deleted remote branches in the background."),
    ("3. Pull first",
     "Pull merges teammates' commits into your branch (git pull --no-rebase). "
     "It checks first: says 'Already up to date' if nothing is new, and offers to "
     "move local files out of the way. Afterwards it shows which files changed."),
    ("4. Edit your files",
     "Make your changes in your editor as usual. Git only notices them; "
     "nothing is saved in history yet."),
    ("5. Check",
     "Status lists changed, new (untracked) and deleted files and whether you "
     "are ahead / behind the remote. View Log shows the latest 500 commits. "
     "Incoming / Outgoing lists exactly what a Pull would bring in and a Push "
     "would send."),
    ("6. Commit",
     "Pick 'Add all files' or Choose Files (git add), write a short summary "
     "and optional description, then Commit (git commit). A commit is a "
     "saved snapshot - but only on your PC."),
    ("7. Push",
     "Push uploads your commits to the remote (git push) so others can pull "
     "them. A brand-new branch is created on the remote automatically. If the "
     "remote has newer commits, Push is refused - Pull first, then Push again."),
]

for _title, _body in _GUIDE_STEPS:
    tk.Label(guide_section, text=_title, font=("Arial", 10, "bold"), justify="left")\
      .pack(anchor="w")
    tk.Label(guide_section, text=_body, font=("Arial", 9), justify="left",
             wraplength=_GUIDE_WRAP).pack(anchor="w", padx=(12, 0), pady=(0, 6))

tk.Label(guide_section, text="Tips", font=("Arial", 10, "bold")).pack(anchor="w", pady=(6, 0))
for _tip in (
    "Fetch only checks the remote; Pull also changes your files.",
    "Never-committed file with the same name as an incoming one (e.g. .gitignore)? "
    "Pull offers to rename yours to <name>.local-backup - compare, then delete it.",
    "Uncommitted edits in files the pull changes? Pull offers to stash them, "
    "pull, and restore them automatically.",
    "Merge conflict? Fix the <<<<<<< / >>>>>>> parts in the listed files and "
    "commit, or run 'git merge --abort' in the Terminal tab to cancel.",
    "Stash ▾ saves unfinished work aside (e.g. before switching branch); "
    "Apply latest stash brings it back, View stashes lists them all.",
    "Network actions run in the background - wait for the status line under "
    "the buttons (e.g. 'Pulling...') to clear.",
    "Keep the summary short (about 50 chars); put details in the description.",
):
    tk.Label(guide_section, text="• " + _tip, font=("Arial", 9), justify="left",
             wraplength=_GUIDE_WRAP).pack(anchor="w", padx=(12, 0), pady=(0, 4))

# ---- Workflow Graph Tab
graph_top = tk.Frame(graph_tab)
graph_top.pack(fill="x", padx=10, pady=6)

tk.Button(graph_top, text="Refresh Graph", command=refresh_workflow_graph).pack(side="left")
tk.Button(graph_top, text="?", width=2, command=show_graph_help).pack(side="left", padx=(5, 0))
tk.Button(graph_top, text="Plot Graph", command=show_plotly_graph).pack(side="left", padx=(5, 0))

tk.Label(
    graph_top,
    text="ASCII graph: '*' = commit, '|' continues branch, '/' and '\\' connect branches. "
         "Top = newest, bottom = oldest.",
    font=("Arial", 8)
).pack(side="left", padx=10)

graph_body = tk.Frame(graph_tab)
graph_body.pack(fill="both", expand=True, padx=10, pady=(0,10))
graph_body.grid_columnconfigure(0, weight=2)
graph_body.grid_columnconfigure(1, weight=3)
graph_body.grid_rowconfigure(0, weight=1)

# LEFT: ASCII Text graph
ascii_wrap = tk.Frame(graph_body, bd=1, relief="sunken")
ascii_wrap.grid(row=0, column=0, sticky="nsew", padx=(0,8))
ascii_wrap.grid_rowconfigure(0, weight=1)
ascii_wrap.grid_columnconfigure(0, weight=1)

ascii_text = tk.Text(ascii_wrap, wrap="none", font=("Courier New", 10), bd=0)
ascii_y = tk.Scrollbar(ascii_wrap, orient="vertical", command=ascii_text.yview)
ascii_x = tk.Scrollbar(ascii_wrap, orient="horizontal", command=ascii_text.xview)
ascii_text.configure(yscrollcommand=ascii_y.set, xscrollcommand=ascii_x.set)

ascii_text.grid(row=0, column=0, sticky="nsew")
ascii_y.grid(row=0, column=1, sticky="ns")
ascii_x.grid(row=1, column=0, sticky="ew")

# Color tags for different commit types in the ASCII graph
ascii_text.tag_configure("kind_normal", foreground="black")
ascii_text.tag_configure("kind_merge", foreground="red")          # merges = red
ascii_text.tag_configure("kind_branch_tip", foreground="blue")    # branch tips = blue
ascii_text.tag_configure("kind_copy", foreground="dark orange")   # copy/restore = orange

# ---- Terminal Tab
terminal_frame = tk.Frame(terminal_tab)
terminal_frame.pack(fill="both", expand=True, padx=12, pady=12)

terminal_prompt_row = tk.Frame(terminal_frame)
terminal_prompt_row.pack(fill="x", pady=(6, 6))

terminal_prompt_box = tk.Frame(terminal_prompt_row, bd=1, relief="sunken", bg="white")
terminal_prompt_box.pack(side="left", fill="x", expand=True)

terminal_prompt_var = tk.StringVar(value="(no repo) >>> ")
terminal_prompt_label = tk.Label(
    terminal_prompt_box,
    textvariable=terminal_prompt_var,
    font=("Consolas", 10),
    bg="white"
)
terminal_prompt_label.pack(side="left", padx=(6, 0), pady=2)

terminal_entry = tk.Entry(terminal_prompt_box, bd=0, highlightthickness=0)
terminal_entry.pack(side="left", fill="x", expand=True, padx=(6, 6), pady=2)
terminal_entry.bind("<Return>", lambda _e: run_git_command())

tk.Button(terminal_prompt_row, text="Run Git Command", command=run_git_command).pack(side="left", padx=(8, 0))

terminal_output = scrolledtext.ScrolledText(terminal_frame, wrap="word", height=18, state="disabled")
terminal_output.pack(fill="both", expand=True)
terminal_output.tag_configure("cmd", foreground="green")

terminal_actions = tk.Frame(terminal_frame)
terminal_actions.pack(fill="x", pady=(6, 0))
tk.Button(terminal_actions, text="Clear Output", command=lambda: terminal_output.config(state="normal") or terminal_output.delete("1.0", "end") or terminal_output.config(state="disabled")).pack(side="left")

# RIGHT: tables
right_col = tk.Frame(graph_body)
right_col.grid(row=0, column=1, sticky="nsew")
right_col.grid_rowconfigure(0, weight=1)
right_col.grid_rowconfigure(1, weight=1)
right_col.grid_columnconfigure(0, weight=1)

merges_frame = tk.Frame(right_col, bd=1, relief="sunken")
merges_frame.grid(row=0, column=0, sticky="nsew", pady=(0,8))
tk.Label(merges_frame, text="Merges (who merged what)", font=("Arial", 10, "bold"))\
  .grid(row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 6))

merges_cols = ("sha", "date", "author", "from", "into", "message")
merges_table = ttk.Treeview(merges_frame, columns=merges_cols, show="headings")
for col, w in zip(merges_cols, (90, 90, 160, 170, 170, 500)):
    merges_table.heading(col, text=col.upper())
    merges_table.column(col, width=w, anchor="w")

merges_y = ttk.Scrollbar(merges_frame, orient="vertical", command=merges_table.yview)
merges_x = ttk.Scrollbar(merges_frame, orient="horizontal", command=merges_table.xview)
merges_table.configure(yscrollcommand=merges_y.set, xscrollcommand=merges_x.set)
merges_table.grid(row=1, column=0, sticky="nsew", padx=8)
merges_y.grid(row=1, column=1, sticky="ns")
merges_x.grid(row=2, column=0, sticky="ew", padx=8, pady=(0,8))
merges_frame.grid_rowconfigure(1, weight=1)
merges_frame.grid_columnconfigure(0, weight=1)

commits_frame = tk.Frame(right_col, bd=1, relief="sunken")
commits_frame.grid(row=1, column=0, sticky="nsew")
tk.Label(commits_frame, text="Recent Commits   (double-click a commit to see its files)",
         font=("Arial", 10, "bold"))\
  .grid(row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 6))

commits_cols = ("sha", "date", "author", "branch", "files", "file names", "commit", "description")
commits_table = ttk.Treeview(commits_frame, columns=commits_cols, show="headings")
for col, w in zip(commits_cols, (90, 90, 160, 110, 50, 260, 300, 400)):
    commits_table.heading(col, text=col.upper())
    commits_table.column(col, width=w, anchor="w")

commits_y = ttk.Scrollbar(commits_frame, orient="vertical", command=commits_table.yview)
commits_x = ttk.Scrollbar(commits_frame, orient="horizontal", command=commits_table.xview)
commits_table.configure(yscrollcommand=commits_y.set, xscrollcommand=commits_x.set)
commits_table.grid(row=1, column=0, sticky="nsew", padx=8)
commits_table.bind("<Double-1>", show_commit_files)
commits_table.bind("<Return>", show_commit_files)
commits_y.grid(row=1, column=1, sticky="ns")
commits_x.grid(row=2, column=0, sticky="ew", padx=8, pady=(0,8))
commits_frame.grid_rowconfigure(1, weight=1)
commits_frame.grid_columnconfigure(0, weight=1)

# ---- About Tab (logo + download)
try:
    logo_img = Image.open(resource_path("insightsnet_logo.png")).resize((120, 120))
    logo_photo = ImageTk.PhotoImage(logo_img)
    logo_label = tk.Label(about_tab, image=logo_photo)
    logo_label.image = logo_photo
    logo_label.pack(pady=(30,10))
except Exception:
    pass

def smart_pdf_name():
    base = "igrm_User_Guide"
    ver = "v0.35"
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    repo_name = ""
    try:
        if repo and repo.working_dir:
            repo_name = os.path.basename(repo.working_dir.rstrip(os.sep))
    except Exception:
        pass
    parts = [p for p in [base, repo_name, ver, date_str] if p]
    return "_".join(parts) + ".pdf"

def download_pdf():
    src = resource_path("InsightsNetGitRepoManager_guideline.pdf")
    if not os.path.exists(src):
        messagebox.showerror("Error", "PDF file not found.")
        return
    dest = filedialog.asksaveasfilename(
        title="Save User Guide As",
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf")],
        initialfile=smart_pdf_name(),
    )
    if dest:
        try:
            shutil.copyfile(src, dest)
            messagebox.showinfo("Saved", f"User guide saved to:\n{dest}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save file:\n{e}")

tk.Label(
    about_tab,
    text="Download the InsightsNet GitRepo Manager documentation and guidelines here.",
    font=("Arial", 10),
    pady=10
).pack()
tk.Button(about_tab, text="Download User Guide (PDF)", command=download_pdf).pack(pady=10)
tk.Label(
    about_tab,
    text="-----------------------------------------\nInsightsNet GitRepo Manager\nVersion 0.35\n© 2026",
    font=("Arial", 12),
    pady=(20)
).pack()
_insightsnet_credit(about_tab, size=12, fg="#000").pack(pady=(0, 20))

# ---- Git AuthN Tab (UI + remote tools)
# Scrollable container so the whole tab is reachable without resizing the window.
auth_outer = tk.Frame(auth_tab)
auth_outer.pack(fill="both", expand=True)

auth_canvas = tk.Canvas(auth_outer, highlightthickness=0)
auth_scrollbar = tk.Scrollbar(auth_outer, orient="vertical", command=auth_canvas.yview)
auth_scroll_frame = tk.Frame(auth_canvas)

auth_scroll_frame.bind(
    "<Configure>", lambda e: auth_canvas.configure(scrollregion=auth_canvas.bbox("all")))
_auth_canvas_window = auth_canvas.create_window((0, 0), window=auth_scroll_frame, anchor="nw")
# Keep the inner frame as wide as the canvas so content stays centred, not left-hugging.
auth_canvas.bind(
    "<Configure>", lambda e: auth_canvas.itemconfigure(_auth_canvas_window, width=e.width))
auth_canvas.configure(yscrollcommand=auth_scrollbar.set)

auth_canvas.pack(side="left", fill="both", expand=True)
auth_scrollbar.pack(side="right", fill="y")
_tab_canvases[str(auth_tab)] = auth_canvas

auth_wrap = tk.LabelFrame(auth_scroll_frame, text="Authentication", padx=20, pady=20, font=("Arial", 12, "bold"))
auth_wrap.pack(fill="both", expand=True, padx=20, pady=20)

try:
    auth_logo_img = Image.open(resource_path("insightsnet_logo.png")).resize((120, 120))
    auth_logo_photo = ImageTk.PhotoImage(auth_logo_img)
    auth_logo_label = tk.Label(auth_wrap, image=auth_logo_photo)
    auth_logo_label.image = auth_logo_photo
    auth_logo_label.pack(pady=(5, 10))
except Exception:
    pass

tk.Label(auth_wrap, text="Welcome to InsightsNet GitRepo Manager", font=("Arial", 14, "bold")).pack(pady=(0, 10))
tk.Label(auth_wrap, text="Configure your GitLab/GitHub author identity", font=("Arial", 11)).pack(pady=(0, 15))

tk.Button(auth_wrap, text="Show Git Identity", command=_show_effective_identity).pack(pady=(0, 15))

name_frame = tk.Frame(auth_wrap); name_frame.pack(pady=5)
tk.Label(name_frame, text="Name:", width=8, anchor="e").grid(row=0, column=0, padx=5)
auth_name_var = tk.StringVar()
auth_name_entry = tk.Entry(name_frame, textvariable=auth_name_var, width=35); auth_name_entry.grid(row=0, column=1)

email_frame = tk.Frame(auth_wrap); email_frame.pack(pady=5)
tk.Label(email_frame, text="Email:", width=8, anchor="e").grid(row=0, column=0, padx=5)
auth_email_var = tk.StringVar()
auth_email_entry = tk.Entry(email_frame, textvariable=auth_email_var, width=35); auth_email_entry.grid(row=0, column=1)

apply_frame = tk.Frame(auth_wrap); apply_frame.pack(pady=14)
tk.Button(apply_frame, text="Apply Loaded Repository", command=_apply_identity_repo, width=20).grid(row=0, column=0, padx=10)
tk.Button(apply_frame, text="Apply Globally", command=_apply_identity_global, width=18).grid(row=0, column=1, padx=10)

# ---- Remote authentication: pick a method, configure it in its own window ----
# StringVars live on the tab (created once) so the HTTPS helpers keep working even
# while the HTTPS window is closed; the window just binds Entry widgets to them.
auth_pat_host_var = tk.StringVar()
auth_pat_user_var = tk.StringVar()
auth_pat_token_var = tk.StringVar()
auth_pat_status_var = tk.StringVar(value="")

tk.Label(auth_wrap, text="Remote authentication", font=("Arial", 11, "bold")).pack(pady=(20, 2))
tk.Label(
    auth_wrap,
    text="Choose how this machine authenticates to GitLab / GitHub, then configure it.",
    font=("Arial", 9), fg="#555").pack(pady=(0, 12))

auth_method_row = tk.Frame(auth_wrap); auth_method_row.pack(pady=(0, 8))
tk.Button(auth_method_row, text="HTTPS\n(Access Token)", command=open_https_auth_window,
          width=20, height=3, font=("Arial", 10, "bold")).grid(row=0, column=0, padx=14)
tk.Button(auth_method_row, text="SSH\n(Keys)", command=open_ssh_auth_window,
          width=20, height=3, font=("Arial", 10, "bold")).grid(row=0, column=1, padx=14)

# Prefill AuthN fields initially
_prefill_auth_fields()
_prefill_pat_fields()
_update_terminal_prompt()
_drain_ui_queue()

root.mainloop()
















# pyinstaller -y --clean --noupx --onefile --windowed --name="InsightsNetGitRepoManager" --icon=insightsnet_logo_taskbar.ico --add-data "insightsnet_logo_taskbar.ico;." --add-data "insightsnet_logo.png;." --add-data "InsightsNetGitRepoManager_guideline.pdf;." app32.py
