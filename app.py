import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel
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
import textwrap
import queue
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
            capture_output=True, text=True, check=False
        )
        v = (out.stdout or "").strip()
        return v or None
    except Exception:
        return None

def _git_global_set(key: str, value: str) -> bool:
    try:
        subprocess.run(["git", "config", "--global", key, value],
                       capture_output=True, text=True, check=True)
        return True
    except Exception:
        return False

def _ensure_identity_before_commit() -> bool:
    """Ensure repo has user.name/email before committing; try UI values if missing."""
    global repo, auth_name_var, auth_email_var
    if not repo:
        return False

    name, email = _read_identity_from_repo(repo)
    if name and email:
        return True

    ui_name = (auth_name_var.get() if 'auth_name_var' in globals() else '').strip()
    ui_email = (auth_email_var.get() if 'auth_email_var' in globals() else '').strip()

    if ui_name and ui_email:
        try:
            with repo.config_writer() as cw:
                cw.set_value('user', 'name', ui_name)
                cw.set_value('user', 'email', ui_email)
            return True
        except Exception as e:
            messagebox.showerror("Git AuthN", f"Could not write repo identity:\n{e}")
            return False

    messagebox.showwarning(
        "Git identity missing",
        "Git author name/email are not set. Please open the 'Git AuthN' tab and set them."
    )
    return False

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

def switch_origin_to_ssh_any():
    """
    Convert HTTPS -> SSH for ANY host:
      https://HOST/GROUP/REPO(.git) -> git@HOST:GROUP/REPO.git
    If already SSH, just inform.
    """
    r = _get_primary_remote()
    if not r:
        messagebox.showerror("Remote", "No remote found.")
        return
    url = r.url
    if url.startswith("git@") and ":" in url:
        messagebox.showinfo("Remote", f"Remote '{r.name}' is already SSH:\n{url}")
        return
    host, path = _parse_origin_host_and_path()
    if not host or not path:
        messagebox.showerror("Remote", f"Cannot parse remote URL:\n{url}")
        return
    ssh_url = f"git@{host}:{path}.git"
    try:
        r.set_url(ssh_url)
        messagebox.showinfo("Remote", f"Switched '{r.name}' to SSH:\n{ssh_url}")
    except Exception as e:
        messagebox.showerror("Remote", f"Failed to switch remote:\n{e}")

def _ssh_test_to_host(host: str):
    """Common ssh -T tester with accept-new fallback and trust prompt."""
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
    rc, msg = run_ssh(["ssh", "-T", "-o", "StrictHostKeyChecking=accept-new", f"git@{host}"])
    if rc != 255 or "unknown option -- o" not in msg.lower():
        messagebox.showinfo(f"SSH Test ({host})", msg or "(no output)")
        return

    # Fallback for older ssh: plain ssh -T
    rc2, msg2 = run_ssh(["ssh", "-T", f"git@{host}"])
    lower = msg2.lower()
    if "continue connecting (yes/no" in lower or "authenticity of host" in lower:
        trust = messagebox.askyesno(
            f"Trust {host} host key?",
            f"The authenticity of host '{host}' can't be established.\n\n"
            "Do you want to trust this host key and continue?"
        )
        if trust:
            rc3, msg3 = run_ssh(["ssh", "-T", f"git@{host}"], feed_stdin="yes\n")
            messagebox.showinfo(f"SSH Test ({host})", msg3 or "(no output)")
        else:
            messagebox.showinfo(f"SSH Test ({host})", "Aborted by user.")
        return

    messagebox.showinfo(f"SSH Test ({host})", msg2 or "(no output)")

def test_github_ssh():
    """Test SSH auth to GitHub from the GUI (no terminal)."""
    _ssh_test_to_host("github.com")

def test_gitlab_ssh():
    """Test SSH auth to GitLab from the GUI (no terminal)."""
    _ssh_test_to_host("gitlab.com")

def test_origin_host_ssh():
    """Test SSH to the host inferred from the primary remote (works for gitlab.* etc.)."""
    r = _get_primary_remote()
    if not r:
        messagebox.showerror("SSH Test", "No remote found in this repository.")
        return
    host, _ = _parse_origin_host_and_path()
    if not host:
        messagebox.showerror("SSH Test", f"Could not determine host from remote '{r.name}' URL:\n{r.url}")
        return
    _ssh_test_to_host(host)

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

# ---- NEW: remote/branch diagnostics helpers ----

def show_origin_refspec():
    """Display current fetch refspec(s) for the primary remote."""
    r = _get_primary_remote()
    if not r:
        messagebox.showinfo("Remote", "No remote configured.")
        return
    try:
        out = repo.git.config('--get-all', f'remote.{r.name}.fetch')
    except Exception:
        out = f'(no {r.name} or no refspec)'
    messagebox.showinfo(f"{r.name}.fetch refspec", out or '(empty)')

def show_remote_heads():
    """List branches available on the server for the primary remote."""
    r = _get_primary_remote()
    if not r:
        messagebox.showinfo("Remote", "No remote configured.")
        return
    try:
        out = repo.git.ls_remote('--heads', r.name)
    except Exception as e:
        out = f'ls-remote failed:\n{e}'
    messagebox.showinfo(f"{r.name} heads", out or '(none)')

def fix_refspec_and_fetch():
    """Ensure we fetch all branches; then fetch --all --prune."""
    r = _get_primary_remote()
    if not r:
        messagebox.showwarning("Remote", "No remote configured.")
        return
    try:
        repo.git.config(f'remote.{r.name}.fetch', f'+refs/heads/*:refs/remotes/{r.name}/*')
        repo.git.fetch('--all', '--prune')
        messagebox.showinfo("Remote", "Refspec fixed and fetched.\nNow refresh branches.")
    except Exception as e:
        messagebox.showerror("Remote", f"Failed to fix refspec/fetch:\n{e}")

def fetch_all_and_prune():
    """Convenience: fetch --all --prune and refresh the dropdown."""
    try:
        if _has_remote_origin():
            repo.git.fetch('--all', '--prune')
        list_branches(repo.working_dir if repo else None)
        messagebox.showinfo("Fetch", "Fetched and pruned remotes. Branch list refreshed.")
    except Exception as e:
        messagebox.showerror("Fetch", f"Fetch failed:\n{e}")

# =============== Repo / Branch / Commit logic ===============

def browse_folder():
    folder = filedialog.askdirectory()
    if folder:
        clone_dir_entry.delete(0, tk.END)
        clone_dir_entry.insert(0, folder)

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

                base_name = os.path.basename(repo_url.replace("\\", "/"))
                if base_name.endswith(".git"):
                    base_name = base_name[:-4]
                repo_name = base_name or "repo"
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
                    if repo_url.startswith("git@") or repo_url.startswith("ssh://"):
                        if not _ensure_ssh_host_trusted(repo_url):
                            raise Exception("SSH host key not trusted; clone canceled.")
                    repo = Repo.clone_from(repo_url, full_clone_path)
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
                messagebox.showerror("Error", f"Failed to clone/load repo:\n{result['error']}")
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
            _update_terminal_prompt()
            refresh_workflow_graph()

        _post_ui(ui_update)

    # Run synchronously to avoid Tk thread issues during repo switching.
    task()

def list_branches(repo_path=None):
    """Populate branch dropdown with local + remote branches (any remote)."""
    global repo, branch_var, branch_dropdown

    repo_path = repo_path or clone_dir_entry.get()
    if not repo_path or not os.path.exists(repo_path):
        messagebox.showwarning("Error", "Please provide a valid cloned repository path.")
        return

    try:
        repo = Repo(repo_path)

        # Fetch/prune on the primary remote if present
        try:
            r = _get_primary_remote()
            if r:
                r.fetch(prune=True)
        except Exception:
            pass

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
    _update_terminal_prompt()

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

def refresh_branches():
    list_branches()

def git_pull():
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    r = _get_primary_remote()
    if not r:
        messagebox.showwarning("Error", "No remote configured.")
        return
    try:
        r.pull()
        messagebox.showinfo("Success", f"Repository updated via git pull from '{r.name}'.")
    except Exception as e:
        messagebox.showerror("Error", f"Git Pull failed:\n{e}")

def git_fetch_status():
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    try:
        r = _get_primary_remote()
        if r:
            r.fetch()
        status = repo.git.status()
        messagebox.showinfo("Git Status", status)
    except Exception as e:
        messagebox.showerror("Error", f"Git fetch/status failed:\n{e}")

def git_log_branch():
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    branch_name = branch_var.get()
    try:
        try:
            log = repo.git.log(branch_name, '--oneline')
        except Exception:
            r = _get_primary_remote()
            rb = f"{r.name}/{branch_name}" if r else branch_name
            log = repo.git.log(rb, '--oneline')
        messagebox.showinfo(f"Git Log - {branch_name}", log or "No commits found.")
    except Exception as e:
        messagebox.showerror("Error", f"Git log failed:\n{e}")

def git_pull_branch():
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    r = _get_primary_remote()
    if not r:
        messagebox.showwarning("Error", "No remote configured.")
        return
    branch_name = branch_var.get()
    try:
        repo.git.pull(r.name, branch_name)
        messagebox.showinfo("Success", f"Updated branch {branch_name} from '{r.name}'")
    except Exception as e:
        messagebox.showerror("Error", f"Git pull failed:\n{e}")

def git_push():
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
    try:
        out = repo.git.push(r.name, branch_name)
        messagebox.showinfo("Git Push", out or f"Pushed {branch_name} to '{r.name}'.")
    except Exception as e:
        messagebox.showerror("Git Push", f"Git push failed:\n{e}")

# =============== Commit Section ===============

def _set_commit_msg_visibility(show: bool):
    """Show/hide the single commit message row."""
    if show:
        commit_msg_label.grid(row=2, column=0, sticky="w", padx=5, pady=5)
        commit_msg_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5)
    else:
        commit_msg_label.grid_remove()
        commit_msg_entry.grid_remove()

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
    global file_entries
    row_idx = len(file_entries) * 2

    lbl = tk.Label(file_messages_frame, text=os.path.basename(f))
    lbl.grid(row=row_idx, column=0, sticky="w", padx=10)

    entry = tk.Entry(file_messages_frame, width=50)
    entry.grid(row=row_idx + 1, column=0, padx=10, pady=(0, 10))

    btn = tk.Button(file_messages_frame, text="X", fg="red", command=lambda file=f: remove_file(file))
    btn.grid(row=row_idx, column=1, padx=5)

    file_entries[f] = (lbl, entry, btn)

def remove_file(f):
    global selected_files, file_entries
    if f in selected_files:
        selected_files.remove(f)
        lbl, entry, btn = file_entries[f]
        lbl.destroy()
        entry.destroy()
        btn.destroy()
        del file_entries[f]
        refresh_file_entries()

    if not selected_files:
        add_all_checkbox.grid(row=0, column=0, sticky="w", padx=5, pady=(0, 5))
    _refresh_commit_msg_visibility()

def refresh_file_entries():
    for idx, f in enumerate(list(file_entries.keys())):
        lbl, entry, btn = file_entries[f]
        lbl.grid(row=idx * 2, column=0, sticky="w", padx=10)
        entry.grid(row=idx * 2 + 1, column=0, padx=10, pady=(0, 10))
        btn.grid(row=idx * 2, column=1, padx=5)

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

    txt = scrolledtext.ScrolledText(popup, wrap="none")
    txt.grid(row=1, column=0, sticky="nsew", padx=10, pady=0)
    hbar = tk.Scrollbar(popup, orient="horizontal", command=txt.xview)
    hbar.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
    txt.configure(xscrollcommand=hbar.set)

    _colorize_diff_text(txt, diff_text or "(no changes)")
    txt.configure(state="disabled")
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
            ahead_str, behind_str = (counts.split() + ["0", "0"])[:2]
            ahead = int(ahead_str)
            behind = int(behind_str)
        except Exception:
            ahead = behind = 0

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
                repo.git.pull(r.name, branch_name)
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
                repo.git.pull(r.name, branch_name)
            except Exception as e:
                messagebox.showerror("Pull failed", f"Git pull failed:\n{e}")
                return False

        return True
    except Exception as e:
        messagebox.showerror("Sync check failed", f"{e}")
        return False

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

            repo.index.commit(msg)
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
                repo.index.commit(per_msg)
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
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return

    r = _get_primary_remote()
    if not r:
        messagebox.showerror("Error", "No remote found in this repository.")
        return

    branch_name = _current_branch_name() or branch_var.get().strip()
    if not branch_name:
        messagebox.showerror("Error", "Cannot determine the current branch. Checkout a branch before pushing.")
        return

    try:
        tracking = None
        try:
            tracking = repo.active_branch.tracking_branch()
        except Exception:
            tracking = None

        if tracking is None or str(tracking) == '':
            repo.git.push('--set-upstream', r.name, branch_name)
        else:
            repo.git.push(r.name, branch_name)

        popup.destroy()
        messagebox.showinfo("Success", f"Pushed {len(committed_files)} file(s) to {r.name}/{branch_name}")
    except Exception as e:
        err = str(e)
        origin = get_origin_url()
        if "403" in err or "Permission" in err:
            messagebox.showerror(
                "Push failed (auth)",
                f"{err}\n\nRemote: {r.name}\nURL: {origin}\n\n"
                "Fix:\n"
                "• If remote is HTTPS, use a Personal Access Token or switch to SSH.\n"
                "• If remote is SSH, ensure your key is added and 'ssh -T git@HOST' succeeds.\n"
            )
        else:
            messagebox.showerror("Push failed", f"{err}")

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
        msg = c.message.splitlines()[0] if (c.message or "").splitlines() else ""
        branch = _branch_hint_for_commit(r, c.hexsha) or ""
        try:
            files_changed = len(c.stats.files or {})
        except Exception:
            files_changed = 0
        commits_rows.append((short_sha, when, author, branch, files_changed, msg))

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

def show_graph_help():
    """Popup explaining how to read the ASCII workflow graph."""
    help_text = (
        "Workflow Graph Help\n\n"
        "Reading order\n"
        "  • The graph reads from top to bottom: top = newest commits, bottom = oldest.\n\n"
        "What you see on the left (ASCII graph)\n"
        "  • Each '*' is a commit.\n"
        "  • '|' vertical lines show branch history continuing.\n"
        "  • '/' and '\\\\' are just connectors: they move branch lines left/right so\n"
        "    Git can draw splits and merges without overlapping.\n"
        "  • Lines that have only '|' '/' '\\\\' and no '*' are just connector rows\n"
        "    (no commit there) – they are the 'gaps' between commits.\n\n"
        "Colors\n"
        "  • Black  : normal commits.\n"
        "  • Red    : merge commits (two branches joined here).\n"
        "  • Blue   : branch tips (where a branch currently points).\n"
        "  • Orange : commits whose message mentions 'copy' or 'restore'.\n\n"
        "Right-hand tables\n"
        "  • 'Merges' table: shows who merged what, and into which branch.\n"
        "  • 'Recent Commits' table: shows the last few hundred commits with file counts\n"
        "    and a best-guess branch name for each commit.\n"
    )
    messagebox.showinfo("Workflow Graph Help", help_text)

def show_matplotlib_graph():
    """Plot a matplotlib git graph based on actual repo log."""
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    try:
        import matplotlib.pyplot as plt
        from matplotlib.lines import Line2D
        from matplotlib.path import Path
        from matplotlib.patches import PathPatch
    except Exception as e:
        messagebox.showerror(
            "Matplotlib missing",
            f"Matplotlib is required to plot the graph.\n\nError: {e}"
        )
        return

    def rounded_elbow(ax, x0, y0, x1, y1, bend_y, r=0.22, **kw):
        if x0 == x1:
            ax.plot([x0, x1], [y0, y1], **kw)
            return
        dx = x1 - x0
        sx = 1 if dx > 0 else -1
        dy0 = bend_y - y0
        sy0 = 1 if dy0 > 0 else -1
        dy1 = y1 - bend_y
        sy1 = 1 if dy1 > 0 else -1
        def clamp(v, lo, hi): return max(lo, min(hi, v))
        r1 = clamp(r, 0, abs(dy0) / 2 if dy0 != 0 else r)
        r2 = clamp(r, 0, abs(dx) / 2 if dx != 0 else r)
        r3 = clamp(r, 0, abs(dy1) / 2 if dy1 != 0 else r)
        y0a = bend_y - sy0 * r1
        x0a = x0 + sx * r2
        x1a = x1 - sx * r2
        y1a = bend_y + sy1 * r3
        verts = [
            (x0, y0),
            (x0, y0a),
            (x0, bend_y),
            (x0a, bend_y),
            (x1a, bend_y),
            (x1, bend_y),
            (x1, y1a),
            (x1, y1),
        ]
        codes = [
            Path.MOVETO,
            Path.LINETO,
            Path.CURVE3,
            Path.CURVE3,
            Path.LINETO,
            Path.CURVE3,
            Path.CURVE3,
            Path.LINETO,
        ]
        ax.add_patch(PathPatch(Path(verts, codes), fill=False, **kw))

    try:
        raw = repo.git.log(
            "--all", "--topo-order",
            "--pretty=format:%H%x00%P%x00%s",
            "--max-count", "120"
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
        parts = ln.split("\x00", 2)
        if len(parts) != 3:
            continue
        sha, parents_str, msg = parts
        parents = parents_str.split() if parents_str else []
        commits.append((sha, parents, msg))

    parents_map = {cid: ps for cid, ps, _ in commits}
    msg_map = {cid: m for cid, _, m in commits}

    lane_of = {}
    lane_used = set()

    def alloc_lane():
        l = 0
        while l in lane_used:
            l += 1
        lane_used.add(l)
        return l

    for cid, ps, _ in commits:
        if cid not in lane_of:
            lane_of[cid] = alloc_lane()
        if ps:
            p0 = ps[0]
            if p0 not in lane_of:
                lane_of[p0] = lane_of[cid]
            for p in ps[1:]:
                if p not in lane_of:
                    lane_of[p] = alloc_lane()

    y_of = {cid: i for i, (cid, _, _) in enumerate(commits)}

    def color_for_lane(l):
        return f"C{l % 10}"

    N = len(commits)
    fig = plt.figure(figsize=(12, 0.35 * N + 2))
    fig.patch.set_facecolor("white")
    gs = fig.add_gridspec(1, 2, width_ratios=[1.2, 4.0], wspace=0.03)
    # Default subplot parameters (matching requested values).
    fig.subplots_adjust(
        left=0.13, bottom=0.114, right=0.483,
        top=0.936, wspace=0.198, hspace=0.198
    )
    axg = fig.add_subplot(gs[0, 0])
    axt = fig.add_subplot(gs[0, 1])
    axg.set_facecolor("white")
    axt.set_facecolor("white")

    axt.axvline(0.0, linestyle=":", linewidth=1)

    max_lane = max(lane_of.values()) if lane_of else 0
    for lane in range(max_lane + 1):
        axg.plot([lane, lane], [-1, N + 5], linewidth=2, alpha=0.12)

    for cid, ps in parents_map.items():
        if cid not in y_of:
            continue
        x0, y0 = lane_of.get(cid, 0), y_of[cid]
        for p in ps:
            if p not in y_of or p not in lane_of:
                continue
            x1, y1 = lane_of[p], y_of[p]
            bend_y = y0 + 0.35
            rounded_elbow(
                axg, x0, y0, x1, y1, bend_y=bend_y, r=0.22,
                linewidth=2, color=color_for_lane(x0)
            )

    for cid, _, _ in commits:
        axg.scatter([lane_of.get(cid, 0)], [y_of[cid]], s=110, zorder=3,
                    color=color_for_lane(lane_of.get(cid, 0)), edgecolors="none")

    msg_font = 8 if N > 80 else 9
    for cid, _, _ in commits:
        text = msg_map.get(cid, "")
        if len(text) > 60:
            text = text[:57] + "..."
        axt.text(0.02, y_of[cid], text, va="center", fontsize=msg_font)

    axg.set_xlim(-0.7, max_lane + 0.7)
    extra_label_space = 1.2 + (max_lane * 0.35 if max_lane else 0.0)
    axg.set_ylim(N + extra_label_space, -0.5)
    axt.set_ylim(N + extra_label_space, -0.5)
    axg.axis("off")
    axt.set_xlim(0, 1.08)
    axt.axis("off")
    fig.suptitle("IGRM Git Workflow Tree", y=0.995)
    try:
        fig.canvas.manager.set_window_title("IGRM workflow")
    except Exception:
        pass

    # Branch labels at the bottom of each lane (local + remote)
    try:
        def _wrap_label(label: str, width: int = 20) -> str:
            if not label:
                return label
            return "\n".join(textwrap.wrap(
                label, width=width, break_long_words=False, break_on_hyphens=False
            ))

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
        # If labels are long, give the figure a bit more horizontal breathing room.
        max_label_len = 0
        max_label_lines = 1
        for lane, groups in lane_labels.items():
            local_names = sorted({n for n in groups["local"] if not n.endswith("/HEAD")})
            remote_names = sorted({n for n in groups["remote"] if not n.endswith("/HEAD")})
            parts = []
            if local_names:
                parts.append(f"L: {', '.join(local_names)}")
            if remote_names:
                parts.append(f"R: {', '.join(remote_names)}")
            label = " | ".join(parts)
            if label:
                max_label_len = max(max_label_len, len(label))
                max_label_lines = max(max_label_lines, len(_wrap_label(label).splitlines()))

        if max_label_len:
            base_w, base_h = fig.get_size_inches()
            lane_boost = 0.6 * max_lane
            label_boost = min(8.0, max(0.0, (max_label_len - 18) * 0.18))
            fig.set_size_inches(base_w + lane_boost + label_boost, base_h, forward=True)

        # Only draw bottom labels when they fit cleanly; otherwise rely on the legend.
        draw_lane_labels = (max_lane <= 4 and max_label_lines == 1 and max_label_len <= 28)

        for lane, groups in lane_labels.items():
            local_names = sorted({n for n in groups["local"] if not n.endswith("/HEAD")})
            remote_names = sorted({n for n in groups["remote"] if not n.endswith("/HEAD")})
            parts = []
            if local_names:
                parts.append(f"L: {', '.join(local_names)}")
            if remote_names:
                parts.append(f"R: {', '.join(remote_names)}")
            label = " | ".join(parts)
            if not label:
                continue
            if draw_lane_labels:
                y = N + 0.8 + (lane * 0.38)
                x = lane + (0.08 if lane % 2 == 0 else -0.08)
                axg.text(
                    x, y, _wrap_label(label),
                    ha="center", va="bottom", fontsize=7.0, rotation=38
                )

        # Legend on right side: explain L/R and map lane colors to branch labels
        if lane_labels:
            legend_items = []
            for lane in sorted(lane_labels.keys()):
                groups = lane_labels[lane]
                local_names = sorted({n for n in groups["local"] if not n.endswith("/HEAD")})
                remote_names = sorted({n for n in groups["remote"] if not n.endswith("/HEAD")})
                parts = []
                if local_names:
                    parts.append(f"L: {', '.join(local_names)}")
                if remote_names:
                    parts.append(f"R: {', '.join(remote_names)}")
                label = " | ".join(parts) if parts else f"Lane {lane}"
                legend_items.append((lane, label))

            max_items = 12
            shown = legend_items[:max_items]
            handles = [
                Line2D([0], [0], color=color_for_lane(lane), marker="o",
                       linestyle="-", linewidth=2, markersize=6)
                for lane, _ in shown
            ]
            labels = [lbl for _, lbl in shown]
            if len(legend_items) > max_items and labels:
                extra = len(legend_items) - max_items
                labels[-1] = f"{labels[-1]}  (+{extra} more)"

            wrapped_labels = [
                "\n".join(textwrap.wrap(l, width=26, break_long_words=False, break_on_hyphens=False))
                for l in labels
            ]

            # Keep legend within the visible canvas (avoid forcing wide figures).
            axt.legend(
                handles, wrapped_labels,
                loc="upper right",
                bbox_to_anchor=(0.98, 0.98),
                bbox_transform=axt.transAxes,
                fontsize=7,
                frameon=True,
                framealpha=0.90,
                title="Legend (L=Local, R=Remote)",
                title_fontsize=8,
                borderaxespad=0.0,
            )
    except Exception:
        pass
    try:
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    except Exception as e:
        messagebox.showerror(
            "Matplotlib missing",
            f"Matplotlib Tk backend is required to show the scrollable graph.\n\nError: {e}"
        )
        return

    win = Toplevel(root)
    win.title("IGRM workflow")
    win.geometry("1100x800")
    win.minsize(900, 600)
    win.configure(bg="white")

    def _on_plot_close():
        try:
            win.unbind_all("<MouseWheel>")
            win.unbind_all("<Button-4>")
            win.unbind_all("<Button-5>")
        except Exception:
            pass
        try:
            plt.close(fig)
        except Exception:
            pass
        try:
            win.destroy()
        except Exception:
            pass

    win.protocol("WM_DELETE_WINDOW", _on_plot_close)

    toolbar_frame = tk.Frame(win, bg="white")
    toolbar_frame.pack(side="top", fill="x")

    container = tk.Frame(win, bg="white")
    container.pack(fill="both", expand=True)

    plot_canvas = tk.Canvas(container, highlightthickness=0, bg="white")
    vbar = tk.Scrollbar(container, orient="vertical", command=plot_canvas.yview)
    hbar = tk.Scrollbar(container, orient="horizontal", command=plot_canvas.xview)
    plot_canvas.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)

    plot_canvas.pack(side="left", fill="both", expand=True)
    vbar.pack(side="right", fill="y")
    hbar.pack(side="bottom", fill="x")

    inner = tk.Frame(plot_canvas, bg="white")
    plot_canvas.create_window((0, 0), window=inner, anchor="nw")

    def _sync_scrollregion(_evt=None):
        try:
            plot_canvas.configure(scrollregion=plot_canvas.bbox("all"))
        except Exception:
            pass

    inner.bind("<Configure>", _sync_scrollregion)

    fig_canvas = FigureCanvasTkAgg(fig, master=inner)
    fig_widget = fig_canvas.get_tk_widget()
    fig_widget.configure(bg="white", highlightthickness=0)
    fig_widget.pack()
    fig_canvas.draw()

    NavigationToolbar2Tk(fig_canvas, toolbar_frame)
    _sync_scrollregion()

    def _on_plot_mousewheel(event):
        if not win.winfo_exists() or not plot_canvas.winfo_exists():
            return
        if event.num == 5 or event.delta < 0:
            plot_canvas.yview_scroll(1, "units")
        elif event.num == 4 or event.delta > 0:
            plot_canvas.yview_scroll(-1, "units")

    win.bind("<MouseWheel>", _on_plot_mousewheel)
    win.bind("<Button-4>", _on_plot_mousewheel)
    win.bind("<Button-5>", _on_plot_mousewheel)

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

def run_git_command():
    if not _ensure_repo_loaded_for_terminal():
        return
    cmd = terminal_entry.get().strip()
    if not cmd:
        return
    if not cmd.lower().startswith("git "):
        messagebox.showwarning("Terminal", "Only git commands are allowed.")
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
            cmd,
            cwd=repo.working_dir,
            shell=True,
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

root = tk.Tk()
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
try:
    root.iconbitmap(resource_path("insightsnet_logo.ico"))
except Exception:
    pass
try:
    _icon_img = ImageTk.PhotoImage(Image.open(resource_path("insightsnet_logo.png")))
    root.iconphoto(True, _icon_img)
except Exception:
    pass

root.geometry("980x760")
branch_var = tk.StringVar(root)

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

def _on_mousewheel(event):
    if event.num == 5 or event.delta < 0:
        canvas.yview_scroll(1, "units")
    elif event.num == 4 or event.delta > 0:
        canvas.yview_scroll(-1, "units")

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

tk.Button(branch_section, text="List Branches", command=list_branches)\
  .grid(row=1, column=0, padx=5, pady=5)
tk.Button(branch_section, text="Refresh Branches", command=refresh_branches)\
  .grid(row=1, column=1, padx=5, pady=5)
tk.Button(branch_section, text="Git Pull", command=git_pull)\
  .grid(row=1, column=2, padx=5, pady=5)
current_branch_label = tk.Label(branch_section, text="Current branch: N/A")
current_branch_label.grid(row=2, column=0, sticky="w")
branch_dropdown = None

git_check_section = tk.LabelFrame(branch_section, text="Git Operations on Current Branch",
                                  padx=10, pady=10, relief="ridge", font=("Arial", 10, "bold"))
git_check_section.grid(row=4, column=0, columnspan=3, pady=10, sticky="we")
tk.Button(git_check_section, text="Fetch & Status", command=git_fetch_status)\
  .grid(row=0, column=0, padx=5, pady=5)
tk.Button(git_check_section, text="View Log", command=git_log_branch)\
  .grid(row=0, column=1, padx=5, pady=5)
tk.Button(git_check_section, text="Pull Latest", command=git_pull_branch)\
  .grid(row=0, column=2, padx=5, pady=5)
tk.Button(git_check_section, text="Fetch & Prune", command=fetch_all_and_prune)\
  .grid(row=0, column=3, padx=5, pady=5)

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
tk.Button(commit_section, text="Commit Changes", command=commit_changes)\
  .grid(row=3, column=0, columnspan=3, pady=10)

preview_row = tk.Frame(commit_section)
preview_row.grid(row=4, column=0, columnspan=3, pady=(0, 10))
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

# ---- Workflow Graph Tab
graph_top = tk.Frame(graph_tab)
graph_top.pack(fill="x", padx=10, pady=6)

tk.Button(graph_top, text="Refresh Graph", command=refresh_workflow_graph).pack(side="left")
tk.Button(graph_top, text="?", width=2, command=show_graph_help).pack(side="left", padx=(5, 0))
tk.Button(graph_top, text="Plot Graph", command=show_matplotlib_graph).pack(side="left", padx=(5, 0))

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
tk.Label(commits_frame, text="Recent Commits", font=("Arial", 10, "bold"))\
  .grid(row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 6))

commits_cols = ("sha", "date", "author", "branch", "files", "message")
commits_table = ttk.Treeview(commits_frame, columns=commits_cols, show="headings")
for col, w in zip(commits_cols, (90, 90, 160, 110, 70, 600)):
    commits_table.heading(col, text=col.upper())
    commits_table.column(col, width=w, anchor="w")

commits_y = ttk.Scrollbar(commits_frame, orient="vertical", command=commits_table.yview)
commits_x = ttk.Scrollbar(commits_frame, orient="horizontal", command=commits_table.xview)
commits_table.configure(yscrollcommand=commits_y.set, xscrollcommand=commits_x.set)
commits_table.grid(row=1, column=0, sticky="nsew", padx=8)
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
    ver = "v0.26"
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
    text="-----------------------------------------\nInsightsNet GitRepo Manager\nVersion 0.26\nDeveloped by Team InsightsNet\n© 2026",
    font=("Arial", 12),
    pady=20
).pack()

# ---- Git AuthN Tab (UI + remote tools)
auth_wrap = tk.LabelFrame(auth_tab, text="Authentication", padx=20, pady=20, font=("Arial", 12, "bold"))
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

tk.Label(auth_wrap, text="Remote (origin) tools", font=("Arial", 11, "bold")).pack(pady=(18, 4))
tk.Button(auth_wrap, text="Show Origin URL", command=lambda: messagebox.showinfo("Origin", get_origin_url() or "No origin"))\
  .pack(pady=(0,4))

remote_row = tk.Frame(auth_wrap); remote_row.pack(pady=4)
tk.Button(remote_row, text="Switch Origin to SSH", command=switch_origin_to_ssh_any, width=20).grid(row=0, column=0, padx=8)
tk.Button(remote_row, text="Test GitHub SSH", command=test_github_ssh, width=20).grid(row=0, column=1, padx=8)
tk.Button(remote_row, text="Test Origin Host SSH", command=test_origin_host_ssh, width=22).grid(row=0, column=2, padx=8)
tk.Button(remote_row, text="Test GitLab SSH", command=test_gitlab_ssh, width=20).grid(row=0, column=3, padx=8)

diag_row = tk.Frame(auth_wrap); diag_row.pack(pady=4)
tk.Button(diag_row, text="Show origin.fetch", width=20, command=show_origin_refspec).grid(row=0, column=0, padx=8)
tk.Button(diag_row, text="Show Remote Heads", width=20, command=show_remote_heads).grid(row=0, column=1, padx=8)
tk.Button(auth_wrap, text="Fix Refspec & Fetch All", command=fix_refspec_and_fetch).pack(pady=(6, 10))

# Prefill AuthN fields initially
_prefill_auth_fields()
_update_terminal_prompt()
_drain_ui_queue()

root.mainloop()