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
from urllib.parse import urlparse
from git import Repo

repo = None
branch_dropdown = None
selected_files = []
file_entries = {}

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
    result = {"value": False}
    done = threading.Event()
    def _prompt():
        result["value"] = messagebox.askyesno(title, msg)
        done.set()
    root.after(0, _prompt)
    done.wait()
    return result["value"]

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
                    result["ok"] = True
                    result["kind"] = "loaded_existing_clone"
                    result["path"] = full_clone_path
                else:
                    # Case 3: Fresh clone
                    if repo_url.startswith("git@") or repo_url.startswith("ssh://"):
                        if not _ensure_ssh_host_trusted(repo_url):
                            raise Exception("SSH host key not trusted; clone canceled.")
                    repo = Repo.clone_from(repo_url, full_clone_path)
                    result["ok"] = True
                    result["kind"] = "cloned"
                    result["path"] = full_clone_path

        except Exception as e:
            result["error"] = e

        def ui_update():
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

            messagebox.showinfo(title, msg)
            list_branches(path)
            _prefill_auth_fields()

        root.after(0, ui_update)

    threading.Thread(target=task, daemon=True).start()

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

# =============== Commit Section ===============

def toggle_add_all():
    if add_all_var.get():
        choose_button.grid_remove()
        clear_selected_files()
    else:
        choose_button.grid(row=0, column=1, padx=5, pady=(0, 5))

def clear_selected_files():
    global selected_files, file_entries
    selected_files.clear()
    for widget in file_messages_frame.winfo_children():
        widget.destroy()
    file_entries.clear()

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

def refresh_file_entries():
    for idx, f in enumerate(list(file_entries.keys())):
        lbl, entry, btn = file_entries[f]
        lbl.grid(row=idx * 2, column=0, sticky="w", padx=10)
        entry.grid(row=idx * 2 + 1, column=0, padx=10, pady=(0, 10))
        btn.grid(row=idx * 2, column=1, padx=5)

def commit_changes():
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    if not _ensure_identity_before_commit():
        return

    committed_files = []

    try:
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

                has_changes = repo.git.status("--porcelain", "--", rel).strip()
                if not has_changes:
                    continue

                repo.git.add("--", rel)
                repo.index.commit(per_msg)
                committed_files.append((os.path.basename(f), per_msg))

            if not committed_files:
                messagebox.showinfo("Nothing to commit", "No changes detected for the selected files.")
                return

        show_commit_summary(committed_files)

    except Exception as e:
        messagebox.showerror("Error", f"Commit failed:\n{e}")

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

def refresh_workflow_graph():
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return

    # --- Build commit list once (for tables + coloring) ---
    try:
        commits = list(repo.iter_commits("--all", max_count=300))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read commits:\n{e}")
        return

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
        for ref in repo.refs:
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
        ascii_graph = repo.git.log(
            "--graph", "--decorate", "--all",
            "--pretty=format:%h %d %s",   # no %ad %an here
            max_count="300"
        )
    except Exception as e:
        ascii_graph = f"Failed to render git graph: {e}"

    ascii_text.config(state="normal")
    ascii_text.delete("1.0", "end")

    if ascii_graph:
        lines = ascii_graph.splitlines()
    else:
        lines = []

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
    for c in commits:
        short_sha = c.hexsha[:8]
        when = datetime.datetime.fromtimestamp(c.committed_date).strftime("%Y-%m-%d")
        author = c.author.name if c.author else "Unknown"
        msg = c.message.splitlines()[0]

        branch = _branch_hint_for_commit(repo, c.hexsha) or ""

        try:
            files_changed = len(c.stats.files or {})
        except Exception:
            files_changed = 0

        commits_table.insert(
            "",
            "end",
            values=(short_sha, when, author, branch, files_changed, msg)
        )

    # --- Fill Merges table ---
    try:
        raw = repo.git.log(
            "--all", "--merges", "--date=short",
            "--pretty=format:%H%x00%ad%x00%an%x00%s"
        )
        lines = [ln for ln in raw.split("\n") if ln] if raw else []
    except Exception:
        lines = []

    if not lines:
        merges_table.insert("", "end", values=("", "", "", "", "", "No merge commits found"))
        return

    for ln in lines:
        try:
            sha, ad, au, msg = ln.split("\x00", 3)
        except ValueError:
            continue
        try:
            mc = repo.commit(sha)
        except Exception:
            mc = None
        from_name = into_name = ''
        if mc and len(mc.parents) >= 2:
            from_name, into_name = _guess_merge_from_into(repo, mc)
        merges_table.insert("", "end", values=(sha[:8], ad, au, from_name, into_name, msg))

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

# =============== UI ===============

root = tk.Tk()
root.title("InsightsNet GitRepo Manager")

# Taskbar grouping on Windows (safe no-op elsewhere)
try:
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("InsightsNet.GitRepoManager")
except Exception:
    pass

def resource_path(rel_path: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel_path)

# Window icon
try:
    root.iconbitmap(resource_path("insightsnet_logo.ico"))
except Exception:
    pass

root.geometry("980x760")
branch_var = tk.StringVar(root)

# Tabs
notebook = ttk.Notebook(root)
main_tab  = ttk.Frame(notebook)
graph_tab = ttk.Frame(notebook)
about_tab = ttk.Frame(notebook)
auth_tab  = ttk.Frame(notebook)
notebook.add(auth_tab,  text="Git AuthN")
notebook.add(main_tab,  text="Main")
notebook.add(graph_tab, text="Workflow Graph")
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

tk.Label(commit_section, text="Commit message (for all files):").grid(row=2, column=0, sticky="w", padx=5, pady=5)
commit_msg_entry = tk.Entry(commit_section, width=55)
commit_msg_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5)
tk.Button(commit_section, text="Commit Changes", command=commit_changes)\
  .grid(row=3, column=0, columnspan=3, pady=10)

# ---- Workflow Graph Tab
graph_top = tk.Frame(graph_tab)
graph_top.pack(fill="x", padx=10, pady=6)

tk.Button(graph_top, text="Refresh Graph", command=refresh_workflow_graph).pack(side="left")
tk.Button(graph_top, text="?", width=2, command=show_graph_help).pack(side="left", padx=(5, 0))

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
    ver = "v0.15"
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
    text="-----------------------------------------\nInsightsNet GitRepo Manager\nVersion 0.15\nDeveloped by Team InsightsNet\n© 2026",
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

root.mainloop()
