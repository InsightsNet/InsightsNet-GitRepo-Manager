import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel
from tkinter import ttk
from PIL import Image, ImageTk
import shutil
import subprocess
import os
import sys
import ctypes
import threading
import datetime
import re
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
    """
    Ensure repo has user.name/email before committing.
    If missing, try to use values from the AuthN tab. If still missing, block.
    """
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
        return  # UI not built yet
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

# =============== Repo / Branch / Commit logic ===============

def _has_remote_origin() -> bool:
    """Return True if repo has a remote named 'origin'."""
    global repo
    try:
        return repo is not None and any(r.name == "origin" for r in repo.remotes)
    except Exception:
        return False

def browse_folder():
    folder = filedialog.askdirectory()
    if folder:
        clone_dir_entry.delete(0, tk.END)
        clone_dir_entry.insert(0, folder)

def clone_repo():
    """
    If 'Repo URL' is provided: clone (or load if exists).
    If empty but Local Clone Directory points to a repo: load it.
    """
    repo_url = repo_entry.get().strip()
    base_dir = clone_dir_entry.get().strip()

    if not repo_url and not base_dir:
        messagebox.showwarning("Input Error", "Please provide a repo URL or a local repo path.")
        return

    download_button.config(state=tk.DISABLED)

    def task():
        global repo
        try:
            # load directly if only local path provided
            if not repo_url and os.path.isdir(base_dir) and os.path.isdir(os.path.join(base_dir, ".git")):
                repo = Repo(base_dir)
                messagebox.showinfo("Loaded", f"Loaded existing repository:\n{base_dir}")
                list_branches(base_dir)
                _prefill_auth_fields()
                return

            if not os.path.exists(base_dir):
                os.makedirs(base_dir, exist_ok=True)

            base_name = os.path.basename(repo_url.replace("\\", "/"))
            if base_name.endswith(".git"):
                base_name = base_name[:-4]
            repo_name = base_name or "repo"
            full_clone_path = os.path.join(base_dir, repo_name)

            if os.path.isdir(full_clone_path) and os.path.isdir(os.path.join(full_clone_path, ".git")):
                repo = Repo(full_clone_path)
                messagebox.showinfo("Loaded", f"Loaded existing repository at:\n{full_clone_path}")
                list_branches(full_clone_path)
                _prefill_auth_fields()
                return

            repo = Repo.clone_from(repo_url, full_clone_path)
            messagebox.showinfo("Success", f"Repository cloned to:\n{full_clone_path}")
            list_branches(full_clone_path)
            _prefill_auth_fields()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to clone/load repo:\n{e}")
        finally:
            download_button.config(state=tk.NORMAL)

    threading.Thread(target=task, daemon=True).start()

def list_branches(repo_path=None):
    """Populate branch dropdown with local + remote (origin) branches."""
    global repo, branch_var, branch_dropdown

    repo_path = repo_path or clone_dir_entry.get()
    if not repo_path or not os.path.exists(repo_path):
        messagebox.showwarning("Error", "Please provide a valid cloned repository path.")
        return

    try:
        repo = Repo(repo_path)

        # Make sure we have all remote heads locally
        try:
            if _has_remote_origin():
                repo.git.fetch("--all", "--prune")
        except Exception:
            pass

        # Local branches
        local = {str(h) for h in getattr(repo, "branches", [])}

        # Remote branches under origin (strip the 'origin/' prefix)
        remote = set()
        try:
            if _has_remote_origin():
                for rf in repo.remotes.origin.refs:
                    n = getattr(rf, "remote_head", None) or (rf.name.split("/", 1)[1] if "/" in rf.name else rf.name)
                    if n and n != "HEAD":
                        remote.add(n)
        except Exception:
            pass

        # Union of local + remote names
        all_names = sorted(local | remote)
        if not all_names:
            messagebox.showwarning("Branches", "No branches found (local or remote).")
            return

        # Determine current branch (may be detached)
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
    """Checkout local branch, or create tracking branch from origin/<name> if missing."""
    global repo
    target = branch_var.get().strip()
    if not target:
        return
    try:
        local_names = {str(h) for h in getattr(repo, "branches", [])}

        if target in local_names:
            # Simple checkout
            repo.git.checkout(target)
        else:
            # Create local branch tracking origin/<target>
            if _has_remote_origin():
                remote_full = f"origin/{target}"
                remote_heads = [r.name for r in repo.remotes.origin.refs]
                if remote_full in remote_heads:
                    repo.git.checkout("-b", target, "--track", remote_full)
                else:
                    raise Exception(f"Remote branch '{remote_full}' not found.")
            else:
                raise Exception("No 'origin' remote; cannot create tracking branch.")

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
    try:
        repo.remotes.origin.pull()
        messagebox.showinfo("Success", "Repository updated via git pull.")
    except Exception as e:
        messagebox.showerror("Error", f"Git Pull failed:\n{e}")

def git_fetch_status():
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    try:
        if repo.remotes and any(r.name == "origin" for r in repo.remotes):
            repo.remotes.origin.fetch()
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
        # Prefer local; fall back to origin/branch if exists
        try:
            log = repo.git.log(branch_name, '--oneline')
        except Exception:
            log = repo.git.log(f"origin/{branch_name}", '--oneline')
        messagebox.showinfo(f"Git Log - {branch_name}", log or "No commits found.")
    except Exception as e:
        messagebox.showerror("Error", f"Git log failed:\n{e}")

def git_pull_branch():
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return
    branch_name = branch_var.get()
    try:
        repo.git.pull("origin", branch_name)
        messagebox.showinfo("Success", f"Updated branch {branch_name}")
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
            # Ensure file is inside repo
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
            # nothing valid was added, keep the checkbox visible
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
    # Ensure name/email exist before committing
    if not _ensure_identity_before_commit():
        return

    committed_files = []

    try:
        if add_all_var.get():
            # One commit for everything staged
            msg = commit_msg_entry.get().strip()
            if not msg:
                messagebox.showwarning("Error", "Please enter a commit message for all files.")
                return

            repo.git.add(A=True)  # stage all
            staged = repo.git.diff("--name-only", "--cached").splitlines()
            if not staged:
                messagebox.showinfo("Nothing to commit", "No changes are staged.")
                return

            repo.index.commit(msg)  # one commit
            committed_files = [(os.path.basename(p), msg) for p in staged]

        else:
            # One commit per selected file (with its own message)
            if not selected_files:
                messagebox.showwarning("Error", "No files selected.")
                return

            # Ensure every selected file has a message
            for f in selected_files:
                per_msg = file_entries[f][1].get().strip()
                if not per_msg:
                    messagebox.showwarning("Error", f"Please enter a commit message for {os.path.basename(f)}")
                    return

            # Commit each file separately
            for f in selected_files:
                per_msg = file_entries[f][1].get().strip()

                try:
                    rel = os.path.relpath(f, repo.working_dir)
                except Exception:
                    rel = f

                # Only commit if there are changes for this file (staged or unstaged)
                has_changes = repo.git.status("--porcelain", "--", rel).strip()
                if not has_changes:
                    # no changes for this file; skip
                    continue

                # stage and commit just this file
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

    tk.Label(popup, text="Files committed:").pack(pady=5)
    for f, msg in committed_files:
        tk.Label(popup, text=f"{f}  --->  {msg}").pack(anchor="w", padx=10)

    tk.Button(popup, text="Git Push", command=lambda: push_changes(popup, committed_files)).pack(pady=10)

def push_changes(popup, committed_files):
    global repo
    branch_name = branch_var.get().strip()
    if not branch_name:
        messagebox.showwarning("Error", "No branch selected.")
        return
    try:
        # First push needs upstream; subsequent pushes don't.
        tracking = None
        try:
            tracking = repo.active_branch.tracking_branch()
        except Exception:
            tracking = None

        if tracking is None or str(tracking) == "":
            repo.git.push("--set-upstream", "origin", branch_name)
        else:
            repo.git.push("origin", branch_name)

        popup.destroy()
        messagebox.showinfo("Success", f"Pushed {len(committed_files)} file(s) to {branch_name}")
    except Exception as e:
        messagebox.showerror("Error", f"Push failed:\n{e}")

# =============== Workflow Graph helpers ===============

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

    # First parent = INTO (the branch you had checked out)
    into_name = _name_rev_safe(repo, parents[0].hexsha)
    # Second parent = FROM (branch merged in)
    from_name = _name_rev_safe(repo, parents[1].hexsha)

    # If Git resolves "main" for into but commit was on another branch,
    # also check decorations (HEAD -> ...) to override
    decorations = repo.git.log(
        "-1", "--pretty=%D", merge_commit.hexsha
    ).strip()
    if "HEAD ->" in decorations:
        into_name = decorations.split("HEAD ->")[1].split(",")[0].strip()

    return (from_name, into_name)

def refresh_workflow_graph():
    global repo
    if not repo:
        messagebox.showwarning("Error", "No repository loaded.")
        return

    try:
        ascii_graph = repo.git.log(
            "--graph", "--decorate", "--all", "--date=short",
            "--pretty=format:%h %ad %an %d %s",
            max_count="300"
        )
    except Exception as e:
        ascii_graph = f"Failed to render git graph: {e}"

    ascii_text.config(state="normal")
    ascii_text.delete("1.0", "end")
    ascii_text.insert("1.0", ascii_graph or "No history found.")
    ascii_text.config(state="disabled")

    for table in (merges_table, commits_table):
        for row in table.get_children():
            table.delete(row)

    try:
        commits = list(repo.iter_commits("--all", max_count=300))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read commits:\n{e}")
        return

    for c in commits:
        short_sha = c.hexsha[:8]
        when = datetime.datetime.fromtimestamp(c.committed_date).strftime("%Y-%m-%d")
        author = c.author.name if c.author else "Unknown"
        msg = c.message.splitlines()[0]
        try:
            files_changed = len(c.stats.files or {})
        except Exception:
            files_changed = 0
        commits_table.insert("", "end", values=(short_sha, when, author, files_changed, msg))

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

# =============== UI ===============
root = tk.Tk()
root.title("InsightsNet GitRepo Manager")

# --- Taskbar grouping on Windows (safe no-op elsewhere) ---
try:
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
        "InsightsNet.GitRepoManager.0.9"
    )
except Exception:
    pass

def resource_path(rel_path: str) -> str:
    """Absolute path to resource (works in dev and PyInstaller onefile)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel_path)

# --- Window icon ---
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
clone_section = tk.LabelFrame(scrollable_frame, text="Clone / Load Repository", padx=10, pady=10, relief="groove", font=("Arial", 12, "bold"))
clone_section.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="we")

tk.Label(clone_section, text="Enter a Git URL + directory (to clone) OR paste a local repo path in 'Local Clone Directory' to load.", font=("Arial", 10)).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
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

branch_section = tk.LabelFrame(scrollable_frame, text="Branch Management", padx=10, pady=10, relief="groove", font=("Arial", 12, "bold"))
branch_section.grid(row=1, column=0, columnspan=3, padx=10, pady=10, sticky="we")
tk.Label(branch_section, text="Manage your Git branches.", font=("Arial", 10)).grid(row=0, column=0, columnspan=3, sticky="w")
tk.Button(branch_section, text="List Branches", command=list_branches).grid(row=1, column=0, padx=5, pady=5)
tk.Button(branch_section, text="Refresh Branches", command=refresh_branches).grid(row=1, column=1, padx=5, pady=5)
tk.Button(branch_section, text="Git Pull", command=git_pull).grid(row=1, column=2, padx=5, pady=5)
current_branch_label = tk.Label(branch_section, text="Current branch: N/A")
current_branch_label.grid(row=2, column=0, sticky="w")
branch_dropdown = None

git_check_section = tk.LabelFrame(branch_section, text="Git Operations on Current Branch", padx=10, pady=10, relief="ridge", font=("Arial", 10, "bold"))
git_check_section.grid(row=4, column=0, columnspan=3, pady=10, sticky="we")
tk.Button(git_check_section, text="Fetch & Status", command=git_fetch_status).grid(row=0, column=0, padx=5, pady=5)
tk.Button(git_check_section, text="View Log", command=git_log_branch).grid(row=0, column=1, padx=5, pady=5)
tk.Button(git_check_section, text="Pull Latest", command=git_pull_branch).grid(row=0, column=2, padx=5, pady=5)

commit_section = tk.LabelFrame(scrollable_frame, text="Commit Changes", padx=10, pady=10, relief="groove", font=("Arial", 12, "bold"))
commit_section.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="we")

add_all_var = tk.BooleanVar()
add_all_checkbox = tk.Checkbutton(commit_section, text="Add all files", variable=add_all_var, command=toggle_add_all)
add_all_checkbox.grid(row=0, column=0, sticky="w", padx=5, pady=(0, 5))
choose_button = tk.Button(commit_section, text="Choose Files", command=choose_files)
choose_button.grid(row=0, column=1, padx=5, pady=(0, 5))

file_frame = tk.LabelFrame(commit_section, text="Selected Files", padx=10, pady=10, relief="groove", font=("Arial", 12, "bold"))
file_frame.grid(row=1, column=0, columnspan=3, padx=10, pady=(0, 10), sticky="we")
file_messages_frame = tk.Frame(file_frame)
file_messages_frame.pack(fill="both", expand=True)

tk.Label(commit_section, text="Commit message (for all files):").grid(row=2, column=0, sticky="w", padx=5, pady=5)
commit_msg_entry = tk.Entry(commit_section, width=55)
commit_msg_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5)
tk.Button(commit_section, text="Commit Changes", command=commit_changes).grid(row=3, column=0, columnspan=3, pady=10)

# ---- Workflow Graph Tab
graph_top = tk.Frame(graph_tab)
graph_top.pack(fill="x", padx=10, pady=6)
tk.Button(graph_top, text="Refresh Graph", command=refresh_workflow_graph).pack(side="left")

graph_body = tk.Frame(graph_tab)
graph_body.pack(fill="both", expand=True, padx=10, pady=(0,10))
graph_body.grid_columnconfigure(0, weight=2)
graph_body.grid_columnconfigure(1, weight=3)
graph_body.grid_rowconfigure(0, weight=1)

ascii_wrap = tk.Frame(graph_body, bd=1, relief="sunken")
ascii_wrap.grid(row=0, column=0, sticky="nsew", padx=(0,8))

ascii_text = tk.Text(ascii_wrap, wrap="none", font=("Courier New", 10), bd=0)
ascii_x = tk.Scrollbar(ascii_wrap, orient="horizontal", command=ascii_text.xview)
ascii_y = tk.Scrollbar(ascii_wrap, orient="vertical", command=ascii_text.yview)
ascii_text.configure(xscrollcommand=ascii_x.set, yscrollcommand=ascii_y.set)
ascii_text.grid(row=0, column=0, sticky="nsew")
ascii_y.grid(row=0, column=1, sticky="ns")
ascii_x.grid(row=1, column=0, sticky="ew")
ascii_wrap.grid_rowconfigure(0, weight=1)
ascii_wrap.grid_columnconfigure(0, weight=1)

right_col = tk.Frame(graph_body)
right_col.grid(row=0, column=1, sticky="nsew")
right_col.grid_rowconfigure(0, weight=1)
right_col.grid_rowconfigure(1, weight=1)
right_col.grid_columnconfigure(0, weight=1)

merges_frame = tk.Frame(right_col, bd=1, relief="sunken")
merges_frame.grid(row=0, column=0, sticky="nsew", pady=(0,8))
tk.Label(merges_frame, text="Merges (who merged what)", font=("Arial", 10, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 6))

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
tk.Label(commits_frame, text="Recent Commits", font=("Arial", 10, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 6))

commits_cols = ("sha", "date", "author", "files", "message")
commits_table = ttk.Treeview(commits_frame, columns=commits_cols, show="headings")
for col, w in zip(commits_cols, (90, 90, 160, 70, 600)):
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
    base = "User_Guide_insightsnet-git-repo-management"
    ver = "v0.9"
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
    text="-----------------------------------------\nInsightsNet GitRepo Manager\nVersion 0.9\nDeveloped by Team InsightsNet\n© 2025",
    font=("Arial", 12),
    pady=20
).pack()

# ---- Git AuthN Tab (UI) ----
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

apply_frame = tk.Frame(auth_wrap); apply_frame.pack(pady=20)
tk.Button(apply_frame, text="Apply Loaded Repository", command=_apply_identity_repo, width=20).grid(row=0, column=0, padx=20)
tk.Button(apply_frame, text="Apply Globally", command=_apply_identity_global, width=18).grid(row=0, column=1, padx=20)

# Fill fields on start (will also refresh after clone/list/switch)
_prefill_auth_fields()

root.mainloop()
