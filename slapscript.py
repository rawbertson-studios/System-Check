#!/usr/bin/env python3
"""
audit_since_boot.py
Collect a system activity audit since last boot (cross-platform: Linux, macOS, Windows)
Requires: psutil  (pip install psutil)
Outputs:
  - audit_since_boot.json  (detailed structured data)
  - audit_summary.txt      (human-readable text summary)
"""

import os
import sys
import json
import time
import shutil
import getpass
import subprocess
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except Exception:
    print("This script requires 'psutil'. Install it with:")
    print("    pip install psutil")
    sys.exit(1)


# -----------------------
# Helpers
# -----------------------
def ts_to_iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat()


def safe_run(cmd, timeout=10):
    """Run a shell command and return stdout text."""
    try:
        res = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, text=True
        )
        return res.stdout.strip() or res.stderr.strip()
    except Exception:
        return ""


# -----------------------
# Core collectors
# -----------------------
def get_boot_time():
    bt = psutil.boot_time()
    return {"boot_time_epoch": bt, "boot_time_iso": ts_to_iso(bt)}


def get_processes_since_boot(boot_time):
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'create_time', 'cmdline']):
        info = p.info
        ctime = info.get('create_time') or 0
        if ctime >= boot_time:
            procs.append({
                "pid": info.get('pid'),
                "name": info.get('name'),
                "username": info.get('username'),
                "create_time_iso": ts_to_iso(ctime),
                "cmdline": " ".join(info.get('cmdline') or [])
            })
    procs.sort(key=lambda x: x['create_time_iso'])
    return procs


def scan_recent_files(paths, boot_time, limit_per_path=100):
    """Find recently modified files."""
    results = []
    for base in paths:
        base = os.path.expanduser(base)
        if not os.path.exists(base):
            continue
        for dirpath, _, filenames in os.walk(base):
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                try:
                    st = os.stat(fp)
                    if st.st_mtime >= boot_time:
                        results.append((fp, st.st_mtime))
                except Exception:
                    continue
        results = sorted(results, key=lambda x: x[1], reverse=True)[:limit_per_path]
    return [{"path": fp, "modified": ts_to_iso(ts)} for fp, ts in results]


def collect_shell_histories():
    """Preview last few lines of known shell histories."""
    home = Path.home()
    history_paths = [
        home / ".bash_history",
        home / ".zsh_history",
        home / ".local/share/fish/fish_history",
    ]
    previews = []
    for path in history_paths:
        if path.exists():
            try:
                lines = path.read_text(errors="ignore").splitlines()[-10:]
                previews.append({"file": str(path), "recent": lines})
            except Exception:
                pass
    return previews


def collect_system_logs_since_boot(boot_iso):
    """Collect limited logs depending on platform."""
    plat = sys.platform
    if plat.startswith("linux") and shutil.which("journalctl"):
        out = safe_run(f"journalctl --since='{boot_iso}' --no-pager -n 50", timeout=10)
        return {"method": "journalctl", "excerpt": out.splitlines()[-20:]}
    elif plat == "darwin" and shutil.which("log"):
        out = safe_run(f"log show --style syslog --start '{boot_iso}' --last 1d | tail -n 50", timeout=10)
        return {"method": "log show", "excerpt": out.splitlines()[-20:]}
    elif plat.startswith("win") and shutil.which("wevtutil"):
        out = safe_run("wevtutil qe System /c:50 /f:text", timeout=10)
        return {"method": "wevtutil", "excerpt": out.splitlines()[-20:]}
    return {"method": "none", "excerpt": []}


# -----------------------
# Human-readable summary
# -----------------------
def write_human_summary(data, filename="audit_summary.txt"):
    lines = []
    lines.append(f"=== SYSTEM AUDIT SINCE LAST BOOT ===\n")
    lines.append(f"Generated: {data['generated_at']}")
    lines.append(f"User: {data['user']}")
    lines.append(f"Boot Time: {data['boot']['boot_time_iso']}")
    lines.append("")

    # Processes
    procs = data["processes_since_boot"]
    lines.append(f"--- Processes Started Since Boot ({len(procs)} total) ---")
    for p in procs[-10:]:
        lines.append(f"[{p['create_time_iso']}] {p['username']} ran '{p['name']}' ({p['cmdline']})")

    # Files
    files = data["recent_files"]
    lines.append(f"\n--- Files Modified Since Boot ({len(files)} shown) ---")
    for f in files[:10]:
        lines.append(f"[{f['modified']}] {f['path']}")

    # Shell History
    hist = data["shell_history"]
    if hist:
        lines.append("\n--- Shell History (last few commands) ---")
        for h in hist:
            lines.append(f"From: {h['file']}")
            for cmd in h['recent']:
                lines.append(f"  {cmd}")

    # Logs
    logs = data["system_logs_excerpt"]
    lines.append("\n--- System Logs (excerpt) ---")
    if logs["excerpt"]:
        lines.extend(["  " + l for l in logs["excerpt"]])
    else:
        lines.append("  (No logs captured)")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\nSummary written to: {filename}")


# -----------------------
# Main
# -----------------------
def main():
    boot = get_boot_time()
    boot_time = boot["boot_time_epoch"]
    boot_iso = boot["boot_time_iso"]
    user = getpass.getuser()

    print(f"Collecting system activity since last boot ({boot_iso})...")

    processes = get_processes_since_boot(boot_time)
    home = str(Path.home())
    scan_paths = [home, os.path.join(home, "Documents"), os.path.join(home, "Downloads")]
    recent_files = scan_recent_files(scan_paths, boot_time)
    shell_history = collect_shell_histories()
    logs = collect_system_logs_since_boot(boot_iso)

    data = {
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(),
        "user": user,
        "boot": boot,
        "processes_since_boot": processes,
        "recent_files": recent_files,
        "shell_history": shell_history,
        "system_logs_excerpt": logs,
    }

    with open("audit_since_boot.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    write_human_summary(data)

    print("\n✅ Done. Detailed JSON and human summary written.")


if __name__ == "__main__":
    main()
