System-Check is a ready-to-run cross-platform Python script that gathers a reasonable, privacy-respecting audit of what happened on your machine since the last boot. It collects:

last boot time (system uptime)

processes started since boot (owner, PID, start time, cmdline)

recently modified files under specified directories (by modification time)

shell history files (bash, zsh, fish) if present

system logs since boot (uses journalctl on Linux, log on macOS, Windows Event Log via wevtutil if available)

recent user logins (where available)

Notes & caveats

For full system logs (especially Windows security events or system-wide journalctl access), run the script with elevated privileges (Administrator / root).

The script is conservative about scanning file paths — it scans the user home by default. Modify scan_paths to expand scope, but be mindful: scanning large trees can take time.

The script writes a JSON report (audit_since_boot.json) and prints a short summary.

Tested libraries: psutil is required (pip install psutil). Other commands used rely on OS tools (journalctl, wevtutil, log) which are present on typical Linux/Windows/macOS installations.
