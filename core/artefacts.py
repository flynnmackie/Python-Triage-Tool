"""The artefact catalogue (Tab 3, methodology s3.5.4).

Curated triage set of high-value artefacts, mapped to the KAPE (Windows) and
UAC (Unix) categories reviewed in Chapter 2. This is deliberately a TRIAGE set,
not full-disk parity - breadth is where the single-platform incumbents win and
is out of scope (see future work).

Collection patterns used:
  - command        : is_command=True, output captured as text/CSV
  - unlocked file  : is_command=False
  - locked file    : is_command=False + prepare= (export an unlocked copy first)
  - directory      : is_command=False + prepare= (zip on target) + is_archive=True

Volatility drives collection order (NFR3): live command output is most volatile
(80-95); on-disk artefacts are persistent (10-20).
"""

from __future__ import annotations

from .models import Artefact, OSFamily

_WIN_TMP = r"C:\Windows\Temp"

# --- Windows ---------------------------------------------------------------
WINDOWS_CATALOGUE: list[Artefact] = [
    # Volatile - live state, collected first.
    Artefact("win_proc", "Running processes", "Volatile", OSFamily.WINDOWS,
             volatility=95,
             spec="Get-Process | Select-Object * | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_netconn", "Network connections", "Volatile", OSFamily.WINDOWS,
             volatility=95,
             spec="Get-NetTCPConnection | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_sessions", "Logged-on users", "Volatile", OSFamily.WINDOWS,
             volatility=90, spec="query user"),
    Artefact("win_services", "Services", "Volatile", OSFamily.WINDOWS,
             volatility=85,
             spec="Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_tasks", "Scheduled tasks", "Volatile", OSFamily.WINDOWS,
             volatility=80,
             spec="Get-ScheduledTask | Select-Object TaskName,TaskPath,State | ConvertTo-Csv -NoTypeInformation"),

    # Registry hives - locked; export an unlocked copy with reg save.
    Artefact("win_reg_system", "SYSTEM hive", "Hives", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_TMP}\rtc_system.hiv",
             prepare=rf"reg save HKLM\SYSTEM {_WIN_TMP}\rtc_system.hiv /y"),
    Artefact("win_reg_software", "SOFTWARE hive", "Hives", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_TMP}\rtc_software.hiv",
             prepare=rf"reg save HKLM\SOFTWARE {_WIN_TMP}\rtc_software.hiv /y"),
    Artefact("win_reg_sam", "SAM hive", "Hives", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_TMP}\rtc_sam.hiv",
             prepare=rf"reg save HKLM\SAM {_WIN_TMP}\rtc_sam.hiv /y"),
    Artefact("win_reg_security", "SECURITY hive", "Hives", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_TMP}\rtc_sechive.hiv",
             prepare=rf"reg save HKLM\SECURITY {_WIN_TMP}\rtc_sechive.hiv /y"),

    # Event logs - locked; export with wevtutil epl.
    Artefact("win_evtx_security", "Security event log", "EventLogs", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_TMP}\rtc_security.evtx",
             prepare=rf"wevtutil epl Security {_WIN_TMP}\rtc_security.evtx /ow:true"),
    Artefact("win_evtx_system", "System event log", "EventLogs", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_TMP}\rtc_system_evtx.evtx",
             prepare=rf"wevtutil epl System {_WIN_TMP}\rtc_system_evtx.evtx /ow:true"),
    Artefact("win_evtx_application", "Application event log", "EventLogs", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_TMP}\rtc_application.evtx",
             prepare=rf"wevtutil epl Application {_WIN_TMP}\rtc_application.evtx /ow:true"),
    Artefact("win_evtx_powershell", "PowerShell operational log", "EventLogs", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_TMP}\rtc_pwsh.evtx",
             prepare=rf'wevtutil epl "Microsoft-Windows-PowerShell/Operational" {_WIN_TMP}\rtc_pwsh.evtx /ow:true'),

    # Prefetch - a directory; zip on target, fetch, flatten.
    Artefact("win_prefetch", "Prefetch", "Prefetch", OSFamily.WINDOWS,
             volatility=15, is_command=False, is_archive=True,
             spec=rf"{_WIN_TMP}\rtc_prefetch.zip",
             prepare=rf"Compress-Archive -Path C:\Windows\Prefetch\* -DestinationPath {_WIN_TMP}\rtc_prefetch.zip -Force"),
]

# --- Unix-like -------------------------------------------------------------
_NIX_TMP = "/tmp"

UNIX_CATALOGUE: list[Artefact] = [
    # Volatile.
    Artefact("nix_proc", "Running processes", "Volatile", OSFamily.UNIX,
             volatility=95, spec="ps aux"),
    Artefact("nix_netconn", "Network connections", "Volatile", OSFamily.UNIX,
             volatility=95, spec="ss -tunap"),
    Artefact("nix_who", "Logged-on users", "Volatile", OSFamily.UNIX,
             volatility=90, spec="who -a"),
    Artefact("nix_last", "Login history", "Volatile", OSFamily.UNIX,
             volatility=85, spec="last -F -w"),
    Artefact("nix_cron_list", "User crontab", "Volatile", OSFamily.UNIX,
             volatility=80, spec="crontab -l 2>/dev/null; echo '--- /etc/crontab ---'; cat /etc/crontab 2>/dev/null"),

    # Logs - root-owned; zip via sudo into /tmp, chmod so UnixUser can fetch it.
    Artefact("nix_varlog", "System logs (/var/log)", "SystemLogs", OSFamily.UNIX,
             volatility=15, is_command=False, is_archive=True, requires_sudo=True,
             spec=f"{_NIX_TMP}/rtc_varlog.zip",
             prepare=f"sh -c 'cd /var/log && zip -r {_NIX_TMP}/rtc_varlog.zip . >/dev/null 2>&1; chmod 644 {_NIX_TMP}/rtc_varlog.zip'"),

    # Root shell history - copy out via sudo, then fetch the readable copy.
    Artefact("nix_bash_history", "Root shell history", "History", OSFamily.UNIX,
             volatility=15, is_command=False, requires_sudo=True,
             spec=f"{_NIX_TMP}/rtc_root_bash_history",
             prepare=f"sh -c 'cp /root/.bash_history {_NIX_TMP}/rtc_root_bash_history; chmod 644 {_NIX_TMP}/rtc_root_bash_history'"),
]


def catalogue_for(os_family: OSFamily) -> list[Artefact]:
    if os_family is OSFamily.WINDOWS:
        return WINDOWS_CATALOGUE
    if os_family is OSFamily.UNIX:
        return UNIX_CATALOGUE
    return []