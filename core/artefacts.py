"""The artefact catalogue (Tab 3, methodology s3.5.4).

This is the finalised list of artfeacts against the KAPE/UAC
categories. A few illustrative entries are given per platform; COMPLETE the
catalogue here. Keep 'volatility' honest so collection ordering is correct
(higher number = more volatile = collected first).

Windows artefacts are collected via PowerShell over the WinRM transport;
Unix artefacts via commands / file fetches over the SSH transport.
"""

from __future__ import annotations

from .models import Artefact, OSFamily

# --- Windows ---------------------------------------------------------------
WINDOWS_CATALOGUE: list[Artefact] = [
    Artefact("win_proc", "Running processes", "Volatile", OSFamily.WINDOWS,
             volatility=90, spec="Get-Process | Select-Object * | ConvertTo-Csv"),
    Artefact("win_netconn", "Network connections", "Volatile", OSFamily.WINDOWS,
             volatility=90, spec="Get-NetTCPConnection | ConvertTo-Csv"),
    Artefact("win_sessions", "Logged-on users", "Volatile", OSFamily.WINDOWS,
             volatility=85, spec="query user"),
    Artefact("win_evtx_security", "Security event log", "Logs", OSFamily.WINDOWS,
             volatility=20, spec=r"C:\Windows\System32\winevt\Logs\Security.evtx",
             is_command=False),
    # TODO: System.evtx, Application.evtx, registry hives (SYSTEM/SOFTWARE/SAM/
    # NTUSER), Prefetch, scheduled tasks, ... justify each against Chapter 2.
]

# --- Unix-like -------------------------------------------------------------
UNIX_CATALOGUE: list[Artefact] = [
    Artefact("nix_proc", "Running processes", "Volatile", OSFamily.UNIX,
             volatility=90, spec="ps aux"),
    Artefact("nix_netconn", "Network connections", "Volatile", OSFamily.UNIX,
             volatility=90, spec="ss -tunap"),
    Artefact("nix_who", "Logged-on users", "Volatile", OSFamily.UNIX,
             volatility=85, spec="who -a"),
    Artefact("nix_authlog", "Auth log", "Logs", OSFamily.UNIX,
             volatility=20, spec="/var/log/auth.log", is_command=False),
    # TODO: syslog, bash history, crontab/cron dirs, systemd journal, ...
]


def catalogue_for(os_family: OSFamily) -> list[Artefact]:
    if os_family is OSFamily.WINDOWS:
        return WINDOWS_CATALOGUE
    if os_family is OSFamily.UNIX:
        return UNIX_CATALOGUE
    return []
