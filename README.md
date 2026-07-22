# Remote Triage Collector (working title)

Cross-platform, agentless forensic triage tool. Python controller reaching
Windows targets over WinRM/PowerShell Remoting (pypsrp) and Unix-like targets
over SSH (paramiko). See dissertation Chapter 3 for the design.

## Layout

* `core/`        research logic: discovery, access, collection, models, hashing, audit, credentials, artefacts
* `transports/`  protocol wrappers behind one `Transport` interface
* `gui/`         thin GUI layer (three tabs + log panel)
* `main.py`      entry point

## Build order

1. `core/discovery.py` (helpers provided) -> test headless against  subnet.
2. `transports/` -> get one command running on a Windows and a Linux VM.
3. `core/access.py` -> three-state verification.
4. `core/collection.py` -> hash + package, volatility-ordered.
5. `gui/` -> wire tabs to the working core.



