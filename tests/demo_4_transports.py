"""Demo 4 - Transport methods (WinRM + SSH).

Exercises the four transport operations directly on one Windows and one Linux
host: test_access, run_command, fetch_file, and remote_hash. Proves both
transports speak to their targets and that hashing-at-source works.

Run from the project root:  python tests/demo_4_transports.py
"""

from transports.winrm_transport import WinRMTransport
from transports.ssh_transport import SSHTransport
from tests.demo_config import (
    WIN_STANDALONE_IP, LINUX_IP, WIN_STANDALONE_PROFILE, LINUX_PROFILE,
)


def exercise(name, transport, cmd, file_path):
    print(f"\n=== {name} ===")
    print(f"  test_access : {transport.test_access().value}")
    out = transport.run_command(cmd).decode(errors="replace").strip().splitlines()
    print(f"  run_command : {out[0] if out else '(no output)'}")
    data = transport.fetch_file(file_path)
    print(f"  fetch_file  : {len(data)} bytes from {file_path}")
    print(f"  remote_hash : {transport.remote_hash(file_path)}")
    transport.close()


# Windows: read the always-present, unlocked hosts file.
exercise(
    "WinRM  " + WIN_STANDALONE_IP,
    WinRMTransport(WIN_STANDALONE_IP, WIN_STANDALONE_PROFILE),
    cmd="$env:COMPUTERNAME",
    file_path=r"C:\Windows\System32\drivers\etc\hosts",
)

# Linux: read /etc/hostname.
exercise(
    "SSH    " + LINUX_IP,
    SSHTransport(LINUX_IP, LINUX_PROFILE),
    cmd="uname -a",
    file_path="/etc/hostname",
)
