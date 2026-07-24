"""Demo 3 - Remote-access verification (three-state).

For each host + credential profile, shows whether the channel is absent,
present-but-unauthenticated, or authenticated - and confirms the OS on
success. Also demonstrates the audit trail (writes demo_audit.csv).

Includes a deliberate wrong-password case to show the PRESENT_NO_AUTH state.

Run from the project root:  python tests/demo_3_access.py
"""

from core.models import Host, CredentialProfile, CredKind
from core.credentials import CredentialStore
from core.audit import AuditLog
from core.access import verify_host
from tests.demo_config import (
    WIN_STANDALONE_IP, WIN_DOMAIN_DC_IP, LINUX_IP,
    WIN_STANDALONE_PROFILE, WIN_DOMAIN_PROFILE, LINUX_PROFILE,
)

store = CredentialStore()
for p in (WIN_STANDALONE_PROFILE, WIN_DOMAIN_PROFILE, LINUX_PROFILE):
    store.add(p)

# A deliberately wrong credential to show the "credentials rejected" state.
bad = CredentialProfile(name="Bad creds", kind=CredKind.LOCAL_NTLM,
                        username="WindowsUser", secret="wrong-password")
store.add(bad)

audit = AuditLog("demo_audit.csv")

checks = [
    (WIN_STANDALONE_IP, WIN_STANDALONE_PROFILE.name),
    (WIN_DOMAIN_DC_IP,  WIN_DOMAIN_PROFILE.name),
    (LINUX_IP,          LINUX_PROFILE.name),
    (WIN_STANDALONE_IP, bad.name),               # expect PRESENT_NO_AUTH
]

print("=== Access verification ===\n")
print(f"  {'Host':16} {'Profile':16} {'WinRM':16} {'SSH':16} {'Confirmed OS'}")
print(f"  {'-'*16} {'-'*16} {'-'*16} {'-'*16} {'-'*12}")
for ip, profile_name in checks:
    host = Host(ip=ip)
    host.profile_name = profile_name
    verify_host(host, store, audit)
    os_txt = host.actual_os.value if host.actual_os else "-"
    print(f"  {ip:16} {profile_name:16} {host.winrm_state.value:16} {host.ssh_state.value:16} {os_txt}")

print("\nAudit trail written to demo_audit.csv")
