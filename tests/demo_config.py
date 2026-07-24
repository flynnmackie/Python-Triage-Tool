"""Shared configuration for the demonstration test scripts.

Edit the IPs and credentials to match your lab, then run any of the
demo_*.py scripts from the PROJECT ROOT, e.g.:

    python tests/demo_2_discovery.py

NOTE: these are demonstration / development-test scripts, not part of the
tool. Do not commit real credentials - keep this file git-ignored, or blank
the passwords before pushing.
"""

from core.models import CredentialProfile, CredKind, OSFamily

# --- Targets --------------------------------------------------------------
WIN_STANDALONE_IP = "10.10.10.102"
WIN_DOMAIN_DC_IP  = "10.10.10.100"
WIN_DOMAIN_WS_IP  = "10.10.10.101"
LINUX_IP          = "10.10.10.103"

SCAN_RANGE = "10.10.10.100-110"   # includes live + dead addresses for the scan demo

# --- Credentials (edit to match your lab) ---------------------------------
WIN_STANDALONE_PROFILE = CredentialProfile(
    name="Standalone Admin", kind=CredKind.LOCAL_NTLM,
    username="WindowsUser", secret="password12345",
)

WIN_DOMAIN_PROFILE = CredentialProfile(
    name="Domain Admin", kind=CredKind.DOMAIN_KERBEROS,
    username="Administrator", domain="TEST", secret="Password12345!",
)

LINUX_PROFILE = CredentialProfile(
    name="Linux UnixUser", kind=CredKind.SSH_PASSWORD,
    username="UnixUser", secret="password1234",
    # sudo_secret defaults to the SSH password if left blank
)
