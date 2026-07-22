from core.models import Host, CredentialProfile, CredKind, Artefact, OSFamily
from core.audit import AuditLog
from core.collection import collect_from_host
from transports.winrm_transport import WinRMTransport

profile = CredentialProfile(
    name="Domain Admin",
    kind=CredKind.DOMAIN_KERBEROS,
    username="Administrator",
    domain="TEST",
    secret="Password12345!",
)

# Two deliberately safe artefacts: a command, and a readable/unlocked file.
test_artefacts = [
    Artefact("win_proc", "Running processes", "Volatile", OSFamily.WINDOWS,
             volatility=90,
             spec="Get-Process | Select-Object Name,Id | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_hosts", "hosts file", "Test", OSFamily.WINDOWS,
             volatility=10,
             spec=r"C:\Windows\System32\drivers\etc\hosts", is_command=False),
]

audit = AuditLog("scratch_audit.csv")

for ip in ["10.10.10.100", "10.10.10.101"]:   # DC, then domain workstation
    print(f"\n=== {ip} ===")
    host = Host(ip=ip)
    transport = WinRMTransport(host.ip, profile)
    results = collect_from_host(host, test_artefacts, transport, audit, out_root="collected")
    transport.close()
    for r in results:
        status = "collected" if r.collected else f"FAILED: {r.error}"
        print(f"  {r.artefact_id:12} {status:20} match={r.hash_match}")