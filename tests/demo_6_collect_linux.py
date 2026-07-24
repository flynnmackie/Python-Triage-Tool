"""Demo 6 - Full Linux artefact collection.

Collects the entire Unix catalogue from one host: volatile commands, plus the
root-owned artefacts (/var/log, root shell history) gathered via sudo -S into
a per-run working directory, then fetched and hash-verified. Demonstrates the
sudo path, archive-then-flatten, and cleanup.

Requires UnixUser to have sudo rights.

Run from the project root:  python tests/demo_6_collect_linux.py
"""

from core.models import Host, OSFamily
from core.audit import AuditLog
from core.artefacts import catalogue_for
from core.collection import collect_from_host, run_timestamp
from transports.ssh_transport import SSHTransport
from tests.demo_config import LINUX_IP, LINUX_PROFILE

run = run_timestamp()
audit = AuditLog("demo_audit.csv")

host = Host(ip=LINUX_IP)
host.actual_os = OSFamily.UNIX             # required: staging path branches on this

transport = SSHTransport(host.ip, LINUX_PROFILE)
print(f"=== LINUX collection  {host.ip}  (run {run}) ===\n")
results = collect_from_host(host, catalogue_for(OSFamily.UNIX),
                            transport, audit, out_root="collected", run_folder=run)
transport.close()

for r in results:
    status = "ok" if r.collected else f"FAILED: {r.error}"
    print(f"  {r.artefact_id:22} {status:55} match={r.hash_match}")

print(f"\nOutput under: collected/{run}/{host.ip}/")
print("Audit trail:  demo_audit.csv")
