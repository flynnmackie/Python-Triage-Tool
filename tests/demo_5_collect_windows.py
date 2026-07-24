"""Demo 5 - Full Windows artefact collection.

Collects the entire Windows catalogue from one host: volatile commands, the
registry hives and event logs (locked -> exported via reg save / wevtutil),
and Prefetch (locked directory -> robocopy + zip -> flattened). Each file is
hash-verified source-to-destination; a per-run working directory is created
and cleaned up; every step is logged.

Run from the project root:  python tests/demo_5_collect_windows.py
"""

from core.models import Host, OSFamily
from core.audit import AuditLog
from core.artefacts import catalogue_for
from core.collection import collect_from_host, run_timestamp
from transports.winrm_transport import WinRMTransport
from tests.demo_config import WIN_STANDALONE_IP, WIN_STANDALONE_PROFILE

run = run_timestamp()
audit = AuditLog("demo_audit.csv")

host = Host(ip=WIN_STANDALONE_IP)
host.actual_os = OSFamily.WINDOWS          # required: staging path branches on this

transport = WinRMTransport(host.ip, WIN_STANDALONE_PROFILE)
print(f"=== WINDOWS collection  {host.ip}  (run {run}) ===\n")
results = collect_from_host(host, catalogue_for(OSFamily.WINDOWS),
                            transport, audit, out_root="collected", run_folder=run)
transport.close()

for r in results:
    status = "ok" if r.collected else f"FAILED: {r.error}"
    print(f"  {r.artefact_id:22} {status:55} match={r.hash_match}")

print(f"\nOutput under: collected/{run}/{host.ip}/")
print("Audit trail:  demo_audit.csv")
