"""Demo 2 - Host discovery and OS fingerprinting.

Scans a range and shows, for each live host, the liveness result, the OS
guess, the confidence, and the evidence the guess was based on (TTL + ports).
Demonstrates the heuristic-with-confidence fingerprinting.

Run from the project root:  python tests/demo_2_discovery.py
"""

from core.discovery import expand_targets, discover
from tests.demo_config import SCAN_RANGE

print(f"=== Discovery scan of {SCAN_RANGE} ===\n")
ips = expand_targets(SCAN_RANGE)
hosts = discover(ips)

live = [h for h in hosts if h.is_up]
print(f"{len(live)} host(s) up of {len(ips)} scanned:\n")
print(f"  {'Host':16} {'OS guess':10} {'Confidence':11} Basis")
print(f"  {'-'*16} {'-'*10} {'-'*11} {'-'*30}")
for h in live:
    print(f"  {h.ip:16} {h.os_guess.value:10} {h.confidence:11} {h.fingerprint_basis}")
