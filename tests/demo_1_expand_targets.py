"""Demo 1 - Target expansion and input validation.

Shows how a typed target string becomes a list of IPs, and that malformed
input is rejected cleanly rather than crashing. No network needed.

Run from the project root:  python tests/demo_1_expand_targets.py
"""

from core.discovery import expand_targets

print("=== Valid inputs ===")
for spec in ["10.10.10.102", "10.10.10.100-103", "10.10.10.0/30"]:
    print(f"  {spec:20} -> {expand_targets(spec)}")

print("\n=== Invalid inputs (should raise a clean error, not crash) ===")
for spec in ["abc", "10.10.10.999", "10.10.10.10-5", "", "10.10/24"]:
    try:
        expand_targets(spec)
        print(f"  {spec!r:20} -> NO ERROR (unexpected!)")
    except ValueError as exc:
        print(f"  {spec!r:20} -> rejected: {exc}")
