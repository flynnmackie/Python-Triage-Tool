"""Module 3 - artefact collection (methodology s3.5.4).

Selection is free-order but DISPATCH is ordered by volatility (NFR3). Each
artefact is hashed at source and on receipt (NFR1); every step is logged (NFR2);
output is written per host (FR6).
"""

from __future__ import annotations

from pathlib import Path

from .audit import AuditLog
from .hashing import sha256_bytes
from .models import Artefact, CollectionResult, Host


def order_by_volatility(artefacts: list[Artefact]) -> list[Artefact]:
    """Most volatile first (order of volatility, RFC 3227 / NFR3)."""
    return sorted(artefacts, key=lambda a: a.volatility, reverse=True)


def _basename(remote_path: str) -> str:
    """Last path component, tolerant of both / and \\ separators."""
    return remote_path.replace("\\", "/").rstrip("/").split("/")[-1] or "artefact"


def collect_from_host(
    host: Host,
    artefacts: list[Artefact],
    transport,           # a Transport instance for this host
    audit: AuditLog,
    out_root: str | Path,
) -> list[CollectionResult]:
    """Collect the selected artefacts from one host, most volatile first."""
    ordered = order_by_volatility(artefacts)
    results: list[CollectionResult] = []

    host_dir = Path(out_root) / host.ip
    host_dir.mkdir(parents=True, exist_ok=True)

    for artefact in ordered:
        result = CollectionResult(host_ip=host.ip, artefact_id=artefact.id)
        try:
            if artefact.is_command:
                # Volatile output generated on the fly - nothing on-disk to
                # hash at source; we hash what we received.
                data = transport.run_command(artefact.spec)
                source_hash = None
                out_name = f"{artefact.id}.txt"
            else:
                # A file: hash it ON the target first (NFR1), then fetch and
                # hash what arrived, so the two can be compared.
                source_hash = transport.remote_hash(artefact.spec)
                data = transport.fetch_file(artefact.spec)
                out_name = f"{artefact.id}_{_basename(artefact.spec)}"

            received_hash = sha256_bytes(data)

            out_path = host_dir / out_name
            out_path.write_bytes(data)

            result.collected = True
            result.source_hash = source_hash
            result.received_hash = received_hash
            result.output_path = str(out_path)

            audit.log(
                host.ip, "collect", artefact=artefact.name,
                source_hash=source_hash or "", received_hash=received_hash,
                outcome="ok",
            )
        except Exception as exc:
            # One artefact failing must not abort the rest of the host.
            result.collected = False
            result.error = str(exc)
            audit.log(
                host.ip, "collect", artefact=artefact.name,
                outcome="error", detail=str(exc),
            )

        results.append(result)

    return results