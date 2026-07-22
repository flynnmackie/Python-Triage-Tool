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

from datetime import datetime


def run_timestamp() -> str:
    """One folder name per run: sorts chronologically, no illegal characters."""
    return datetime.now().strftime("%Y-%m-%d-%H%M_%Ss")


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
    run_folder: str,
) -> list[CollectionResult]:
    """Collect the selected artefacts from one host, most volatile first."""
    ordered = order_by_volatility(artefacts)
    results: list[CollectionResult] = []

    host_dir = Path(out_root) / run_folder / host.ip
    host_dir.mkdir(parents=True, exist_ok=True)

    for artefact in ordered:
        result = CollectionResult(host_ip=host.ip, artefact_id=artefact.id)
        prepared_temp = None      # set only if we created a temp file to clean up
        try:
            if artefact.is_command:
                # Volatile output generated on the fly - nothing to hash at source.
                data = transport.run_command(artefact.spec)
                source_hash = None
                out_name = f"{artefact.id}.txt"
            else:
                if artefact.prepare:
                    # Locked file: ask Windows to write an unlocked copy first,
                    # then fetch THAT. spec points at the copy's location.
                    transport.run_command(artefact.prepare)
                    prepared_temp = artefact.spec
                    audit.log(host.ip, "prepare", artefact=artefact.name,
                              outcome="ok", detail=f"created {artefact.spec}")

                # A file (either an unlocked original, or the prepared copy):
                # hash on the target (NFR1), fetch, then compare.
                source_hash = transport.remote_hash(artefact.spec)
                data = transport.fetch_file(artefact.spec)
                out_name = f"{artefact.id}_{_basename(artefact.spec)}"

            received_hash = sha256_bytes(data)

            category_dir = host_dir / artefact.category
            category_dir.mkdir(parents=True, exist_ok=True)
            out_path = category_dir / out_name
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
            result.collected = False
            result.error = str(exc)
            audit.log(
                host.ip, "collect", artefact=artefact.name,
                outcome="error", detail=str(exc),
            )
        finally:
            # Remove any temp file we created - even if the fetch above failed.
            # This is the footprint-minimisation guarantee (NFR4).
            if prepared_temp is not None:
                try:
                    transport.delete_remote(prepared_temp)
                    audit.log(host.ip, "cleanup", artefact=artefact.name,
                              outcome="ok", detail=f"removed {prepared_temp}")
                except Exception as exc:
                    audit.log(host.ip, "cleanup", artefact=artefact.name,
                              outcome="error", detail=str(exc))

        results.append(result)

    return results