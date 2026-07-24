"""Windows transport over WinRM / PowerShell Remoting via pypsrp.

Same four-method shape as the SSH transport. Auth mechanism is chosen from the
credential kind; payload encryption is always on (NFR5) even over HTTP:5985,
which is the deliberate lab choice over HTTPS/certificates.
"""

from __future__ import annotations

import base64
import socket

from pypsrp.client import Client

from core.models import AccessState, CredentialProfile, CredKind
from .base import Transport

WINRM_HTTP_PORT = 5985


class WinRMTransport(Transport):
    def __init__(self, host_ip: str, profile: CredentialProfile):
        super().__init__(host_ip, profile)
        self._client: Client | None = None

    def _connect(self) -> Client:
        """Open (once) and return a pypsrp client."""
        if self._client is not None:
            return self._client

        # Both domain (NTLM-from-workgroup) and standalone use 'negotiate' here.
        auth = "negotiate"

        username = self.profile.username
        if self.profile.kind is CredKind.DOMAIN_KERBEROS and self.profile.domain:
            username = f"{self.profile.domain}\\{self.profile.username}"

        self._client = Client(
            self.host_ip,
            username=username,
            password=self.profile.secret,
            auth=auth,
            encryption="always",   # message-level encryption over HTTP (NFR5)
            ssl=False,             # HTTP:5985, not HTTPS
            port=WINRM_HTTP_PORT,
        )
        return self._client

    def test_access(self) -> AccessState:
        # 1. Is the WinRM port open at all?
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            if s.connect_ex((self.host_ip, WINRM_HTTP_PORT)) != 0:
                return AccessState.ABSENT
        # 2. Port open - do the credentials authenticate?
        try:
            client = self._connect()
            client.execute_ps("$env:COMPUTERNAME")   # trivial probe command
        except Exception:
            return AccessState.PRESENT_NO_AUTH
        return AccessState.AUTHENTICATED

    def run_command(self, command: str, use_sudo: bool = False) -> bytes:
        client = self._connect()
        output, _streams, _had_errors = client.execute_ps(command)
        return output.encode("utf-8", errors="replace")

    def fetch_file(self, remote_path: str) -> bytes:
        import tempfile, os
        client = self._connect()
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            client.fetch(remote_path, tmp.name)
            with open(tmp.name, "rb") as f:
                return f.read()
        finally:
            os.unlink(tmp.name)

    def remote_hash(self, remote_path: str) -> str | None:
        client = self._connect()
        ps = f"(Get-FileHash -Algorithm SHA256 '{remote_path}').Hash"
        out, _streams, _had_errors = client.execute_ps(ps)
        out = out.strip().lower()
        return out or None

    def delete_remote(self, remote_path: str) -> None:
        client = self._connect()
        # -Force to remove read-only/hidden; -EA SilentlyContinue so a missing
        # file doesn't raise (cleanup should be quiet).
        ps = f"Remove-Item -LiteralPath '{remote_path}' -Force -ErrorAction SilentlyContinue"
        client.execute_ps(ps)

    def close(self) -> None:
        self._client = None

    def _ps(self, script: str) -> str:
        client = self._connect()
        output, streams, had_errors = client.execute_ps(script)
        if had_errors:
            errs = "; ".join(str(e) for e in streams.error) or "unknown PowerShell error"
            raise RuntimeError(f"PowerShell error: {errs}")
        return output