import socket
import ssl


from smtp_bench_pro.domain.diagnostic_options import DiagnosticsOptions, DiagnosticsProfile
from smtp_bench_pro.domain.enums import ProbeStatus, SecurityMode
from smtp_bench_pro.domain.models import SMTPServerTarget
from smtp_bench_pro.engine.smtp_probe import SMTPProbe


class FakeSocket:
    def __init__(self, responses: list[str]):
        self.buffer = "".join(responses).encode("utf-8")
        self.commands: list[str] = []
        self.closed = False

    def recv(self, size: int) -> bytes:
        if not self.buffer:
            return b""
        chunk = self.buffer[:size]
        self.buffer = self.buffer[size:]
        return chunk

    def sendall(self, payload: bytes) -> None:
        self.commands.append(payload.decode("ascii").strip())

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def close(self) -> None:
        self.closed = True

    def version(self) -> str:
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def getpeercert(self):
        return {
            "subject": ((('commonName', 'mail.example.com'),),),
            "issuer": ((('commonName', 'Example CA'),),),
            "notAfter": "Jan 01 00:00:00 2030 GMT",
            "subjectAltName": (("DNS", "mail.example.com"),),
        }


class FakeContext:
    def wrap_socket(self, sock, server_hostname: str):
        sock.server_hostname = server_hostname
        return sock


def fake_context_factory() -> FakeContext:
    return FakeContext()


def patch_network(monkeypatch, fake_socket: FakeSocket) -> None:
    monkeypatch.setattr(socket, "gethostbyname", lambda hostname: "192.0.2.1")
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: fake_socket)


def test_plain_probe_captures_banner_and_ehlo(monkeypatch) -> None:
    fake_socket = FakeSocket([
        "220 mail.example.com ESMTP\r\n",
        "250-mail.example.com\r\n250-PIPELINING\r\n250 SIZE 1024\r\n",
    ])
    patch_network(monkeypatch, fake_socket)
    target = SMTPServerTarget("mail.example.com", 25, SecurityMode.PLAIN)

    result = SMTPProbe(context_factory=fake_context_factory).run(target)

    assert result.success
    assert result.status == ProbeStatus.SUCCESS
    assert result.banner == "220 mail.example.com ESMTP"
    assert "PIPELINING" in result.capabilities
    assert fake_socket.commands == ["EHLO mail.example.com", "NOOP", "QUIT"]
    assert result.command_diagnostic_results[0].command == "NOOP"
    assert result.command_diagnostic_results[0].executed is True
    assert {item.command: item.executed for item in result.command_diagnostic_results}["VRFY"] is False


def test_starttls_probe_wraps_socket_and_recaptures_ehlo(monkeypatch) -> None:
    fake_socket = FakeSocket([
        "220 mail.example.com ESMTP\r\n",
        "250-mail.example.com\r\n250 STARTTLS\r\n",
        "220 Ready to start TLS\r\n",
        "250-mail.example.com\r\n250 AUTH LOGIN PLAIN\r\n",
    ])
    patch_network(monkeypatch, fake_socket)
    target = SMTPServerTarget("mail.example.com", 587, SecurityMode.STARTTLS)

    result = SMTPProbe(context_factory=fake_context_factory).run(target)

    assert result.success
    assert result.tls_information is not None
    assert result.tls_information.tls_version == "TLSv1.3"
    assert result.capabilities_before_tls == {"MAIL.EXAMPLE.COM": [], "STARTTLS": []}
    assert result.capabilities_after_tls["AUTH"] == ["LOGIN", "PLAIN"]
    assert result.auth_mechanisms_after_tls == ["LOGIN", "PLAIN"]
    assert "STARTTLS" in fake_socket.commands


def test_starttls_not_supported(monkeypatch) -> None:
    fake_socket = FakeSocket([
        "220 mail.example.com ESMTP\r\n",
        "250-mail.example.com\r\n250 PIPELINING\r\n",
    ])
    patch_network(monkeypatch, fake_socket)
    target = SMTPServerTarget("mail.example.com", 587, SecurityMode.STARTTLS)

    result = SMTPProbe(context_factory=fake_context_factory).run(target)

    assert not result.success
    assert result.status == ProbeStatus.STARTTLS_NOT_SUPPORTED


def test_smtps_probe_captures_tls(monkeypatch) -> None:
    fake_socket = FakeSocket([
        "220 mail.example.com ESMTP\r\n",
        "250-mail.example.com\r\n250 SIZE 1024\r\n",
    ])
    patch_network(monkeypatch, fake_socket)
    target = SMTPServerTarget("mail.example.com", 465, SecurityMode.SMTPS)

    result = SMTPProbe(context_factory=fake_context_factory).run(target)

    assert result.success
    assert result.tls_information is not None
    assert result.tls_handshake_ms is not None


def test_timeout_failure(monkeypatch) -> None:
    monkeypatch.setattr(socket, "gethostbyname", lambda hostname: "192.0.2.1")
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda address, timeout: (_ for _ in ()).throw(TimeoutError("timed out")),
    )
    target = SMTPServerTarget("mail.example.com", 25, SecurityMode.PLAIN)

    result = SMTPProbe().run(target)

    assert result.status == ProbeStatus.TIMEOUT


def test_certificate_failure(monkeypatch) -> None:
    class BadContext:
        def wrap_socket(self, sock, server_hostname: str):
            raise ssl.SSLCertVerificationError("certificate verify failed")

    fake_socket = FakeSocket([])
    patch_network(monkeypatch, fake_socket)
    target = SMTPServerTarget("mail.example.com", 465, SecurityMode.SMTPS)

    result = SMTPProbe(context_factory=lambda: BadContext()).run(target)

    assert result.status == ProbeStatus.CERTIFICATE_ERROR



def test_extended_profile_executes_optional_commands(monkeypatch) -> None:
    fake_socket = FakeSocket([
        "220 mail.example.com ESMTP\r\n",
        "250-mail.example.com\r\n250 SIZE 1024\r\n",
        "250 OK\r\n",
        "214 Help\r\n",
        "252 Cannot VRFY user\r\n",
        "502 Disabled\r\n",
    ])
    patch_network(monkeypatch, fake_socket)
    target = SMTPServerTarget("mail.example.com", 25, SecurityMode.PLAIN)

    result = SMTPProbe(context_factory=fake_context_factory).run(
        target, diagnostics_options=DiagnosticsOptions.from_profile(DiagnosticsProfile.EXTENDED)
    )

    assert fake_socket.commands == [
        "EHLO mail.example.com",
        "NOOP",
        "HELP",
        "VRFY postmaster",
        "EXPN postmaster",
        "QUIT",
    ]
    assert {item.command: item.executed for item in result.command_diagnostic_results} == {
        "NOOP": True,
        "HELP": True,
        "VRFY": True,
        "EXPN": True,
    }


def test_manual_profile_respects_flags(monkeypatch) -> None:
    fake_socket = FakeSocket([
        "220 mail.example.com ESMTP\r\n",
        "250-mail.example.com\r\n250 SIZE 1024\r\n",
        "214 Help\r\n",
    ])
    patch_network(monkeypatch, fake_socket)
    target = SMTPServerTarget("mail.example.com", 25, SecurityMode.PLAIN)
    options = DiagnosticsOptions(profile=DiagnosticsProfile.MANUAL, test_noop=False, test_help=True)

    result = SMTPProbe(context_factory=fake_context_factory).run(target, diagnostics_options=options)

    assert fake_socket.commands == ["EHLO mail.example.com", "HELP", "QUIT"]
    results = {item.command: item for item in result.command_diagnostic_results}
    assert results["NOOP"].executed is False
    assert results["HELP"].executed is True
    assert results["VRFY"].executed is False
    assert results["EXPN"].executed is False
