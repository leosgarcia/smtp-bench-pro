"""SMTP probing engine using standard library socket and ssl."""

from __future__ import annotations

from contextlib import suppress
import logging
import socket
import ssl
import time

from smtp_bench_pro.domain.diagnostic_options import (
    CommandDiagnosticResult,
    CommandDiagnosticStatus,
    DiagnosticsOptions,
)
from smtp_bench_pro.domain.enums import ProbeStatus, SecurityMode
from smtp_bench_pro.domain.models import SMTPServerTarget
from smtp_bench_pro.domain.results import SMTPProbeResult
from smtp_bench_pro.engine.capabilities import auth_mechanisms, parse_ehlo_capabilities, supports_starttls
from smtp_bench_pro.engine.tls_probe import inspect_tls_socket
from smtp_bench_pro.logging_config import sanitize_log_message

logger = logging.getLogger(__name__)
COMMAND_TEMPLATES = {
    "NOOP": "NOOP",
    "HELP": "HELP",
    "VRFY": "VRFY postmaster",
    "EXPN": "EXPN postmaster",
}


class SMTPProbe:
    """Executes one SMTP/ESMTP probe for a target without sending mail or authenticating."""

    def __init__(self, context_factory=ssl.create_default_context):
        self._context_factory = context_factory

    def run(
        self, target: SMTPServerTarget, diagnostics_options: DiagnosticsOptions | None = None
    ) -> SMTPProbeResult:
        options = diagnostics_options or DiagnosticsOptions()
        start_total = time.perf_counter()
        resolved_ip = self._resolve_ip(target.hostname)
        if resolved_ip is None:
            return self._failure(target, None, ProbeStatus.DNS_ERROR, "DNS_ERROR", "Failed to resolve hostname")

        sock: socket.socket | ssl.SSLSocket | None = None
        try:
            tcp_start = time.perf_counter()
            raw_sock = socket.create_connection((target.hostname, target.port), timeout=target.timeout)
            tcp_ms = self._elapsed_ms(tcp_start)
            raw_sock.settimeout(target.timeout)
            sock = raw_sock

            tls_ms = None
            tls_information = None
            if target.security_mode == SecurityMode.SMTPS:
                tls_start = time.perf_counter()
                sock = self._context_factory().wrap_socket(raw_sock, server_hostname=target.hostname)
                tls_ms = self._elapsed_ms(tls_start)
                tls_information = inspect_tls_socket(sock)

            banner_start = time.perf_counter()
            banner = self._read_response(sock)[0]
            banner_ms = self._elapsed_ms(banner_start)

            ehlo_ms, ehlo_lines = self._send_ehlo(sock, target.hostname)
            capabilities_before_tls = parse_ehlo_capabilities(ehlo_lines)
            capabilities_after_tls: dict[str, list[str]] = {}
            command_responses: dict[str, str] = {}
            command_results: list[CommandDiagnosticResult] = []
            starttls_ms = None

            if target.security_mode == SecurityMode.STARTTLS:
                if not supports_starttls(capabilities_before_tls):
                    return SMTPProbeResult(
                        hostname=target.hostname,
                        resolved_ip=resolved_ip,
                        port=target.port,
                        security_mode=target.security_mode,
                        success=False,
                        status=ProbeStatus.STARTTLS_NOT_SUPPORTED,
                        error_type="STARTTLS_NOT_SUPPORTED",
                        error_message="STARTTLS was not advertised by the server",
                        tcp_connect_ms=tcp_ms,
                        banner_ms=banner_ms,
                        ehlo_ms=ehlo_ms,
                        total_ms=self._elapsed_ms(start_total),
                        banner=banner,
                        ehlo_hostname=target.hostname,
                        capabilities=capabilities_before_tls,
                        capabilities_before_tls=capabilities_before_tls,
                        auth_mechanisms_before_tls=auth_mechanisms(capabilities_before_tls),
                        diagnostics_options=options,
                    )
                starttls_start = time.perf_counter()
                self._send_command(sock, "STARTTLS")
                starttls_response, _ = self._read_response(sock)
                starttls_ms = self._elapsed_ms(starttls_start)
                if not starttls_response.startswith("220"):
                    return self._failure(
                        target,
                        resolved_ip,
                        ProbeStatus.PROTOCOL_ERROR,
                        "PROTOCOL_ERROR",
                        f"Unexpected STARTTLS response: {starttls_response}",
                        total_start=start_total,
                    )
                tls_start = time.perf_counter()
                try:
                    sock = self._context_factory().wrap_socket(sock, server_hostname=target.hostname)
                except ssl.SSLCertVerificationError as exc:
                    return self._starttls_failure_result(
                        target,
                        resolved_ip,
                        ProbeStatus.CERTIFICATE_ERROR,
                        "CERTIFICATE_ERROR",
                        str(exc),
                        start_total,
                        tcp_ms,
                        banner_ms,
                        ehlo_ms,
                        starttls_ms,
                        banner,
                        capabilities_before_tls,
                        options,
                    )
                except ssl.SSLError as exc:
                    return self._starttls_failure_result(
                        target,
                        resolved_ip,
                        ProbeStatus.TLS_ERROR,
                        "TLS_ERROR",
                        str(exc),
                        start_total,
                        tcp_ms,
                        banner_ms,
                        ehlo_ms,
                        starttls_ms,
                        banner,
                        capabilities_before_tls,
                        options,
                    )
                tls_ms = self._elapsed_ms(tls_start)
                tls_information = inspect_tls_socket(sock)
                ehlo_ms, ehlo_lines = self._send_ehlo(sock, target.hostname)
                capabilities_after_tls = parse_ehlo_capabilities(ehlo_lines)

            active_capabilities = capabilities_after_tls or capabilities_before_tls
            command_results = self._run_command_diagnostics(sock, options)
            command_responses = {
                result.command: result.response_message
                for result in command_results
                if result.executed and result.response_message
            }
            self._quit(sock)
            return SMTPProbeResult(
                hostname=target.hostname,
                resolved_ip=resolved_ip,
                port=target.port,
                security_mode=target.security_mode,
                success=True,
                status=ProbeStatus.SUCCESS,
                tcp_connect_ms=tcp_ms,
                banner_ms=banner_ms,
                ehlo_ms=ehlo_ms,
                starttls_ms=starttls_ms,
                tls_handshake_ms=tls_ms,
                total_ms=self._elapsed_ms(start_total),
                banner=banner,
                ehlo_hostname=target.hostname,
                capabilities=active_capabilities,
                capabilities_before_tls=capabilities_before_tls,
                capabilities_after_tls=capabilities_after_tls,
                auth_mechanisms_before_tls=auth_mechanisms(capabilities_before_tls),
                auth_mechanisms_after_tls=auth_mechanisms(capabilities_after_tls),
                command_responses=command_responses,
                command_diagnostic_results=command_results,
                diagnostics_options=options,
                tls_information=tls_information,
            )
        except TimeoutError as exc:
            return self._failure(target, resolved_ip, ProbeStatus.TIMEOUT, "TIMEOUT", str(exc), start_total)
        except ConnectionRefusedError as exc:
            return self._failure(
                target, resolved_ip, ProbeStatus.CONNECTION_REFUSED, "CONNECTION_REFUSED", str(exc), start_total
            )
        except ssl.SSLCertVerificationError as exc:
            return self._failure(
                target, resolved_ip, ProbeStatus.CERTIFICATE_ERROR, "CERTIFICATE_ERROR", str(exc), start_total
            )
        except ssl.SSLError as exc:
            return self._failure(target, resolved_ip, ProbeStatus.TLS_ERROR, "TLS_ERROR", str(exc), start_total)
        except OSError as exc:
            return self._failure(target, resolved_ip, ProbeStatus.UNKNOWN_ERROR, "UNKNOWN_ERROR", str(exc), start_total)
        except Exception as exc:
            logger.exception("Unexpected SMTP probe failure for %s:%s", target.hostname, target.port)
            return self._failure(target, resolved_ip, ProbeStatus.UNKNOWN_ERROR, "UNKNOWN_ERROR", str(exc), start_total)
        finally:
            if sock is not None:
                with suppress(OSError):
                    sock.close()

    def _resolve_ip(self, hostname: str) -> str | None:
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def _send_ehlo(self, sock: socket.socket | ssl.SSLSocket, hostname: str) -> tuple[float, list[str]]:
        start = time.perf_counter()
        self._send_command(sock, f"EHLO {hostname}")
        _first, lines = self._read_response(sock)
        return self._elapsed_ms(start), lines

    def _run_command_diagnostics(
        self, sock: socket.socket | ssl.SSLSocket, options: DiagnosticsOptions
    ) -> list[CommandDiagnosticResult]:
        allowed = {command.split()[0] for command in options.allowed_commands()}
        results: list[CommandDiagnosticResult] = []
        for key, command in COMMAND_TEMPLATES.items():
            if key not in allowed:
                results.append(
                    CommandDiagnosticResult(
                        command=key,
                        executed=False,
                        status=CommandDiagnosticStatus.NOT_TESTED,
                        reason=f"Disabled by {options.profile.value.upper()} diagnostics profile",
                    )
                )
                continue
            try:
                self._send_command(sock, command)
                response, _ = self._read_response(sock)
                response = sanitize_log_message(response)
                response_code = response[:3] if len(response) >= 3 and response[:3].isdigit() else None
                supported, status = self._classify_command_response(key, response_code)
                results.append(
                    CommandDiagnosticResult(
                        command=key,
                        executed=True,
                        supported=supported,
                        response_code=response_code,
                        response_message=response,
                        status=status,
                    )
                )
            except OSError as exc:
                logger.info("SMTP command diagnostic failed for %s: %s", key, sanitize_log_message(exc))
                results.append(
                    CommandDiagnosticResult(
                        command=key,
                        executed=True,
                        supported=None,
                        response_message=f"ERROR {sanitize_log_message(exc)}",
                        status=CommandDiagnosticStatus.UNKNOWN,
                        reason="Command diagnostic failed during transport",
                    )
                )
        return results

    def _classify_command_response(
        self, command: str, response_code: str | None
    ) -> tuple[bool | None, CommandDiagnosticStatus]:
        if response_code is None:
            return None, CommandDiagnosticStatus.UNKNOWN
        if command in {"VRFY", "EXPN"}:
            if response_code in {"250", "251", "252"}:
                return True, CommandDiagnosticStatus.ENABLED
            if response_code.startswith(("5", "4")):
                return False, CommandDiagnosticStatus.DISABLED
            return None, CommandDiagnosticStatus.UNKNOWN
        if command in {"NOOP", "HELP"}:
            if response_code.startswith("2"):
                return True, CommandDiagnosticStatus.ENABLED
            if response_code.startswith(("5", "4")):
                return False, CommandDiagnosticStatus.DISABLED
        return None, CommandDiagnosticStatus.UNKNOWN

    def _send_command(self, sock: socket.socket | ssl.SSLSocket, command: str) -> None:
        sock.sendall((command + "\r\n").encode("ascii"))

    def _read_line(self, sock: socket.socket | ssl.SSLSocket) -> str:
        chunks: list[bytes] = []
        while True:
            char = sock.recv(1)
            if not char:
                break
            chunks.append(char)
            if char == b"\n":
                break
        return b"".join(chunks).decode("utf-8", errors="replace").strip()

    def _read_response(self, sock: socket.socket | ssl.SSLSocket) -> tuple[str, list[str]]:
        lines: list[str] = []
        while True:
            line = self._read_line(sock)
            if not line:
                break
            lines.append(line)
            if len(line) < 4 or line[3] == " ":
                break
        first = lines[0] if lines else ""
        return first, lines

    def _quit(self, sock: socket.socket | ssl.SSLSocket) -> None:
        with suppress(OSError):
            self._send_command(sock, "QUIT")

    def _starttls_failure_result(
        self,
        target: SMTPServerTarget,
        resolved_ip: str | None,
        status: ProbeStatus,
        error_type: str,
        error_message: str,
        total_start: float,
        tcp_ms: float,
        banner_ms: float,
        ehlo_ms: float,
        starttls_ms: float | None,
        banner: str | None,
        capabilities_before_tls: dict[str, list[str]],
        diagnostics_options: DiagnosticsOptions,
    ) -> SMTPProbeResult:
        return SMTPProbeResult(
            hostname=target.hostname,
            resolved_ip=resolved_ip,
            port=target.port,
            security_mode=target.security_mode,
            success=False,
            status=status,
            error_type=error_type,
            error_message=sanitize_log_message(error_message),
            tcp_connect_ms=tcp_ms,
            banner_ms=banner_ms,
            ehlo_ms=ehlo_ms,
            starttls_ms=starttls_ms,
            total_ms=self._elapsed_ms(total_start),
            banner=banner,
            ehlo_hostname=target.hostname,
            capabilities=capabilities_before_tls,
            capabilities_before_tls=capabilities_before_tls,
            auth_mechanisms_before_tls=auth_mechanisms(capabilities_before_tls),
            diagnostics_options=diagnostics_options,
        )

    def _failure(
        self,
        target: SMTPServerTarget,
        resolved_ip: str | None,
        status: ProbeStatus,
        error_type: str,
        error_message: str,
        total_start: float | None = None,
    ) -> SMTPProbeResult:
        return SMTPProbeResult(
            hostname=target.hostname,
            resolved_ip=resolved_ip,
            port=target.port,
            security_mode=target.security_mode,
            success=False,
            status=status,
            error_type=error_type,
            error_message=sanitize_log_message(error_message),
            total_ms=self._elapsed_ms(total_start) if total_start is not None else None,
        )

    def _elapsed_ms(self, start: float) -> float:
        return round((time.perf_counter() - start) * 1000.0, 2)
