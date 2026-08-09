"""DNS Resolver and Mail Routing Diagnostics engine for SMTP Bench Pro 0.3.0."""

from __future__ import annotations

from datetime import UTC, datetime
import ipaddress
import logging
from typing import Protocol

import dns.exception
import dns.name
import dns.rcode
import dns.resolver
import dns.reversename

from smtp_bench_pro.domain.mail_dns import (
    AddressRecord,
    DNSQueryResult,
    DNSQueryStatus,
    FCRDNSResult,
    FCRDNSStatus,
    MailDomainTarget,
    MailRoutingDiagnosticResult,
    MXDiagnosticResult,
    MXRecord,
    MXStatus,
    PTRDiagnosticResult,
)

logger = logging.getLogger("smtp_bench_pro.mail_dns")


class IMailDNSResolver(Protocol):
    """Protocol contract for Mail DNS Resolver, enabling Fake DNS Resolvers in tests."""

    def resolve_mx(self, domain: str) -> DNSQueryResult: ...
    def resolve_a(self, hostname: str) -> DNSQueryResult: ...
    def resolve_aaaa(self, hostname: str) -> DNSQueryResult: ...
    def resolve_ptr(self, ip_address: str) -> DNSQueryResult: ...
    def resolve_txt(self, name: str) -> DNSQueryResult: ...
    def detect_cname(self, hostname: str) -> bool: ...


class MailDNSResolver:
    """Production DNS Resolver using dnspython."""

    def __init__(self, timeout: float = 3.0, custom_nameserver: str | None = None) -> None:
        self.timeout = timeout
        self.custom_nameserver = custom_nameserver
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

        if custom_nameserver:
            # Validate IP of custom nameserver
            try:
                ipaddress.ip_address(custom_nameserver)
                self._resolver.nameservers = [custom_nameserver]
            except ValueError as exc:
                raise ValueError(f"Invalid custom nameserver IP '{custom_nameserver}': {exc}") from exc

    def _query(self, qname: str, rdatatype: str) -> DNSQueryResult:
        now_utc = datetime.now(UTC).isoformat()
        try:
            answer = self._resolver.resolve(qname, rdatatype)
            answers = tuple(str(rdata) for rdata in answer)
            return DNSQueryResult(
                name=qname,
                record_type=rdatatype,
                status=DNSQueryStatus.SUCCESS,
                answers=answers,
                queried_at=now_utc,
            )
        except dns.resolver.NXDOMAIN as exc:
            return DNSQueryResult(
                name=qname,
                record_type=rdatatype,
                status=DNSQueryStatus.NXDOMAIN,
                error_type="NXDOMAIN",
                error_message=str(exc),
                queried_at=now_utc,
            )
        except dns.resolver.NoAnswer as exc:
            return DNSQueryResult(
                name=qname,
                record_type=rdatatype,
                status=DNSQueryStatus.NO_ANSWER,
                error_type="NoAnswer",
                error_message=str(exc),
                queried_at=now_utc,
            )
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as exc:
            return DNSQueryResult(
                name=qname,
                record_type=rdatatype,
                status=DNSQueryStatus.TIMEOUT,
                error_type="Timeout",
                error_message=str(exc),
                queried_at=now_utc,
            )
        except dns.resolver.NoNameservers as exc:
            return DNSQueryResult(
                name=qname,
                record_type=rdatatype,
                status=DNSQueryStatus.SERVFAIL,
                error_type="SERVFAIL",
                error_message=str(exc),
                queried_at=now_utc,
            )
        except Exception as exc:
            err_msg = str(exc)
            status = DNSQueryStatus.ERROR
            if "REFUSED" in err_msg.upper():
                status = DNSQueryStatus.REFUSED
            elif "SERVFAIL" in err_msg.upper():
                status = DNSQueryStatus.SERVFAIL

            return DNSQueryResult(
                name=qname,
                record_type=rdatatype,
                status=status,
                error_type=type(exc).__name__,
                error_message=err_msg,
                queried_at=now_utc,
            )

    def resolve_mx(self, domain: str) -> DNSQueryResult:
        return self._query(domain, "MX")

    def resolve_a(self, hostname: str) -> DNSQueryResult:
        return self._query(hostname, "A")

    def resolve_aaaa(self, hostname: str) -> DNSQueryResult:
        return self._query(hostname, "AAAA")

    def resolve_ptr(self, ip_address: str) -> DNSQueryResult:
        try:
            rev_name = dns.reversename.from_address(ip_address).to_text()
        except Exception as exc:
            return DNSQueryResult(
                name=ip_address,
                record_type="PTR",
                status=DNSQueryStatus.ERROR,
                error_type=type(exc).__name__,
                error_message=str(exc),
                queried_at=datetime.now(UTC).isoformat(),
            )
        return self._query(rev_name, "PTR")

    def resolve_txt(self, name: str) -> DNSQueryResult:
        return self._query(name, "TXT")

    def detect_cname(self, hostname: str) -> bool:
        """Detects if a hostname is a CNAME alias."""
        try:
            result = self._query(hostname, "CNAME")
            return result.status == DNSQueryStatus.SUCCESS and len(result.answers) > 0
        except Exception:
            return False


def parse_mx_answers(mx_query: DNSQueryResult) -> tuple[MXRecord, ...]:
    """Parses raw MX answers into a tuple of MXRecord objects."""
    records: list[MXRecord] = []
    if mx_query.status != DNSQueryStatus.SUCCESS or not mx_query.answers:
        return ()

    for ans in mx_query.answers:
        parts = ans.strip().split(maxsplit=1)
        if len(parts) == 2:
            try:
                pref = int(parts[0])
                raw_exch = parts[1].strip()
                if raw_exch == ".":
                    records.append(MXRecord(preference=pref, exchange=".", is_null_mx=True))
                else:
                    exch = raw_exch.rstrip(".").lower()
                    is_null = (pref == 0 and not exch) or exch == "."
                    records.append(MXRecord(preference=pref, exchange=exch, is_null_mx=is_null))
            except ValueError:
                continue
        elif len(parts) == 1:
            raw_exch = parts[0].strip()
            if raw_exch == ".":
                records.append(MXRecord(preference=0, exchange=".", is_null_mx=True))
            else:
                exch = raw_exch.rstrip(".").lower()
                is_null = not exch or exch == "."
                records.append(MXRecord(preference=0, exchange=exch, is_null_mx=is_null))

    records.sort(key=lambda r: (r.preference, r.exchange))
    return tuple(records)


def is_ip_private_or_reserved(ip_str: str) -> bool:
    """Checks if an IP address is private, loopback, link-local, or unspecified."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return bool(
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
        )
    except ValueError:
        return False


class MailRoutingDiagnosticsService:
    """Orchestrates Mail Routing Diagnostics (MX, A/AAAA, PTR, FCRDNS)."""

    def __init__(self, resolver: IMailDNSResolver) -> None:
        self.resolver = resolver

    def diagnose(self, target: MailDomainTarget) -> MailRoutingDiagnosticResult:
        now_utc = datetime.now(UTC).isoformat()
        domain = target.domain

        # 1. Resolve MX
        mx_query = self.resolver.resolve_mx(domain)
        parsed_records = parse_mx_answers(mx_query)

        # Check for Null MX
        has_null_mx = any(r.is_null_mx for r in parsed_records)
        if has_null_mx:
            null_mx_record = MXRecord(preference=0, exchange=".", is_null_mx=True)
            mx_diag = MXDiagnosticResult(
                status=MXStatus.NULL_MX,
                records=(null_mx_record,),
                raw_records=mx_query.answers,
            )
            ptr_diag = PTRDiagnosticResult(results=())
            return MailRoutingDiagnosticResult(
                domain=domain,
                queried_at=now_utc,
                mx_record=mx_diag,
                ptr_record=ptr_diag,
            )

        if not parsed_records:
            mx_diag = MXDiagnosticResult(
                status=MXStatus.NO_MX,
                records=(),
                raw_records=mx_query.answers,
            )
            ptr_diag = PTRDiagnosticResult(results=())
            return MailRoutingDiagnosticResult(
                domain=domain,
                queried_at=now_utc,
                mx_record=mx_diag,
                ptr_record=ptr_diag,
            )

        mx_status = MXStatus.SINGLE_MX if len(parsed_records) == 1 else MXStatus.MULTIPLE_MX

        # 2. For each MX record, resolve A and AAAA, and detect CNAME
        resolved_mx_records: list[MXRecord] = []
        all_ips: list[str] = []

        for r in parsed_records:
            cname = self.resolver.detect_cname(r.exchange)
            addrs_v4: list[AddressRecord] = []
            addrs_v6: list[AddressRecord] = []

            # A query
            a_query = self.resolver.resolve_a(r.exchange)
            if a_query.status == DNSQueryStatus.SUCCESS:
                for ip in a_query.answers:
                    try:
                        ipaddress.IPv4Address(ip)
                        addrs_v4.append(AddressRecord(ip=ip, family="IPv4"))
                        all_ips.append(ip)
                    except ValueError:
                        pass

            # AAAA query
            aaaa_query = self.resolver.resolve_aaaa(r.exchange)
            if aaaa_query.status == DNSQueryStatus.SUCCESS:
                for ip in aaaa_query.answers:
                    try:
                        ipaddress.IPv6Address(ip)
                        addrs_v6.append(AddressRecord(ip=ip, family="IPv6"))
                        all_ips.append(ip)
                    except ValueError:
                        pass

            resolved_mx_records.append(
                MXRecord(
                    preference=r.preference,
                    exchange=r.exchange,
                    is_null_mx=False,
                    addresses_v4=tuple(sorted(addrs_v4, key=lambda a: a.ip)),
                    addresses_v6=tuple(sorted(addrs_v6, key=lambda a: a.ip)),
                    cname_detected=cname,
                )
            )

        mx_diag = MXDiagnosticResult(
            status=mx_status,
            records=tuple(resolved_mx_records),
            raw_records=mx_query.answers,
        )

        # 3. PTR and FCRDNS for collected unique IPs
        unique_ips = sorted(set(all_ips))
        ptr_results: list[FCRDNSResult] = []

        for ip in unique_ips:
            if is_ip_private_or_reserved(ip):
                ptr_results.append(
                    FCRDNSResult(
                        ip=ip,
                        ptr_hostnames=(),
                        status=FCRDNSStatus.NOT_APPLICABLE,
                        forward_ips=(),
                    )
                )
                continue

            ptr_query = self.resolver.resolve_ptr(ip)
            if ptr_query.status != DNSQueryStatus.SUCCESS or not ptr_query.answers:
                ptr_results.append(
                    FCRDNSResult(
                        ip=ip,
                        ptr_hostnames=(),
                        status=FCRDNSStatus.NO_PTR,
                        forward_ips=(),
                    )
                )
                continue

            # Normalize PTR hostnames
            ptrs = tuple(sorted(ans.rstrip(".").lower() for ans in ptr_query.answers))

            # Resolve forward A/AAAA for each PTR hostname
            fwd_ips_set: set[str] = set()
            for ptr_host in ptrs:
                fwd_a = self.resolver.resolve_a(ptr_host)
                if fwd_a.status == DNSQueryStatus.SUCCESS:
                    fwd_ips_set.update(fwd_a.answers)

                fwd_aaaa = self.resolver.resolve_aaaa(ptr_host)
                if fwd_aaaa.status == DNSQueryStatus.SUCCESS:
                    fwd_ips_set.update(fwd_aaaa.answers)

            forward_ips = tuple(sorted(fwd_ips_set))
            is_match = ip in fwd_ips_set

            if is_match:
                fcrdns_status = FCRDNSStatus.MATCH
            elif len(ptrs) > 1 and not is_match:
                fcrdns_status = FCRDNSStatus.MULTIPLE_PTR
            else:
                fcrdns_status = FCRDNSStatus.MISMATCH

            ptr_results.append(
                FCRDNSResult(
                    ip=ip,
                    ptr_hostnames=ptrs,
                    status=fcrdns_status,
                    forward_ips=forward_ips,
                )
            )

        ptr_diag = PTRDiagnosticResult(results=tuple(ptr_results))

        return MailRoutingDiagnosticResult(
            domain=domain,
            queried_at=now_utc,
            mx_record=mx_diag,
            ptr_record=ptr_diag,
        )
