"""Dedicated JSON serializers and deserializers for Mail DNS Diagnostics."""

from __future__ import annotations

from dataclasses import asdict
from enum import Enum
import json

from smtp_bench_pro.domain.mail_dns import (
    AddressRecord,
    DKIMDiagnosticResult,
    DKIMSelectorResult,
    DKIMStatus,
    DMARCDiagnosticResult,
    DMARCStatus,
    FCRDNSResult,
    FCRDNSStatus,
    MailDNSFinding,
    MailDNSSeverity,
    MailIdentitySummary,
    MailRoutingDiagnosticResult,
    MXDiagnosticResult,
    MXRecord,
    MXStatus,
    PTRDiagnosticResult,
    SPFDiagnosticResult,
    SPFStatus,
    SPFTerm,
)


def _json_default(obj: object) -> object:
    if isinstance(obj, Enum):
        return obj.value
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def serialize_to_json(data: object) -> str:
    return json.dumps(data, default=_json_default, ensure_ascii=False)


# --- ROUTING SERIALIZATION ---


def serialize_routing_result(routing: MailRoutingDiagnosticResult) -> tuple[str, str]:
    """Returns (mx_json, ptr_json)."""
    mx_data = {
        "status": routing.mx_record.status.value,
        "raw_records": list(routing.mx_record.raw_records),
        "records": [
            {
                "preference": r.preference,
                "exchange": r.exchange,
                "is_null_mx": r.is_null_mx,
                "cname_detected": r.cname_detected,
                "addresses_v4": [asdict(a) for a in r.addresses_v4],
                "addresses_v6": [asdict(a) for a in r.addresses_v6],
            }
            for r in routing.mx_record.records
        ],
    }

    ptr_data = {
        "results": [
            {
                "ip": r.ip,
                "ptr_hostnames": list(r.ptr_hostnames),
                "status": r.status.value,
                "forward_ips": list(r.forward_ips),
            }
            for r in routing.ptr_record.results
        ]
    }

    return serialize_to_json(mx_data), serialize_to_json(ptr_data)


def deserialize_routing_result(
    domain: str,
    queried_at: str,
    mx_json: str,
    ptr_json: str,
) -> MailRoutingDiagnosticResult:
    mx_dict = json.loads(mx_json)
    ptr_dict = json.loads(ptr_json)

    mx_records: list[MXRecord] = []
    for r in mx_dict.get("records", []):
        addrs_v4 = tuple(AddressRecord(**a) for a in r.get("addresses_v4", []))
        addrs_v6 = tuple(AddressRecord(**a) for a in r.get("addresses_v6", []))
        mx_records.append(
            MXRecord(
                preference=r["preference"],
                exchange=r["exchange"],
                is_null_mx=r["is_null_mx"],
                addresses_v4=addrs_v4,
                addresses_v6=addrs_v6,
                cname_detected=r.get("cname_detected", False),
            )
        )

    mx_diag = MXDiagnosticResult(
        status=MXStatus(mx_dict["status"]),
        records=tuple(mx_records),
        raw_records=tuple(mx_dict.get("raw_records", [])),
    )

    ptr_results: list[FCRDNSResult] = []
    for p in ptr_dict.get("results", []):
        ptr_results.append(
            FCRDNSResult(
                ip=p["ip"],
                ptr_hostnames=tuple(p.get("ptr_hostnames", [])),
                status=FCRDNSStatus(p["status"]),
                forward_ips=tuple(p.get("forward_ips", [])),
            )
        )

    ptr_diag = PTRDiagnosticResult(results=tuple(ptr_results))

    return MailRoutingDiagnosticResult(
        domain=domain,
        queried_at=queried_at,
        mx_record=mx_diag,
        ptr_record=ptr_diag,
    )


# --- SPF SERIALIZATION ---


def serialize_spf_result(spf: SPFDiagnosticResult) -> str:
    data = {
        "status": spf.status.value,
        "raw_record": spf.raw_record,
        "terms": [asdict(t) for t in spf.terms],
        "dns_lookup_count": spf.dns_lookup_count,
        "void_lookup_count": spf.void_lookup_count,
        "all_qualifier": spf.all_qualifier,
        "uses_ptr_mechanism": spf.uses_ptr_mechanism,
        "validation_error": spf.validation_error,
    }
    return serialize_to_json(data)


def deserialize_spf_result(spf_json: str) -> SPFDiagnosticResult:
    data = json.loads(spf_json)
    terms = tuple(SPFTerm(**t) for t in data.get("terms", []))
    return SPFDiagnosticResult(
        status=SPFStatus(data["status"]),
        raw_record=data.get("raw_record"),
        terms=terms,
        dns_lookup_count=data.get("dns_lookup_count", 0),
        void_lookup_count=data.get("void_lookup_count", 0),
        all_qualifier=data.get("all_qualifier"),
        uses_ptr_mechanism=data.get("uses_ptr_mechanism", False),
        validation_error=data.get("validation_error"),
    )




# --- DKIM SERIALIZATION ---


def serialize_dkim_result(dkim: DKIMDiagnosticResult) -> str:
    data = {
        "domain": dkim.domain,
        "selectors": list(dkim.selectors),
        "checked_at": dkim.checked_at,
        "results": [
            {
                "selector": result.selector,
                "query_name": result.query_name,
                "status": result.status.value,
                "raw_record": result.raw_record,
                "key_type": result.key_type,
                "public_key_present": result.public_key_present,
                "public_key_bits": result.public_key_bits,
                "flags": list(result.flags),
                "services": list(result.services),
                "hash_algorithms": list(result.hash_algorithms),
                "notes": list(result.notes),
                "validation_errors": list(result.validation_errors),
            }
            for result in dkim.results
        ],
    }
    return serialize_to_json(data)


def deserialize_dkim_result(dkim_json: str | dict | None, domain: str = "") -> DKIMDiagnosticResult:
    if not dkim_json:
        return DKIMDiagnosticResult(domain=domain, selectors=(), results=(), checked_at="")
    data = json.loads(dkim_json) if isinstance(dkim_json, str) else dkim_json
    results = []
    for item in data.get("results", []):
        try:
            status = DKIMStatus(item.get("status") or DKIMStatus.ABSENT.value)
        except ValueError:
            status = DKIMStatus.INVALID_SYNTAX
        results.append(
            DKIMSelectorResult(
                selector=str(item.get("selector") or ""),
                query_name=str(item.get("query_name") or ""),
                status=status,
                raw_record=item.get("raw_record"),
                key_type=item.get("key_type"),
                public_key_present=bool(item.get("public_key_present", False)),
                public_key_bits=item.get("public_key_bits"),
                flags=tuple(item.get("flags") or ()),
                services=tuple(item.get("services") or ()),
                hash_algorithms=tuple(item.get("hash_algorithms") or ()),
                notes=tuple(item.get("notes") or ()),
                validation_errors=tuple(item.get("validation_errors") or ()),
            )
        )
    return DKIMDiagnosticResult(
        domain=str(data.get("domain") or domain),
        selectors=tuple(data.get("selectors") or ()),
        results=tuple(results),
        checked_at=str(data.get("checked_at") or ""),
    )


# --- DMARC SERIALIZATION ---


def serialize_dmarc_result(dmarc: DMARCDiagnosticResult) -> str:
    data = {
        "status": dmarc.status.value,
        "raw_record": dmarc.raw_record,
        "policy": dmarc.policy,
        "subdomain_policy": dmarc.subdomain_policy,
        "pct": dmarc.pct,
        "adkim": dmarc.adkim,
        "aspf": dmarc.aspf,
        "rua": list(dmarc.rua),
        "ruf": list(dmarc.ruf),
        "organizational_domain": dmarc.organizational_domain,
        "validation_errors": list(dmarc.validation_errors),
    }
    return serialize_to_json(data)


def deserialize_dmarc_result(dmarc_json: str) -> DMARCDiagnosticResult:
    data = json.loads(dmarc_json)
    return DMARCDiagnosticResult(
        status=DMARCStatus(data["status"]),
        raw_record=data.get("raw_record"),
        policy=data.get("policy"),
        subdomain_policy=data.get("subdomain_policy"),
        pct=data.get("pct", 100),
        adkim=data.get("adkim", "r"),
        aspf=data.get("aspf", "r"),
        rua=tuple(data.get("rua", [])),
        ruf=tuple(data.get("ruf", [])),
        organizational_domain=data.get("organizational_domain", ""),
        validation_errors=tuple(data.get("validation_errors", [])),
    )


# --- IDENTITY SUMMARY SERIALIZATION ---


def serialize_identity_summary(summary: MailIdentitySummary, dkim: DKIMDiagnosticResult | None = None) -> str:
    data = asdict(summary)
    if dkim is None:
        return serialize_to_json(data)
    return serialize_to_json({"summary": data, "dkim": json.loads(serialize_dkim_result(dkim))})


def deserialize_identity_summary(summary_json: str) -> MailIdentitySummary:
    data = json.loads(summary_json)
    if isinstance(data, dict) and "summary" in data:
        data = data.get("summary") or {}
    data.setdefault("dkim_valid_selectors", 0)
    data.setdefault("dkim_total_selectors", 0)
    return MailIdentitySummary(**data)


def deserialize_dkim_from_identity_summary(summary_json: str, domain: str = "") -> DKIMDiagnosticResult:
    data = json.loads(summary_json)
    if isinstance(data, dict) and isinstance(data.get("dkim"), dict):
        return deserialize_dkim_result(data["dkim"], domain=domain)
    return DKIMDiagnosticResult(domain=domain, selectors=(), results=(), checked_at="")


# --- FINDINGS SERIALIZATION ---


def serialize_mail_dns_findings(findings: tuple[MailDNSFinding, ...]) -> str:
    data = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "category": f.category,
            "description": f.description,
            "evidence": f.evidence,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]
    return serialize_to_json(data)


def deserialize_mail_dns_findings(findings_json: str) -> tuple[MailDNSFinding, ...]:
    data = json.loads(findings_json)
    findings: list[MailDNSFinding] = []
    for f in data:
        findings.append(
            MailDNSFinding(
                id=f["id"],
                title=f["title"],
                severity=MailDNSSeverity(f["severity"]),
                category=f["category"],
                description=f["description"],
                evidence=f["evidence"],
                recommendation=f["recommendation"],
            )
        )
    return tuple(findings)
