"""Formal SPF record parser according to RFC 7208."""

from __future__ import annotations

import ipaddress

from smtp_bench_pro.domain.mail_dns import SPFTerm

# Qualifiers RFC 7208 §4.1
_QUALIFIERS = {"+", "-", "~", "?"}
_PREFIX_LOOKUPS = (
    "ip4:",
    "ip6:",
    "a:",
    "mx:",
    "ptr:",
    "include:",
    "exists:",
    "exp:",
    "redirect:",
)


def parse_spf_record(raw_record: str) -> tuple[tuple[SPFTerm, ...], str | None]:
    """Parses a raw SPF record string into a tuple of SPFTerm objects.

    Returns:
        (terms, validation_error)
        If validation_error is not None, syntax is invalid according to RFC 7208.
    """
    cleaned = raw_record.strip()
    tokens = cleaned.split()

    if not tokens or tokens[0].lower() != "v=spf1":
        return (), "Record does not start with 'v=spf1'."

    terms: list[SPFTerm] = []
    # Process terms after 'v=spf1'
    for token in tokens[1:]:
        term, err = parse_spf_term(token)
        if err:
            return tuple(terms), f"Invalid term '{token}': {err}"
        if term:
            terms.append(term)

    return tuple(terms), None


def parse_spf_term(token: str) -> tuple[SPFTerm | None, str | None]:
    """Parses a single SPF token/term.

    Returns:
        (SPFTerm, error_message)
    """
    if not token:
        return None, "Empty token"

    raw = token
    # Check for modifier (key=value)
    if "=" in token and not token.startswith(_PREFIX_LOOKUPS):
        parts = token.split("=", 1)
        name = parts[0].lower()
        val = parts[1]
        if not name or not val:
            return None, "Malformed modifier"
        if name == "redirect":
            return SPFTerm(
                qualifier="+",
                mechanism="redirect",
                value=val,
                raw=raw,
                is_modifier=True,
                causes_dns_lookup=True,
            ), None
        elif name == "exp":
            return SPFTerm(
                qualifier="+",
                mechanism="exp",
                value=val,
                raw=raw,
                is_modifier=True,
                causes_dns_lookup=False,
            ), None
        else:
            # Unknown modifier (RFC 7208 §6.2)
            return SPFTerm(
                qualifier="+",
                mechanism=name,
                value=val,
                raw=raw,
                is_modifier=True,
                causes_dns_lookup=False,
            ), None

    # Parse qualifier
    qualifier = "+"
    body = token
    if token[0] in _QUALIFIERS:
        qualifier = token[0]
        body = token[1:]

    if not body:
        return None, "Missing mechanism name after qualifier"

    # Split mechanism name and value (if separated by : or /)
    if ":" in body:
        mech_name, val = body.split(":", 1)
    elif "/" in body and not body.lower().startswith(("ip4", "ip6")):
        mech_name, val = body.split("/", 1)
        val = "/" + val
    else:
        mech_name = body
        val = None

    mech_name_lower = mech_name.lower()

    if mech_name_lower == "all":
        if val is not None:
            return None, "'all' mechanism cannot have target/arguments"
        return SPFTerm(
            qualifier=qualifier,
            mechanism="all",
            value=None,
            raw=raw,
            is_modifier=False,
            causes_dns_lookup=False,
        ), None

    elif mech_name_lower == "include":
        if not val:
            return None, "'include' mechanism requires a domain spec"
        return SPFTerm(
            qualifier=qualifier,
            mechanism="include",
            value=val,
            raw=raw,
            is_modifier=False,
            causes_dns_lookup=True,
        ), None

    elif mech_name_lower in ("a", "mx"):
        causes_lookup = True
        return SPFTerm(
            qualifier=qualifier,
            mechanism=mech_name_lower,
            value=val,
            raw=raw,
            is_modifier=False,
            causes_dns_lookup=causes_lookup,
        ), None

    elif mech_name_lower == "ip4":
        if not val:
            return None, "'ip4' mechanism requires an IP or CIDR value"
        # Validate IPv4 network
        try:
            ipaddress.IPv4Network(val, strict=False)
        except ValueError as exc:
            return None, f"Invalid ip4 CIDR/address '{val}': {exc}"
        return SPFTerm(
            qualifier=qualifier,
            mechanism="ip4",
            value=val,
            raw=raw,
            is_modifier=False,
            causes_dns_lookup=False,
        ), None

    elif mech_name_lower == "ip6":
        if not val:
            return None, "'ip6' mechanism requires an IPv6 or CIDR value"
        # Validate IPv6 network
        try:
            ipaddress.IPv6Network(val, strict=False)
        except ValueError as exc:
            return None, f"Invalid ip6 CIDR/address '{val}': {exc}"
        return SPFTerm(
            qualifier=qualifier,
            mechanism="ip6",
            value=val,
            raw=raw,
            is_modifier=False,
            causes_dns_lookup=False,
        ), None

    elif mech_name_lower == "ptr":
        return SPFTerm(
            qualifier=qualifier,
            mechanism="ptr",
            value=val,
            raw=raw,
            is_modifier=False,
            causes_dns_lookup=True,
        ), None

    elif mech_name_lower == "exists":
        if not val:
            return None, "'exists' mechanism requires a domain spec"
        return SPFTerm(
            qualifier=qualifier,
            mechanism="exists",
            value=val,
            raw=raw,
            is_modifier=False,
            causes_dns_lookup=True,
        ), None

    elif mech_name_lower == "redirect":
        if not val:
            return None, "'redirect' modifier requires a domain spec"
        return SPFTerm(
            qualifier="+",
            mechanism="redirect",
            value=val,
            raw=raw,
            is_modifier=True,
            causes_dns_lookup=True,
        ), None

    elif mech_name_lower == "exp":
        if not val:
            return None, "'exp' modifier requires a domain spec"
        return SPFTerm(
            qualifier="+",
            mechanism="exp",
            value=val,
            raw=raw,
            is_modifier=True,
            causes_dns_lookup=False,
        ), None

    else:
        return None, f"Unknown SPF mechanism '{mech_name}'"
