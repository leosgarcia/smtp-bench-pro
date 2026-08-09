"""Formal DMARC record parser according to RFC 7489."""

from __future__ import annotations

import re

# Allowed values for DMARC tags
_VALID_POLICIES = {"none", "quarantine", "reject"}
_VALID_ALIGNMENTS = {"r", "s"}
_TAG_PATTERN = re.compile(r"^\s*([a-zA-Z0-9]+)\s*=\s*(.*?)\s*$")


def parse_dmarc_record(raw_record: str) -> tuple[dict[str, str], list[str]]:
    """Parses a raw DMARC record string into tag-value mappings.

    Returns:
        (parsed_tags, validation_errors)
    """
    errors: list[str] = []
    cleaned = raw_record.strip()

    # Split terms by semicolon
    raw_tokens = [t.strip() for t in cleaned.split(";") if t.strip()]

    if not raw_tokens:
        return {}, ["Empty DMARC record."]

    # Validate first tag must be v=DMARC1
    first_match = _TAG_PATTERN.match(raw_tokens[0])
    if not first_match or first_match.group(1).lower() != "v" or first_match.group(2).upper() != "DMARC1":
        return {}, ["DMARC record must begin with 'v=DMARC1'."]

    seen_tags: set[str] = set()
    parsed_tags: dict[str, str] = {}

    for token in raw_tokens:
        match = _TAG_PATTERN.match(token)
        if not match:
            errors.append(f"Malformed DMARC tag token '{token}'.")
            continue

        tag_name = match.group(1).lower()
        tag_val = match.group(2)

        # Check for duplicate tags (RFC 7489 §6.3)
        if tag_name in seen_tags:
            errors.append(f"Duplicate DMARC tag '{tag_name}' detected.")
            continue
        seen_tags.add(tag_name)

        parsed_tags[tag_name] = tag_val

    # Validate mandatory 'p' tag
    if "p" not in parsed_tags:
        errors.append("Mandatory DMARC policy tag 'p' is missing.")
    elif parsed_tags["p"].lower() not in _VALID_POLICIES:
        errors.append(f"Invalid DMARC policy 'p={parsed_tags['p']}'. Must be none, quarantine, or reject.")

    # Validate optional 'sp' tag
    if "sp" in parsed_tags and parsed_tags["sp"].lower() not in _VALID_POLICIES:
        errors.append(f"Invalid DMARC subdomain policy 'sp={parsed_tags['sp']}'. Must be none, quarantine, or reject.")

    # Validate optional 'pct' tag
    if "pct" in parsed_tags:
        try:
            pct_val = int(parsed_tags["pct"])
            if pct_val < 0 or pct_val > 100:
                errors.append(f"Invalid 'pct' value '{parsed_tags['pct']}'. Must be between 0 and 100.")
        except ValueError:
            errors.append(f"Invalid non-integer 'pct' value '{parsed_tags['pct']}'.")

    # Validate optional 'adkim' tag
    if "adkim" in parsed_tags and parsed_tags["adkim"].lower() not in _VALID_ALIGNMENTS:
        errors.append(f"Invalid DKIM alignment 'adkim={parsed_tags['adkim']}'. Must be 'r' or 's'.")

    # Validate optional 'aspf' tag
    if "aspf" in parsed_tags and parsed_tags["aspf"].lower() not in _VALID_ALIGNMENTS:
        errors.append(f"Invalid SPF alignment 'aspf={parsed_tags['aspf']}'. Must be 'r' or 's'.")

    return parsed_tags, errors


def parse_dmarc_report_uris(uri_string: str) -> tuple[str, ...]:
    """Parses a comma-separated list of DMARC report URIs (rua/ruf)."""
    if not uri_string:
        return ()

    uris: list[str] = []
    raw_parts = [p.strip() for p in uri_string.split(",") if p.strip()]

    for part in raw_parts:
        # Preserve URI format (e.g. mailto:dmarc@example.com or mailto:dmarc@example.com!10m)
        if part.lower().startswith("mailto:"):
            uris.append(part)
        else:
            # Reformat or accept URI
            uris.append(part)

    return tuple(uris)
