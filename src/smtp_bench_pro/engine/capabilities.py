"""EHLO capability parsing helpers."""


def parse_ehlo_capabilities(lines: list[str]) -> dict[str, list[str]]:
    """Parse ESMTP EHLO response lines into normalized capabilities."""
    capabilities: dict[str, list[str]] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line.startswith("250"):
            continue
        content = line[4:].strip() if len(line) > 4 else ""
        if not content:
            continue
        parts = content.split()
        name = parts[0].upper()
        values = parts[1:]
        capabilities[name] = values
    return capabilities


def supports_starttls(capabilities: dict[str, list[str]]) -> bool:
    return "STARTTLS" in capabilities


def auth_mechanisms(capabilities: dict[str, list[str]]) -> list[str]:
    """Return normalized AUTH mechanisms from EHLO capabilities."""
    return sorted({value.upper() for value in capabilities.get("AUTH", [])})
