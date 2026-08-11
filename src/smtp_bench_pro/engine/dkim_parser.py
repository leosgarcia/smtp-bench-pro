"""Static DKIM record parser for Mail DNS Diagnostics."""

from __future__ import annotations

import base64
import re

from smtp_bench_pro.domain.mail_dns import DKIMSelectorResult, DKIMStatus

_SELECTOR_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?"
_SELECTOR_RE = re.compile(rf"^{_SELECTOR_LABEL}(?:\.{_SELECTOR_LABEL})*$")
_INVALID_SELECTOR_CHARS = re.compile(r"[@:/\?#\s]")
_SUPPORTED_KEYS = {"rsa", "ed25519"}


def normalize_dkim_selectors(raw_selectors: str | tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    if raw_selectors is None:
        return ()
    if isinstance(raw_selectors, str):
        parts = re.split(r"[,;\n\r\t ]+", raw_selectors)
    else:
        parts = [str(selector) for selector in raw_selectors]
    selectors = []
    seen = set()
    for part in parts:
        selector = part.strip().strip(".").lower()
        if not selector or selector in seen:
            continue
        selectors.append(selector)
        seen.add(selector)
    return tuple(selectors)


def is_valid_selector(selector: str) -> bool:
    return bool(selector and not _INVALID_SELECTOR_CHARS.search(selector) and _SELECTOR_RE.match(selector))


def dkim_query_name(selector: str, domain: str) -> str:
    return f"{selector}._domainkey.{domain}".lower()


def parse_dkim_record(selector: str, query_name: str, raw_record: str | None) -> DKIMSelectorResult:
    if not is_valid_selector(selector):
        return DKIMSelectorResult(
            selector=selector,
            query_name=query_name,
            status=DKIMStatus.INVALID_SYNTAX,
            validation_errors=("Selector DKIM inválido.",),
        )
    if raw_record is None or not raw_record.strip():
        return DKIMSelectorResult(
            selector=selector,
            query_name=query_name,
            status=DKIMStatus.ABSENT,
            validation_errors=("Registro DKIM ausente.",),
        )

    tags: dict[str, str] = {}
    errors: list[str] = []
    for raw_part in raw_record.strip().strip('"').split(";"):
        part = raw_part.strip()
        if not part:
            continue
        if "=" not in part:
            errors.append(f"Tag DKIM sem '=': {part}")
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip().strip('"')
        if not key:
            errors.append("Tag DKIM sem nome.")
            continue
        if key in tags:
            errors.append(f"Tag DKIM duplicada: {key}")
            continue
        tags[key] = value

    version = tags.get("v")
    if version is not None and version.upper() != "DKIM1":
        errors.append(f"Versão DKIM inválida: {version}")

    key_type = (tags.get("k") or "rsa").lower()
    if key_type not in _SUPPORTED_KEYS:
        return DKIMSelectorResult(
            selector=selector,
            query_name=query_name,
            status=DKIMStatus.UNSUPPORTED_KEY_TYPE,
            raw_record=raw_record,
            key_type=key_type,
            public_key_present=bool(tags.get("p")),
            flags=_split_tag(tags.get("t")),
            services=_split_tag(tags.get("s")) or ("*",),
            hash_algorithms=_split_tag(tags.get("h")),
            notes=(f"Tipo de chave DKIM não suportado: {key_type}",),
            validation_errors=tuple(errors),
        )

    public_key = tags.get("p")
    if public_key is not None and public_key == "":
        return DKIMSelectorResult(
            selector=selector,
            query_name=query_name,
            status=DKIMStatus.REVOKED,
            raw_record=raw_record,
            key_type=key_type,
            public_key_present=False,
            flags=_split_tag(tags.get("t")),
            services=_split_tag(tags.get("s")) or ("*",),
            hash_algorithms=_split_tag(tags.get("h")),
            notes=("Chave DKIM revogada por p= vazio.",),
            validation_errors=tuple(errors),
        )
    if not public_key:
        errors.append("Tag p ausente.")
        return _invalid_key(selector, query_name, raw_record, key_type, tags, errors)

    key_bytes: bytes
    try:
        key_bytes = base64.b64decode(_compact_public_key(public_key), validate=True)
    except Exception:
        errors.append("Chave pública DKIM não é base64 válido.")
        return _invalid_key(selector, query_name, raw_record, key_type, tags, errors)

    bits = _public_key_bits(key_type, key_bytes)
    notes = []
    if key_type == "rsa" and bits is None:
        notes.append("Chave RSA decodificada, mas tamanho não pôde ser determinado de forma portátil.")
    if key_type == "ed25519" and bits is None:
        bits = len(key_bytes) * 8 if key_bytes else None

    status = DKIMStatus.INVALID_SYNTAX if errors else DKIMStatus.VALID
    return DKIMSelectorResult(
        selector=selector,
        query_name=query_name,
        status=status,
        raw_record=raw_record,
        key_type=key_type,
        public_key_present=True,
        public_key_bits=bits,
        flags=_split_tag(tags.get("t")),
        services=_split_tag(tags.get("s")) or ("*",),
        hash_algorithms=_split_tag(tags.get("h")),
        notes=tuple(notes),
        validation_errors=tuple(errors),
    )


def _split_tag(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part.strip().lower() for part in value.split(":") if part.strip())


def _compact_public_key(value: str) -> str:
    return re.sub(r"\s+", "", value)


def _invalid_key(
    selector: str,
    query_name: str,
    raw_record: str,
    key_type: str,
    tags: dict[str, str],
    errors: list[str],
) -> DKIMSelectorResult:
    return DKIMSelectorResult(
        selector=selector,
        query_name=query_name,
        status=DKIMStatus.INVALID_PUBLIC_KEY,
        raw_record=raw_record,
        key_type=key_type,
        public_key_present=False,
        flags=_split_tag(tags.get("t")),
        services=_split_tag(tags.get("s")) or ("*",),
        hash_algorithms=_split_tag(tags.get("h")),
        validation_errors=tuple(errors),
    )


def _public_key_bits(key_type: str, key_bytes: bytes) -> int | None:
    if key_type == "ed25519":
        return len(key_bytes) * 8 if key_bytes else None
    if key_type != "rsa":
        return None
    return _rsa_der_bits(key_bytes)


def _rsa_der_bits(data: bytes) -> int | None:
    # Supports common DER RSAPublicKey sequence. SubjectPublicKeyInfo may return None.
    try:
        pos = 0
        if data[pos] != 0x30:
            return None
        _, pos = _read_len(data, pos + 1)
        if pos >= len(data) or data[pos] != 0x02:
            return None
        modulus_len, pos = _read_len(data, pos + 1)
        modulus = data[pos : pos + modulus_len]
        while modulus and modulus[0] == 0:
            modulus = modulus[1:]
        return len(modulus) * 8 if modulus else None
    except Exception:
        return None


def _read_len(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    length = int.from_bytes(data[pos : pos + count], "big")
    return length, pos + count
