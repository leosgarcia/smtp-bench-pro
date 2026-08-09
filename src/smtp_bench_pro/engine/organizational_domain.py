"""Organizational domain resolution using tldextract (Public Suffix List)."""

from __future__ import annotations

import logging
import tldextract

logger = logging.getLogger("smtp_bench_pro.mail_dns")

# Initialize TLDExtract with network fetching disabled (100% offline using bundled PSL)
_EXTRACTOR = tldextract.TLDExtract(cache_dir=False, suffix_list_urls=())


def get_organizational_domain(domain: str) -> str:
    """Returns the Organizational Domain (registered domain under PSL) for a given domain.

    Examples:
    - example.com -> example.com
    - sub.example.com -> example.com
    - empresa.com.br -> empresa.com.br
    - sub.empresa.com.br -> empresa.com.br
    - deep.sub.example.co.uk -> example.co.uk
    """
    clean = domain.rstrip(".").lower()
    if not clean:
        return ""

    try:
        extracted = _EXTRACTOR(clean)
        # top_domain_under_public_suffix returns domain + suffix (e.g., empresa.com.br)
        reg_domain = getattr(extracted, "top_domain_under_public_suffix", None) or getattr(
            extracted, "registered_domain", ""
        )
        if reg_domain:
            return reg_domain.lower()
        # Fallback to domain itself if registered_domain is empty (e.g., TLD or single label)
        return clean
    except Exception as exc:
        logger.warning("Failed to extract organizational domain for '%s': %s", domain, exc)
        return clean
