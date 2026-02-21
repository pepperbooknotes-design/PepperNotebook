#!/usr/bin/env python3
"""
Simple GDPR-style PII scanner and anonymizer.

What it does:
1) Ask for a URL.
2) Download page text.
3) Detect common personal data patterns (email, phone, date of birth, etc.).
4) Show the findings.
5) Produce an anonymized version of the text suitable for safer sharing in reports.

Note:
This is regex-based detection, so it is useful for demos and basic screening,
but not perfect for legal/compliance-grade workflows.
"""

from __future__ import annotations

import hashlib
import re
from html import unescape
from typing import Dict, List, Pattern, Tuple

from urllib import error, request


# Regex rules for common GDPR-relevant personal data.
# You can add more patterns depending on your domain.
PII_PATTERNS: Dict[str, Pattern[str]] = {
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)\d{3,4}[\s.-]?\d{3,4}\b"),
    "date_of_birth": re.compile(r"\b(?:0?[1-9]|[12]\d|3[01])[/-](?:0?[1-9]|1[0-2])[/-](?:19\d{2}|20[0-2]\d)\b"),
    "national_id_like": re.compile(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b"),  # e.g., SSN-like pattern
    "credit_card_like": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")


def fetch_page_text(url: str, timeout: int = 15) -> str:
    """Download a web page and return human-readable text (very simple HTML stripping)."""
    with request.urlopen(url, timeout=timeout) as response:
        # Try to decode with server-provided charset, fallback to utf-8.
        charset = response.headers.get_content_charset() or "utf-8"
        html = response.read().decode(charset, errors="replace")

    # Remove scripts/styles first so they do not pollute extracted text.
    html = re.sub(r"<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>", " ", html, flags=re.IGNORECASE)
    html = re.sub(r"<style\b[^<]*(?:(?!</style>)<[^<]*)*</style>", " ", html, flags=re.IGNORECASE)

    # Remove remaining tags, decode entities, normalize spaces.
    text = TAG_RE.sub(" ", html)
    text = unescape(text)
    text = WHITESPACE_RE.sub(" ", text).strip()
    return text


def detect_pii(text: str) -> Dict[str, List[str]]:
    """Find matches for each PII pattern and return unique sorted values."""
    found: Dict[str, List[str]] = {}

    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            # Deduplicate and sort for clean output.
            unique = sorted(set(m.strip() for m in matches if m.strip()))
            found[pii_type] = unique

    return found


def hash_value(value: str) -> str:
    """Create a stable pseudonymous token using SHA-256."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"hash_{digest[:12]}"


def anonymize_text(text: str, findings: Dict[str, List[str]]) -> Tuple[str, Dict[str, Dict[str, str]]]:
    """
    Replace detected PII with pseudonymous or masked forms.

    Returns:
        anonymized_text: updated text
        mapping: original->replacement by PII category
    """
    anonymized = text
    mapping: Dict[str, Dict[str, str]] = {}

    for pii_type, values in findings.items():
        mapping[pii_type] = {}
        for original in values:
            if pii_type == "email":
                # Example masking: keep domain visibility limited, hash local part.
                replacement = f"<EMAIL:{hash_value(original)}>"
            elif pii_type == "phone":
                # Keep only last 2 digits visible.
                digits = re.sub(r"\D", "", original)
                replacement = f"<PHONE:***{digits[-2:] if len(digits) >= 2 else '**'}>"
            elif pii_type == "date_of_birth":
                replacement = "<DOB:REDACTED>"
            elif pii_type == "credit_card_like":
                replacement = "<CARD:REDACTED>"
            elif pii_type == "national_id_like":
                replacement = "<NATIONAL_ID:REDACTED>"
            elif pii_type == "ip_address":
                replacement = "<IP:MASKED>"
            else:
                replacement = f"<{pii_type.upper()}:REDACTED>"

            mapping[pii_type][original] = replacement
            anonymized = anonymized.replace(original, replacement)

    return anonymized, mapping


def print_findings(findings: Dict[str, List[str]]) -> None:
    """Pretty-print the detected PII categories and values."""
    if not findings:
        print("No obvious PII patterns were detected.")
        return

    print("\nDetected GDPR-style personal data:")
    for pii_type, values in findings.items():
        print(f"- {pii_type} ({len(values)} found)")
        for value in values:
            print(f"  • {value}")


def main() -> None:
    """CLI flow for scanning and anonymizing one URL."""
    print("GDPR PII Scanner + Anonymizer")
    url = input("Enter URL to scan: ").strip()

    if not url:
        print("No URL provided. Exiting.")
        return

    # Add default protocol for convenience.
    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        url = f"https://{url}"

    try:
        text = fetch_page_text(url)
    except (error.URLError, ValueError) as exc:
        print(f"Failed to fetch URL: {exc}")
        return

    findings = detect_pii(text)
    print_findings(findings)

    anonymized_text, mapping = anonymize_text(text, findings)

    print("\nAnonymization mapping (original -> replacement):")
    if not mapping:
        print("No replacements were needed.")
    else:
        for pii_type, pairs in mapping.items():
            print(f"- {pii_type}:")
            for original, replacement in pairs.items():
                print(f"  • {original} -> {replacement}")

    # Show only a preview so output stays readable.
    preview_length = 1500
    print("\nAnonymized text preview:")
    print(anonymized_text[:preview_length] + ("..." if len(anonymized_text) > preview_length else ""))


if __name__ == "__main__":
    main()
