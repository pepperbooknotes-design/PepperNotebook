#!/usr/bin/env python3
"""
GDPR-style PII scanner and anonymizer for local text files.

What it does:
1) Accept a text file path as input.
2) Read the file contents.
3) Detect common personal data patterns (email, phone, date of birth, etc.).
4) Show findings.
5) Produce and optionally save an anonymized version.

Note:
Regex-based detection is useful for demos and basic screening,
but it is not a legal/compliance-grade solution.
"""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Pattern, Tuple


PII_PATTERNS: Dict[str, Pattern[str]] = {
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)\d{3,4}[\s.-]?\d{3,4}\b"),
    "date_of_birth": re.compile(r"\b(?:0?[1-9]|[12]\d|3[01])[/-](?:0?[1-9]|1[0-2])[/-](?:19\d{2}|20[0-2]\d)\b"),
    "national_id_like": re.compile(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b"),
    "credit_card_like": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


def detect_pii(text: str) -> Dict[str, List[str]]:
    """Find matches for each PII pattern and return unique sorted values."""
    found: Dict[str, List[str]] = {}

    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            unique = sorted(set(m.strip() for m in matches if m.strip()))
            found[pii_type] = unique

    # Reduce common overlap where long card numbers are partially detected as phone values.
    if "phone" in found and "credit_card_like" in found:
        card_values = found["credit_card_like"]

        def overlaps_credit_card(phone_value: str) -> bool:
            digits = re.sub(r"\D", "", phone_value)
            return len(digits) >= 8 and any(digits in re.sub(r"\D", "", card) for card in card_values)

        filtered_phones = [phone for phone in found["phone"] if not overlaps_credit_card(phone)]
        if filtered_phones:
            found["phone"] = filtered_phones
        else:
            del found["phone"]

    return found


def hash_value(value: str) -> str:
    """Create a stable pseudonymous token using SHA-256."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"hash_{digest[:12]}"


def anonymize_text(text: str, findings: Dict[str, List[str]]) -> Tuple[str, Dict[str, Dict[str, str]]]:
    """Replace detected PII with pseudonymous or masked forms."""
    anonymized = text
    mapping: Dict[str, Dict[str, str]] = {}

    for pii_type, values in findings.items():
        mapping[pii_type] = {}
        for original in sorted(values, key=len, reverse=True):
            if pii_type == "email":
                replacement = f"<EMAIL:{hash_value(original)}>"
            elif pii_type == "phone":
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan and anonymize PII in a text file.")
    parser.add_argument("text_file", help="Path to the input text file to scan.")
    parser.add_argument(
        "--output",
        help="Optional path to save anonymized text. Defaults to '<input_stem>_anonymized.txt'.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.text_file)

    if not input_path.exists() or not input_path.is_file():
        print(f"Input file does not exist or is not a file: {input_path}")
        return

    text = input_path.read_text(encoding="utf-8")
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

    output_path = Path(args.output) if args.output else input_path.with_name(f"{input_path.stem}_anonymized.txt")
    output_path.write_text(anonymized_text, encoding="utf-8")
    print(f"\nAnonymized file written to: {output_path}")

    preview_length = 1200
    print("\nAnonymized text preview:")
    print(anonymized_text[:preview_length] + ("..." if len(anonymized_text) > preview_length else ""))


if __name__ == "__main__":
    main()
