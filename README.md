# PepperNotebook

## GDPR PII scanner demo

This repository includes `gdpr_pii_scanner.py`, a simple Python script that:

1. asks for a URL,
2. fetches and extracts page text,
3. detects common GDPR-style PII patterns (email, phone, DOB-like values, ID-like values, etc.),
4. prints findings,
5. creates an anonymized version of the text by masking/redacting/pseudonymizing matched values.

### Run

```bash
python3 gdpr_pii_scanner.py
```

No third-party dependencies are required.
