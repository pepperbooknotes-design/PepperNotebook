# PepperNotebook

## GDPR PII scanner demo

This repository includes `gdpr_pii_scanner.py`, a simple Python script that:

1. asks for a URL,
2. fetches and extracts page text,
3. detects common GDPR-style PII patterns (email, phone, DOB-like values, ID-like values, etc.),
4. prints findings,
5. creates an anonymized version of the text by masking/redacting/pseudonymizing matched values.

### Run URL scanner

```bash
python3 gdpr_pii_scanner.py
```

## Local text-file scanner and anonymizer

This repository also includes `gdpr_pii_file_scanner.py`, which scans a local text file and writes an anonymized output file.

### Example data

A sample input file with personal information examples is available at:

- `sample_personal_info.txt`

### Run file scanner

```bash
python3 gdpr_pii_file_scanner.py sample_personal_info.txt
```

Optional output path:

```bash
python3 gdpr_pii_file_scanner.py sample_personal_info.txt --output anonymized_output.txt
```

No third-party dependencies are required.
