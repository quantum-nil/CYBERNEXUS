# Email Security Intelligence

CyberNexus now exposes a domain/email investigation workflow at
`POST /api/intelligence/email/investigate` and a read-only DNS reverification
workflow at `POST /api/intelligence/email/remediation/verify`.

## Investigation behavior

- Accepts an email address or fully-qualified domain and normalizes Unicode
  domains to IDNA/Punycode. It reports whether the input was an `email` or a
  `domain` and never claims that a mailbox exists.
- Inspects SPF TXT records, detects duplicates and syntax problems, follows
  `include` and `redirect`, detects cycles, and reports the RFC lookup count.
  DNS policy discovery is separate from sender-IP SPF verification; trusted
  SMTP context remains required for the latter.
- Parses DMARC `p`, `sp`, `rua`, `ruf`, `adkim`, `aspf`, and `pct`, explains
  policy strength, and identifies invalid or monitoring-only policies.
- Inspects a requested DKIM selector, or verifies DKIM signatures from trusted
  original RFC5322 bytes using `dkimpy`. An unavailable selector is `UNKNOWN`,
  not a signature failure.
- Combines MX/DNS, RDAP age, maintained disposable-provider data, existing
  CyberNexus threat providers, and local lookalike detection into a
  source-attributed score. Provider failures remain unknown.
- Generates copyable SPF/DMARC guidance and provider-generated DKIM actions.
  It never fabricates DKIM keys, overwrites DNS, or changes third-party zones.
  Recommendations require verified ownership and explicit approval.
- Uses bounded DNS timeouts, in-process caching, best-effort rate limiting,
  NXDOMAIN/SERVFAIL/TIMEOUT distinction, and an explicit DNSSEC validation
  state. No SMTP probing or user-controlled HTTP fetch is performed.

## Frontend

The Email analysis service now supports email/domain investigation, optional
DKIM selector input, optional original-message input, `.eml` upload, SPF/DKIM/
DMARC cards, threat evidence, DNS detail inspection, copyable recommendations,
and post-change DNS reverification.

The existing `/api/intelligence/email/authentication` endpoint remains
compatible and now returns the richer investigation alongside its legacy
authentication result.

## Reproducible tests

`tests/test_email_security_investigation.py` covers IDN normalization,
malformed input, SPF recursion, DMARC parsing, missing selectors, and the
no-fabricated-DKIM-key rule. Existing email, contact, and authentication tests
continue to pass. Live results are obtained through DNS/provider calls at
runtime; Gmail is not hardcoded.
