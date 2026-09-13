# Validation record

Local validation on 2026-09-13:

- Windows, Python 3.12.14, OpenSSL 3.5.8.
- `python -m unittest discover -s tests -v`: **21 tests passed**.
- Actual loopback HTTP and TLS servers exercised; no external hosts scanned.
- Coverage includes trusted TLS, untrusted certificates, hostname mismatch, certificate-expiry warning, HTTP plaintext, redirect non-following, HEAD rejection, connection refusal, JSON serialization, cookie-value exclusion, CLI exit behavior, URL validation and target deduplication.
- Test certificates were generated at runtime; no private keys are shipped.

An initial run exposed a Windows sandbox interaction with Python temporary directories using restrictive ACLs. Disposable test fixtures now inherit parent ACLs. The application report writer still uses `NamedTemporaryFile`; atomic report replacement passed integration testing.

The GitHub Actions matrix is configured for macOS, Ubuntu and Windows with Python 3.11, 3.12 and 3.13. Those remote jobs have **not yet been run**. Local success must not be represented as macOS/Linux validation or a full security audit.

No live-site vulnerability assessment or third-party security review has been performed.
