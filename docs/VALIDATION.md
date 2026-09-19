# Validation record

Local validation on 2026-09-13:

- Windows, Python 3.12.14, OpenSSL 3.5.8.
- `python -m unittest discover -s tests -v`: **21 tests passed**.
- Actual loopback HTTP and TLS servers exercised; no external hosts scanned.
- Coverage includes trusted TLS, untrusted certificates, hostname mismatch, certificate-expiry warning, HTTP plaintext, redirect non-following, HEAD rejection, connection refusal, JSON serialization, cookie-value exclusion, CLI exit behavior, URL validation and target deduplication.
- Test certificates were generated at runtime; no private keys are shipped.

An initial run exposed a Windows sandbox interaction with Python temporary directories using restrictive ACLs. Disposable test fixtures now inherit parent ACLs. The application report writer still uses `NamedTemporaryFile`; atomic report replacement passed integration testing.

## GitHub Actions validation — 2026-09-19

All nine jobs passed in [CI run 35441649897](https://github.com/afastic-agent0/SurfaceCheck/actions/runs/35441649897) for commit `d5d0ce69d4b3f7d2cf628dbeb268e012f8d7c028`:

| Platform | Python versions | Result |
| --- | --- | --- |
| Windows | 3.11, 3.12, 3.13 | All passed |
| macOS | 3.11, 3.12, 3.13 | All passed |
| Ubuntu | 3.11, 3.12, 3.13 | All passed |

Each job installs the package and test dependencies, runs the 21-test suite, and checks the installed `surfacecheck --version` entry point. The same 21 tests also passed again locally on 2026-09-19. Subsequent release-preparation changes only update documentation and ignore rules; the validated Python source and tests are unchanged.

No live-site vulnerability assessment or third-party security review has been performed.
