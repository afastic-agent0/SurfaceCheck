# SurfaceCheck 1.0 (POC)

A small TLS and HTTP security posture checker for explicitly supplied URLs. It complements [NetScannerMacOS](https://github.com/afastic-agent0/NetScannerMacOS): discover a service there, then inspect its HTTP(S) endpoint here.

Version 1.0.0 retains the focused POC scope below. The version number does not imply a comprehensive security audit or production-readiness certification. The example report records the earlier 0.1.0 local fixture run.

SurfaceCheck uses Python 3.11+ and the standard library. It does not require root, packet capture, API keys or an LLM. Intended for macOS, Linux and Windows; see [validation evidence](docs/VALIDATION.md) for platforms actually tested.

## What it checks

- TLS certificate chain and hostname verification against the selected trust store.
- Negotiated TLS version/cipher, certificate SHA-256 fingerprint and expiration.
- Plaintext HTTP and HTTPS responses missing an active HSTS policy.
- Missing CSP and `nosniff` on HTML responses.
- Cookie attributes that deserve review, without saving cookie names or values.
- Redirects, unsupported HEAD requests and connection failures, reported explicitly.

These observations are not proof of exploitability. Missing headers and cookie flags may be intentional; findings require application context. A successful check is not a security certification.

## Quick start

From the repository directory (no installation required):

```bash
python3 -m surfacecheck --help
python3 -m surfacecheck https://your-authorized-host.example/ --json report.json
```

On Windows, use `python` or `py -3` instead of `python3`.

Optional installation in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
surfacecheck https://your-authorized-host.example/ --fail-on medium
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

Private CA, multiple explicit targets and custom timing:

```bash
python3 -m surfacecheck https://localhost:8443/ http://127.0.0.1:8080/ \
  --ca-file /path/to/private-ca.pem --timeout 5 --interval 1 --json report.json
```

`--ca-file` selects a PEM trust bundle while preserving hostname and certificate verification. There is no insecure TLS option. An existing report at `--json` is replaced atomically; its parent directory must already exist.

## Scope and request behavior

Only assess systems you own or are authorized to test. SurfaceCheck sends one HEAD request per normalized unique target, sequentially, with a default 0.5-second pause between targets. It accepts at most 32 URLs and does not discover hosts, scan port ranges, crawl, follow redirects or retry requests. URLs must have an HTTP(S) scheme and valid host/port; credentials, query strings and fragments are rejected. DNS names resolve using your system resolver; private and loopback destinations are allowed.

It reads response headers and closes the connection without consuming the response body. HEAD can still cause server-side work; this is an active check, not passive monitoring. Socket timeouts apply per blocking operation, not as a whole-run deadline. DNS resolution and servers that trickle header bytes can take longer. Do not expose this CLI as a public scanning service without additional isolation, scope controls and deadlines.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Checks completed; no finding met the selected threshold (default `--fail-on never`). |
| 1 | A finding met `--fail-on low`, `medium` or `high`. |
| 2 | Invalid input, failed/partial check or report-write failure. Takes priority over 1. |
| 130 | Interrupted by the user. |

A TLS verification failure is a high-severity observation and an incomplete check, so it returns 2. A 405/501 response is partial; there is no automatic GET fallback. A 3xx response describes only the redirecting endpoint. HTTP error status codes are recorded as received, not interpreted as authentication success or failure.

## Reports and credentials

The JSON schema is versioned (`schema_version: 1`). Each result includes the normalized target, completion status, HTTP status, TLS metadata when available, findings and elapsed time. See [example report](examples/local-report.json).

No credentials are accepted, fetched from environment variables or reused from browsers. Proxy environment variables are not used. Cookie values, raw headers, redirect locations, response bodies and raw exception messages are not retained. Target URLs **including their paths**, timestamps, certificate fingerprints and observations are retained; avoid putting secrets in paths and handle reports according to your environment's requirements. Temporary report files use the platform's `tempfile` protections; final access follows platform filesystem semantics.

## Development

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m unittest discover -s tests -v
```

Tests use local loopback servers and generate disposable TLS certificates. `cryptography` is needed only for tests. No internet targets or real credentials are used. GitHub Actions is configured for Python 3.11–3.13 on macOS, Linux and Windows.

See [architecture](docs/ARCHITECTURE.md), [validation](docs/VALIDATION.md) and [security scope](SECURITY.md).

## Limitations

- Only the negotiated TLS connection is observed; there is no exhaustive cipher/protocol enumeration or revocation check.
- Header checks apply to the selected path's HEAD response. They do not establish site-wide policy, CSP effectiveness, cookie purpose, or exploitability.
- Certificate validation errors are grouped; the tool does not claim to distinguish expiration from an untrusted chain or hostname mismatch.
- No login flows, authenticated sessions, bearer tokens, vulnerability payloads, JavaScript execution or remediation actions.
- Initial POC: API and report fields may evolve with schema-version changes.

MIT licensed. This is a separate implementation; no NetScannerMacOS or RAPTOR source was copied.
