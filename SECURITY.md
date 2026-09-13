# Security scope

SurfaceCheck is a POC for authorized endpoint inspection. It has no payload execution, port-range scanning, credential acquisition or automatic remediation.

For a potential tool vulnerability, share a minimal reproducer using local fixtures. Do not post private target URLs, reports, credentials or production certificates/keys in public issues. If GitHub private vulnerability reporting is enabled for the repository, use that channel for sensitive reports.

Known boundaries: system DNS determines destinations; arbitrary private/loopback targets are permitted; timeouts are per socket operation; no process-wide deadline; no revocation verification; no complete CSP/HSTS grammar validation; certificate failures stop HTTP inspection. Treat findings as triage observations.
