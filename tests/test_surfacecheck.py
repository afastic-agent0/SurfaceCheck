import contextlib
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from surfacecheck.checker import analyze_headers, inspect, parse_target
from surfacecheck.cli import main, write_report


class TestDirectory:
    """Disposable fixtures with inherited Windows ACLs (also works in AppContainers)."""
    def __init__(self):
        self.path = Path(tempfile.gettempdir()).resolve() / ("surfacecheck-test-" + uuid.uuid4().hex)
        self.path.mkdir()
        self.name = str(self.path)

    def __enter__(self):
        return self.name

    def __exit__(self, *args):
        self.cleanup()

    def cleanup(self):
        # Only delete this fixture's immediate files; never recurse or follow links.
        for child in self.path.iterdir():
            child.unlink()
        self.path.rmdir()


class TargetTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(parse_target("https://EXAMPLE.com/a").url, "https://example.com:443/a")
        self.assertEqual(parse_target("http://[::1]:8080/").host, "::1")
        self.assertEqual(parse_target("https://example.com/café").path, "/caf%C3%A9")

    def test_invalid_inputs(self):
        for value in ["", "example.com", "ftp://example.com", "http://user:password@example.com", "http://example.com/?key=secret", "http://example.com/#x", "http://example.com:0", "http://example.com:65536", "http://example.com:", "http://example.com\r\nInjected:x", "http://example.com\\@other.com", "http://[fe80::1%en0]", "http://127.1", "http://2130706433", "http://0x7f000001", "http://bad_host", "http://-host"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_target(value)

    def test_rejects_all_inputs_before_network(self):
        with patch("surfacecheck.cli.inspect") as probe, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main(["https://example.com", "http://user:SECRET@example.com"])
        self.assertEqual(caught.exception.code, 2)
        probe.assert_not_called()

    def test_invalid_input_not_echoed(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit):
            main(["http://user:SECRET@example.com"])
        self.assertNotIn("SECRET", error.getvalue())

    def test_numeric_bounds(self):
        for option, value in [("--timeout", "nan"), ("--timeout", "inf"), ("--timeout", "0"), ("--interval", "-1")]:
            with self.subTest(option=option, value=value), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(["https://example.com", option, value])

    def test_max_targets(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["https://example.com"] * 33)


class HeaderTests(unittest.TestCase):
    def test_strong_html_headers(self):
        headers = [("Content-Type", "text/html"), ("Content-Security-Policy", "default-src 'none'"), ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"), ("X-Content-Type-Options", "nosniff"), ("Set-Cookie", "session=SECRET; Secure; HttpOnly; SameSite=Lax")]
        self.assertEqual(analyze_headers(headers, "https"), [])

    def test_json_does_not_require_html_headers(self):
        self.assertEqual(analyze_headers([("Content-Type", "application/json")], "http"), [])

    def test_missing_and_disabled_hsts(self):
        self.assertEqual(analyze_headers([], "https")[0]["code"], "HSTS_MISSING")
        for value in ["max-age=0", "max-age=oops", "includeSubDomains", "max-age=5; max-age=10"]:
            with self.subTest(value=value):
                self.assertEqual(analyze_headers([("Strict-Transport-Security", value)], "https")[0]["code"], "HSTS_INACTIVE")

    def test_cookie_values_never_returned(self):
        results = analyze_headers([("Set-Cookie", "session=SECRET; SameSite=None"), ("Set-Cookie", "token=OTHER; Secure; HttpOnly; SameSite=Strict")], "http")
        self.assertIn("COOKIE_NONE_INSECURE", [f["code"] for f in results])
        self.assertNotIn("SECRET", json.dumps(results))
        self.assertNotIn("OTHER", json.dumps(results))
        self.assertTrue(all("1 Set-Cookie" in f["message"] for f in results))


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.server.seen.append(self.path)
        self.send_response(302 if self.path == "/redirect" else 405 if self.path == "/unsupported" else 200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Set-Cookie", "session=DO_NOT_SAVE; Secure; HttpOnly; SameSite=Lax")
        if self.path == "/redirect":
            self.send_header("Location", "http://127.0.0.1:1/SECRET_DESTINATION")
        self.end_headers()

    def log_message(self, *args):
        pass


@contextlib.contextmanager
def server(context=None):
    instance = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    instance.daemon_threads = True
    instance.seen = []
    if context:
        instance.socket = context.wrap_socket(instance.socket, server_side=True)
    thread = threading.Thread(target=instance.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = TestDirectory()
        root = Path(cls.temp.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SurfaceCheck ephemeral test")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=7))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        cls.cert_path = root / "test.pem"
        cls.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path = root / "key.pem"
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(cls.cert_path, key_path)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_http_one_request_and_no_cookie_leak(self):
        with server() as endpoint:
            result = inspect(parse_target(f"http://127.0.0.1:{endpoint.server_port}/"))
            self.assertEqual(endpoint.seen, ["/"])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["findings"][0]["code"], "HTTP_PLAINTEXT")
        self.assertNotIn("DO_NOT_SAVE", json.dumps(result))

    def test_redirect_not_followed_or_retained(self):
        with server() as endpoint:
            result = inspect(parse_target(f"http://127.0.0.1:{endpoint.server_port}/redirect"))
            self.assertEqual(endpoint.seen, ["/redirect"])
        self.assertEqual(result["http_status"], 302)
        self.assertNotIn("SECRET_DESTINATION", json.dumps(result))

    def test_head_unsupported_no_get_fallback(self):
        with server() as endpoint:
            result = inspect(parse_target(f"http://127.0.0.1:{endpoint.server_port}/unsupported"))
            self.assertEqual(endpoint.seen, ["/unsupported"])
        self.assertEqual(result["status"], "partial")

    def test_tls_verified_and_expiry_observed(self):
        with server(self.context) as endpoint:
            result = inspect(parse_target(f"https://127.0.0.1:{endpoint.server_port}/"), ca_file=str(self.cert_path))
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["tls"]["verified"])
        self.assertIn(result["tls"]["version"], ("TLSv1.2", "TLSv1.3"))
        self.assertEqual(len(result["tls"]["certificate_sha256"]), 64)
        self.assertIn("CERT_EXPIRING", [f["code"] for f in result["findings"]])

    def test_untrusted_certificate_blocks_http(self):
        with server(self.context) as endpoint:
            result = inspect(parse_target(f"https://127.0.0.1:{endpoint.server_port}/"))
            self.assertEqual(endpoint.seen, [])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["findings"][0]["code"], "TLS_VERIFY_FAILED")

    def test_hostname_mismatch_blocks_http(self):
        with server(self.context) as endpoint:
            result = inspect(parse_target(f"https://localhost:{endpoint.server_port}/"), ca_file=str(self.cert_path))
            self.assertEqual(endpoint.seen, [])
        self.assertEqual(result["findings"][0]["code"], "TLS_VERIFY_FAILED")

    def test_refused_connection_is_error_not_clean(self):
        with socket.socket() as bound:
            bound.bind(("127.0.0.1", 0))
            result = inspect(parse_target(f"http://127.0.0.1:{bound.getsockname()[1]}/"), timeout=0.2)
        self.assertEqual(result["status"], "error")

    def test_cli_json_and_severity_exit(self):
        with server() as endpoint, TestDirectory() as temp:
            report = Path(temp) / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main([f"http://127.0.0.1:{endpoint.server_port}/", "--json", str(report), "--fail-on", "medium"])
            self.assertEqual(code, 1)
            saved = json.loads(report.read_text())
            self.assertEqual(saved["schema_version"], 1)
            self.assertNotIn("DO_NOT_SAVE", report.read_text())

    def test_cli_partial_exit(self):
        with server() as endpoint, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([f"http://127.0.0.1:{endpoint.server_port}/unsupported"]), 2)

    def test_deduplicates_targets(self):
        with server() as endpoint, contextlib.redirect_stdout(io.StringIO()):
            url = f"http://127.0.0.1:{endpoint.server_port}/"
            self.assertEqual(main([url, url]), 0)
            self.assertEqual(endpoint.seen, ["/"])

    def test_atomic_json_escaping(self):
        with TestDirectory() as temp:
            path = Path(temp) / "report.json"
            data = {"example": "quotes\" and\nnewlines"}
            write_report(path, data)
            self.assertEqual(json.loads(path.read_text()), data)
            self.assertEqual(list(Path(temp).iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
