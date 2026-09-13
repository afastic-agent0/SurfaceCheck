"""Command line, deterministic exit status and atomic JSON reports."""

import argparse
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import time
from datetime import datetime, timezone

from . import __version__
from .checker import inspect, parse_target


def bounded_number(minimum, maximum):
    def parse(value):
        try:
            number = float(value)
        except ValueError:
            raise argparse.ArgumentTypeError("Expected a number") from None
        if not math.isfinite(number) or not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f"Expected a finite number from {minimum} to {maximum}")
        return number
    return parse


def write_report(path: Path, report: dict):
    """Create a private temporary file then atomically replace destination."""
    temp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            temp = Path(handle.name)
            json.dump(report, handle, indent=2, ensure_ascii=True, allow_nan=False)
            handle.write("\n")
        os.replace(temp, path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="SurfaceCheck POC: one HEAD request per explicit URL. Only check systems you are authorized to assess.")
    parser.add_argument("urls", nargs="+", help="Up to 32 HTTP(S) URLs; no credentials or query strings")
    parser.add_argument("--timeout", type=bounded_number(0.1, 30), default=5.0, help="Per blocking socket operation, seconds (default: 5; DNS may take longer)")
    parser.add_argument("--interval", type=bounded_number(0.1, 60), default=0.5, help="Delay between targets, seconds (default: 0.5)")
    parser.add_argument("--ca-file", help="PEM trust bundle for private HTTPS services")
    parser.add_argument("--json", dest="json_path", type=Path, help="Write JSON report (replaces an existing file)")
    parser.add_argument("--fail-on", choices=["never", "low", "medium", "high"], default="never", help="Return 1 at this finding severity or higher (errors always return 2)")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    if len(args.urls) > 32:
        parser.error("At most 32 URLs are allowed per run")
    try:
        targets = list(dict.fromkeys(parse_target(url) for url in args.urls))
    except (ValueError, UnicodeError):
        # Never echo potentially credential-bearing input on validation failure.
        parser.error("Invalid target: use HTTP(S), a valid host/port and path, without credentials, queries, fragments or whitespace")
    results = []
    try:
        for index, target in enumerate(targets):
            if index:
                time.sleep(args.interval)
            result = inspect(target, timeout=args.timeout, ca_file=args.ca_file)
            results.append(result)
            print(f"{target.url}  {result['status'].upper()}  HTTP {result['http_status'] or '-'}")
            for item in result["findings"]:
                print(f"  {item['severity'].upper():6} {item['code']}: {item['message']}")
        report = {"schema_version": 1, "tool": "SurfaceCheck", "version": __version__, "generated_at": datetime.now(timezone.utc).isoformat(), "results": results}
        if args.json_path:
            write_report(args.json_path, report)
    except OSError as exc:
        print(f"Could not write report ({type(exc).__name__}).", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    if any(r["status"] != "ok" for r in results):
        return 2
    ranks = {"info": 0, "low": 1, "medium": 2, "high": 3, "never": 4}
    return int(any(ranks[f["severity"]] >= ranks[args.fail_on] for r in results for f in r["findings"]))
