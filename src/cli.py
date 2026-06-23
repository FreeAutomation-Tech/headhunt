import argparse
import sys
from pathlib import Path
from typing import List

from .scanner import scan_url, ScanResult
from .reporter import print_banner, print_result, print_summary


def scan_single(url: str, follow: bool, timeout: int) -> ScanResult:
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return scan_url(url, follow_redirects=follow, timeout=timeout)


def scan_from_file(path: str, follow: bool, timeout: int) -> List[ScanResult]:
    text = Path(path).read_text("utf-8")
    urls = [line.strip() for line in text.splitlines() if line.strip()]
    results = []
    for url in urls:
        results.append(scan_single(url, follow, timeout))
    return results


def main():
    parser = argparse.ArgumentParser(
        description="HeadHunt — HTTP Security Header Analyzer for Pentesters"
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    sub = parser.add_subparsers(title="commands", dest="command")

    scan_p = sub.add_parser("scan", help="Scan a URL or file of URLs")
    scan_p.add_argument("target", help="URL to scan or path to file with --file")
    scan_p.add_argument("--file", "-f", action="store_true",
                        help="Treat target as a file containing URLs (one per line)")
    scan_p.add_argument("--no-follow", action="store_true",
                        help="Do not follow redirects")
    scan_p.add_argument("--timeout", type=int, default=15,
                        help="Request timeout in seconds (default: 15)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        if not args.json:
            print_banner()

        if args.file:
            results = scan_from_file(args.target, not args.no_follow, args.timeout)
        else:
            result = scan_single(args.target, not args.no_follow, args.timeout)
            results = [result]

        if args.json:
            from .reporter import output_json as out
            out(results)
        else:
            for r in results:
                print_result(r)
            if len(results) > 1:
                print_summary(results)

        if any(r.error for r in results):
            sys.exit(1)


if __name__ == "__main__":
    main()
