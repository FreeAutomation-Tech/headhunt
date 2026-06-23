import json
from typing import List

from .scanner import ScanResult, HEADER_CHECKS

SEVERITY_COLORS = {
    "HIGH": "\033[91m",    # Red
    "MEDIUM": "\033[93m",  # Yellow
    "LOW": "\033[94m",     # Blue
    "INFO": "\033[90m",    # Gray
}
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def print_banner():
    print(BOLD + "  _   _           _   _           _   " + RESET)
    print(BOLD + " | | | | ___  ___| |_| |_ ___ _ _| |_ " + RESET)
    print(BOLD + " | |_| |/ _ \\/ _ \\  _|  _/ -_) '_| _|" + RESET)
    print(BOLD + "  \\___/ \\___/\\___/\\__|\\__\\___|_|  \\__|" + RESET)
    print(BOLD + "  HTTP Security Header Analyzer v1.0" + RESET)
    print()


def print_result(result: ScanResult):
    print(f"\n{BOLD}URL:{RESET} {result.url}")
    if result.status_code:
        print(f"{BOLD}Status:{RESET} {result.status_code}")
    if result.redirect_url:
        print(f"{BOLD}Redirects to:{RESET} {result.redirect_url}")

    if result.error:
        print(f"\n{BOLD}Error:{RESET} {result.error}")
        return

    print(f"{BOLD}Grade:{RESET} {result.grade}  ({result.score}/100)")
    print()

    issues_found = 0
    for h in result.headers:
        check = HEADER_CHECKS.get(h.header_key, {})
        sev = check.get("severity", "INFO")

        if h.present:
            icon = GREEN + "[OK]" + RESET
            if sev == "INFO":
                label = colorize(f"[{sev}]", SEVERITY_COLORS[sev])
                print(f"  {icon} {label} {h.header_key}: {h.value}")
            else:
                print(f"  {icon} {h.header_key}: {h.value}")
        else:
            icon = colorize("[MISSING]", SEVERITY_COLORS[sev])
            label = colorize(f"[{sev}]", SEVERITY_COLORS[sev])
            print(f"  {icon} {label} {h.header_key}")
            print(f"         {h.description}")
            print(f"         {colorize('Fix: ' + h.advice, SEVERITY_COLORS[sev])}")
            issues_found += 1

    if issues_found == 0:
        print(f"  {GREEN}All security headers are properly set!{RESET}")
    print()


def print_summary(results: List[ScanResult]):
    print(f"\n{BOLD}Summary ({len(results)} URLs scanned):{RESET}")
    print(f"  {'URL':<45} {'Grade':>6} {'Score':>6} {'Issues':>7}")
    print(f"  {'-'*45} {'-'*6} {'-'*6} {'-'*7}")
    for r in results:
        issues = sum(1 for h in r.headers if not h.present)
        color = GREEN if r.grade in ("A", "B") else SEVERITY_COLORS.get("MEDIUM")
        grade_colored = colorize(r.grade, color)
        print(
            f"  {r.url:<45} {grade_colored:>6} {r.score:>5}%"
            f" {colorize(str(issues), SEVERITY_COLORS.get('HIGH')):>7}"
        )
    print()


def output_json(results: List[ScanResult]):
    data = {
        "tool": "HeadHunt v1.0",
        "scanned_urls": len(results),
        "results": [r.to_dict() for r in results],
    }
    print(json.dumps(data, indent=2))
