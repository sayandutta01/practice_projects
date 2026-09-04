import argparse
import json
import sys
from pathlib import Path


def validate_bandit_report(report_path: Path) -> int:
    if not report_path.exists():
        print(f"Bandit report not found: {report_path}")
        return 2

    try:
        report = json.loads(
            report_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        print(f"Could not read Bandit report: {error}")
        return 2

    errors = report.get("errors", [])
    results = report.get("results", [])

    if errors:
        print(f"Bandit encountered {len(errors)} scanning error(s):")

        for error in errors:
            filename = error.get("filename", "unknown file")
            reason = error.get("reason", "unknown reason")
            print(f"[ERROR] {filename}: {reason}")

        return 1

    print(
        f"Bandit report validated: "
        f"{len(results)} vulnerability finding(s), "
        "0 scanning errors."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a Bandit JSON report."
    )
    parser.add_argument(
        "report",
        nargs="?",
        default="bandit-report.json",
    )
    args = parser.parse_args()

    return validate_bandit_report(Path(args.report))


if __name__ == "__main__":
    sys.exit(main())