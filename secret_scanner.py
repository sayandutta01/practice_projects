import argparse
import json
import math
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

EXCLUDED_DIRS = {
    ".git",
    ".jenkins-venv",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
}

MAX_FILE_SIZE = 1_000_000
KNOWN_PATTERNS = {
    "AWS Access Key ID": re.compile(
        r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"
    ),
    "GitHub Token": re.compile(
        r"(?<![A-Za-z0-9_])"
        r"(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})"
        r"(?![A-Za-z0-9_])"
    ),
    "JWT": re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}"
        r"(?![A-Za-z0-9_-])"
    ),
    "Database Connection String": re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)"
        r"://[^/\s:@\"']+:[^@\s\"']+@[^\s\"'<>]+"
    ),
        "Private Key": re.compile(
        r"-----BEGIN "
        r"(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
        r"|-----BEGIN PGP "
        r"PRIVATE KEY BLOCK-----"
    ),
    "Google API Key": re.compile(
        r"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"
    ),
    "Stripe Secret Key": re.compile(
        r"(?<![A-Za-z0-9_])sk_(?:live|test)_[A-Za-z0-9]{16,}"
    ),
}
CONTEXT_SECRET_PATTERN = re.compile(
    r"(?i)\b[A-Za-z0-9_-]*"
    r"(?:api[_-]?key|secret|token|password|passwd|pwd|credential)"
    r"[A-Za-z0-9_-]*\s*[:=]\s*[\"']?"
    r"([A-Za-z0-9_./+=-]{16,})"
)

HIGH_ENTROPY_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z0-9_+/=-]{24,})(?![A-Za-z0-9_])"
)

PLACEHOLDER_MARKERS = {
    "example",
    "dummy",
    "sample",
    "placeholder",
    "changeme",
    "replace_me",
    "your_key",
    "xxxxxxxx",
}

@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    detector: str
    severity: str
    masked_value: str
    entropy: float | None = None


def shannon_entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def character_class_count(value: str) -> int:
    return sum(
        (
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(not char.isalnum() for char in value),
        )
    )


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)

    return f"{value[:4]}...{value[-4:]}"


def is_placeholder(value: str) -> bool:
    lowered_value = value.lower()
    return any(marker in lowered_value for marker in PLACEHOLDER_MARKERS)


def get_line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1

def scan_known_patterns(text: str, file_path: Path) -> list[Finding]:
    findings = []

    for detector, pattern in KNOWN_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)

            if is_placeholder(value):
                continue

            findings.append(
                Finding(
                    file=str(file_path),
                    line=get_line_number(text, match.start()),
                    detector=detector,
                    severity="HIGH",
                    masked_value=mask_secret(value),
                )
            )

    return findings

def scan_context_entropy(text: str, file_path: Path) -> list[Finding]:
    findings = []

    for match in CONTEXT_SECRET_PATTERN.finditer(text):
        value = match.group(1)

        if is_placeholder(value):
            continue

        entropy = shannon_entropy(value)

        if entropy < 3.5:
            continue

        findings.append(
            Finding(
                file=str(file_path),
                line=get_line_number(text, match.start(1)),
                detector="Context + Entropy",
                severity="HIGH",
                masked_value=mask_secret(value),
                entropy=round(entropy, 2),
            )
        )

    return findings

def scan_high_entropy(text: str, file_path: Path) -> list[Finding]:
    findings = []

    for match in HIGH_ENTROPY_PATTERN.finditer(text):
        value = match.group(1)

        if is_placeholder(value):
            continue

        entropy = shannon_entropy(value)

        if entropy < 4.5 or character_class_count(value) < 3:
            continue

        findings.append(
            Finding(
                file=str(file_path),
                line=get_line_number(text, match.start(1)),
                detector="High Entropy",
                severity="MEDIUM",
                masked_value=mask_secret(value),
                entropy=round(entropy, 2),
            )
        )

    return findings

def iter_files(root: Path):
    if root.is_file():
        yield root
        return

    try:
        for path in root.iterdir():
            if path.is_symlink():
                continue

            if path.is_dir():
                if path.name not in EXCLUDED_DIRS:
                    yield from iter_files(path)

            elif path.is_file() and path.name != "secret-scan-report.json":
                yield path

    except OSError:
        return


def read_text_file(file_path: Path) -> str | None:
    try:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return None

        content = file_path.read_bytes()

        if b"\x00" in content:
            return None

        return content.decode("utf-8", errors="ignore")

    except OSError:
        return None

def scan_path(root: Path) -> list[Finding]:
    root = root.resolve()
    unique_findings = {}

    for file_path in iter_files(root):
        text = read_text_file(file_path)

        if text is None:
            continue

        if root.is_file():
            display_path = Path(root.name)
        else:
            display_path = file_path.relative_to(root)

        detected = (
            scan_known_patterns(text, display_path)
            + scan_context_entropy(text, display_path)
            + scan_high_entropy(text, display_path)
        )

        for finding in detected:
            key = (
                finding.file,
                finding.line,
                finding.masked_value,
            )
            unique_findings.setdefault(key, finding)

    return sorted(
        unique_findings.values(),
        key=lambda finding: (
            finding.file,
            finding.line,
            finding.detector,
        ),
    )

def print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("Secret scan completed: no secrets detected.")
        return

    print(f"Secret scan detected {len(findings)} possible secret(s):")

    for finding in findings:
        entropy_text = (
            f", entropy={finding.entropy}"
            if finding.entropy is not None
            else ""
        )

        print(
            f"[{finding.severity}] "
            f"{finding.file}:{finding.line} - "
            f"{finding.detector} - "
            f"{finding.masked_value}{entropy_text}"
        )


def write_json_report(
    findings: list[Finding],
    report_path: Path,
) -> None:
    report = {
        "summary": {
            "total": len(findings),
            "high": sum(
                finding.severity == "HIGH"
                for finding in findings
            ),
            "medium": sum(
                finding.severity == "MEDIUM"
                for finding in findings
            ),
        },
        "findings": [
            asdict(finding)
            for finding in findings
        ],
    }

    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan source code for possible secrets."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan.",
    )
    parser.add_argument(
        "--json-report",
        default="secret-scan-report.json",
        help="Location of the JSON report.",
    )
    args = parser.parse_args()

    scan_root = Path(args.path)

    if not scan_root.exists():
        print(
            f"Error: path does not exist: {scan_root}",
            file=sys.stderr,
        )
        return 2

    findings = scan_path(scan_root)
    print_findings(findings)

    report_path = Path(args.json_report)

    try:
        write_json_report(findings, report_path)
        print(f"JSON report written to: {report_path}")
    except OSError as error:
        print(
            f"Could not write JSON report: {error}",
            file=sys.stderr,
        )
        return 2

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())    

    