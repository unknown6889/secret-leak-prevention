import json
import math
import re
import sys
import subprocess
from pathlib import Path

PATTERNS_FILE = Path(__file__).parent / "patterns.json"
ENTROPY_THRESHOLD = 4.3
MIN_STRING_LENGTH = 20

# Extensions to skip (binaries, generated files, etc.)
IGNORED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".lock", ".min.js", ".woff", ".woff2"}


def load_patterns():
    with open(PATTERNS_FILE) as f:
        raw = json.load(f)
    return {name: re.compile(pattern) for name, pattern in raw.items()}


def shannon_entropy(data):
    """Computes the Shannon entropy of a string, in bits per character."""
    if not data:
        return 0.0
    entropy = 0.0
    for char in set(data):
        p_x = data.count(char) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy


def get_staged_files():
    """Returns the list of files currently staged for commit."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True
    )
    return [f for f in result.stdout.splitlines() if f]


def get_all_tracked_files():
    """Returns all files tracked by Git in the repository (used in CI)."""
    result = subprocess.run(
        ["git", "ls-files"],
        capture_output=True, text=True
    )
    return [f for f in result.stdout.splitlines() if f]


def get_staged_content(filepath):
    """Returns the staged content of a file (not the one on disk)."""
    result = subprocess.run(
        ["git", "show", f":{filepath}"],
        capture_output=True, text=True
    )
    return result.stdout


def scan_for_patterns(content, patterns):
    findings = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        for name, pattern in patterns.items():
            match = pattern.search(line)
            if match:
                findings.append({
                    "type": "pattern",
                    "rule": name,
                    "line": line_num,
                    "preview": match.group(0)[:6] + "..." + match.group(0)[-4:] if len(match.group(0)) > 12 else "***"
                })
    return findings


def scan_for_entropy(content):
    findings = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        for candidate in re.findall(r"[A-Za-z0-9+/=_\-]{%d,}" % MIN_STRING_LENGTH, line):
            score = shannon_entropy(candidate)
            if score >= ENTROPY_THRESHOLD:
                findings.append({
                    "type": "entropy",
                    "rule": f"High entropy string (score: {score:.2f})",
                    "line": line_num,
                    "preview": candidate[:6] + "..." + candidate[-4:]
                })
    return findings


def scan_file(filepath, patterns, from_disk=False):
    if any(filepath.endswith(ext) for ext in IGNORED_EXTENSIONS):
        return []
    if from_disk:
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (FileNotFoundError, IsADirectoryError):
            return []
    else:
        content = get_staged_content(filepath)
    findings = scan_for_patterns(content, patterns)
    findings += scan_for_entropy(content)
    for f in findings:
        f["file"] = filepath
    return findings


def main():
    patterns = load_patterns()

    if "--all" in sys.argv:
        files_to_scan = get_all_tracked_files()
    else:
        files_to_scan = get_staged_files()

    all_findings = []
    use_disk = "--all" in sys.argv
    for filepath in files_to_scan:
        all_findings.extend(scan_file(filepath, patterns, from_disk=use_disk))

    if all_findings:
        print("\nPotential secrets detected, commit blocked:\n")
        for f in all_findings:
            print(f"  [{f['type'].upper()}] {f['file']}:{f['line']} ({f['rule']}, preview: {f['preview']})")
        print(f"\n{len(all_findings)} finding(s). Fix or remove these before committing.")
        print("If this is a false positive, add the file to an exclusion list (coming soon).\n")
        sys.exit(1)
    else:
        print("No secrets detected. Commit allowed.")
        sys.exit(0) 


if __name__ == "__main__":
    main()
