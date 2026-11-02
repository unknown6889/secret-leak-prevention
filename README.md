# Secret Leak Prevention

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF.svg)](https://github.com/features/actions)
[![Tests](https://img.shields.io/badge/Tests-pytest-0A9EDC.svg)](https://docs.pytest.org/)

> A Git pre-commit hook that blocks commits containing secrets (API keys, tokens, private keys) before they ever reach version control, combining known-pattern matching with Shannon entropy analysis to catch both documented and unknown secret formats.

---

## Why this project

Hardcoded credentials in Git repositories are a leading cause of initial access for attackers. Once a secret is committed, it stays in the repository's history forever, even if the file is later deleted or the secret rotated. The safest fix is to catch the secret **before** it is ever committed, a shift-left approach to security.

Most leaked-secret scanners only catch well-known formats (AWS keys, GitHub tokens, Stripe keys). This project adds a second layer: entropy analysis, which flags any high-randomness string, including custom or proprietary secrets that no pattern would recognize.

## How it works

```
git commit ──► pre-commit hook ──► detector.py ──► staged files scanned
                                                       │
                              ┌────────────────────────┴────────────────────────┐
                              ▼                                                 ▼
                    Pattern matching                                 Shannon entropy analysis
              (AWS, GitHub, Stripe, Slack...)                  (catches unknown/custom secrets)
                              │                                                 │
                              └────────────────────────┬────────────────────────┘
                                                         ▼
                                      Secret found → commit blocked
                                      Nothing found → commit allowed
```

1. **Detection**: `detector.py` loads a set of known secret patterns (`patterns.json`, based on widely used references such as TruffleHog's regex list) and scans every staged file against them.
2. **Entropy analysis**: in parallel, every long alphanumeric string in the staged content is scored with Shannon entropy. A high score (≥ 4.3 bits/char) flags a likely random secret, even one that matches no known pattern.
3. **Enforcement**: if anything is found, the script exits with a non-zero status, which Git uses as the signal to abort the commit. No secret value is ever printed in full, only a short masked preview.

## Stack

- **Python** (detection engine, no external dependencies at runtime)
- **Git hooks** (`pre-commit`, triggered automatically on every commit)
- **pytest** (unit tests for the detection logic)
- **GitHub Actions** (CI safety net: re-runs tests and a full-repo scan on every push)

## Installation

```bash
git clone https://github.com/unknown6889/secret-leak-prevention.git
cd secret-leak-prevention
./install.sh
```

This installs the hook into `.git/hooks/pre-commit`. Git hooks are never version-controlled by Git itself, so `install.sh` needs to be run once after cloning, or after cloning any repository where you want this protection active.

## Try it

```bash
echo 'aws_key = "AKIA_REPLACE_WITH_FAKE_VALUE"' > test.py
git add test.py
git commit -m "test"
```

The commit will be blocked, with the file, line number, and matched rule shown, and the secret itself never printed in full.

```bash
rm test.py
git reset
```

## Running the detector manually

```bash
python3 detector.py          # scans staged files only (used by the hook)
python3 detector.py --all    # scans every file tracked by Git (used in CI)
```

## Automation

Every push and pull request triggers a GitHub Actions workflow that:
1. Runs the unit test suite (`pytest tests/`)
2. Scans the entire repository for secrets (`detector.py --all`)

This acts as a second line of defense in case the local hook was never installed, or bypassed with `git commit --no-verify`.

See it run: [Actions tab](../../actions)

## Design choice: how test fixtures avoid false positives

The test suite needs realistic fake secrets to verify the detection logic, but a naive approach (writing a complete fake AWS key or token directly in the test file) would get blocked by the hook's own pattern and entropy checks, and more importantly, would silently exclude the `tests/` folder from protection if handled with a blanket ignore rule.

Instead, fake credentials are built by string concatenation at runtime:

```python
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
```

The literal source file never contains a string that matches a pattern or crosses the entropy threshold, since the scanner only reads static file content, not what the code produces when executed. This keeps 100% of the codebase, including the tests, under full scanner coverage, with no exclusion list, no suppression comments, and no blind spot for a real secret accidentally committed later.

## Known limitations

The detector works on raw file text with regex and entropy analysis, it does not parse or execute code. This means a secret deliberately or accidentally split across string literals, for example:

```python
aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
```

will not be flagged, since neither fragment matches a known pattern or crosses the entropy threshold on its own. This is not specific to this tool: it is a general limitation of static, text-based secret scanners (including production tools like Gitleaks or TruffleHog in their default mode), none of which execute the code to see what value it actually produces at runtime.

A more robust detector would parse Python files with the `ast` module, fold constant string concatenations at analysis time, and scan the reconstructed value. This is a natural next improvement for this project, and the kind of gap worth closing with defense in depth rather than relying on a single scanning layer (hence the CI scan in addition to the local hook).

## Project structure

```
detector.py                     # Detection engine (patterns + entropy)
patterns.json                   # Known secret patterns (AWS, GitHub, Stripe, etc.)
install.sh                      # Installs the pre-commit hook
tests/
├── conftest.py                 # Allows tests to import detector.py
└── test_detector.py            # Unit tests for the detection logic
.github/workflows/
└── secret-scan.yml             # CI: tests + full-repo scan on every push
```

## Author

**d3m0s-null**
Final-year cybersecurity engineering student @ CESI

[GitHub](https://github.com/unknown6889)
