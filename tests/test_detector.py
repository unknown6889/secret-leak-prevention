import pytest
from detector import shannon_entropy, scan_for_patterns, scan_for_entropy, load_patterns

# Fake credentials used only for testing detection logic.
# Built by concatenation so the literal source file never contains
# a string that would itself match a secret pattern or trigger the
# entropy check. This keeps the scanner fully effective on this file too.
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_HIGH_ENTROPY_TOKEN = "aK9x7mQ2pL8" + "vN4wZ1yR3tB" + "6uD0fH5jK9"
FAKE_PRIVATE_KEY_HEADER = "-----BEGIN RSA" + " PRIVATE KEY-----"


class TestShannonEntropy:
    def test_empty_string_has_zero_entropy(self):
        assert shannon_entropy("") == 0.0

    def test_repeated_character_has_zero_entropy(self):
        assert shannon_entropy("a" * 10) == 0.0

    def test_random_looking_string_has_high_entropy(self):
        score = shannon_entropy(FAKE_HIGH_ENTROPY_TOKEN)
        assert score >= 4.3

    def test_normal_sentence_has_lower_entropy(self):
        score = shannon_entropy("hello world this is a normal sentence")
        assert score < 4.3


class TestScanForPatterns:
    def test_detects_aws_access_key(self):
        patterns = load_patterns()
        content = f'aws_key = "{FAKE_AWS_KEY}"'
        findings = scan_for_patterns(content, patterns)
        assert len(findings) == 1
        assert findings[0]["rule"] == "AWS Access Key"
        assert findings[0]["line"] == 1

    def test_detects_private_key_block(self):
        patterns = load_patterns()
        content = FAKE_PRIVATE_KEY_HEADER
        findings = scan_for_patterns(content, patterns)
        assert len(findings) == 1

    def test_normal_text_triggers_no_finding(self):
        patterns = load_patterns()
        content = "this is just a normal comment in the code"
        findings = scan_for_patterns(content, patterns)
        assert len(findings) == 0

    def test_finding_includes_correct_line_number(self):
        patterns = load_patterns()
        content = f'line one\nline two\naws_key = "{FAKE_AWS_KEY}"'
        findings = scan_for_patterns(content, patterns)
        assert findings[0]["line"] == 3

    def test_preview_never_exposes_full_secret(self):
        patterns = load_patterns()
        content = f'aws_key = "{FAKE_AWS_KEY}"'
        findings = scan_for_patterns(content, patterns)
        assert FAKE_AWS_KEY not in findings[0]["preview"]


class TestScanForEntropy:
    def test_detects_high_entropy_string(self):
        content = f'token = "{FAKE_HIGH_ENTROPY_TOKEN}"'
        findings = scan_for_entropy(content)
        assert len(findings) >= 1

    def test_ignores_short_strings(self):
        content = 'short = "abc123"'
        findings = scan_for_entropy(content)
        assert len(findings) == 0

    def test_ignores_normal_prose(self):
        content = "this is a long sentence written in plain english without any secret"
        findings = scan_for_entropy(content)
        assert len(findings) == 0


class TestLoadPatterns:
    def test_loads_patterns_successfully(self):
        patterns = load_patterns()
        assert len(patterns) > 0

    def test_patterns_are_compiled_regex(self):
        import re
        patterns = load_patterns()
        for pattern in patterns.values():
            assert isinstance(pattern, re.Pattern)
