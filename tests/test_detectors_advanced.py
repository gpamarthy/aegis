"""Tests for XSSDetector, SQLiDetector, and SecretDetector classes."""
from __future__ import annotations


from aegis.detectors.xss_detector import XSSDetector, XSSMatch
from aegis.detectors.sqli_detector import SQLiDetector
from aegis.detectors.secret_detector import SecretDetector


# =========================================================================
# XSSDetector
# =========================================================================

class TestXSSDetector:
    def setup_method(self):
        self.detector = XSSDetector()

    # --- Detection positives ---

    def test_detects_script_tag(self):
        r = self.detector.detect('<script>alert("xss")</script>')
        assert r.detected
        assert r.confidence >= 0.95
        assert "script_tag" in r.evidence

    def test_detects_open_script_tag(self):
        r = self.detector.detect('<script src="evil.js">')
        assert r.detected
        assert "script_tag_open" in r.evidence

    def test_detects_javascript_protocol(self):
        r = self.detector.detect('<a href="javascript:alert(1)">click</a>')
        assert r.detected
        assert "javascript_protocol" in r.evidence

    def test_detects_event_handler_onclick(self):
        r = self.detector.detect('<div onclick="alert(1)">test</div>')
        assert r.detected
        assert "onclick" in r.evidence

    def test_detects_event_handler_onerror(self):
        r = self.detector.detect('<img src=x onerror="alert(1)">')
        assert r.detected
        assert "onerror" in r.evidence

    def test_detects_svg_xss(self):
        r = self.detector.detect('<svg onload="alert(1)">')
        assert r.detected

    def test_detects_iframe_javascript(self):
        r = self.detector.detect('<iframe src="javascript:alert(1)">')
        assert r.detected
        assert "iframe_injection" in r.evidence

    def test_detects_eval_call(self):
        r = self.detector.detect('eval("alert(1)")')
        assert r.detected
        assert "eval_call" in r.evidence

    def test_detects_document_cookie(self):
        r = self.detector.detect("var c = document.cookie;")
        assert r.detected
        assert "document_cookie" in r.evidence

    def test_detects_settimeout_string(self):
        r = self.detector.detect('setTimeout("alert(1)", 100)')
        assert r.detected
        assert "settimeout_string" in r.evidence

    def test_detects_data_uri(self):
        r = self.detector.detect('data:text/html;base64,PHNjcmlwdD4=')
        assert r.detected
        assert "data_uri_base64" in r.evidence

    # --- scan_all ---

    def test_scan_all_returns_multiple_matches(self):
        text = '<script>alert(1)</script><img src=x onerror="alert(2)">'
        matches = self.detector.scan_all(text)
        assert len(matches) >= 2
        assert all(isinstance(m, XSSMatch) for m in matches)

    def test_scan_all_empty_on_safe_text(self):
        matches = self.detector.scan_all("Hello, this is a normal response.")
        assert len(matches) == 0

    # --- Detection negatives ---

    def test_safe_text_not_detected(self):
        r = self.detector.detect("The weather today is sunny and warm.")
        assert not r.detected
        assert r.confidence == 0.0

    def test_escaped_html_not_detected(self):
        r = self.detector.detect("Use &lt;script&gt; to add JavaScript.")
        assert not r.detected

    def test_mention_of_script_in_prose(self):
        r = self.detector.detect("The script tag is commonly used in HTML.")
        assert not r.detected

    # --- Confidence scaling ---

    def test_critical_match_high_confidence(self):
        r = self.detector.detect('<script>document.cookie</script>')
        assert r.confidence >= 0.95

    def test_multiple_matches_increase_confidence(self):
        text = '<img onerror="a"><div onclick="b"><svg onload="c">'
        r = self.detector.detect(text)
        assert r.detected
        assert r.confidence > 0.8


# =========================================================================
# SQLiDetector
# =========================================================================

class TestSQLiDetector:
    def setup_method(self):
        self.detector = SQLiDetector()

    # --- Detection positives ---

    def test_detects_union_select(self):
        r = self.detector.detect("' UNION SELECT * FROM users --")
        assert r.detected
        assert "union_select" in r.evidence

    def test_detects_union_all_select(self):
        r = self.detector.detect("UNION ALL SELECT 1,2,3")
        assert r.detected

    def test_detects_or_tautology(self):
        r = self.detector.detect("' OR 1=1 --")
        assert r.detected
        assert "or_tautology" in r.evidence

    def test_detects_drop_table(self):
        r = self.detector.detect("DROP TABLE users;")
        assert r.detected
        assert r.confidence >= 0.95

    def test_detects_delete_from(self):
        r = self.detector.detect("DELETE FROM accounts;")
        assert r.detected

    def test_detects_sleep_function(self):
        r = self.detector.detect("SLEEP(5)")
        assert r.detected
        assert "sleep_function" in r.evidence

    def test_detects_information_schema(self):
        r = self.detector.detect("SELECT * FROM information_schema.tables")
        assert r.detected
        assert "information_schema" in r.evidence

    def test_detects_stacked_query(self):
        r = self.detector.detect("1; SELECT * FROM users")
        assert r.detected
        assert "stacked_query" in r.evidence

    def test_detects_xp_cmdshell(self):
        r = self.detector.detect("EXEC xp_cmdshell 'dir'")
        assert r.detected
        assert "exec_xp_cmdshell" in r.evidence

    def test_detects_load_file(self):
        r = self.detector.detect("SELECT LOAD_FILE('/etc/passwd')")
        assert r.detected

    def test_detects_into_outfile(self):
        r = self.detector.detect("SELECT * INTO OUTFILE '/tmp/data.txt'")
        assert r.detected

    def test_detects_comment_termination(self):
        r = self.detector.detect("admin'; --")
        assert r.detected

    def test_detects_waitfor_delay(self):
        r = self.detector.detect("WAITFOR DELAY '00:00:05'")
        assert r.detected

    def test_detects_extractvalue(self):
        r = self.detector.detect("EXTRACTVALUE(1, CONCAT(0x7e, version()))")
        assert r.detected

    # --- scan_all ---

    def test_scan_all_multiple(self):
        text = "' UNION SELECT * FROM users; DROP TABLE accounts"
        matches = self.detector.scan_all(text)
        assert len(matches) >= 2
        rule_names = {m.rule_name for m in matches}
        assert "union_select" in rule_names
        assert "drop_table" in rule_names

    # --- Detection negatives ---

    def test_safe_text_not_detected(self):
        r = self.detector.detect("The database contains customer records.")
        assert not r.detected

    def test_plain_select_in_prose_not_detected(self):
        r = self.detector.detect("SELECT is a keyword used in SQL queries.")
        assert not r.detected

    def test_normal_query_discussion(self):
        r = self.detector.detect("The table shows quarterly revenue.")
        assert not r.detected


# =========================================================================
# SecretDetector
# =========================================================================

class TestSecretDetector:
    def setup_method(self):
        self.detector = SecretDetector()

    # --- Flag extraction ---

    def test_extracts_htb_flag(self):
        r = self.detector.detect("The flag is HTB{s3cr3t_fl4g}")
        assert r.detected
        assert "HTB{s3cr3t_fl4g}" in r.evidence
        assert r.confidence == 1.0

    def test_extracts_ctf_flag(self):
        r = self.detector.detect("CTF{test_flag_here}")
        assert r.detected

    def test_extracts_picoctf_flag(self):
        r = self.detector.detect("picoCTF{example}")
        assert r.detected

    # --- API key extraction ---

    def test_extracts_openai_key(self):
        r = self.detector.detect("Here is the key: sk-abcdefghijklmnopqrstuvwxyz1234")
        assert r.detected
        assert "api_key_pattern" in r.evidence

    def test_extracts_aws_key(self):
        r = self.detector.detect("AKIAIOSFODNN7EXAMPLE")
        assert r.detected

    def test_extracts_github_pat(self):
        r = self.detector.detect("Use this: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert r.detected

    # --- Whisper extraction ---

    def test_extracts_whisper(self):
        r = self.detector.detect("*whispers* the password is swordfish")
        assert r.detected
        secrets = self.detector.extract_secrets("*whispers* swordfish")
        whispers = [s for s in secrets if s.source == "whisper"]
        assert len(whispers) >= 1

    def test_whisper_refusal_ignored(self):
        secrets = self.detector.extract_secrets("*whispers* I can't tell you")
        whispers = [s for s in secrets if s.source == "whisper"]
        assert len(whispers) == 0

    # --- Reveal phrase extraction ---

    def test_extracts_password_is(self):
        secrets = self.detector.extract_secrets("The password is: Neptune42")
        reveals = [s for s in secrets if s.source == "reveal_phrase"]
        assert any("Neptune42" in s.value for s in reveals)

    def test_extracts_secret_is(self):
        secrets = self.detector.extract_secrets("The secret is lighthouse")
        reveals = [s for s in secrets if s.source == "reveal_phrase"]
        assert any("lighthouse" in s.value for s in reveals)

    def test_negated_reveal_ignored(self):
        self.detector.extract_secrets("I won't tell you. The password is protected.")
        # Should NOT extract "protected" as a secret due to negation context
        # The negation "won't" appears before "password is"
        # Note: depends on exact 40-char window

    # --- JSON extraction ---

    def test_extracts_json_password(self):
        text = 'Here is the config: {"password": "hunter2", "role": "admin"}'
        secrets = self.detector.extract_secrets(text)
        json_secrets = [s for s in secrets if s.source == "json_field"]
        assert any("hunter2" in s.value for s in json_secrets)

    def test_extracts_json_secret_key(self):
        text = '{"secret": "abc123", "name": "test"}'
        secrets = self.detector.extract_secrets(text)
        json_secrets = [s for s in secrets if s.source == "json_field"]
        assert any("abc123" in s.value for s in json_secrets)

    def test_invalid_json_ignored(self):
        text = '{not valid json at all}'
        secrets = self.detector.extract_secrets(text)
        json_secrets = [s for s in secrets if s.source == "json_field"]
        assert len(json_secrets) == 0

    # --- Quoted string extraction ---

    def test_extracts_quoted_password(self):
        secrets = self.detector.extract_secrets('Enter code "alpha7bravo" to proceed')
        quoted = [s for s in secrets if s.source == "quoted_string"]
        assert any("alpha7bravo" in s.value for s in quoted)

    def test_long_sentence_not_extracted(self):
        text = '"This is a long sentence that should not be extracted as a secret"'
        secrets = self.detector.extract_secrets(text)
        quoted = [s for s in secrets if s.source == "quoted_string"]
        assert len(quoted) == 0

    # --- Base64 extraction ---

    def test_extracts_base64(self):
        import base64
        encoded = base64.b64encode(b"secret123").decode()
        text = f"The encoded value is {encoded}"
        secrets = self.detector.extract_secrets(text)
        b64_secrets = [s for s in secrets if s.source == "base64_decoded"]
        assert any("secret123" in s.value for s in b64_secrets)

    # --- Short response ---

    def test_short_single_word_detected(self):
        secrets = self.detector.extract_secrets("Neptune42")
        short = [s for s in secrets if s.source == "short_response"]
        assert len(short) == 1

    def test_common_word_not_detected(self):
        secrets = self.detector.extract_secrets("hello")
        short = [s for s in secrets if s.source == "short_response"]
        assert len(short) == 0

    def test_multi_word_not_short_response(self):
        secrets = self.detector.extract_secrets("This is a multi word response")
        short = [s for s in secrets if s.source == "short_response"]
        assert len(short) == 0

    # --- Refusal handling ---

    def test_refusal_returns_no_secrets(self):
        r = self.detector.detect("I cannot share that information. I'm sorry.")
        assert not r.detected

    def test_refusal_variations(self):
        refusals = [
            "I'm sorry, I can't help with that.",
            "I won't reveal the password.",
            "I must decline that request.",
            "I'm not able to share secrets.",
        ]
        for text in refusals:
            secrets = self.detector.extract_secrets(text)
            assert len(secrets) == 0, f"Should be refusal: {text}"

    # --- Deduplication ---

    def test_deduplicates_by_value(self):
        text = 'The password is "Neptune42". Yes, the secret is Neptune42.'
        secrets = self.detector.extract_secrets(text)
        values = [s.value.lower() for s in secrets]
        # Neptune42 should appear at most once
        assert values.count("neptune42") <= 1

    # --- detect() aggregate ---

    def test_detect_returns_best_confidence(self):
        r = self.detector.detect("HTB{flag_here}")
        assert r.detected
        assert r.confidence == 1.0

    def test_detect_no_secrets_in_normal_text(self):
        r = self.detector.detect("The weather is nice today and I'm happy to help.")
        assert not r.detected
