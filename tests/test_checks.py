"""Response evaluation and failure classification.
Author: Dr. Denys Dutykh."""
import monitor


class FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code


def evaluate(target, status=200, body=""):
    return monitor.Checker(monitor.Config())._evaluate(target, FakeResponse(status), body)


def make(url="https://example.com", **kw):
    return monitor.Target(name=url, url=url, **kw)


def test_2xx_and_3xx_healthy():
    for code in (200, 204, 301, 302, 399):
        assert evaluate(make(), code)[0] is True


def test_429_treated_as_alive():
    """Rate limiting means the server is up and talking to us."""
    assert evaluate(make(), 429)[0] is True


def test_4xx_5xx_unhealthy():
    for code in (404, 500, 502, 503):
        healthy, error, _ = evaluate(make(), code)
        assert healthy is False
        assert str(code) in error


def test_content_check_catches_200_with_broken_page():
    """A CMS error page returns HTTP 200; status alone cannot catch it."""
    target = make(expect_text="Welcome to my site")
    assert evaluate(target, 200, "<h1>Welcome to my site</h1>")[0] is True
    healthy, error, _ = evaluate(target, 200, "<h1>Database connection error</h1>")
    assert healthy is False
    assert "expected text" in error


def test_content_regex():
    target = make(expect_text=r"v\d+\.\d+", expect_regex=True)
    assert evaluate(target, 200, "version v2.1 online")[0] is True
    assert evaluate(target, 200, "version unknown")[0] is False


def test_api_json_field_mismatch():
    target = make(url="http://x.y/health", kind="api", expected_status=200,
                  expected_response={"status": "healthy"})
    assert evaluate(target, 200, '{"status": "healthy"}')[0] is True
    healthy, error, _ = evaluate(target, 200, '{"status": "degraded"}')
    assert healthy is False and "degraded" in error


def test_api_missing_key():
    target = make(url="http://x.y/h", kind="api", expected_status=200,
                  expected_response={"database": "connected"})
    healthy, error, _ = evaluate(target, 200, '{"status": "ok"}')
    assert healthy is False and "Missing key" in error


def test_api_invalid_json_is_not_a_crash():
    target = make(url="http://x.y/h", kind="api", expected_status=200,
                  expected_response={"status": "ok"})
    healthy, error, _ = evaluate(target, 200, "<html>gateway timeout</html>")
    assert healthy is False and "Invalid JSON" in error


def test_api_json_array_does_not_raise():
    """A JSON list used to reach the bare `except Exception` via TypeError."""
    target = make(url="http://x.y/h", kind="api", expected_status=200,
                  expected_response={"status": "ok"})
    healthy, error, _ = evaluate(target, 200, '["a", "b"]')
    assert healthy is False and "JSON object" in error


class TestFailureClassification:
    def test_tls(self):
        assert monitor.classify_failure("SSL error: certificate has expired", None) == "tls"

    def test_timeout(self):
        assert monitor.classify_failure("Timeout after 30 seconds", None) == "timeout"

    def test_dns(self):
        assert monitor.classify_failure(
            "Request failed: ... Name or service not known", None) == "dns"

    def test_conn(self):
        assert monitor.classify_failure(
            "Request failed: ... Connection refused", None) == "conn"

    def test_http_status(self):
        assert monitor.classify_failure("Unexpected status code: 503", 503) == "http_status"

    def test_healthy_has_no_class(self):
        assert monitor.classify_failure(None, 200) is None


def test_ssl_valid_not_claimed_when_tls_never_negotiated():
    """The old code inferred ssl_valid from the error string and reported
    'SSL Valid: True' for DNS failures and refused connections."""
    import types
    cfg = monitor.Config()
    checker = monitor.Checker(cfg)
    cfg.max_retries = 1

    def boom(*a, **kw):
        raise monitor.RequestException("Name or service not known")

    checker._session = lambda: types.SimpleNamespace(request=boom, headers={})
    healthy, details = checker.check(make(url="https://nonexistent.invalid"))
    assert healthy is False
    assert details["ssl_valid"] is None, "must be unknown, never True"


def test_redaction_strips_secrets_and_truncates():
    out = monitor.redact({"status": "ok", "api_key": "super-secret", "token": "abc"})
    assert "super-secret" not in out and "abc" not in out
    assert "<redacted>" in out and "ok" in out
    assert len(monitor.redact({"k": "x" * 5000}, limit=200)) < 300


def test_human_duration():
    assert monitor.human_duration(45) == "45s"
    assert monitor.human_duration(3600) == "1h"
    assert monitor.human_duration(9000) == "2h 30m"
    assert monitor.human_duration(90000) == "1d 1h"
