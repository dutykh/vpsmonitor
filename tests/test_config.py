"""Configuration parsing: the pipe DSL, TOML, and malformed input.
Author: Dr. Denys Dutykh."""
import pytest

import monitor


def test_websites_parsed(config):
    assert [t.url for t in config.websites] == [
        "https://example.com", "https://www.example.com"]
    assert all(t.kind == "website" for t in config.websites)


def test_api_dsl_full_form(monkeypatch):
    monkeypatch.setenv("API_ENDPOINTS",
                       "Scholar|http://127.0.0.1:8000/health|200|status:healthy,database:connected")
    cfg = monitor.Config()
    api = cfg.api_endpoints[0]
    assert api.name == "Scholar"
    assert api.expected_status == 200
    assert api.expected_response == {"status": "healthy", "database": "connected"}


def test_api_dsl_coerces_types(monkeypatch):
    monkeypatch.setenv("API_ENDPOINTS", "A|http://x.y/h|200|ready:true,count:5,ratio:0.5,name:ok")
    api = monitor.Config().api_endpoints[0]
    assert api.expected_response == {"ready": True, "count": 5, "ratio": 0.5, "name": "ok"}


def test_malformed_api_record_is_reported_not_silently_dropped(monkeypatch, caplog):
    """A typo used to disable an endpoint with no visible sign at all."""
    monkeypatch.setenv("API_ENDPOINTS", "BrokenRecordNoPipe;Good|http://x.y/h|200")
    with caplog.at_level("ERROR"):
        cfg = monitor.Config()
    assert len(cfg.api_endpoints) == 1
    assert cfg.api_endpoints[0].name == "Good"
    assert any("malformed" in r.message.lower() for r in caplog.records)


def test_missing_credentials_raise(monkeypatch):
    monkeypatch.delenv("SMTP_PASSWORD")
    with pytest.raises(monitor.ConfigError, match="SMTP credentials"):
        monitor.Config()


def test_no_targets_raises(monkeypatch):
    monkeypatch.setenv("WEBSITES", "")
    with pytest.raises(monitor.ConfigError, match="No websites or APIs"):
        monitor.Config()


def test_invalid_url_raises(monkeypatch):
    monkeypatch.setenv("WEBSITES", "ftp://example.com")
    with pytest.raises(monitor.ConfigError, match="Invalid URL"):
        monitor.Config()


def test_multiple_recipients(monkeypatch):
    monkeypatch.setenv("ALERT_EMAIL", "a@x.com, b@y.com")
    assert monitor.Config().alert_email == ["a@x.com", "b@y.com"]


def test_bad_integer_falls_back_to_default(monkeypatch, caplog):
    monkeypatch.setenv("TIMEOUT", "not-a-number")
    with caplog.at_level("WARNING"):
        assert monitor.Config().timeout == 30


def test_toml_targets_take_precedence(tmp_path, monkeypatch):
    toml = tmp_path / "targets.toml"
    toml.write_text("""
[[website]]
name = "Home"
url = "https://example.org"
expect = "Welcome"

[[api]]
name = "Health"
url = "http://127.0.0.1:9000/health"
expected_status = 200
[api.expected_response]
status = "ok"
""")
    cfg = monitor.Config(targets_file=toml)
    assert len(cfg.targets) == 2
    assert cfg.websites[0].expect_text == "Welcome"
    assert cfg.api_endpoints[0].expected_response == {"status": "ok"}


def test_duplicate_target_names_rejected(monkeypatch):
    monkeypatch.setenv("WEBSITES", "https://example.com")
    monkeypatch.setenv("API_ENDPOINTS", "https://example.com|https://example.com|200")
    with pytest.raises(monitor.ConfigError, match="Duplicate target name"):
        monitor.Config()


@pytest.mark.parametrize("url,expected", [
    ("https://example.com", "example.com"),
    ("https://www.example.com", "example.com"),
    ("https://app.example.com", "example.com"),
    ("https://www.app.example.com", "example.com"),
    ("https://deep.sub.example.org", "example.org"),
    ("http://127.0.0.1:8000/api", "127.0.0.1"),
    ("http://localhost:9000/health", "localhost"),
])
def test_grouping_pairs_apex_and_www(url, expected):
    assert monitor.registrable_domain(url) == expected
