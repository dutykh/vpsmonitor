"""Alert coalescing and email composition.
Author: Dr. Denys Dutykh."""
from datetime import timedelta

import monitor


def transition(url, kind="DOWN", duration=None, error="Unexpected status code: 503"):
    target = monitor.Target(name=url, url=url)
    return monitor.Transition(
        target=target, healthy=False, kind=kind, incident_id=abs(hash(url)) % 1000,
        duration_s=duration,
        details={"status_code": 503, "response_time_ms": 8.0, "error": error,
                 "fail_class": "http_status"},
    )


def test_apex_and_www_coalesce_into_one_email(config):
    """7 domains monitored as 14 URLs used to mean two near-identical emails
    per incident. They must now arrive as one."""
    notifier = monitor.EmailNotifier(config, dry_run=True)
    pair = [transition("https://app.example.com"),
            transition("https://www.app.example.com")]
    composed = notifier._compose_down(pair, monitor.now_utc(), None)
    assert len(composed) == 1
    subject, body, _html, _key = composed[0]
    assert "example.com" in subject
    # ...but both targets must still be individually visible.
    assert "app.example.com" in body and "www.app.example.com" in body


def test_multiple_domains_named_in_subject(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    items = [transition("https://a.example.com"), transition("https://b.example.net")]
    subject = notifier._compose_down(items, monitor.now_utc(), None)[0][0]
    assert "2 domains" in subject and "2 targets" in subject


def test_grouping_can_be_disabled(config):
    config.group_alerts = False
    notifier = monitor.EmailNotifier(config, dry_run=True)
    items = [transition("https://a.example.com"), transition("https://b.example.net")]
    assert len(notifier._compose_down(items, monitor.now_utc(), None)) == 2


def test_still_down_subject_for_realert(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    items = [transition("https://a.example.com", kind="REALERT", duration=7200)]
    subject, body, _, _ = notifier._compose_down(items, monitor.now_utc(), None)[0]
    assert "STILL DOWN" in subject
    assert "down for 2h" in body


def test_resolved_email_reports_duration(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    t = transition("https://a.example.com", kind="RESOLVED", duration=9000)
    t.started_at = monitor.now_utc() - timedelta(seconds=9000)
    subject, body, _, _ = notifier._compose_resolved([t], monitor.now_utc())[0]
    assert "RESOLVED" in subject and "2h 30m" in subject
    assert "Duration: 2h 30m" in body


def test_mixed_failure_classes_are_flagged(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    a = transition("https://a.example.com")
    b = transition("https://b.example.com", error="Timeout after 30 seconds")
    b.details["fail_class"] = "timeout"
    body = notifier._compose_down([a, b], monitor.now_utc(), None)[0][1]
    assert "mixed failure types" in body


def test_banner_is_rendered(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    body = notifier._compose_down([transition("https://a.example.com")],
                                  monitor.now_utc(), "Monitoring gap of 6h")[0][1]
    assert "Monitoring gap of 6h" in body


def test_dedup_keys_differ_per_incident_set(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    ts = monitor.now_utc()
    one = notifier._compose_down([transition("https://a.example.com")], ts, None)[0][3]
    two = notifier._compose_down([transition("https://b.example.com")], ts, None)[0][3]
    assert one != two


def test_api_body_is_redacted_in_alert(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    t = transition("http://127.0.0.1:8000/health")
    t.target.kind = "api"
    t.details["response_data"] = {"status": "degraded", "api_token": "SECRET123"}
    body = notifier._compose_down([t], monitor.now_utc(), None)[0][1]
    assert "SECRET123" not in body and "<redacted>" in body


def test_dry_run_sends_nothing(config):
    assert monitor.EmailNotifier(config, dry_run=True).send("s", "b") is False


def test_html_alternative_is_produced(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    _, _, html, _ = notifier._compose_down([transition("https://a.example.com")],
                                           monitor.now_utc(), None)[0]
    assert html.startswith("<html>") and "a.example.com" in html
