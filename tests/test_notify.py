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
    assert subject == "[DOWN] app.example.com: 2 targets failing"
    # ...but both targets must still be individually visible.
    assert "app.example.com" in body and "www.app.example.com" in body


def test_a_subdomain_is_never_announced_as_its_parent(config):
    """On 12 November 2026 an outage of a photo subdomain arrived titled with the
    main domain, which reads as the main site being down."""
    notifier = monitor.EmailNotifier(config, dry_run=True)
    pair = [transition("https://photo.example.com"),
            transition("https://www.photo.example.com")]
    subject = notifier._compose_down(pair, monitor.now_utc(), None)[0][0]
    assert subject == "[DOWN] photo.example.com: 2 targets failing"


def test_one_target_is_singular(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    subject = notifier._compose_down([transition("https://a.example.com")],
                                     monitor.now_utc(), None)[0][0]
    assert subject == "[DOWN] a.example.com: 1 target failing"


def test_multiple_sites_named_in_subject(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    items = [transition("https://a.example.com"), transition("https://b.example.net")]
    subject = notifier._compose_down(items, monitor.now_utc(), None)[0][0]
    assert "2 sites" in subject and "2 targets" in subject
    assert "a.example.com" in subject and "b.example.net" in subject


def test_suspected_monitoring_host_is_in_the_subject(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    subject = notifier._compose_down([transition("https://a.example.com")],
                                     monitor.now_utc(), "banner", suspect_self=True)[0][0]
    assert "monitoring host suspected" in subject


def test_html_part_escapes_what_the_server_sent(config):
    """A remote API's field values reach the error text; they must not become live
    HTML (a tracking image, a fake login link) in the alert."""
    notifier = monitor.EmailNotifier(config, dry_run=True)
    t = transition("https://a.example.com",
                   error="API field 'status' is '<img src=https://evil/x.gif>', expected 'ok'")
    html = notifier._compose_down([t], monitor.now_utc(), "<b>banner</b>")[0][2]
    assert "<img" not in html and "&lt;img" in html
    assert "<b>banner" not in html


def test_secrets_in_urls_are_masked_in_alerts(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    t = transition("https://user:hunter2@a.example.com/health?api_key=SECRET123&x=1")
    _, body, html, _ = notifier._compose_down([t], monitor.now_utc(), None)[0]
    assert "hunter2" not in body and "SECRET123" not in body
    assert "hunter2" not in html and "SECRET123" not in html
    assert "api_key=***" in body and "x=1" in body


def test_nested_secrets_are_redacted():
    text = monitor.redact({"detail": {"db_password": "hunter2", "ok": True},
                           "items": [{"token": "abc"}]})
    assert "hunter2" not in text and "abc" not in text and '"ok": true' in text


def test_flapping_notice_names_the_targets_and_the_rule(config):
    notifier = monitor.EmailNotifier(config, dry_run=True)
    t = transition("https://photo.example.com")
    t.flap_event, t.flapping, t.flap_changes, t.flap_failures, t.flap_checks = \
        "start", True, 6, 3, 12
    subject, body, html, key = notifier._compose_flap([t], monitor.now_utc(), None)
    assert subject.startswith("[FLAPPING] photo.example.com")
    assert "6 changes of state and 3 failed checks in its last 12 checks" in body
    assert "lasted 15m" in body and key.startswith("FLAP:")


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
