"""Mail transport: sender, connection mode, refused logins and the spare route.
Author: Dr. Denys Dutykh."""
import shlex
import smtplib
import sys

import pytest

import monitor


class FakeServer:
    """Stands in for the SMTP connection and records what the notifier does."""

    def __init__(self, login_error=None):
        self.login_error = login_error
        self.logins = []
        self.messages = []

    def login(self, user, password):
        if self.login_error is not None:
            raise self.login_error
        self.logins.append((user, password))

    def send_message(self, msg):
        self.messages.append(msg)

    def close(self):
        pass


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr(monitor.time, "sleep", lambda _s: None)


@pytest.fixture
def spare(tmp_path, monkeypatch):
    """A spare-route command that writes the subject and the body into a file."""
    script = tmp_path / "spare.py"
    script.write_text(
        "import sys\n"
        "with open(sys.argv[1], 'a') as out:\n"
        "    out.write('SUBJECT=' + sys.argv[2] + '\\n' + sys.stdin.read() + '\\n--\\n')\n")
    out = tmp_path / "spare.out"
    command = f"{shlex.quote(sys.executable)} {shlex.quote(str(script))} {out} {{subject}}"
    monkeypatch.setenv("FALLBACK_COMMAND", command)
    return out


def unreachable(*_args, **_kwargs):
    raise ConnectionRefusedError("mail server is down")


def test_sender_is_the_login_address_and_message_id_uses_its_domain(monkeypatch):
    monkeypatch.setenv("SMTP_USERNAME", "vpsmonitor@example.org")
    server = FakeServer()
    monkeypatch.setattr(monitor, "_smtp_connect", lambda *a, **k: server)
    assert monitor.EmailNotifier(monitor.Config()).send("[TEST] subject", "body", kind="TEST")
    msg = server.messages[0]
    assert msg["From"] == "vpsmonitor@example.org"
    assert msg["Message-ID"].endswith("@example.org>")
    assert "vpsmonitor.local" not in msg["Message-ID"]


def test_sender_domain_falls_back_to_the_host_name_for_a_bare_login():
    assert monitor._sender_domain("vpsmonitor") == monitor.socket.getfqdn()
    assert monitor._sender_domain("Name <a@b.org>") == "b.org"


def test_refused_login_is_not_retried(config, monkeypatch):
    """The mail server bans an address after a few refused logins; the same
    wrong password must not be sent twice."""
    calls = []

    def connect(*args, **kwargs):
        calls.append(args)
        return FakeServer(login_error=smtplib.SMTPAuthenticationError(535, b"bad password"))

    monkeypatch.setattr(monitor, "_smtp_connect", connect)
    assert monitor.EmailNotifier(config).send("s", "b", kind="TEST") is False
    assert len(calls) == 1


def test_other_failures_are_tried_twice(config, monkeypatch, no_sleep):
    calls = []

    def connect(*args, **kwargs):
        calls.append(args)
        raise ConnectionRefusedError("down")

    monkeypatch.setattr(monitor, "_smtp_connect", connect)
    assert monitor.EmailNotifier(config).send("s", "b", kind="TEST") is False
    assert len(calls) == 2


@pytest.mark.parametrize("security, implicit, starttls", [
    ("ssl", True, False), ("starttls", False, True), ("plain", False, False)])
def test_connection_mode(monkeypatch, security, implicit, starttls):
    seen = {"implicit": False, "starttls": False}

    class Plain:
        def __init__(self, *a, **k):
            pass

        def starttls(self, **_k):
            seen["starttls"] = True

    class Implicit(Plain):
        def __init__(self, *a, **k):
            seen["implicit"] = True

    monkeypatch.setattr(monitor.smtplib, "SMTP", Plain)
    monkeypatch.setattr(monitor.smtplib, "SMTP_SSL", Implicit)
    monitor._smtp_connect("mail.example.com", 587, security, 5)
    assert seen == {"implicit": implicit, "starttls": starttls}


def test_spare_route_carries_an_alert_when_mail_fails(spare, monkeypatch, no_sleep):
    monkeypatch.setattr(monitor, "_smtp_connect", unreachable)
    config = monitor.Config()
    assert monitor.EmailNotifier(config).send("[DOWN] a.example.com", "it is down",
                                              kind="DOWN") is True
    text = spare.read_text()
    assert "SUBJECT=[DOWN] a.example.com" in text and "it is down" in text


@pytest.mark.parametrize("kind", ["TEST", "SUMMARY"])
def test_spare_route_is_not_used_for_test_and_summary(spare, monkeypatch, no_sleep, kind):
    monkeypatch.setattr(monitor, "_smtp_connect", unreachable)
    assert monitor.EmailNotifier(monitor.Config()).send("s", "b", kind=kind) is False
    assert not spare.exists()


def test_spare_route_unused_when_mail_succeeds(spare, monkeypatch):
    monkeypatch.setattr(monitor, "_smtp_connect", lambda *a, **k: FakeServer())
    assert monitor.EmailNotifier(monitor.Config()).send("s", "b", kind="DOWN") is True
    assert not spare.exists()


def test_without_spare_route_a_failure_is_reported(config, monkeypatch, no_sleep):
    monkeypatch.setattr(monitor, "_smtp_connect", unreachable)
    assert monitor.EmailNotifier(config).send("s", "b", kind="DOWN") is False


def test_spare_route_failing_counts_as_failure(monkeypatch, no_sleep):
    monkeypatch.setenv("FALLBACK_COMMAND",
                       f"{shlex.quote(sys.executable)} -c 'import sys; sys.exit(3)'")
    monkeypatch.setattr(monitor, "_smtp_connect", unreachable)
    assert monitor.EmailNotifier(monitor.Config()).send("s", "b", kind="DOWN") is False


def test_spare_route_is_recorded_and_not_repeated(spare, db, monkeypatch, no_sleep):
    monkeypatch.setattr(monitor, "_smtp_connect", unreachable)
    notifier = monitor.EmailNotifier(monitor.Config(), db)
    assert notifier.send("[SSL] a", "b", kind="SSL", dedup_key="SSL:a:day") is True
    row = db.query_one("SELECT state, last_error FROM notifications WHERE dedup_key=?",
                       ("SSL:a:day",))
    assert row["state"] == "fallback" and "down" in row["last_error"]
    assert notifier.send("[SSL] a", "b", kind="SSL", dedup_key="SSL:a:day") is False
    assert spare.read_text().count("SUBJECT=") == 1


def test_failure_without_spare_route_is_recorded_as_failed(config, db, monkeypatch, no_sleep):
    monkeypatch.setattr(monitor, "_smtp_connect", unreachable)
    notifier = monitor.EmailNotifier(config, db)
    assert notifier.send("s", "b", kind="DOWN", dedup_key="k") is False
    assert db.query_one("SELECT state FROM notifications WHERE dedup_key='k'")["state"] == "failed"


def test_subject_is_one_argument_whatever_it_contains(monkeypatch, tmp_path):
    """No shell is involved, so quotes and semicolons in a subject are inert."""
    out = tmp_path / "argv.txt"
    script = tmp_path / "show.py"
    script.write_text(f"import sys\nopen({str(out)!r}, 'w').write(repr(sys.argv[1:]))\n")
    command = f"{shlex.quote(sys.executable)} {shlex.quote(str(script))} {{subject}}"
    subject = "[DOWN] x'; touch /tmp/never; echo \""
    assert monitor.run_fallback(command, subject, "body") is True
    assert out.read_text() == repr([subject])


def test_emergency_message_honours_implicit_tls(monkeypatch):
    monkeypatch.setenv("SMTP_SECURITY", "ssl")
    monkeypatch.setenv("SMTP_PORT", "465")
    seen = {}
    server = FakeServer()

    def connect(host, port, security, timeout):
        seen["args"] = (host, port, security, timeout)
        return server

    monkeypatch.setattr(monitor, "_smtp_connect", connect)
    monitor._emergency_notify("[MONITOR BROKEN] subject", "body")
    assert seen["args"] == ("mail.example.com", 465, "ssl", 30)
    assert server.messages and server.messages[0]["From"] == "monitor@example.com"


def test_emergency_message_uses_spare_route_without_mail_settings(spare, monkeypatch):
    monkeypatch.delenv("SMTP_SERVER")
    monkeypatch.setattr(monitor, "_smtp_connect", unreachable)
    monitor._emergency_notify("[MONITOR BROKEN] subject", "the settings are broken")
    assert "the settings are broken" in spare.read_text()
