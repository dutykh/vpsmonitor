"""Routes: which channels carry each kind of message.
Author: Dr. Denys Dutykh (Mathematics Department, Khalifa University of Science and
Technology, Abu Dhabi, UAE)."""
import ast
import shlex
import sys

import pytest

import monitor


class FakeServer:
    def __init__(self):
        self.messages = []

    def login(self, user, password):
        pass

    def send_message(self, msg):
        self.messages.append(msg)

    def close(self):
        pass


@pytest.fixture
def server(monkeypatch):
    fake = FakeServer()
    monkeypatch.setattr(monitor, "_smtp_connect", lambda *a, **k: fake)
    return fake


@pytest.fixture
def no_mail(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("no mail may be sent here")
    monkeypatch.setattr(monitor, "_smtp_connect", refuse)


def recording_command(tmp_path, name="record", status=0):
    """A command line writing its arguments and its standard input to a file."""
    script = tmp_path / f"{name}.py"
    out = tmp_path / f"{name}.out"
    script.write_text(
        "import sys\n"
        f"with open({str(out)!r}, 'a') as fh:\n"
        "    fh.write(repr(sys.argv[1:]) + '\\n' + sys.stdin.read() + '\\n--\\n')\n"
        f"sys.exit({status})\n")
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(script))}", out


@pytest.fixture
def recorder(tmp_path, monkeypatch):
    command, out = recording_command(tmp_path)
    monkeypatch.setenv("MESSAGE_COMMAND",
                       command + " --level {level} --kind {kind} --title {subject}")
    return out


def calls(out):
    if not out.exists():
        return []
    blocks = [b for b in out.read_text().split("\n--\n") if b.strip()]
    return [(ast.literal_eval(b.split("\n", 1)[0]), b.split("\n", 1)[1]) for b in blocks]


def test_every_kind_goes_by_email_by_default(config):
    assert config.routes == {kind: ["email"] for kind in monitor.ROUTED_KINDS}


@pytest.mark.parametrize("raw, channels", [
    ("email", ["email"]), ("command", ["command"]), ("email,command", ["email", "command"]),
    ("command + email", ["command", "email"]), ("Email, email", ["email"]),
    ("none", []), ("NONE", []), ("", ["email"]),
])
def test_routes_are_parsed(monkeypatch, recorder, raw, channels):
    monkeypatch.setenv("ROUTE_SUMMARY", raw)
    assert monitor.Config().routes["SUMMARY"] == channels


@pytest.mark.parametrize("raw", ["smoke", "none,email", "telegram"])
def test_a_wrong_route_is_refused(monkeypatch, raw):
    monkeypatch.setenv("ROUTE_DOWN", raw)
    with pytest.raises(monitor.ConfigError, match="ROUTE_DOWN"):
        monitor.Config()


def test_no_mail_settings_are_needed_without_an_email_route(monkeypatch, recorder):
    for key in ("SMTP_SERVER", "SMTP_USERNAME", "SMTP_PASSWORD", "ALERT_EMAIL"):
        monkeypatch.delenv(key)
    for kind in monitor.ROUTED_KINDS:
        monkeypatch.setenv(f"ROUTE_{kind}", "command")
    config = monitor.Config()
    assert not config.uses("email") and config.email_problem()


def test_the_command_channel_needs_a_command(monkeypatch):
    monkeypatch.setenv("ROUTE_DOWN", "email,command")
    with pytest.raises(monitor.ConfigError, match="MESSAGE_COMMAND"):
        monitor.Config()


def test_a_relay_without_login_needs_only_a_sender(monkeypatch, server):
    monkeypatch.delenv("SMTP_USERNAME")
    monkeypatch.delenv("SMTP_PASSWORD")
    with pytest.raises(monitor.ConfigError, match="SMTP_FROM"):
        monitor.Config()
    monkeypatch.setenv("SMTP_FROM", "monitor@example.org")
    assert monitor.Notifier(monitor.Config()).send("[TEST] s", "b", kind="TEST")
    assert server.messages[0]["From"] == "monitor@example.org"


def test_a_message_by_command_carries_subject_kind_and_level(monkeypatch, recorder, no_mail):
    monkeypatch.setenv("ROUTE_DOWN", "command")
    assert monitor.Notifier(monitor.Config()).send("[DOWN] a.example.com", "it is down",
                                                   kind="DOWN")
    (argv, stdin), = calls(recorder)
    assert argv == ["--level", "error", "--kind", "down", "--title", "[DOWN] a.example.com"]
    assert "it is down" in stdin


def test_placeholders_inside_a_subject_are_left_alone(monkeypatch, recorder, no_mail):
    monkeypatch.setenv("ROUTE_NOTIFY", "command")
    subject = "[SECURITY] {level} {kind} '; rm -rf ~"
    assert monitor.Notifier(monitor.Config()).send(subject, "b", kind="NOTIFY")
    assert calls(recorder)[0][0][-1] == subject


def test_both_channels_carry_the_message(monkeypatch, recorder, server, db):
    monkeypatch.setenv("ROUTE_RESOLVED", "email,command")
    notifier = monitor.Notifier(monitor.Config(), db)
    assert notifier.deliver("[RESOLVED] a", "back", kind="RESOLVED", dedup_key="r1") == "sent"
    assert len(server.messages) == 1 and len(calls(recorder)) == 1
    row = db.query_one("SELECT state, channels FROM notifications WHERE dedup_key='r1'")
    assert (row["state"], row["channels"]) == ("sent", "email,command")


def test_one_working_channel_is_enough(monkeypatch, tmp_path, server):
    command, _ = recording_command(tmp_path, "broken", status=4)
    monkeypatch.setenv("MESSAGE_COMMAND", command)
    monkeypatch.setenv("ROUTE_DOWN", "command,email")
    assert monitor.Notifier(monitor.Config()).deliver("[DOWN] a", "b", kind="DOWN") == "sent"
    assert len(server.messages) == 1


def test_route_none_sends_nothing(monkeypatch, recorder, no_mail):
    monkeypatch.setenv("ROUTE_SUMMARY", "none")
    notifier = monitor.Notifier(monitor.Config())
    assert notifier.deliver("[Daily] Uptime", "body", kind="SUMMARY") == "skipped"
    assert notifier.send("[Daily] Uptime", "body", kind="SUMMARY") is False
    assert calls(recorder) == []


def test_flapping_notices_travel_with_their_kinds(monkeypatch, recorder, no_mail):
    monkeypatch.setenv("ROUTE_DOWN", "command")
    monkeypatch.setenv("ROUTE_RESOLVED", "none")
    notifier = monitor.Notifier(monitor.Config())
    assert notifier.deliver("[FLAPPING] a", "b", kind="FLAP") == "sent"
    assert notifier.deliver("[STEADY] a", "b", kind="STEADY") == "skipped"
    assert calls(recorder)[0][0][:4] == ["--level", "warn", "--kind", "flap"]


def test_spare_route_carries_what_the_command_could_not(monkeypatch, tmp_path, no_mail):
    broken, _ = recording_command(tmp_path, "broken", status=3)
    spare, spare_out = recording_command(tmp_path, "spare")
    monkeypatch.setenv("MESSAGE_COMMAND", broken)
    monkeypatch.setenv("FALLBACK_COMMAND", spare + " {subject}")
    monkeypatch.setenv("ROUTE_DOWN", "command")
    assert monitor.Notifier(monitor.Config()).deliver("[DOWN] a", "b", kind="DOWN") == "fallback"
    assert calls(spare_out)[0][0] == ["[DOWN] a"]


def test_spare_route_is_not_the_command_that_just_failed(monkeypatch, tmp_path, no_mail):
    broken, out = recording_command(tmp_path, "broken", status=3)
    monkeypatch.setenv("MESSAGE_COMMAND", broken)
    monkeypatch.setenv("FALLBACK_COMMAND", broken)
    monkeypatch.setenv("ROUTE_DOWN", "command")
    assert monitor.Notifier(monitor.Config()).deliver("[DOWN] a", "b", kind="DOWN") == "failed"
    assert len(calls(out)) == 1


def test_notify_routed_nowhere_exits_cleanly(monkeypatch, no_mail):
    """The watchdog touches its stamp on exit status 0; a message routed nowhere
    on purpose must not look like a failed delivery."""
    monkeypatch.setenv("ROUTE_NOTIFY", "none")
    assert monitor.main(["--notify", "[SECURITY] test"]) == 0


def test_test_command_uses_the_command_channel_only(monkeypatch, recorder, no_mail, capsys):
    assert monitor.main(["--test-command"]) == 0
    (argv, stdin), = calls(recorder)
    assert argv[:4] == ["--level", "info", "--kind", "test"]
    assert "sent by the command channel" in stdin
    assert "Test message sent by command." in capsys.readouterr().out


def test_test_command_without_a_command_says_so(capsys):
    assert monitor.main(["--test-command"]) == 1
    assert "MESSAGE_COMMAND is empty" in capsys.readouterr().err


def test_status_names_the_routes(monkeypatch, recorder, capsys):
    monkeypatch.setenv("ROUTE_SUMMARY", "none")
    monkeypatch.setenv("ROUTE_DOWN", "email,command")
    assert monitor.main(["--status"]) == 0
    out = capsys.readouterr().out
    assert "down by email and command" in out and "summary not sent" in out
