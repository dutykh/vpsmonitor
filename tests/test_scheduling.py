"""Alert scheduling: the escalation ladder and the cron-jitter grace window.

These cover the production bug where ALERT_COOLDOWN equalled the cron period and
alerts silently alternated between odd and even hours.
Author: Dr. Denys Dutykh.
"""
import monitor


def test_jitter_grace_absorbs_early_cron_run():
    # The exact regression: a run arriving 3 seconds early measured 3597s against
    # a 3600s threshold, and the old `now > last + cooldown` check skipped the hour.
    assert monitor.is_notification_due(3597, 3600) is True
    assert monitor.is_notification_due(3600, 3600) is True
    assert monitor.is_notification_due(3301, 3600) is True     # within 300s slack
    assert monitor.is_notification_due(1800, 3600) is False    # genuinely too early


def test_first_notification_is_immediate():
    assert monitor.is_notification_due(0, None) is True
    count, offset = monitor.plan_next_notification(0.0, 0)
    assert count == 1
    assert offset == 3600


def test_thirty_hour_outage_sends_six_emails_not_thirty():
    """Replays the real 2026-08-30/31 adean outage: hourly checks, 3s early."""
    count, next_offset = 0, 0.0
    hours_sent = []
    for hour in range(31):
        elapsed = hour * 3600 - 3
        if monitor.is_notification_due(elapsed, next_offset):
            count, next_offset = monitor.plan_next_notification(elapsed, count)
            hours_sent.append(hour)
    assert hours_sent == [0, 1, 3, 7, 15, 27]
    assert len(hours_sent) == 6


def test_schedule_does_not_compress_after_firing_early():
    """Without slack inside plan_next_notification the ladder slides back to hourly."""
    count, next_offset = monitor.plan_next_notification(-3, 0)
    assert next_offset == 3600
    count, next_offset = monitor.plan_next_notification(3597, count)
    assert next_offset == 3 * 3600, "second gap must be 2h, not 1h"


def test_escalation_is_monotonic_and_unbounded():
    count, offset = 0, 0.0
    offsets = []
    for _step in range(12):
        count, offset = monitor.plan_next_notification(offset, count)
        offsets.append(offset)
    assert offsets == sorted(offsets)
    assert offsets[-1] > 51 * 3600


def test_long_gap_jumps_to_correct_step_without_bursting():
    """A 6-hour monitoring gap must produce ONE email at the right rung,
    not a backdated burst of every step that elapsed while we were blind."""
    count, offset = monitor.plan_next_notification(6 * 3600, 1)
    # Steps at +0, +1h and +3h are all in the past; the next rung is +7h.
    assert count == 3
    assert offset == 7 * 3600

    # An even longer blackout still yields a single step, further up the ladder.
    count, offset = monitor.plan_next_notification(40 * 3600, 1)
    assert offset == 51 * 3600


def test_changes_ignore_a_sustained_outage():
    assert monitor.count_changes([False] * 12) == 0
    assert monitor.count_changes([True] * 12) == 0
    assert monitor.count_changes([True, False] * 6) == 11
    assert monitor.count_changes([True, False, True]) == 2
    assert monitor.count_changes([]) == 0


def test_long_gap_past_the_ladder_sends_one_reminder_not_a_burst():
    """A monitor off from 30 h to 200 h used to send seven reminders in half an
    hour on its return, one per daily rung it had missed."""
    count, offset = monitor.plan_next_notification(200 * 3600, 6)
    assert offset > 200 * 3600
    assert monitor.is_notification_due(200 * 3600 + 300, offset) is False


def test_daily_tail_keeps_its_rhythm():
    count, offset = monitor.plan_next_notification(51 * 3600 - 3, 6)
    assert offset == 75 * 3600
    count, offset = monitor.plan_next_notification(75 * 3600 - 3, count)
    assert offset == 99 * 3600


def test_alert_cooldown_scales_the_ladder():
    """ALERT_COOLDOWN was read and never used; it now sets the first reminder."""
    count, offset = monitor.plan_next_notification(0.0, 0, scale=2.0)
    assert offset == 2 * 3600
    count, offset = monitor.plan_next_notification(2 * 3600 - 3, count, scale=2.0)
    assert offset == 6 * 3600
