from app.parser.auth_parser import AuthLogParser


CRON_OPEN_LOG = (
    "2026-10-05T08:30:01.987514+05:30 "
    "ubuntu-HP-EliteBook-840-G6 "
    "CRON[14577]: pam_unix(cron:session): "
    "session opened for user root(uid=0) by root(uid=0)"
)

CRON_CLOSE_LOG = (
    "2026-10-05T08:30:01.988807+05:30 "
    "ubuntu-HP-EliteBook-840-G6 "
    "CRON[14577]: pam_unix(cron:session): "
    "session closed for user root"
)


def test_cron_session_open():
    event = AuthLogParser.parse(CRON_OPEN_LOG)

    assert event is not None
    assert event["event_type"] == "session"
    assert event["action"] == "cron_session_open"
    assert event["username"] == "root"
    assert event["status"] == "success"
    assert event["severity"] == "low"

    print("\nCRON SESSION OPEN")
    print("event_type:", event["event_type"])
    print("action:", event["action"])
    print("username:", event["username"])
    print("status:", event["status"])
    print("severity:", event["severity"])
    print("message:", event["message"])


def test_cron_session_close():
    event = AuthLogParser.parse(CRON_CLOSE_LOG)

    assert event is not None
    assert event["event_type"] == "session"
    assert event["action"] == "cron_session_close"
    assert event["username"] == "root"
    assert event["status"] == "success"
    assert event["severity"] == "low"

    print("\nCRON SESSION CLOSE")
    print("event_type:", event["event_type"])
    print("action:", event["action"])
    print("username:", event["username"])
    print("status:", event["status"])
    print("severity:", event["severity"])
    print("message:", event["message"])


if __name__ == "__main__":
    test_cron_session_open()
    test_cron_session_close()

    print("\nCRON parser tests passed.")
