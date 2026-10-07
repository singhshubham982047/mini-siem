from app.parser.auth_parser import AuthLogParser


OPEN_LOG = (
    "2026-10-06T18:52:36.881715+05:30 "
    "ubuntu-HP-EliteBook-840-G6 gdm-password]: "
    "pam_unix(gdm-password:session): session opened for user "
    "ubuntu(uid=1000) by ubuntu(uid=0)"
)

CLOSE_LOG = (
    "2026-10-06T18:52:41.762740+05:30 "
    "ubuntu-HP-EliteBook-840-G6 gdm-password]: "
    "pam_unix(gdm-password:session): session closed for user ubuntu"
)


parser = AuthLogParser()

print("\n--- GDM SESSION OPEN ---")

result = parser.parse(OPEN_LOG)

if result is None:
    raise RuntimeError("GDM session-open log was not parsed.")

for key in [
    "timestamp",
    "source",
    "event_type",
    "action",
    "username",
    "status",
    "severity",
    "message",
]:
    print(f"{key}: {result.get(key)}")

assert result["event_type"] == "session"
assert result["action"] == "gdm_session_open"
assert result["username"] == "ubuntu"
assert result["status"] == "success"


print("\n--- GDM SESSION CLOSE ---")

result = parser.parse(CLOSE_LOG)

if result is None:
    raise RuntimeError("GDM session-close log was not parsed.")

for key in [
    "timestamp",
    "source",
    "event_type",
    "action",
    "username",
    "status",
    "severity",
    "message",
]:
    print(f"{key}: {result.get(key)}")

assert result["event_type"] == "session"
assert result["action"] == "gdm_session_close"
assert result["username"] == "ubuntu"
assert result["status"] == "success"


print("\nGDM session parser tests passed.")
