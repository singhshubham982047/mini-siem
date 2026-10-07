from app.parser.auth_parser import AuthLogParser


log = (
    "2026-10-06T10:30:15.123456+05:30 "
    "ubuntu-HP-EliteBook-840-G6 sshd[5678]: "
    "Accepted publickey for ubuntu from 192.168.1.25 port 52234 ssh2: "
    "ED25519 SHA256:example"
)

parser = AuthLogParser()
result = parser.parse(log)

print("\n--- SSH Public-Key Login Test ---")
print(f"Raw log: {log}")

if result is None:
    print("ERROR: Log was not recognized")
    raise SystemExit(1)

print("Result: Log parsed successfully")

for key in [
    "timestamp",
    "source",
    "event_type",
    "action",
    "username",
    "src_ip",
    "src_port",
    "status",
    "severity",
    "message",
]:
    print(f"  {key}: {result.get(key)}")

assert result["event_type"] == "authentication"
assert result["action"] == "login"
assert result["username"] == "ubuntu"
assert result["src_ip"] == "192.168.1.25"
assert result["src_port"] == 52234
assert result["status"] == "success"
assert result["severity"] == "low"

print("\nSSH public-key parser test passed.")
