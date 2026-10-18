
import re
from datetime import datetime


class AuthLogParser:
    """Parse Linux authentication and session log entries."""

    FAILED_LOGIN_PATTERN = re.compile(
        r"Failed password for (?:invalid user )?"
        r"(?P<username>\S+) from (?P<src_ip>\S+) "
        r"port (?P<src_port>\d+)"
    )
    SUCCESSFUL_LOGIN_PATTERN = re.compile(
        r"Accepted password for (?P<username>\S+) "
        r"from (?P<src_ip>\S+) port (?P<src_port>\d+)"
    )
    SUCCESSFUL_PUBLICKEY_PATTERN = re.compile(
        r"Accepted publickey for (?P<username>\S+) "
        r"from (?P<src_ip>\S+) port (?P<src_port>\d+)"
    )
    INVALID_USER_PATTERN = re.compile(
        r"Invalid user (?P<username>\S+) from (?P<src_ip>\S+)"
    )

    SUDO_COMMAND_PATTERN = re.compile(
        r"sudo:\s+(?P<username>\S+)\s*:\s+"
        r"TTY=(?P<tty>\S+)\s*;\s+"
        r"PWD=(?P<pwd>[^;]+)\s*;\s+"
        r"USER=(?P<target_user>\S+)\s*;\s+"
        r"COMMAND=(?P<command>.+)$"
    )
    SUDO_INCORRECT_PASSWORD_PATTERN = re.compile(
        r"sudo:\s+(?P<username>\S+)\s*:\s+"
        r"(?P<attempts>\d+)\s+incorrect password attempts?"
    )
    UNIX_CHKPWD_FAILURE_PATTERN = re.compile(
        r"unix_chkpwd\[\d+\]:\s+password check failed for user "
        r"\((?P<username>[^)]+)\)"
    )
    SUDO_SESSION_OPEN_PATTERN = re.compile(
        r"sudo:\s+pam_unix\(sudo:session\):\s+"
        r"session opened for user "
        r"(?P<target_user>\S+)\(uid=(?P<target_uid>\d+)\) "
        r"by (?P<username>\S+)\(uid=(?P<uid>\d+)\)"
    )
    SUDO_SESSION_CLOSE_PATTERN = re.compile(
        r"sudo:\s+pam_unix\(sudo:session\):\s+"
        r"session closed for user (?P<target_user>\S+)"
    )
    SUDO_AUTH_FAILURE_PATTERN = re.compile(
        r"sudo:\s+pam_unix\(sudo:auth\):\s+"
        r"authentication failure;.*?\buser=(?P<username>\S+)"
    )

    CRON_SESSION_OPEN_PATTERN = re.compile(
        r"CRON\[\d+\]:\s+pam_unix\(cron:session\):\s+"
        r"session opened for user "
        r"(?P<username>\S+)\(uid=(?P<uid>\d+)\)\s+by\s+"
        r"(?P<by_user>\S+)\(uid=(?P<by_uid>\d+)\)"
    )
    CRON_SESSION_CLOSE_PATTERN = re.compile(
        r"CRON\[\d+\]:\s+pam_unix\(cron:session\):\s+"
        r"session closed for user (?P<username>\S+)"
    )
    GDM_SESSION_OPEN_PATTERN = re.compile(
        r"gdm-password\]:\s+pam_unix\(gdm-password:session\):\s+"
        r"session opened for user "
        r"(?P<username>\S+)\(uid=(?P<uid>\d+)\)\s+by\s+"
        r"(?P<by_user>\S+)\(uid=(?P<by_uid>\d+)\)"
    )
    GDM_SESSION_CLOSE_PATTERN = re.compile(
        r"gdm-password\]:\s+pam_unix\(gdm-password:session\):\s+"
        r"session closed for user (?P<username>\S+)"
    )
    GDM_KEYRING_UNLOCK_PATTERN = re.compile(
        r"gdm-password\]:\s+gkr-pam:\s+unlocked login keyring"
    )
    SYSTEMD_SESSION_OPEN_PATTERN = re.compile(
        r"systemd-logind\[\d+\]:\s+"
        r"New session '(?P<session_id>[^']+)' "
        r"of user '(?P<username>[^']+)' "
        r"with class '(?P<session_class>[^']+)' "
        r"and type '(?P<session_type>[^']+)'"
    )
    SYSTEMD_SESSION_CLOSE_PATTERN = re.compile(
        r"systemd-logind\[\d+\]:\s+"
        r"Removed session (?P<session_id>\S+)\."
    )
    PKEXEC_SESSION_OPEN_PATTERN = re.compile(
        r"pkexec:\s+pam_unix\(polkit-1:session\):\s+"
        r"session opened for user "
        r"(?P<target_user>\S+)\(uid=(?P<target_uid>\d+)\)\s+by\s+"
        r"(?P<username>\S+)\(uid=(?P<uid>\d+)\)"
    )

    @staticmethod
    def parse_timestamp(log_line: str) -> datetime:
        iso_match = re.match(
            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
            r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))",
            log_line,
        )
        if iso_match:
            return datetime.fromisoformat(
                iso_match.group(1).replace("Z", "+00:00")
            )

        traditional_match = re.match(
            r"^(?P<month>[A-Z][a-z]{2}) "
            r"(?P<day>\d{1,2}) "
            r"(?P<time>\d{2}:\d{2}:\d{2})",
            log_line,
        )
        if not traditional_match:
            return datetime.now()

        timestamp_text = (
            f"{traditional_match.group('month')} "
            f"{traditional_match.group('day')} "
            f"{traditional_match.group('time')}"
        )
        return datetime.strptime(
            f"{datetime.now().year} {timestamp_text}",
            "%Y %b %d %H:%M:%S",
        )

    @classmethod
    def parse(cls, log_line: str) -> dict | None:
        timestamp = cls.parse_timestamp(log_line)

        def event(
            event_type, action, username, status, severity, message,
            src_ip=None, src_port=None
        ):
            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": event_type,
                "action": action,
                "username": username,
                "src_ip": src_ip,
                "dst_ip": None,
                "src_port": src_port,
                "dst_port": None,
                "status": status,
                "severity": severity,
                "message": message,
                "raw_log": log_line,
            }

        # SSH authentication failures
        match = cls.FAILED_LOGIN_PATTERN.search(log_line)
        if match:
            return event(
                "authentication", "login", match.group("username"),
                "failure", "medium", "Failed SSH login attempt",
                match.group("src_ip"), int(match.group("src_port"))
            )

        # SSH successful password login
        match = cls.SUCCESSFUL_LOGIN_PATTERN.search(log_line)
        if match:
            return event(
                "authentication", "login", match.group("username"),
                "success", "low", "Successful SSH login",
                match.group("src_ip"), int(match.group("src_port"))
            )

        # SSH successful public-key login
        match = cls.SUCCESSFUL_PUBLICKEY_PATTERN.search(log_line)
        if match:
            return event(
                "authentication", "login", match.group("username"),
                "success", "low", "Successful SSH public-key login",
                match.group("src_ip"), int(match.group("src_port"))
            )

        # SSH invalid username
        match = cls.INVALID_USER_PATTERN.search(log_line)
        if match:
            return event(
                "authentication", "login", match.group("username"),
                "failure", "medium", "SSH login attempt with invalid user",
                match.group("src_ip")
            )

        # unix_chkpwd: password check failed
        match = cls.UNIX_CHKPWD_FAILURE_PATTERN.search(log_line)
        if match:
            return event(
                "authentication", "sudo_authentication",
                match.group("username"), "failure", "medium",
                "Password check failed"
            )

        # sudo reports the total number of incorrect attempts
        match = cls.SUDO_INCORRECT_PASSWORD_PATTERN.search(log_line)
        if match:
            username = match.group("username")
            attempts = int(match.group("attempts"))
            return event(
                "authentication", "sudo_authentication",
                username, "failure", "high",
                f"Sudo reported {attempts} incorrect password attempts"
            )

        # PAM sudo authentication failure
        match = cls.SUDO_AUTH_FAILURE_PATTERN.search(log_line)
        if match:
            return event(
                "authentication", "sudo_authentication",
                match.group("username"), "failure", "medium",
                "Failed sudo authentication attempt"
            )

        # sudo command execution
        match = cls.SUDO_COMMAND_PATTERN.search(log_line)
        if match:
            return event(
                "privilege_escalation", "sudo_command",
                match.group("username"), "success", "medium",
                f"Sudo command executed as {match.group('target_user')}: "
                f"{match.group('command').strip()}"
            )

        # sudo session opened
        match = cls.SUDO_SESSION_OPEN_PATTERN.search(log_line)
        if match:
            return event(
                "privilege_escalation", "sudo_session_open",
                match.group("username"), "success", "low",
                f"Sudo session opened for {match.group('target_user')}"
            )

        # sudo session closed
        match = cls.SUDO_SESSION_CLOSE_PATTERN.search(log_line)
        if match:
            return event(
                "privilege_escalation", "sudo_session_close",
                match.group("target_user"), "success", "low",
                f"Sudo session closed for {match.group('target_user')}"
            )

        # CRON session opened
        match = cls.CRON_SESSION_OPEN_PATTERN.search(log_line)
        if match:
            return event(
                "session", "cron_session_open", match.group("username"),
                "success", "low",
                f"CRON session opened for user {match.group('username')}"
            )

        # CRON session closed
        match = cls.CRON_SESSION_CLOSE_PATTERN.search(log_line)
        if match:
            return event(
                "session", "cron_session_close", match.group("username"),
                "success", "low",
                f"CRON session closed for user {match.group('username')}"
            )

        # GDM session opened
        match = cls.GDM_SESSION_OPEN_PATTERN.search(log_line)
        if match:
            return event(
                "session", "gdm_session_open", match.group("username"),
                "success", "low",
                f"Desktop login session opened for user {match.group('username')}"
            )

        # GDM session closed
        match = cls.GDM_SESSION_CLOSE_PATTERN.search(log_line)
        if match:
            return event(
                "session", "gdm_session_close", match.group("username"),
                "success", "low",
                f"Desktop login session closed for user {match.group('username')}"
            )

        # GDM keyring unlock
        if cls.GDM_KEYRING_UNLOCK_PATTERN.search(log_line):
            return event(
                "authentication", "keyring_unlock", None,
                "success", "low", "GDM login keyring unlocked"
            )

        # systemd session opened
        match = cls.SYSTEMD_SESSION_OPEN_PATTERN.search(log_line)
        if match:
            return event(
                "session", "systemd_session_open", match.group("username"),
                "success", "low",
                f"Systemd session {match.group('session_id')} opened for user "
                f"{match.group('username')} "
                f"(class={match.group('session_class')}, "
                f"type={match.group('session_type')})"
            )

        # systemd session closed
        match = cls.SYSTEMD_SESSION_CLOSE_PATTERN.search(log_line)
        if match:
            return event(
                "session", "systemd_session_close", None,
                "success", "low",
                f"Systemd session {match.group('session_id')} removed"
            )

        # pkexec session opened
        match = cls.PKEXEC_SESSION_OPEN_PATTERN.search(log_line)
        if match:
            return event(
                "privilege_escalation", "pkexec_session_open",
                match.group("username"), "success", "medium",
                f"Pkexec session opened as {match.group('target_user')} "
                f"by {match.group('username')}"
            )

        return None
