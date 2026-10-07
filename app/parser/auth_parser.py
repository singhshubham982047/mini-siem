import re
from datetime import datetime


class AuthLogParser:
    """
    Parse Linux SSH authentication log entries.
    """

    FAILED_LOGIN_PATTERN = re.compile(
        r"Failed password for (?:invalid user )?"
        r"(?P<username>\S+) "
        r"from (?P<src_ip>\S+) "
        r"port (?P<src_port>\d+)"
    )

    SUCCESSFUL_LOGIN_PATTERN = re.compile(
        r"Accepted password for "
        r"(?P<username>\S+) "
        r"from (?P<src_ip>\S+) "
        r"port (?P<src_port>\d+)"
    )
    SUCCESSFUL_PUBLICKEY_PATTERN = re.compile(
        r"Accepted publickey for "
        r"(?P<username>\S+) "
        r"from (?P<src_ip>\S+) "
        r"port (?P<src_port>\d+)"
    )
    INVALID_USER_PATTERN = re.compile(
        r"Invalid user " r"(?P<username>\S+) " r"from (?P<src_ip>\S+)"
    )

    SUDO_COMMAND_PATTERN = re.compile(
        r"sudo:\s+"
        r"(?P<username>\S+)\s*:\s+"
        r"TTY=(?P<tty>\S+)\s*;\s+"
        r"PWD=(?P<pwd>[^;]+)\s*;\s+"
        r"USER=(?P<target_user>\S+)\s*;\s+"
        r"COMMAND=(?P<command>.+)$"
    )

    SUDO_SESSION_OPEN_PATTERN = re.compile(
        r"sudo:\s+pam_unix\(sudo:session\):\s+"
        r"session opened for user "
        r"(?P<target_user>\S+)\(uid=(?P<target_uid>\d+)\) "
        r"by "
        r"(?P<username>\S+)\(uid=(?P<uid>\d+)\)"
    )

    SUDO_SESSION_CLOSE_PATTERN = re.compile(
        r"sudo:\s+pam_unix\(sudo:session\):\s+"
        r"session closed for user "
        r"(?P<target_user>\S+)"
    )
    SUDO_AUTH_FAILURE_PATTERN = re.compile(
        r"sudo:\s+pam_unix\(sudo:auth\):\s+"
        r"authentication failure;"
        r".*?\buser=(?P<username>\S+)"
    )
    CRON_SESSION_OPEN_PATTERN = re.compile(
        r"CRON\[\d+\]:\s+pam_unix\(cron:session\):\s+"
        r"session opened for user "
        r"(?P<username>\S+)\(uid=(?P<uid>\d+)\)"
        r"\s+by\s+"
        r"(?P<by_user>\S+)\(uid=(?P<by_uid>\d+)\)"
    )

    CRON_SESSION_CLOSE_PATTERN = re.compile(
        r"CRON\[\d+\]:\s+pam_unix\(cron:session\):\s+"
        r"session closed for user "
        r"(?P<username>\S+)"
    )
    GDM_SESSION_OPEN_PATTERN = re.compile(
        r"gdm-password\]:\s+pam_unix\(gdm-password:session\):\s+"
        r"session opened for user "
        r"(?P<username>\S+)\(uid=(?P<uid>\d+)\)"
        r"\s+by\s+"
        r"(?P<by_user>\S+)\(uid=(?P<by_uid>\d+)\)"
    )

    GDM_SESSION_CLOSE_PATTERN = re.compile(
        r"gdm-password\]:\s+pam_unix\(gdm-password:session\):\s+"
        r"session closed for user "
        r"(?P<username>\S+)"
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
        r"systemd-logind\[\d+\]:\s+" r"Removed session (?P<session_id>\S+)\."
    )
    PKEXEC_SESSION_OPEN_PATTERN = re.compile(
        r"pkexec:\s+pam_unix\(polkit-1:session\):\s+"
        r"session opened for user "
        r"(?P<target_user>\S+)\(uid=(?P<target_uid>\d+)\)"
        r"\s+by\s+"
        r"(?P<username>\S+)\(uid=(?P<uid>\d+)\)"
    )

    @staticmethod
    def parse_timestamp(log_line: str) -> datetime:
        """
        Parse timestamps from Linux authentication logs.

        Supports:

        1. Traditional syslog format:
           Sep 23 09:15:22

        2. ISO-8601 format used by the current system:
           2026-10-03T19:12:49.346518+05:30
        """

        # -------------------------------------------------
        # ISO-8601 timestamp
        # -------------------------------------------------

        iso_match = re.match(
            r"^(?P<timestamp>"
            r"\d{4}-\d{2}-\d{2}"
            r"T"
            r"\d{2}:\d{2}:\d{2}"
            r"(?:\.\d+)?"
            r"(?:Z|[+-]\d{2}:\d{2})"
            r")",
            log_line,
        )

        if iso_match:
            return datetime.fromisoformat(
                iso_match.group("timestamp").replace(
                    "Z",
                    "+00:00",
                )
            )

        # -------------------------------------------------
        # Traditional syslog timestamp
        # -------------------------------------------------

        timestamp_match = re.match(
            r"^(?P<month>[A-Z][a-z]{2}) "
            r"(?P<day>\d{1,2}) "
            r"(?P<time>\d{2}:\d{2}:\d{2})",
            log_line,
        )

        if not timestamp_match:
            return datetime.now()

        timestamp_text = (
            f"{timestamp_match.group('month')} "
            f"{timestamp_match.group('day')} "
            f"{timestamp_match.group('time')}"
        )

        current_year = datetime.now().year

        return datetime.strptime(
            f"{current_year} {timestamp_text}",
            "%Y %b %d %H:%M:%S",
        )

    @classmethod
    def parse(cls, log_line: str) -> dict | None:
        """
        Parse a Linux authentication log line.

        Returns:
            A dictionary containing structured event data,
            or None if the line is not recognized.
        """

        timestamp = cls.parse_timestamp(log_line)

        # Failed SSH login
        failed_match = cls.FAILED_LOGIN_PATTERN.search(log_line)

        sudo_match = AuthLogParser.SUDO_COMMAND_PATTERN.search(log_line)

        if sudo_match:
            username = sudo_match.group("username")
            target_user = sudo_match.group("target_user")
            command = sudo_match.group("command").strip()

            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "privilege_escalation",
                "action": "sudo_command",
                "username": username,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "status": "success",
                "severity": "medium",
                "message": (f"Sudo command executed as {target_user}: {command}"),
                "raw_log": log_line,
            }

        sudo_session_open_match = AuthLogParser.SUDO_SESSION_OPEN_PATTERN.search(
            log_line
        )

        if sudo_session_open_match:
            username = sudo_session_open_match.group("username")
            target_user = sudo_session_open_match.group("target_user")

            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "privilege_escalation",
                "action": "sudo_session_open",
                "username": username,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "status": "success",
                "severity": "low",
                "message": (f"Sudo session opened for {target_user}"),
                "raw_log": log_line,
            }
        sudo_session_close_match = AuthLogParser.SUDO_SESSION_CLOSE_PATTERN.search(
            log_line
        )

        if sudo_session_close_match:
            target_user = sudo_session_close_match.group("target_user")

            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "privilege_escalation",
                "action": "sudo_session_close",
                "username": target_user,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "status": "success",
                "severity": "low",
                "message": (f"Sudo session closed for {target_user}"),
                "raw_log": log_line,
            }
        sudo_auth_failure_match = AuthLogParser.SUDO_AUTH_FAILURE_PATTERN.search(
            log_line
        )

        if sudo_auth_failure_match:
            username = sudo_auth_failure_match.group("username")

            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "authentication",
                "action": "sudo_authentication",
                "username": username,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "status": "failure",
                "severity": "medium",
                "message": "Failed sudo authentication attempt",
                "raw_log": log_line,
            }

        if failed_match:
            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "authentication",
                "action": "login",
                "username": failed_match.group("username"),
                "src_ip": failed_match.group("src_ip"),
                "src_port": int(failed_match.group("src_port")),
                "status": "failure",
                "severity": "medium",
                "message": "Failed SSH login attempt",
                "raw_log": log_line,
            }

        # Successful SSH login
        successful_match = cls.SUCCESSFUL_LOGIN_PATTERN.search(log_line)

        if successful_match:
            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "authentication",
                "action": "login",
                "username": successful_match.group("username"),
                "src_ip": successful_match.group("src_ip"),
                "src_port": int(successful_match.group("src_port")),
                "status": "success",
                "severity": "low",
                "message": "Successful SSH login",
                "raw_log": log_line,
            }

        match = cls.SUCCESSFUL_PUBLICKEY_PATTERN.search(log_line)

        if match:
            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "authentication",
                "action": "login",
                "username": match.group("username"),
                "src_ip": match.group("src_ip"),
                "dst_ip": None,
                "src_port": int(match.group("src_port")),
                "dst_port": None,
                "status": "success",
                "severity": "low",
                "message": "Successful SSH public-key login",
                "raw_log": log_line,
            }
        # Invalid SSH user
        invalid_user_match = cls.INVALID_USER_PATTERN.search(log_line)

        if invalid_user_match:
            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "authentication",
                "action": "login",
                "username": invalid_user_match.group("username"),
                "src_ip": invalid_user_match.group("src_ip"),
                "status": "failure",
                "severity": "medium",
                "message": "SSH login attempt with invalid user",
                "raw_log": log_line,
            }

        cron_open_match = cls.CRON_SESSION_OPEN_PATTERN.search(log_line)

        if cron_open_match:
            username = cron_open_match.group("username")

            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "session",
                "action": "cron_session_open",
                "username": username,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "status": "success",
                "severity": "low",
                "message": f"CRON session opened for user {username}",
                "raw_log": log_line,
            }

        cron_close_match = cls.CRON_SESSION_CLOSE_PATTERN.search(log_line)

        if cron_close_match:
            username = cron_close_match.group("username")

            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "session",
                "action": "cron_session_close",
                "username": username,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "status": "success",
                "severity": "low",
                "message": f"CRON session closed for user {username}",
                "raw_log": log_line,
            }
        gdm_open_match = cls.GDM_SESSION_OPEN_PATTERN.search(log_line)

        if gdm_open_match:
            username = gdm_open_match.group("username")

            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "session",
                "action": "gdm_session_open",
                "username": username,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "status": "success",
                "severity": "low",
                "message": f"Desktop login session opened for user {username}",
                "raw_log": log_line,
            }

        gdm_close_match = cls.GDM_SESSION_CLOSE_PATTERN.search(log_line)

        if gdm_close_match:
            username = gdm_close_match.group("username")

            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "session",
                "action": "gdm_session_close",
                "username": username,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "status": "success",
                "severity": "low",
                "message": f"Desktop login session closed for user {username}",
                "raw_log": log_line,
            }

        gdm_keyring_match = cls.GDM_KEYRING_UNLOCK_PATTERN.search(log_line)

        if gdm_keyring_match:
            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "authentication",
                "action": "keyring_unlock",
                "username": None,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "status": "success",
                "severity": "low",
                "message": "GDM login keyring unlocked",
                "raw_log": log_line,
            }

        systemd_open_match = cls.SYSTEMD_SESSION_OPEN_PATTERN.search(log_line)

        if systemd_open_match:
            username = systemd_open_match.group("username")
            session_id = systemd_open_match.group("session_id")
            session_class = systemd_open_match.group("session_class")
            session_type = systemd_open_match.group("session_type")

            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "session",
                "action": "systemd_session_open",
                "username": username,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "status": "success",
                "severity": "low",
                "message": (
                    f"Systemd session {session_id} opened for user "
                    f"{username} "
                    f"(class={session_class}, type={session_type})"
                ),
                "raw_log": log_line,
            }

        systemd_close_match = cls.SYSTEMD_SESSION_CLOSE_PATTERN.search(log_line)

        if systemd_close_match:
            session_id = systemd_close_match.group("session_id")

            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "session",
                "action": "systemd_session_close",
                "username": None,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "status": "success",
                "severity": "low",
                "message": f"Systemd session {session_id} removed",
                "raw_log": log_line,
            }

        pkexec_match = cls.PKEXEC_SESSION_OPEN_PATTERN.search(log_line)

        if pkexec_match:
            username = pkexec_match.group("username")
            target_user = pkexec_match.group("target_user")

            return {
                "timestamp": timestamp,
                "source": "linux",
                "event_type": "privilege_escalation",
                "action": "pkexec_session_open",
                "username": username,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "status": "success",
                "severity": "medium",
                "message": (
                    f"Pkexec session opened as {target_user} " f"by {username}"
                ),
                "raw_log": log_line,
            }
        return None
