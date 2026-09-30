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

    INVALID_USER_PATTERN = re.compile(
        r"Invalid user " r"(?P<username>\S+) " r"from (?P<src_ip>\S+)"
    )

    @staticmethod
    def parse_timestamp(log_line: str) -> datetime:
        """
        Extract the timestamp from a Linux syslog entry.

        Example:
        Sep 23 09:15:22
        """

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

        return None
