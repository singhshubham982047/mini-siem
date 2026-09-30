from app.parser.auth_parser import AuthLogParser


def main():
    test_logs = [
        (
            "Sep 23 09:15:22 ubuntu sshd[1234]: "
            "Failed password for testuser from 192.168.1.100 "
            "port 54321 ssh2"
        ),
        (
            "Sep 23 09:16:10 ubuntu sshd[1235]: "
            "Accepted password for admin from 10.0.0.25 "
            "port 45678 ssh2"
        ),
        ("Sep 23 09:17:05 ubuntu sshd[1236]: " "Invalid user hacker from 172.16.0.50"),
        ("Sep 23 09:18:00 ubuntu systemd[1]: " "Started some system service"),
    ]

    for index, log_line in enumerate(test_logs, start=1):
        print(f"\n--- Test Log {index} ---")
        print(f"Raw log: {log_line}")

        parsed_event = AuthLogParser.parse(log_line)

        if parsed_event is None:
            print("Result: Log not recognized")
            continue

        print("Result: Log parsed successfully")

        for field, value in parsed_event.items():
            print(f"  {field}: {value}")


if __name__ == "__main__":
    main()
