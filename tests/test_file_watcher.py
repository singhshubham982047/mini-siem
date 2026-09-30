import threading
import time
from pathlib import Path

from app.collector.file_watcher import FileWatcher

TEST_FILE = Path("sample_logs/test-watcher.log")


def main():
    TEST_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    TEST_FILE.write_text(
        "Initial line\n",
        encoding="utf-8",
    )

    received_lines = []

    def handle_line(line: str):
        print(f"Received: {line}")
        received_lines.append(line)

    watcher = FileWatcher(
        file_path=str(TEST_FILE),
        callback=handle_line,
        poll_interval=0.1,
    )

    watcher_thread = threading.Thread(
        target=watcher.start,
        daemon=True,
    )

    watcher_thread.start()

    time.sleep(0.3)

    # Append new log entries.
    with TEST_FILE.open(
        "a",
        encoding="utf-8",
    ) as log_file:
        log_file.write("New log line 1\n")
        log_file.write("New log line 2\n")

    time.sleep(0.5)

    watcher.stop()

    watcher_thread.join(timeout=2)

    expected = [
        "New log line 1",
        "New log line 2",
    ]

    if received_lines != expected:
        raise RuntimeError(f"Unexpected lines: {received_lines}")

    print("\nFile watcher test passed")

    TEST_FILE.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
