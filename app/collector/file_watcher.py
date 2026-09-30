import time
from pathlib import Path
from typing import Callable


class FileWatcher:
    """
    Watch a log file and process newly appended lines.
    """

    def __init__(
        self,
        file_path: str,
        callback: Callable[[str], None],
        poll_interval: float = 1.0,
    ):
        self.file_path = Path(file_path)
        self.callback = callback
        self.poll_interval = poll_interval
        self.running = False

    def start(self):
        """
        Start watching the file.

        Existing content is skipped. Only newly appended
        lines are processed.
        """

        if not self.file_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.file_path}")

        self.running = True

        with self.file_path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as log_file:

            # Start at the current end of the file.
            log_file.seek(0, 2)

            print(f"Watching log file: {self.file_path}")

            while self.running:
                line = log_file.readline()

                if line:
                    line = line.rstrip("\n")

                    if line:
                        self.callback(line)

                else:
                    time.sleep(self.poll_interval)

    def stop(self):
        """
        Stop watching the file.
        """

        self.running = False
