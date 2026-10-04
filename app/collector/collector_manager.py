from sqlalchemy.orm import Session

from app.collector.file_watcher import FileWatcher
from app.database.repository import EventRepository
from app.detection.engine import DetectionEngine
from app.parser.auth_parser import AuthLogParser


class CollectorManager:
    """
    Connects the file watcher, parser, database,
    and detection engine.
    """

    def __init__(
        self,
        db: Session,
        file_path: str,
        log_source_id: int,
    ):
        self.db = db
        self.file_path = file_path
        self.log_source_id = log_source_id

        self.watcher = FileWatcher(
            file_path=file_path,
            callback=self.process_log_line,
            poll_interval=0.5,
        )

    def process_log_line(self, raw_log: str):
        """
        Process one newly received log line.
        """

        print(f"\nNew log: {raw_log}")

        # 1. Parse the raw log
        parsed_event = AuthLogParser.parse(raw_log)

        if parsed_event is None:
            print("Log ignored: unsupported format")
            return

        print(
            f"Parsed event: "
            f"{parsed_event['event_type']} | "
            f"{parsed_event['action']} | "
            f"user={parsed_event['username']} | "
            f"src_ip={parsed_event['src_ip']}"
        )

        # 2. Store the parsed event
        event = EventRepository.create(
            db=self.db,
            log_source_id=self.log_source_id,
            **parsed_event,
        )

        print(f"Event stored in PostgreSQL: ID={event.id}")

        # 3. Run detection rules
        alerts = DetectionEngine.process_event(
            db=self.db,
            event=event,
        )

        # 4. Report generated alerts
        for alert in alerts:
            print("\n🚨 ALERT GENERATED")
            print(f"  Rule: {alert.rule_name}")
            print(f"  Severity: {alert.severity}")
            print(f"  Source IP: {alert.src_ip}")
            print(f"  Title: {alert.title}")

    def start(self):
        """
        Start collecting logs.
        """

        print(f"Starting collector for: {self.file_path}")

        self.watcher.start()

    def stop(self):
        """
        Stop collecting logs.
        """

        self.watcher.stop()
