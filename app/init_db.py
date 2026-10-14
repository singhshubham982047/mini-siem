
import os
import time

from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app.database.connection import Base, SessionLocal, engine
from app.database import models
from app.database.models import DetectionRule, LogSource


DETECTION_RULES = [
    {
        "name": "ssh_brute_force",
        "description": "Detect repeated failed SSH login attempts.",
        "rule_type": "authentication",
        "severity": "high",
        "threshold": 5,
        "window_minutes": 5,
        "enabled": True,
    },
    {
        "name": "successful_login_after_failures",
        "description": "Detect a successful login after multiple failed attempts.",
        "rule_type": "authentication",
        "severity": "high",
        "threshold": 3,
        "window_minutes": 5,
        "enabled": True,
    },
    {
        "name": "multiple_users_same_ip",
        "description": "Detect authentication attempts involving multiple users from one IP.",
        "rule_type": "authentication",
        "severity": "high",
        "threshold": 3,
        "window_minutes": 5,
        "enabled": True,
    },
    {
        "name": "port_scan",
        "description": "Detect repeated network connection attempts that may indicate scanning.",
        "rule_type": "network",
        "severity": "medium",
        "threshold": 5,
        "window_minutes": 5,
        "enabled": True,
    },
    {
        "name": "sudo_authentication_failure",
        "description": "Detect repeated sudo authentication failures.",
        "rule_type": "authentication",
        "severity": "high",
        "threshold": 3,
        "window_minutes": 5,
        "enabled": True,
    },
]


def initialize_database():
    # Wait for PostgreSQL to accept connections.
    for attempt in range(1, 31):
        try:
            with engine.connect():
                print("Database connection successful.")
            break
        except OperationalError:
            if attempt == 30:
                raise
            print(f"Waiting for database ({attempt}/30)...")
            time.sleep(2)

    # Importing models above registers all mapped tables with Base.
    Base.metadata.create_all(bind=engine)
    print("Database tables are ready.")

    demo_log_path = os.getenv(
        "DEMO_LOG_PATH",
        "/app/demo_logs/docker-demo-auth.log",
    )

    with SessionLocal() as session:
        try:
            # Seed detection rules without overwriting existing rule settings.
            for rule_data in DETECTION_RULES:
                existing_rule = session.scalar(
                    select(DetectionRule).where(
                        DetectionRule.name == rule_data["name"]
                    )
                )
                if existing_rule is None:
                    session.add(DetectionRule(**rule_data))

            # Register the isolated synthetic Docker demo source.
            demo_source = session.scalar(
                select(LogSource).where(
                    LogSource.name == "docker-demo-auth"
                )
            )

            if demo_source is None:
                session.add(
                    LogSource(
                        name="docker-demo-auth",
                        source_type="linux_auth",
                        file_path=demo_log_path,
                        enabled=True,
                    )
                )

            session.commit()
            print("Detection rules and demo log source are ready.")
        except Exception:
            session.rollback()
            raise

    print("Mini SIEM database initialization completed.")


if __name__ == "__main__":
    initialize_database()

