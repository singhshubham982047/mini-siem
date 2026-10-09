from datetime import datetime
from typing import Optional

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.database.models import (
    Alert,
    DetectionRule,
    Event,
    LogSource,
)


class LogSourceRepository:
    """Database operations for log sources."""

    @staticmethod
    def create(
        db: Session,
        name: str,
        source_type: str,
        file_path: str,
    ) -> LogSource:
        log_source = LogSource(
            name=name,
            source_type=source_type,
            file_path=file_path,
        )

        db.add(log_source)
        db.commit()
        db.refresh(log_source)

        return log_source

    @staticmethod
    def get_by_name(
        db: Session,
        name: str,
    ) -> Optional[LogSource]:
        statement = select(LogSource).where(LogSource.name == name)

        return db.scalar(statement)

    @staticmethod
    def get_all(
        db: Session,
    ) -> list[LogSource]:
        statement = select(LogSource).order_by(LogSource.id)

        return list(db.scalars(statement).all())


class EventRepository:
    """Database operations for security events."""

    @staticmethod
    def create(
        db: Session,
        timestamp: datetime,
        source: str,
        event_type: str,
        raw_log: str,
        action: Optional[str] = None,
        username: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        status: Optional[str] = None,
        severity: str = "low",
        message: Optional[str] = None,
        log_source_id: Optional[int] = None,
    ) -> Event:
        event = Event(
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            action=action,
            username=username,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            status=status,
            severity=severity,
            message=message,
            raw_log=raw_log,
            log_source_id=log_source_id,
        )

        db.add(event)
        db.commit()
        db.refresh(event)

        return event

    @staticmethod
    def get_recent(
        db: Session,
        limit: int = 100,
    ) -> list[Event]:
        statement = select(Event).order_by(desc(Event.timestamp)).limit(limit)

        return list(db.scalars(statement).all())

    @staticmethod
    def get_by_id(
        db: Session,
        event_id: int,
    ) -> Optional[Event]:
        """Retrieve a security event by its primary key."""
        return db.get(Event, event_id)

    @staticmethod
    def get_by_source_ip(
        db: Session,
        src_ip: str,
        limit: int = 100,
    ) -> list[Event]:
        statement = (
            select(Event)
            .where(Event.src_ip == src_ip)
            .order_by(desc(Event.timestamp))
            .limit(limit)
        )

        return list(db.scalars(statement).all())


class AlertRepository:
    """Database operations for security alerts."""

    @staticmethod
    def create(
        db: Session,
        rule_name: str,
        severity: str,
        title: str,
        description: Optional[str] = None,
        src_ip: Optional[str] = None,
        username: Optional[str] = None,
    ) -> Alert:
        alert = Alert(
            rule_name=rule_name,
            severity=severity,
            title=title,
            description=description,
            src_ip=src_ip,
            username=username,
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

    @staticmethod
    def get_open(
        db: Session,
        limit: int = 100,
    ) -> list[Alert]:
        statement = (
            select(Alert)
            .where(Alert.status == "open")
            .order_by(desc(Alert.created_at))
            .limit(limit)
        )

        return list(db.scalars(statement).all())


class DetectionRuleRepository:
    """Database operations for detection rules."""

    @staticmethod
    def create(
        db: Session,
        name: str,
        rule_type: str,
        severity: str,
        threshold: int = 1,
        window_minutes: int = 5,
        description: Optional[str] = None,
    ) -> DetectionRule:
        rule = DetectionRule(
            name=name,
            rule_type=rule_type,
            severity=severity,
            threshold=threshold,
            window_minutes=window_minutes,
            description=description,
        )

        db.add(rule)
        db.commit()
        db.refresh(rule)

        return rule

    @staticmethod
    def get_enabled(
        db: Session,
    ) -> list[DetectionRule]:
        statement = select(DetectionRule).where(DetectionRule.enabled.is_(True))

        return list(db.scalars(statement).all())
