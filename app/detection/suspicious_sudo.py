from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Event, Alert


class SuspiciousSudoDetector:
    RULE_NAME = "suspicious_sudo_command"

    SUSPICIOUS_COMMANDS = (
        "sudo su",
        "sudo -i",
        "sudo -s",
        "sudo bash",
        "sudo sh",
        "sudo zsh",
        "sudo passwd",
        "sudo useradd",
        "sudo userdel",
        "sudo usermod",
        "sudo visudo",
        "sudo chmod",
        "sudo chown",
        "sudo systemctl stop",
        "sudo systemctl disable",
        "sudo systemctl mask",
        "sudo iptables",
        "sudo nft",
        "sudo ufw disable",
    )

    @classmethod
    def detect(cls, db: Session, event: Event):
        if event.event_type != "privilege_escalation":
            return None

        if event.action != "sudo_command":
            return None

        if event.status != "success":
            return None

        if not event.message:
            return None

        command = event.message.lower()

        matched_command = None

        for suspicious_command in cls.SUSPICIOUS_COMMANDS:
            if suspicious_command in command:
                matched_command = suspicious_command
                break

        if matched_command is None:
            return None

        existing_alert = db.scalar(
            select(Alert)
            .where(
                Alert.rule_name == cls.RULE_NAME,
                Alert.username == event.username,
                Alert.status == "open",
            )
        )

        if existing_alert:
            return existing_alert

        alert = Alert(
            rule_name=cls.RULE_NAME,
            severity="high",
            title="Suspicious Sudo Command Detected",
            description=(
                f"Suspicious privileged command detected for user "
                f"{event.username}: {event.message}"
            ),
            src_ip=event.src_ip,
            username=event.username,
            status="open",
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert
