from sqlalchemy import select

from app.database.connection import SessionLocal
from app.database.models import DetectionRule

RULES = [
    {
        "name": "ssh_brute_force",
        "description": (
            "Detect repeated failed SSH authentication attempts "
            "from the same source IP."
        ),
        "rule_type": "authentication",
        "severity": "high",
        "threshold": 5,
        "window_minutes": 5,
    },
    {
        "name": "successful_login_after_failures",
        "description": (
            "Detect a successful SSH login after multiple "
            "failed authentication attempts from the same source IP."
        ),
        "rule_type": "authentication",
        "severity": "high",
        "threshold": 3,
        "window_minutes": 5,
    },
    {
        "name": "multiple_users_same_ip",
        "description": (
            "Detect authentication failures against multiple "
            "different usernames from the same source IP."
        ),
        "rule_type": "authentication",
        "severity": "high",
        "threshold": 3,
        "window_minutes": 5,
    },
    {
        "name": "port_scan",
        "description": (
            "Detect connections from the same source IP to "
            "multiple destination ports."
        ),
        "rule_type": "network",
        "severity": "medium",
        "threshold": 5,
        "window_minutes": 5,
    },
    {
        "name": "sudo_authentication_failure",
        "description": "Detects repeated failed sudo authentication attempts",
        "rule_type": "authentication",
        "severity": "high",
        "threshold": 3,
        "window_minutes": 5,
        "enabled": True,
    },
]


def seed_detection_rules():
    with SessionLocal() as db:

        for rule_data in RULES:

            existing_rule = db.scalar(
                select(DetectionRule).where(DetectionRule.name == rule_data["name"])
            )

            if existing_rule:
                print(f"Already exists: " f"{existing_rule.name}")
                continue

            rule = DetectionRule(
                name=rule_data["name"],
                description=rule_data["description"],
                rule_type=rule_data["rule_type"],
                severity=rule_data["severity"],
                threshold=rule_data["threshold"],
                window_minutes=rule_data["window_minutes"],
                enabled=True,
            )

            db.add(rule)

            print(f"Created: {rule_data['name']}")

        db.commit()

        print("\nDetection rule seeding completed.")


if __name__ == "__main__":
    seed_detection_rules()
