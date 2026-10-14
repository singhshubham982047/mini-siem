# 🛡️ Mini SIEM & Security Analytics Engine

<p align="center">
  <strong>A Python-based Security Information and Event Management platform for log collection, threat detection, alerting, and incident investigation.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?logo=streamlit&logoColor=white" alt="Streamlit">
  <img src="https://img.shields.io/badge/PostgreSQL-Database-4169E1?logo=postgresql&logoColor=white" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Docker-Containerized-2496ED?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/SQLAlchemy-ORM-D71F00?logo=sqlalchemy&logoColor=white" alt="SQLAlchemy">
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black" alt="Linux">
</p>

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Detection Capabilities](#-detection-capabilities)
- [Architecture](#-architecture)
- [Technology Stack](#-technology-stack)
- [Repository Structure](#-repository-structure)
- [Prerequisites](#-prerequisites)
- [Docker Installation](#-docker-installation-recommended)
- [Local Installation](#-local-installation)
- [Database Configuration](#-database-configuration)
- [Running the Application](#-running-the-application)
- [Testing](#-testing)
- [Troubleshooting](#-troubleshooting)
- [Security Considerations](#-security-considerations)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)


---

## 📖 Overview

Mini SIEM is a hands-on cybersecurity project that demonstrates a basic security monitoring pipeline. It collects Linux authentication logs, converts raw log entries into structured security events, stores those events in PostgreSQL, evaluates detection rules, and presents the results in a Streamlit dashboard.

The project supports local development with PostgreSQL and a Linux authentication-log collector. A separate Docker-based setup is also being developed to provide an isolated environment with its own PostgreSQL database and synthetic security events.

The project is intended for cybersecurity learning, portfolio demonstration, controlled testing, and understanding the fundamentals of SIEM architecture.

**Note:** This is a learning project, not a replacement for an enterprise SIEM or a production-ready security monitoring platform.

## ✨ Features

- **Log collection:** Watch files for newly appended authentication log entries.
- **Authentication parsing:** Convert supported Linux authentication messages into structured events.
- **PostgreSQL storage:** Persist events, alerts, incidents, log sources, and detection rules.
- **Detection engine:** Evaluate incoming events against configured detection rules.
- **Security alerts:** Generate alerts when supported detection conditions are met.
- **Incident management:** Associate alerts with incidents for investigation.
- **Streamlit dashboard:** Review security events, alerts, incidents, log sources, and detection rules.
- **Automated testing:** Test parsing, repositories, file watching, collection, and detection behavior.
- **Docker setup:** Package the application and its dependencies into containers, with a separate PostgreSQL service.
- **Synthetic demo events:** Generate controlled authentication failures for demonstration without modifying real host authentication logs.

## 🚨 Detection Capabilities

Detection modules present in the project include:

| Detection | Purpose |
|---|---|
| SSH brute force | Identify repeated failed SSH authentication attempts. |
| Suspicious login | Detect selected suspicious authentication sequences, including successful login after multiple failures. |
| Multiple users from one IP | Identify authentication activity involving multiple usernames from a common source IP. |
| Port scan patterns | Detect supported patterns of repeated network connection attempts. |
| Suspicious sudo activity | Identify selected privilege-related commands or authentication failures. |
| Suspicious pkexec activity | Identify selected use of the `pkexec` privilege mechanism. |
| Privilege-event correlation | Correlate supported authentication and privilege-related events. |
| Repeated privilege escalation | Detect configured patterns of repeated successful privileged commands. |

Detection availability and behavior depend on the implemented rule logic, parser support, configuration, and input data. Review the corresponding detection modules and tests for exact conditions.

A triggered rule is an investigative signal, not proof of an attack. Legitimate administrative activity may produce similar patterns.

## 🏗️ Architecture

### Local Linux deployment

```mermaid
flowchart TD
    A[Linux Authentication Log] --> B[File Watcher]
    B --> C[Collector Manager]
    C --> D[Authentication Parser]
    D --> E[(PostgreSQL)]
    E --> F[Detection Engine]
    F --> G[Detection Rules]
    G --> H[Alerts]
    H --> I[Incident Management]
    E --> J[Streamlit Dashboard]
    H --> J
    I --> J
```

### Docker deployment

```mermaid
flowchart TD
    A[Browser] --> B[Streamlit Dashboard]
    B --> C[(Docker PostgreSQL)]
    D[Synthetic Log Generator] --> E[Demo Log File]
    E --> F[File Watcher]
    F --> G[Parser and Collector]
    G --> H[Detection Engine]
    H --> C
    C --> B
```

The Docker demo uses synthetic log entries and an isolated database. It does not require mounting the host's `/var/log/auth.log`.

### Event processing workflow

1. A new supported log entry is appended to the monitored file.
2. The file watcher passes the new line to the collector.
3. The parser extracts supported fields such as username, source IP, event type, and authentication status.
4. The repository stores the normalized event in PostgreSQL.
5. The detection engine evaluates the event against enabled rules.
6. Matching conditions may generate security alerts and associated incidents.
7. The Streamlit dashboard displays the stored information for review.

The file watcher starts at the end of the file and skips existing content. It processes new lines appended after watching begins.

## 🧰 Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| Dashboard | Streamlit |
| Database | PostgreSQL |
| ORM and database access | SQLAlchemy |
| PostgreSQL driver | psycopg |
| Data analysis | Pandas |
| Visualizations | Plotly |
| File monitoring | Python file watcher |
| Local service management | systemd |
| Containerization | Docker |
| Multi-container orchestration | Docker Compose |
| Testing | Python test modules |

## 📂 Repository Structure

The following is a representative structure. Additional modules and tests may exist in your checkout.

```text
mini-siem/
├── app/
│   ├── analytics/
│   ├── collector/
│   │   ├── collector_manager.py
│   │   └── file_watcher.py
│   ├── dashboard/
│   │   ├── data.py
│   │   ├── overview.py
│   │   ├── security_events.py
│   │   ├── alerts.py
│   │   ├── incidents.py
│   │   ├── log_sources.py
│   │   └── detection_rules.py
│   ├── database/
│   │   ├── connection.py
│   │   ├── models.py
│   │   └── repository.py
│   ├── detection/
│   │   ├── brute_force.py
│   │   ├── engine.py
│   │   ├── multiple_users.py
│   │   ├── port_scan.py
│   │   ├── suspicious_login.py
│   │   ├── suspicious_pkexec.py
│   │   ├── suspicious_sudo.py
│   │   └── repeated_privilege_escalation.py
│   ├── parser/
│   ├── init_db.py
│   ├── run_demo_collector.py
│   ├── run_real_auth_collector.py
│   └── streamlit_app.py
├── sample_logs/
├── tests/
├── .dockerignore
├── .env.example
├── .gitignore
├── Dockerfile
├── compose.yaml
├── requirements.txt
└── README.md
```

## 💻 Prerequisites

### For Docker

- Git
- Docker Engine
- Docker Compose v2

Verify the installation:

```bash
docker --version
docker compose version
```

### For local development

- Linux environment compatible with the collector configuration
- Python compatible with the installed dependencies
- PostgreSQL
- Git
- Permission to read the selected log source

On Ubuntu, the local authentication collector typically reads `/var/log/auth.log`. Other Linux distributions may use a different path or logging system.

---

## 🐳 Docker Installation (Recommended)

Docker provides a convenient way to run the dashboard and PostgreSQL without changing the existing host database configuration.

### 1. Clone the repository

Replace the example URL with your actual GitHub repository URL.

```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/<YOUR_REPOSITORY>.git
cd <YOUR_REPOSITORY>
```

### 2. Configure the environment

Create your private environment file:

```bash
cp .env.example .env
chmod 600 .env
nano .env
```

Set a strong, unique password:

```dotenv
POSTGRES_DB=mini_siem
POSTGRES_USER=siem_user
POSTGRES_PASSWORD=REPLACE_WITH_A_STRONG_ALPHANUMERIC_PASSWORD

DASHBOARD_PORT=8501

DEMO_BURST_COUNT=5
DEMO_BURST_DELAY_SECONDS=0.8
```

Replace the password placeholder with your own secret. For the initial Compose configuration, use letters and numbers only because the password is embedded in a database URL.

Never commit `.env` to GitHub.

### 3. Build and start the containers

From the repository root:

```bash
docker compose up --build -d
```

Check service status:

```bash
docker compose ps
```

The Compose configuration defines these services:

| Service | Purpose |
|---|---|
| `db` | PostgreSQL database for the Docker deployment. |
| `init` | Creates missing tables, seeds detection rules, and registers the demo source. |
| `dashboard` | Runs the Streamlit interface. |
| `demo-collector` | Generates synthetic SSH failures and processes them through the existing collection pipeline. |

The first build may take several minutes while Docker downloads the base images and installs Python dependencies.

### 4. Open the dashboard

Once the dashboard container is running, open:

**http://localhost:8501**

If you change `DASHBOARD_PORT` in `.env`, use that port in the browser URL.

### 5. Inspect container logs

View recent logs from all services:

```bash
docker compose logs --tail=100
```

Follow the dashboard logs:

```bash
docker compose logs -f dashboard
```

Follow the demo collector:

```bash
docker compose logs -f demo-collector
```

Press `Ctrl+C` to stop following logs. This does not stop the containers.

### 6. Stop and restart

Stop the containers while retaining named volumes:

```bash
docker compose down
```

Restart them:

```bash
docker compose up -d
```

Rebuild after application code or dependency changes:

```bash
docker compose up --build -d
```

**Warning:** The following command deletes the named volumes, including the Docker PostgreSQL database data and demo logs:

```bash
docker compose down -v
```

Use it only when you intentionally want to remove that data.

### 7. Docker troubleshooting

If a service fails to start, inspect its logs:

```bash
docker compose logs --tail=200 db
docker compose logs --tail=200 init
docker compose logs --tail=200 dashboard
docker compose logs --tail=200 demo-collector
```

Validate the Compose configuration:

```bash
docker compose config
```

The Compose environment must contain a real `POSTGRES_PASSWORD`. The database initialization service must complete successfully before the dashboard and demo collector can start.

The Docker setup should be tested on a clean checkout before it is considered verified.

---

## 🐍 Local Installation

The local installation uses the PostgreSQL instance configured in your `.env` file. It is separate from the containerized database used by Docker Compose.

### 1. Clone the repository

```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/<YOUR_REPOSITORY>.git
cd <YOUR_REPOSITORY>
```

If you already have a local checkout, use that directory instead of cloning again.

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure PostgreSQL

If PostgreSQL is not installed, install and start it using your distribution's package manager and service-management tools.

For Ubuntu, check the service:

```bash
sudo systemctl status postgresql
```

If you are setting up a fresh local database, open the PostgreSQL shell:

```bash
sudo -u postgres psql
```

Create a dedicated application user and database, replacing the password placeholder:

```sql
CREATE USER siem_user WITH PASSWORD 'REPLACE_WITH_A_STRONG_PASSWORD';
CREATE DATABASE mini_siem OWNER siem_user;
\q
```

Do not run these creation commands again if the user or database already exists. Use your existing configuration and avoid altering a working local installation unnecessarily.

### 5. Configure `.env`

Create a local environment file from the template if needed:

```bash
cp .env.example .env
chmod 600 .env
nano .env
```

For the local setup, `app/database/connection.py` expects `DATABASE_URL`.

Example:

```dotenv
DATABASE_URL=postgresql+psycopg://siem_user:REPLACE_WITH_A_STRONG_PASSWORD@localhost:5432/mini_siem
```

Replace the example password with your actual local database password. This example is for the host-based local configuration, not the Docker Compose password settings.

Special characters in a URL password may need percent encoding. Never publish credentials or paste them into public issues.

**If `.env` already works with your local PostgreSQL installation, do not overwrite it simply to follow this example.**

### 6. Initialize the database

Use the schema initialization method appropriate to your current local project.

For the Docker workflow, the newly added `app.init_db` module is intended to initialize the containerized database. Do not run that module against your existing host database without first verifying the active `DATABASE_URL`.

For local development, follow the existing initialization procedure or the project's database setup instructions.

### 7. Start the dashboard

The Streamlit entry point is:

```bash
streamlit run app/streamlit_app.py
```

Open the URL displayed by Streamlit, typically:

http://localhost:8501

### 8. Start the local collector

The local authentication collector can be run in the foreground:

```bash
python -m app.run_real_auth_collector
```

It needs appropriate permission to read `/var/log/auth.log`. Avoid running multiple collectors against the same source unless duplicate processing is intentionally handled.

---

## 🗄️ Database Configuration

The project uses SQLAlchemy to interact with PostgreSQL.

The database models define the following tables:

| Table | Purpose |
|---|---|
| `log_sources` | Configured log sources. |
| `events` | Normalized security events. |
| `detection_rules` | Configured detection conditions. |
| `alerts` | Generated security alerts. |
| `incidents` | Incidents associated with alerts. |
| `alert_events` | Relationships between alerts and their associated events. |

The Docker and local configurations must point to their intended databases. Avoid using the same database for experiments and production workloads.

---

## 🧪 Testing

Run test commands from the project root with the virtual environment activated.

### Syntax compilation

```bash
python -m compileall -q app tests
```

### Repository and pipeline tests

Run the test modules that exist in your checkout. Examples include:

```bash
python -m tests.test_repository
python -m tests.test_auth_parser
python -m tests.test_parser_database
python -m tests.test_file_watcher
python -m tests.test_collector_pipeline
```

### Detection tests

```bash
python -m tests.test_brute_force
python -m tests.test_detection_engine
python -m tests.test_suspicious_login
python -m tests.test_incident_manager
```

Only run commands for test modules that are present in your current repository.

### Docker validation

First validate the Compose configuration:

```bash
docker compose config
```

Then build the application image:

```bash
docker compose build
```

After checking the configuration and confirming that the environment file contains the correct Docker password, start the services:

```bash
docker compose up -d
docker compose ps
docker compose logs --tail=100
```

A successful container start alone does not prove every detection rule works correctly. Review the dashboard and service logs, and validate the event-to-alert pipeline.

### Testing safety notes

- Prefer a dedicated test database for tests that create events, alerts, or incidents.
- Some tests may leave records behind unless they explicitly clean them up.
- Use synthetic logs or controlled fixtures for security testing.
- Do not fabricate entries in a real host's `/var/log/auth.log`.
- Validate both positive and negative detection cases when extending the rules.

---

## 🔧 Troubleshooting

### Database connection fails

- Confirm that PostgreSQL is running.
- Verify the database name, username, password, host, and port.
- Confirm that `DATABASE_URL` points to the intended database.
- Check URL encoding if the password contains special characters.
- For Docker, inspect `docker compose logs db` and `docker compose logs init`.

### Docker dashboard does not start

- Check that Docker Engine is running.
- Run `docker compose config`.
- Confirm that `.env` exists and `POSTGRES_PASSWORD` is set.
- Inspect the `init` service logs.
- Check whether the configured host port is already in use.

### Collector cannot read a log file

- Confirm the file path exists.
- Check permissions for the collector process.
- Verify the log source is enabled.
- Review the collector logs for parser and database errors.

### Dashboard has no events

- Verify that the collector is running.
- Confirm that events are being stored in the database used by the dashboard.
- Refresh the dashboard.
- Remember that the file watcher skips existing content and processes newly appended lines.
- In Docker, check the demo collector logs to see whether synthetic entries were generated.

### Detection alerts are not generated

- Confirm the relevant detection rule exists and is enabled.
- Verify that the event parser recognizes the synthetic or real log format.
- Check the rule threshold and time window.
- Inspect collector and detection-engine logs.
- Review whether enough qualifying events were received within the configured time window.

### A detection fires unexpectedly

- Inspect the matching events and configured time window.
- Distinguish legitimate administration from suspicious behavior.
- Tune detection thresholds only after reviewing the test results and documenting the trade-offs.

---

## 🔐 Security Considerations

- Monitor only systems and logs you own or are authorized to access.
- Never commit `.env`, database passwords, tokens, or private configuration.
- Grant the collector only the permissions needed to read its configured source.
- Keep PostgreSQL restricted to trusted connections.
- Do not expose the Streamlit development server directly to the public internet.
- Use strong credentials and protect database backups.
- Review alerts in context rather than treating them as conclusive proof of compromise.
- Use synthetic events for demonstrations and controlled tests.
- Configure retention, monitoring, backups, and access controls before production use.
- Treat this project as an educational prototype until it has undergone appropriate security testing and operational hardening.

---

## 🛣️ Roadmap

- [ ] Validate Docker setup on a clean clone.
- [ ] Add sanitized screenshots of the dashboard.
- [ ] Improve test isolation and test-database separation.
- [ ] Expand parser coverage for supported authentication log formats.
- [ ] Tune detection rules to reduce false positives.
- [ ] Improve incident investigation and event correlation.
- [ ] Add structured logging and operational health checks.
- [ ] Document secure deployment and backup procedures.
- [ ] Evaluate a secure cloud deployment when required.

---

## 🤝 Contributing

Contributions, bug reports, and suggestions are welcome.

When reporting an issue, include:

- A clear description of the problem.
- Steps to reproduce it.
- Relevant error messages or sanitized logs.
- The expected and actual behavior.
- The affected parser, detection rule, or service.

Do not include passwords, access tokens, or sensitive production log data in issues or pull requests.


---

<p align="center">
  <strong>Built as a practical cybersecurity and security-monitoring project.</strong>
</p>
