
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Copy application code and supporting files
COPY app/ ./app/
COPY tests/ ./tests/
COPY sample_logs/ ./sample_logs/

# Streamlit default port
EXPOSE 8501

# Start the Mini SIEM dashboard
CMD ["streamlit", "run", "app/streamlit_app.py", "--server.address=0.0.0.0", "--server.port=8501"]

