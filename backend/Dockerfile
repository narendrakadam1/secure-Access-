# ==============================================================================
# SECUREASSESS - Backend Orchestrator Service
# Python 3.11 FastAPI with SQLite shared state, LLM client, and WeasyPrint PDF
# ==============================================================================

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install system libraries for networking, SQLite, and WeasyPrint PDF rendering
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libjpeg-dev \
    libopenjp2-7-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data /tmp/artifacts

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
