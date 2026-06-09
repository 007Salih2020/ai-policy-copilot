FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY templates ./templates
COPY data ./data

RUN pip install --no-cache-dir .

COPY .env.example ./

RUN mkdir -p /app/output

ENTRYPOINT ["soc2-copilot"]

