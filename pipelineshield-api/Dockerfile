FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

COPY pyproject.toml ./
COPY src ./src
COPY alembic ./alembic
COPY alembic.ini ./
COPY tests/__init__.py ./tests/__init__.py
COPY tests/fixtures/__init__.py ./tests/fixtures/__init__.py
COPY tests/fixtures/seed_baseline.py ./tests/fixtures/seed_baseline.py

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

EXPOSE 8000

CMD ["uvicorn", "pipelineshield.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
