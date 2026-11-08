# syntax=docker/dockerfile:1
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --upgrade pip \
    && pip install . \
    && useradd --create-home --uid 10001 secref \
    && mkdir -p /scan \
    && chown -R secref:secref /scan /app

USER secref
WORKDIR /scan

ENTRYPOINT ["secref"]
CMD ["--help"]
