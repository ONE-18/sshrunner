FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install --no-install-recommends -y openssh-client \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin app
WORKDIR /app

COPY --chown=app:app server.py README.md ./
COPY --chown=app:app static ./static
RUN mkdir -p /app/data && chown app:app /app/data

USER app
EXPOSE 8080
VOLUME ["/app/data"]

CMD ["python3", "server.py", "--host", "0.0.0.0", "--port", "8080"]
