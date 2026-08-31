FROM python:3.10-slim-bookworm

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir "openbb[all]" openbb-platform-api \
    && openbb-build

EXPOSE 6900

ENTRYPOINT ["openbb-api", "--host", "0.0.0.0"]
