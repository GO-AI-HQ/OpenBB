FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py ./main.py
COPY v3.py ./v3.py
COPY auth_rotation.py ./auth_rotation.py

CMD ["sh", "-c", "uvicorn auth_rotation:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1"]
