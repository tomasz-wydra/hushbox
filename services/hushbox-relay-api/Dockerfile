FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY hushbox_relay_api/ hushbox_relay_api/

EXPOSE 5000

# gunicorn z 4 workerami — threaded dla long polling
CMD ["gunicorn", "--workers=4", "--threads=8", "--timeout=60", "--bind=0.0.0.0:5000", "hushbox_relay_api.server:app"]
