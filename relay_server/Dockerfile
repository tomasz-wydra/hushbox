FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

EXPOSE 5000

# gunicorn z 4 workerami — threaded dla long polling
CMD ["gunicorn", "--workers=4", "--threads=8", "--timeout=60",\
     "--bind=0.0.0.0:5000", "server:app"]
