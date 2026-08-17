FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY hushbox_relay_api/ hushbox_relay_api/

EXPOSE 5000

# JEDEN proces roboczy + dużo wątków.
#
# Long polling sygnalizuje nowe wiadomości przez zdarzenia w pamięci procesu.
# Przy --workers=4 POST trafiał do procesu A i budził wyłącznie oczekujących w A,
# więc klient czekający w procesie B przesypiał cały timeout — wiadomości
# dochodziły z losowym opóźnieniem do 30 s. Long polling jest I/O-bound, więc
# przepustowość dają wątki, nie procesy.
#
# Skalowanie na wiele procesów/instancji wymaga wspólnego pub/sub
# (Redis albo MongoDB change streams) — patrz docstring w server.py.
CMD ["gunicorn", "--workers=1", "--threads=32", "--timeout=60", "--bind=0.0.0.0:5000", "hushbox_relay_api.server:app"]
