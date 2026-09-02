FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py oauth.py ./

# the image itself stays read-only; the oauth database lives on the mounted volume,
# so uid 10001 must own /data (fly creates the mount root as root and chowns to the
# image user on first attach)
RUN useradd --create-home --uid 10001 app
USER app

EXPOSE 8000
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
