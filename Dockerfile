FROM python:3.12-slim

LABEL description="NmapViz - Visualizador gráfico de resultados nmap"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p uploads

EXPOSE 12221

RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app
USER appuser

# Usar "python -m gunicorn" en lugar de "gunicorn" directamente
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:12221", "--workers", "2", "--timeout", "120", "app:app"]