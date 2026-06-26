FROM python:3.11-slim

WORKDIR /app

# Install dependencies first for better Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (excludes .env via .dockerignore)
COPY . .

EXPOSE 8000

# Bind to 0.0.0.0 — required for judges to reach the service
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]