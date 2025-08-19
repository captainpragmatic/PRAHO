# ===============================================================================
# PRAHO PLATFORM - DEVELOPMENT & DEPLOYMENT DOCKER SETUP
# ===============================================================================

# Use Python 3.11 slim image for better performance
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  DJANGO_SETTINGS_MODULE=config.settings.prod

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  postgresql-client \
  build-essential \
  libpq-dev \
  gettext \
  curl \
  && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements/ requirements/
RUN pip install --no-cache-dir -r requirements/prod.txt

# Copy project
COPY . .

# Create static files directory
RUN mkdir -p /app/staticfiles

# Collect static files
RUN python manage.py collectstatic --noinput

# Create non-root user for security
RUN adduser --disabled-password --gecos '' appuser \
  && chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health/ || exit 1

# Expose port
EXPOSE 8000

# Command to run the application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "config.wsgi:application"]
