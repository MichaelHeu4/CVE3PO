#!/bin/sh

# Exit immediately if a command exits with a non-zero status
set -e

echo "--- Starting Database Migrations ---"

# Create migrations if there are model changes
python manage.py makemigrations

# Apply migrations to the database
python manage.py migrate

echo "--- Database is up to date ---"

# Collect static files so WhiteNoise can serve the Django admin CSS/JS
echo "--- Collecting static files ---"
python manage.py collectstatic --noinput

# Start the application
exec "$@"
