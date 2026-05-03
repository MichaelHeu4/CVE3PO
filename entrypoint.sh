#!/bin/sh

# Exit immediately if a command exits with a non-zero status
set -e

echo "--- Starting Database Migrations ---"

# Create migrations if there are model changes
python manage.py makemigrations

# Apply migrations to the database
python manage.py migrate

echo "--- Database is up to date ---"

# Start the application
exec "$@"
