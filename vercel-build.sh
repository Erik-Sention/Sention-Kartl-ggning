#!/bin/bash
# Exit on error
set -e

# Install PostgreSQL development tools
echo "Installing PostgreSQL development libraries..."
apt-get update -y
apt-get install -y libpq-dev postgresql-client

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "Build completed successfully!" 