# Flask Application Deployment Guide

## Common Issues and Solutions

### PostgreSQL Dependency Issues

When deploying a Flask application that uses PostgreSQL (via `psycopg2`), you might encounter this error:

```
Error: Command failed: pip install --disable-pip-version-check --target . --upgrade -r requirements.txt
error: subprocess-exited-with-error

× Getting requirements to build wheel did not run successfully.
│ exit code: 1
╰─> [output]
    running egg_info
    writing psycopg2.egg-info/PKG-INFO
    
    Error: pg_config executable not found.
    
    pg_config is required to build psycopg2 from source.
```

This happens because `psycopg2` requires PostgreSQL development libraries to build from source.

## Solution 1: Use psycopg2-binary

The simplest solution is to use the pre-compiled binary version of psycopg2:

1. In your `requirements.txt`, replace:
   ```
   psycopg2==2.9.9
   ```
   with:
   ```
   psycopg2-binary==2.9.9
   ```

## Solution 2: Install PostgreSQL Development Libraries

If you need to use the source version of `psycopg2`, ensure your build script installs the necessary PostgreSQL development libraries:

```bash
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
```

## Vercel Deployment Configuration

For deploying on Vercel, ensure your `vercel.json` file is properly configured:

```json
{
  "version": 2,
  "builds": [
    {
      "src": "app.py",
      "use": "@vercel/python",
      "config": {
        "buildCommand": "chmod +x vercel-build.sh && ./vercel-build.sh"
      }
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "/app.py"
    }
  ]
}
```

## Standard Deployment Commands

### Build Command
```
chmod +x vercel-build.sh && ./vercel-build.sh
```

### Output Directory
```
.
```

### Install Command
```
pip install -r requirements.txt
```

## Deployment Checklist

1. Ensure `requirements.txt` contains all necessary dependencies
2. Use `psycopg2-binary` instead of `psycopg2` to avoid build issues
3. Make sure `vercel-build.sh` is executable (`chmod +x vercel-build.sh`)
4. Verify your `vercel.json` configuration is correct
5. Check that your application's entry point is correctly specified in routes

## Troubleshooting

If you encounter deployment issues:

1. Check the build logs for specific error messages
2. Verify that all environment variables are properly set
3. Ensure your Python version is compatible with all dependencies
4. For database connection issues, verify connection strings and credentials 