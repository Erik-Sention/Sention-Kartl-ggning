# Dashboard PDF Generator

This feature allows users to export the dashboard as a PDF document that exactly mirrors how it appears in the web browser.

## Overview

The PDF generator uses [Playwright](https://playwright.dev/), a modern browser automation library, to capture the dashboard as a PDF with all CSS, JavaScript, and visual styles intact.

## Installation

To use the PDF generator, you need to install Playwright and its dependencies:

```bash
# Install the Python packages
pip install -r requirements-pdf.txt

# Install browser dependencies
python -m playwright install
```

## How It Works

1. When a user clicks the "Exportera som PDF" button in the dashboard:
   - The frontend sends a request to the `/generate_pdf` endpoint
   - The server passes the user's authentication session cookie to the PDF generator
   - The PDF generator script uses Playwright with the session cookie to load the dashboard page
   - Playwright opens a headless browser, navigates to the URL, and generates a PDF
   - The PDF is saved to `static/generated/output.pdf`
   - The server returns a link to the generated PDF

2. The PDF generator preserves:
   - All styling (CSS)
   - Charts and graphs
   - Background colors and images
   - Data tables
   - User-specific dashboard data (via authentication)

## Authentication

The PDF generator handles authentication by:

1. Passing the user's session cookie from the Flask server to the PDF generator script
2. Setting the cookie in the Playwright browser context before loading the page
3. This ensures the PDF generator can access protected pages like the dashboard

## Manual Usage

You can also generate PDFs manually by running:

```bash
# Without authentication (will likely redirect to login page)
python pdf_generator.py [URL]

# With authentication (provide a session cookie)
python pdf_generator.py [URL] '[{"name":"session","value":"your-session-cookie-value","path":"/"}]'
```

Examples:
```bash
# Generate PDF from local development server
python pdf_generator.py http://localhost:5001/dashboard

# Generate PDF from production with authentication
python pdf_generator.py https://yoursite.vercel.app/dashboard '[{"name":"session","value":"abc123"}]'
```

## Troubleshooting

If you encounter issues with the PDF generation:

1. Check authentication issues:
   - Look for "login_redirect.png" which is created if the script detects a login redirect
   - Verify that session cookies are being passed correctly
   - Try logging in through the browser and copying your session cookie manually

2. Other common issues:
   - Make sure Playwright is installed correctly
   - Check browser dependencies are installed
   - Check the server logs for error messages
   - Verify that the dashboard URL is accessible

## Debug Files

When debugging, the script generates these helpful files:

- `debug_screenshot.png` - Screenshot when page load fails (HTTP error)
- `login_redirect.png` - Screenshot when redirected to login page
- `error_screenshot.png` - Screenshot when an exception occurs

## Files

- `pdf_generator.py` - The main script that uses Playwright to generate PDFs
- `requirements-pdf.txt` - Required Python dependencies
- `app.py` - Contains the `/generate_pdf` endpoint that handles PDF generation requests
- `templates/dashboard.html` - Contains the PDF export button and frontend code 