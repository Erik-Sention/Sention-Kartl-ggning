#!/usr/bin/env python3
"""
PDF Generator Script using Playwright

This script takes a URL as input and generates a PDF of the webpage.
It is designed to capture the full visual appearance of the page including
CSS, JavaScript, and background colors.

Usage:
    python pdf_generator.py [URL] [COOKIE_STRING] [USERNAME] [PASSWORD]

Example:
    python pdf_generator.py http://localhost:3000/dashboard "session=abc123;"
    python pdf_generator.py https://mittprojekt.vercel.app/dashboard "" "username" "password"

The output is saved as output.pdf in the static/generated/ directory.
"""

import asyncio
import os
import sys
import json
import traceback
from pathlib import Path
from playwright.async_api import async_playwright

async def generate_pdf(url, cookies=None, username=None, password=None):
    """
    Generate a PDF from the given URL using Playwright.
    
    Args:
        url (str): The URL to capture as PDF.
        cookies (list): A list of cookie objects to set (for authentication).
        username (str): Username for login if needed.
        password (str): Password for login if needed.
        
    Returns:
        str: Path to the generated PDF file.
    """
    print(f"Generating PDF for URL: {url}")
    print(f"Using cookies: {cookies}")
    print(f"Username provided: {bool(username)}")
    
    # Create debug directory
    debug_dir = Path('debug')
    debug_dir.mkdir(exist_ok=True)
    
    browser = None
    try:
        async with async_playwright() as p:
            print("Launching browser...")
            # Launch a Chromium browser with more debugging
            browser = await p.chromium.launch(
                headless=True,  # Set to False for debugging to see the browser window
                args=['--disable-web-security', '--no-sandbox', '--disable-setuid-sandbox']
            )
            
            print("Creating browser context...")
            # Create a new context with viewport size matching A4 dimensions
            # A4 is approximately 8.27 × 11.69 inches or 210 × 297 mm
            context = await browser.new_context(
                viewport={'width': 1240, 'height': 1754},
                bypass_csp=True  # Bypass Content Security Policy to avoid loading issues
            )
            
            # Add cookies for authentication if provided
            if cookies:
                try:
                    # Get the domain from the URL
                    from urllib.parse import urlparse
                    domain = urlparse(url).netloc
                    print(f"Setting cookies for domain: {domain}")
                    
                    # Add each cookie to the context
                    for cookie in cookies:
                        # Ensure the cookie has the right domain
                        if 'domain' not in cookie:
                            cookie['domain'] = domain
                        await context.add_cookies([cookie])
                    print(f"Added {len(cookies)} cookies to the browser context")
                except Exception as e:
                    print(f"Error adding cookies: {e}")
                    traceback.print_exc()
            
            print("Creating page...")
            # Create a new page
            page = await context.new_page()
            
            # Add dialog handler to automatically accept any dialogs
            page.on("dialog", lambda dialog: dialog.accept())
            
            # Add console message handler for debugging
            page.on("console", lambda msg: print(f"BROWSER CONSOLE: {msg.type}: {msg.text}"))
            
            try:
                print(f"Navigating to URL: {url}")
                # Navigate to the URL and wait for the network to be idle
                response = await page.goto(url, wait_until='networkidle', timeout=60000)
                
                if not response:
                    print("Error: No response received from page.goto()")
                    await page.screenshot(path=str(debug_dir / "no_response.png"))
                    return None
                
                print(f"Page loaded with status: {response.status}")
                if response.status >= 400:
                    print(f"Error: Failed to load page - status code: {response.status}")
                    await page.screenshot(path=str(debug_dir / "error_status.png"))
                    return None
                
                # Wait additional time for any JavaScript to execute
                print("Waiting for page to stabilize...")
                await page.wait_for_timeout(2000)
                
                # Take a screenshot before we check for login redirects
                await page.screenshot(path=str(debug_dir / "before_check.png"))
                
                # Check if we're on the login page instead of the dashboard
                current_url = page.url
                page_title = await page.title()
                print(f"Current page URL: {current_url}")
                print(f"Current page title: {page_title}")
                
                # If redirected to login page and we have credentials, try to login
                login_attempted = False
                if (page_title == "Login" or "login" in current_url.lower()) and username and password:
                    print(f"Redirected to login page. Attempting to login as {username}...")
                    
                    try:
                        # Take screenshot of the login form
                        await page.screenshot(path=str(debug_dir / "login_form.png"))
                        
                        # Fill in login form and submit
                        await page.fill('input[name="email"]', username)
                        await page.fill('input[name="password"]', password)
                        
                        # Click login button
                        await page.click('button[type="submit"]')
                        
                        # Wait for navigation after login
                        print("Logging in and waiting for redirect...")
                        await page.wait_for_load_state('networkidle')
                        await page.wait_for_timeout(3000)  # Extra wait for redirect to complete
                        
                        # Take screenshot after login attempt
                        await page.screenshot(path=str(debug_dir / "after_login.png"))
                        
                        # Check if we've been redirected to the dashboard after login
                        current_url = page.url
                        page_title = await page.title()
                        print(f"After login - URL: {current_url}")
                        print(f"After login - Title: {page_title}")
                        
                        login_attempted = True
                        
                        # If we're still on the login page, login failed
                        if page_title == "Login" or "login" in current_url.lower():
                            print("Login failed - still on login page")
                            return None
                        
                        # Wait a bit more for the dashboard to fully load
                        print("Login successful, waiting for dashboard to load...")
                        await page.wait_for_timeout(5000)
                    except Exception as login_error:
                        print(f"Error during login attempt: {login_error}")
                        traceback.print_exc()
                        await page.screenshot(path=str(debug_dir / "login_error.png"))
                        return None
                elif page_title == "Login" or current_url != url:
                    if not username or not password:
                        print("Redirected to login page but no credentials provided.")
                    print(f"Warning: Redirected to login page ({current_url}). Session cookies may be invalid.")
                    await page.screenshot(path=str(debug_dir / "login_redirect.png"))
                    print(f"Debug screenshot saved to {debug_dir}/login_redirect.png")
                
                # Create the output directory if it doesn't exist
                output_dir = Path('static/generated')
                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = output_dir / 'output.pdf'
                
                # Inject CSS to hide UI elements not needed in PDF
                print("Injecting print-specific CSS...")
                await page.evaluate("""() => {
                    const style = document.createElement('style');
                    style.textContent = `
                        /* Hide headers, footers, buttons, and status messages */
                        nav, 
                        header, 
                        .navbar,
                        footer, 
                        .btn-toolbar,
                        .btn-group,
                        .toast-container,
                        .alert,
                        #loadingOverlay,
                        #toastContainer,
                        .toast,
                        button,
                        .loading-indicator,
                        .btn,
                        #filter-collapse,
                        .card-header .dropdown,
                        .row > .col-auto,
                        .filter-section {
                            display: none !important;
                        }
                        
                        /* Make sure the main content uses the full width */
                        .container, 
                        .container-fluid,
                        .card-body {
                            padding: 0 !important;
                            margin: 0 !important;
                        }
                        
                        /* Remove any loading text or notifications */
                        [data-status="loading"],
                        .status-message,
                        .toast-body {
                            display: none !important;
                        }
                        
                        /* Ensure tables display properly */
                        .table-responsive {
                            overflow: visible !important;
                        }
                        
                        /* Clean spacing */
                        body {
                            padding: 0 !important;
                            margin: 0 !important;
                        }
                        
                        /* Hide any pop-ups, modals and overlays */
                        .modal,
                        .modal-dialog,
                        .modal-backdrop,
                        .dropdown-menu,
                        .popover {
                            display: none !important;
                        }
                    `;
                    document.head.appendChild(style);
                    
                    // Also hide any elements with text mentioning loading or status updates
                    document.querySelectorAll('div, p, span').forEach(el => {
                        const text = el.innerText || '';
                        if (text.includes('Laddar data') || 
                            text.includes('Hämtar information') || 
                            text.includes('Data laddad') ||
                            text.includes('uppdaterats')) {
                            el.style.display = 'none';
                        }
                    });
                    
                    // Make sure tables and graph content remain visible
                    document.querySelectorAll('.chart-container, .table, canvas').forEach(el => {
                        el.style.display = 'block';
                    });
                    
                    console.log('Print-specific styles applied');
                }""")
                
                # Wait for styles to apply
                await page.wait_for_timeout(1000)
                
                # Take a final screenshot before PDF generation
                await page.screenshot(path=str(debug_dir / "before_pdf.png"))
                
                # Generate the PDF with background graphics
                print("Generating PDF...")
                await page.pdf(
                    path=str(output_path),
                    format='A4',
                    print_background=True,
                    margin={
                        'top': '10mm',
                        'right': '10mm',
                        'bottom': '10mm',
                        'left': '10mm'
                    }
                )
                
                print(f"PDF generated successfully: {output_path}")
                return str(output_path)
            
            except Exception as e:
                print(f"Error during page navigation or PDF generation: {e}")
                traceback.print_exc()
                # Take a screenshot to help debug the issue
                try:
                    if page:
                        await page.screenshot(path=str(debug_dir / "error_screenshot.png"))
                        print(f"Error screenshot saved to {debug_dir}/error_screenshot.png")
                except Exception as screenshot_error:
                    print(f"Could not save error screenshot: {screenshot_error}")
                return None
    
    except Exception as e:
        print(f"Error initializing Playwright or browser: {e}")
        traceback.print_exc()
        return None
    
    finally:
        # Make sure we close the browser
        if browser:
            try:
                await browser.close()
                print("Browser closed successfully")
            except Exception as e:
                print(f"Error closing browser: {e}")

def main():
    """Main function to parse command line arguments and run the PDF generation."""
    # Get URL from command line arguments or use default
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = "http://localhost:5001/dashboard"  # Default URL
    
    # Get cookies from command line if provided
    cookies = None
    if len(sys.argv) > 2:
        try:
            cookies_str = sys.argv[2]
            print(f"Processing cookie string: {cookies_str[:20]}..." if len(cookies_str) > 20 else cookies_str)
            # If the cookies are passed as a JSON string
            if cookies_str.startswith('['):
                cookies = json.loads(cookies_str)
                print(f"Parsed JSON cookies: {len(cookies)} cookie(s)")
            # If just a session cookie is passed
            else:
                # Parse the cookie string (simple version)
                cookie_parts = cookies_str.split(';')
                cookies = []
                for part in cookie_parts:
                    if '=' in part:
                        name, value = part.strip().split('=', 1)
                        cookies.append({
                            'name': name,
                            'value': value,
                            'path': '/'
                        })
                print(f"Parsed string cookies: {len(cookies)} cookie(s)")
        except Exception as e:
            print(f"Error parsing cookies: {e}")
            traceback.print_exc()
            cookies = None
    
    # Get username and password if provided
    username = None
    password = None
    if len(sys.argv) > 3:
        username = sys.argv[3]
    if len(sys.argv) > 4:
        password = sys.argv[4]
    
    try:
        # Run the async function
        pdf_path = asyncio.run(generate_pdf(url, cookies, username, password))
        
        if pdf_path:
            print(f"PDF saved to: {pdf_path}")
            return 0
        else:
            print("Failed to generate PDF")
            return 1
    except Exception as e:
        print(f"Unhandled exception in main: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"Critical error: {e}")
        traceback.print_exc()
        sys.exit(1) 