# scanner/utils/http.py

import requests
import random
import time

# Common headers to look like a real browser
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}

# Create a session to persist cookies
session = requests.Session()
session.headers.update(BROWSER_HEADERS)

def fetch_headers(domain):
    """
    Fetch only HTTP headers from a domain.
    """
    url = f"https://{domain}"

    try:
        response = session.get(url, timeout=60, allow_redirects=True)
        return response.headers
    except Exception as e:
        print(f"Error fetching headers: {e}")
        return None

def fetch_cookies(domain):
    """
    Fetch cookies from a domain.
    """
    url = f"https://{domain}"

    try:
        response = session.get(url, timeout=60, allow_redirects=True)
        return response.cookies
    except Exception as e:
        print(f"Error fetching cookies: {e}")
        return None

def fetch_url(url, timeout=5):
    """
    Standard GET request with browser-like headers, session, and polite sleep.
    """
    try:
        # Polite random sleep between 1 and 2.5 seconds
        time.sleep(random.uniform(1.0, 2.5))

        response = session.get(url, timeout=timeout, allow_redirects=True)
        return response
    except requests.RequestException:
        return None
