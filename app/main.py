"""
main.py
A very simple Python script that uses the requests library to fetch JSON
from a URL and print it. This is intentionally minimal for Snyk scanning.
"""

import requests
import sys


def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        print(response.json())
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()