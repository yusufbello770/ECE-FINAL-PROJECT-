import requests
import socket
import time
import random

def generate_test_traffic():
    print("Generating test network traffic...")
    
    # HTTP requests
    print("Making HTTP requests...")
    urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.python.org",
        "https://www.microsoft.com",
        "https://www.amazon.com",
        "https://www.netflix.com",
        "https://www.spotify.com",
        "https://www.twitter.com"
    ]
    
    # Make multiple requests to generate more traffic
    for _ in range(3):  # Make 3 rounds of requests
        for url in urls:
            try:
                response = requests.get(url)
                print(f"Requested {url} - Status: {response.status_code}")
                time.sleep(0.5)  # Small delay between requests
            except Exception as e:
                print(f"Failed to request {url}: {str(e)}")
    
    # DNS lookups
    print("\nPerforming DNS lookups...")
    domains = [
        "google.com",
        "github.com",
        "python.org",
        "microsoft.com",
        "amazon.com",
        "netflix.com",
        "spotify.com",
        "twitter.com",
        "facebook.com",
        "instagram.com"
    ]
    
    # Perform multiple DNS lookups
    for _ in range(2):  # Make 2 rounds of DNS lookups
        for domain in domains:
            try:
                ip = socket.gethostbyname(domain)
                print(f"Resolved {domain} -> {ip}")
                time.sleep(0.3)  # Small delay between lookups
            except Exception as e:
                print(f"Failed to resolve {domain}: {str(e)}")
    
    print("\nTest traffic generation complete!")

if __name__ == "__main__":
    generate_test_traffic() 