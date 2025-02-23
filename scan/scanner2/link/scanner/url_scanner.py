import requests

BLOCKLIST = [
    "malicious-site.com",
    "phishing-example.net",
]

def scan_url(url):
    try:
        # Check blocklist
        domain = url.split('/')[2]
        if domain in BLOCKLIST:
            return {"status": "Malicious", "reason": "Listed in blocklist"}
        
        # Check HTTP response
        response = requests.head(url, timeout=5)
        if response.status_code == 200:
            return {"status": "Safe"}
        else:
            return {"status": "Suspicious", "reason": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"status": "Error", "reason": str(e)}

# Example usage
if __name__ == "__main__":
    result = scan_url("http://malicious-site.com")
    print(result)
