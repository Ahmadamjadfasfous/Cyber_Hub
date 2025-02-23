import json

def generate_report(results):
    try:
        with open("report.json", "w") as report_file:
            json.dump(results, report_file, indent=4)
        print("Report saved as report.json.")
    except Exception as e:
        print(f"Error generating report: {e}")

# Example usage
if __name__ == "__main__":
    scan_results = {
        "file": {"path": "sample_file.exe", "status": "Malicious", "details": ["Suspicious pattern"]},
        "url": {"url": "http://malicious-site.com", "status": "Malicious", "reason": "Listed in blocklist"}
    }
    generate_report(scan_results)
