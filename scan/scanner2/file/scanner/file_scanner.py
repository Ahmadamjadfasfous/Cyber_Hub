import yara

def load_yara_rules(rule_path):
    try:
        return yara.compile(filepath=rule_path)
    except Exception as e:
        print(f"Error loading Yara rules: {e}")
        return None

def scan_file(file_path, rules):
    try:
        matches = rules.match(file_path)
        return matches
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
        return None

# Example usage
if __name__ == "__main__":
    rules = load_yara_rules("rules/suspicious_rules.yara")
    if rules:
        result = scan_file("uploads/sample_file.exe", rules)
        if result:
            print("Malicious file detected:", result)
        else:
            print("File is clean.")
