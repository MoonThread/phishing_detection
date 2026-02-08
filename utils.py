import json
import time

def save_log(result: dict):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"phishing_log_{timestamp}.txt"
    with open(filename, "w") as f:
        f.write("PHISHING DETECTOR LOG\n")
        f.write("====================\n")
        f.write(f"URL: {result['url']}\n")
        f.write(f"Domain: {result['domain']}\n")
        f.write(f"Score: {result['score']}\n")
        f.write(f"Decision: {'PHISHING' if result['is_phishing'] else 'SAFE'}\n")
        f.write("\nTriggered Rules:\n")
        if result['triggered_rules']:
            for r in result['triggered_rules']:
                f.write(f"- {r}\n")
        else:
            f.write("None\n")
    print(f"\nLog saved to {filename}")

def save_json_report(result: dict):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"phishing_report_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=4)
    print(f"JSON report saved to {filename}")
