from detector import detect_phishing
from datetime import datetime
import json
import os

# --- Step 12: Save JSON report ---
def save_json_report(result):
    os.makedirs("reports", exist_ok=True)  # create folder if not exists
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/report_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=4)
    print(f"\n✅ Report saved: {filename}")

# --- Step 12: Save logs ---
def save_log(result):
    os.makedirs("reports", exist_ok=True)
    with open("reports/logs.txt", "a") as f:
        decision = "PHISHING" if result["is_phishing"] else "SAFE"
        f.write(f"{datetime.now()} | {decision} | Score={result['score']} | {result['url']}\n")

# --- Check a single URL ---
def check_single_url():
    url = input("\nEnter URL: ").strip()
    result = detect_phishing(url)

    # Print the result
    print("\n--- scan RESULT ---")
    print("URL:", result["url"])
    print("Domain:", result["domain"])
    print("Score:", result["score"])
    print("Decision:", "PHISHING 🚨" if result["is_phishing"] else "SAFE ✅")

    print("\nTriggered Rules:")
    if result["triggered_rules"]:
        for r in result["triggered_rules"]:
            print("-", r)
    else:
        print("None")

    # Save JSON report and log
    save_json_report(result)
    save_log(result)

# --- Check URLs from a file ---
def check_file(file_path):
    try:
        with open(file_path, "r") as f:
            urls = [line.strip() for line in f if line.strip()]

        print(f"\nTesting {len(urls)} URLs from {file_path}...\n")

        for url in urls:
            result = detect_phishing(url)
            decision = "PHISHING 🚨" if result["is_phishing"] else "SAFE ✅"
            print(f"{decision} | Score={result['score']} | {url}")

            # Save JSON report and log
            save_json_report(result)
            save_log(result)

    except FileNotFoundError:
        print("File not found!")

# --- Main menu ---
def main():
    while True:
        print("\n==============================")
        print(" PHISHING DETECTOR (Rule-Based)")
        print("==============================")
        print("1) Check a URL")
        print("2) Test safe URLs file")
        print("3) Test phishing URLs file")
        print("4) Exit")

        choice = input("\nChoose: ").strip()

        if choice == "1":
            check_single_url()
        elif choice == "2":
            check_file("datasets/safe_urls.txt")
        elif choice == "3":
            check_file("datasets/phishing_urls.txt")
        elif choice == "4":
            print("Bye 👋")
            break
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()
