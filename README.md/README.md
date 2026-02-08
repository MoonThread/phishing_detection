# Phishing Detection System (Rule-Based)

## 📌 Project Description
This project is a simple phishing URL detection system developed in Python.
It detects suspicious URLs using a set of security rules (no AI / no machine learning).

## 🎯 Objectives
- Detect phishing URLs using rule-based analysis
- Give a final decision: SAFE or PHISHING
- Explain why the URL is suspicious (triggered rules + score)

## 🧠 Detection Method
The system uses a scoring approach:
- Each suspicious rule adds points to a total score.
- If the score is greater than or equal to 5, the URL is classified as phishing.

## 📁 Project Structure
phishing_detector/
- main.py (program entry point)
- detector.py (detection engine)
- rules.py (security rules)
- url_utils.py (URL parsing utilities)
- datasets/ (test URLs)

## ▶️ How to Run
1. Open the project folder in VS Code
2. Run the program:

```bash
python main.py
