# VibeCheck

## Description
This tool is a hybrid security scanning and fuzzing suite specifically engineered to audit "vibe-coded" applications like websites and APIs that are rapidly generated using Large Language Models (LLMs) like ChatGPT or Claude. While AI-assisted development produces functional code with zero syntax errors, it notoriously introduces massive architectural blind spots because AI optimizes for immediate functionality rather than defensive security engineering.

## Purpose
The core purpose of this tool is to provide developers and security teams with an automated way to test whether AI-generated codebases have proper security controls and middleware implemented before deployment.

## Features
* **Hardcoded Secrets Detection:** Scans local code repositories using regex matching to find plaintext passwords, API keys, tokens, and placeholders committed by AI models.
* **Missing Endpoint Authorization Auditor:** Parses local backend routing structures to find sensitive API paths missing explicit authentication wrappers or decorators.
* **Weak JWT Validation Checker:** Identifies unsafe configurations in JSON Web Token validation engines (e.g., missing signature verification or generic placeholder secret keys).
* **Automated IDOR-by-Default Tester:** Dynamically fires cross-token requests at local parameters to catch unvalidated numeric endpoint object references.
* **Rate-Limiting & Verbose Error Fuzzer:** Stress-tests local entry forms with concurrent asynchronous payloads to catch missing request throttling and captures 500 Internal Server Errors for leaked server file paths or stack traces.

## System Requirements
* Python 3.8+
* `requests`, `PyJWT` (dynamic fuzzing) and `rich` (pretty terminal report) — see `requirements.txt`. The static scan runs on the standard library alone; the dynamic phase and pretty output degrade gracefully if their optional deps are missing.

## Installation
1. Clone the repository.
2. (Optional but recommended) create a virtual environment.
3. Install dependencies: `pip install -r requirements.txt`

## Usage
The whole suite runs from a single entry point, `main.py`.

```bash
# Static scan only (default) — point it at a project directory
python main.py --dir ./my-vibecoded-app

# Write the final risk report to a file (txt, json, or a styled html page)
python main.py --dir ./my-vibecoded-app --format json --output report.json
python main.py --dir ./my-vibecoded-app --format html --output report.html

# Also run the live dynamic fuzzer against a locally running instance
python main.py --dir ./my-vibecoded-app --dynamic --url http://localhost:3000
```

Run `python main.py --help` for the full list of options (login credentials,
endpoint overrides, request count, etc.). The tool prints a color-coded
vulnerability risk report to the terminal and, with `--output`, writes the same
report to disk as human-readable TXT, machine-readable JSON, or a self-contained,
styled HTML page (open `report.html` in any browser — no internet needed). Its
exit code is `1` when any HIGH/CRITICAL finding is present, so it drops straight
into CI.

Every finding is scored with the **CVSS v3.1** Base metric formula (implemented
per the FIRST specification), so each report shows a numeric 0.0–10.0 score, the
official severity band (None/Low/Medium/High/Critical), and the full vector
string (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). The overall risk
level is driven by the highest CVSS score present.

## Testing Environment
* **Controlled Lab Setup:** This tool is strictly tested within a local, simulated infrastructure environment.
* **Target Applications:** Three intentionally-vulnerable sample apps ship with the repo for testing — `vulnerable-target` (e-commerce), `vulnerable-targets2` (fintech/payments), and `vulnerable-targets3` (admin dashboard) — each seeded with a different mix of flaws and hosted on loopback addresses (localhost / 127.0.0.1).
* **Isolation:** The application boundaries are isolated completely from public web servers, external cloud services, or production institutional systems.

## Sample Output
* insert once final

## Limitations
* insert once final

## Future Improvements
* insert once final

## Ethical Disclaimer
This tool was developed for educational purposes only. It must only be used in authorized and controlled testing environments. Unauthorized testing against real systems, public websites, or third-party services is strictly prohibited.

## Group Members and Roles

**NSSECU02 S04 Group 9:**
* **Kristopher Lance Chiu** - Insert Role Here  
* **Andrea Gayle Garcia** - Insert Role Here 
* **Rainer Gonzaga** - Insert Role Here 
* **Sky Hannah Parado** - Insert Role Here 
* **Jeroen Ralph Tenorio** - Insert Role Here 


## Original Contribution
insert here
