import os
import argparse
import json
import re

def load_config(config_path="tool/scanner_config.json"):
    """
    Reads the JSON configuration file for targets and ignores.
    """

    try:
        with open(config_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"[!] Warning: Config file not found at {config_path}. Using defaults.")

        # Fallback 
        return {
            "target_extensions": [".js", ".ts", ".tsx", ".env"],
            "ignore_dirs": ["node_modules", ".git", ".next", "dist", "build"]
        }

def get_files_to_scan(target_dir, config):
    """
    Walks through the target directory and returns a list of valid file paths
    based on the provided configuration.
    """

    target_extensions = config.get("target_extensions", [])
    ignore_dirs = config.get("ignore_dirs", [])
    
    files_to_scan = []

    for root, dirs, files in os.walk(target_dir):
        # Modify the 'dirs' list in-place to prevent os.walk from entering ignored directories
        dirs[:] = [d for d in dirs if d not in ignore_dirs]

        for file in files:
            # Check if the file ends with one of our target extensions
            if any(file.endswith(ext) for ext in target_extensions):
                full_path = os.path.join(root, file)
                files_to_scan.append(full_path)

    return files_to_scan

def scan_for_secrets(file_path):
    """
    Reads a file line-by-line and applies regex to find hardcoded secrets.
    """
    # Rule 1: Catch variable names like secret, password, token, or api_key being assigned a string
    context_regex = re.compile(r'(?i)(password|secret|api_key|apikey|token)\s*[:=]\s*[\'"]([^\'"]+)[\'"]')
    
    # Rule 2: Catch strict token formats (e.g., sk- followed by 32 alphanumeric characters)
    format_regex = re.compile(r'sk-[a-zA-Z0-9]{32}')
    
    findings = []

    try:
        # Open the file and read it line by line
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_number, line in enumerate(file, 1):
                
                # Check Rule 1
                if context_regex.search(line):
                    findings.append({
                        "type": "Predictable Variable Name",
                        "line": line_number,
                        "content": line.strip()[:100] # Truncate so we don't print massive lines
                    })
                
                # Check Rule 2
                if format_regex.search(line):
                    findings.append({
                        "type": "Exposed API Token (sk- format)",
                        "line": line_number,
                        "content": line.strip()[:100]
                    })
                    
    except Exception as e:
        pass 

    return findings

def main():
    parser = argparse.ArgumentParser(description="Vibe Fuzzer SAST Module: Static Code Scanner")
    parser.add_argument("--dir", required=True, help="Path to the application directory you want to scan")
    
    args = parser.parse_args()
    target_directory = args.dir

    if not os.path.isdir(target_directory):
        print(f"Error: The directory '{target_directory}' does not exist.")
        return

    print(f"[*] Initializing scan on directory: {target_directory}")
    config = load_config()
    files = get_files_to_scan(target_directory, config)

    print(f"[*] Found {len(files)} relevant files to scan.\n")
    print("[*] Starting Search...")
    total_secrets_found = 0
    
    # Loop through the files we found and scan them
    for file_path in files:
        secrets_found = scan_for_secrets(file_path)
        
        if secrets_found:
            print(f"\n[!] WARNING: Potential secrets found in: {file_path}")
            for secret in secrets_found:
                print(f"    -> Line {secret['line']} | Type: {secret['type']}")
                total_secrets_found += 1

    print(f"\n[*] Secrets scan complete. Total potential secrets found: {total_secrets_found}")

if __name__ == "__main__":
    main()