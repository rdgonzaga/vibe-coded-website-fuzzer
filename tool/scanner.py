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

def scan_jwt_config(file_path):
    """
    Reads a file line-by-line and checks for weak JWT configurations.
    """

    # check if website allows the use of expired tokens
    ignore_exp_regex = re.compile(r'(?i)ignoreExpiration\s*:\s*true')

    # check if website allows the use of tokens before its set valid time
    ignore_nb4_regex = re.compile(r'(?i)ignoreNotBefore\s*:\s*true')

    # check if website has no signature verfication
    alg_none_regex = re.compile(r'(?i)algorithms\s*:\s*\[?[\'"]none[\'"]\]?')

    # checks for common placeholders in jwt.sign/jwt.verify
    weak_placeholder_regex = re.compile(r'jwt\.(verify|sign)\s*\([^,]+,\s*[\'"](supersecret|secret|changeme|123456|default)[\'"]')

    findings = []

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_number, line in enumerate(file, 1):
                if ignore_exp_regex.search(line):
                    findings.append({
                        "type": "Insecure JWT: ignoreExpiration = true",
                        "line": line_number,
                        "content": line.strip()[:100]
                    }) 

                if ignore_nb4_regex.search(line):
                    findings.append({
                        "type": "Insecure JWT: ignoreNotBefore = true",
                        "line": line_number,
                        "content": line.strip()[:100]
                    })

                if alg_none_regex.search(line):
                    findings.append({
                        "type": "Insecure JWT: 'none' algorithm accepted",
                        "line": line_number,
                        "content": line.strip()[:100]
                    })

                if weak_placeholder_regex.search(line):
                    findings.append({
                        "type": "Insecure JWT: predictable secret key is hardcoded",
                        "line": line_number,
                        "content": line.strip()[:100]
                    })

                if 'jwt.sign' in line and 'expiresIn' not in line:
                    findings.append({
                        "type": "Insecure JWT: Token created without expiresIn flag",
                        "line": line_number,
                        "content": line.strip()[:100]
                    })
    except Exception as e:
        pass

    return findings 

def scan_route_logic(file_path):
    """
    Parses backend API routing files to check if sensitive endpoints are missing
    explicit authentication middleware.
    """

    # only analyze api directories
    if 'api' not in file_path.lower():
            return[]

    # feel free to add more
    sensitive_keywords = ['user', 'admin', 'profile', 'account', 'settings', 'payment', 'billing']
    auth_keywords = ['middleware', 'isauthenticated', 'requireauth', 
                     'verifytoken', 'getserversession', 'jwt.verify']
    ownership_keywords = ['!== decoded.id', '!= user.id', '!== req.user.id', 
                          'token.id ===', 'user.id ===']

    is_sensitive = any(sens_word in file_path.lower() for sens_word in sensitive_keywords)

    if not is_sensitive:
        return[]

    findings = []
    has_auth = False
    has_owner_check = False
    is_parameterized = '[id]' in file_path.lower()

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read().lower()

            # check if there's auth logic in file
            if any(auth_word in content for auth_word in auth_keywords):
                has_auth = True

            if any(own_word in content for own_word in ownership_keywords):
                has_owner_check = True

        if not has_auth:
            findings.append({
                "type": "Missing Route Authentication for Senstive Endpoints",
                "line": 1,
                "content": f"File '{os.path.basename(file_path)}' lacks recognized auth checks."
            })

        if is_parameterized and not has_owner_check:
            findings.append({
                "type": "Broken Object-Level (IDOR) Risk",
                "line": 1,
                "content": f"File '{os.path.basename(file_path)}' takes [id] parameter but lacks explicit ownership validation." 
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
    total_weak_config_found = 0
    total_route_flaws_found = 0
    
    # Loop through the files we found and scan them
    for file_path in files:
        secrets_found = scan_for_secrets(file_path)
        weak_config_found = scan_jwt_config(file_path)
        route_flaw_found = scan_route_logic(file_path)

        
        if secrets_found:
            print(f"\n[!] WARNING: Potential secrets found in: {file_path}")
            for secret in secrets_found:
                print(f"    -> Line {secret['line']} | Type: {secret['type']}")
                total_secrets_found += 1

        if weak_config_found:
            print(f"\n[!] WARNING: Potentially weak JWT configurations found in: {file_path}")
            for weak_config in weak_config_found:
                print(f"    -> Line {weak_config['line']} | Type: {weak_config['type']}")
                total_weak_config_found += 1

        if route_flaw_found:
            print(f"\n[!] WARNING: Missing authorization controls found in: {file_path}")
            for flaw in route_flaw_found:
                print(f"    -> Line {flaw['line']} | Type: {flaw['type']}")
                total_route_flaws_found += 1

    print(f"""\n[*] Scan complete.
        Total potential secrets found: {total_secrets_found}
        Total weak JWT configurations found: {total_weak_config_found}
        Total authorization flaws found: {total_route_flaws_found}
    """)
    

if __name__ == "__main__":
    main()