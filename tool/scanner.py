import os
import argparse
import json
import re

# Resolved relative to this file so it works regardless of the calling CWD.
_DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner_config.json")

def load_config(config_path=None):
    """
    Reads the JSON configuration file for targets and ignores.
    """
    if config_path is None:
        config_path = _DEFAULT_CONFIG

    try:
        with open(config_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"[!] Warning: Config file not found at {config_path}. Using defaults.")

        # Fallback
        return {
            "target_extensions": [".js", ".ts", ".tsx", ".jsx", ".env", ".env.local"],
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

            # check if it has ownership validation
            if any(own_word in content for own_word in ownership_keywords):
                has_owner_check = True

        if not has_auth:
            findings.append({
                "type": "Missing Route Authentication for Sensitive Endpoints",
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

def scan_plaintext_passwords(file_path):
    """
    Scans for plaintext password comparisons that use equality
    and flagging when standard cryptographic libraries are missing.
    """

    if file_path.endswith(('.json', '.env', '.md')):
        return []

    findings = []
    
    password_keywords = ['password', 'passwd', 'pwd']
    crypto_keywords = ['bcrypt', 'argon2', 'scrypt', 'hash', 'compare']
    
    equality_regex = re.compile(r'===|==|!==|!=')

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_number, line in enumerate(file, 1):
                lower_line = line.lower()

                # check for comparison
                if equality_regex.search(line):
                    if any(pwd in lower_line for pwd in password_keywords):
                        # check for libraries
                        if not any(crypto in lower_line for crypto in crypto_keywords):
                            findings.append({
                                "type": "Unsafe password comparison (Plaintext)",
                                "line": line_number,
                                "content": line.strip()[:100]
                            })
                            
    except Exception as e:
        pass 

    return findings

def scan_insecure_storage(file_path):
    """
    Scans frontend logic files for instances where authentication tokens 
    are being saved to highly accessible web storage (localStorage/sessionStorage).
    """

    if not file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
        return []

    findings = []
    
    storage_keywords = ['localstorage.setitem', 'sessionstorage.setitem']
    auth_keywords = ['token', 'jwt', 'auth', 'session']

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_number, line in enumerate(file, 1):
                lower_line = line.lower()
                
                if any(storage in lower_line for storage in storage_keywords):
                    if any(auth in lower_line for auth in auth_keywords):
                        findings.append({
                            "type": "Insecure token storage (XSS Risk)",
                            "line": line_number,
                            "content": line.strip()[:100]
                        })
                            
    except Exception as e:
        pass 

    return findings

def scan_sql_injection(file_path):
    """
    Scans for potential SQL Injection vulnerabilities by checking for direct string
    concatenation within SQL queries.
    """
    
    if not file_path.endswith(('.js', '.ts', '.jsx', '.tsx')):
        return []

    findings = []
    
    sql_keywords = ['select *', 'select ', 'insert into ', 'update ', 'delete from ']
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_number, line in enumerate(file, 1):
                lower_line = line.lower()
                
                # check for literals and direct concatenation
                if any(sql in lower_line for sql in sql_keywords):
                    if '${' in line or '+' in line:
                        if '?' not in line and '$1' not in line:
                            findings.append({
                                "type": "Potential SQL Injection (Direct Concatenation)",
                                "line": line_number,
                                "content": line.strip()[:100]
                            })
                            
    except Exception as e:
        pass 

    return findings

def scan_stub_code(file_path):
    """
    Flags placeholder / stub code (TODO/FIXME, fake auth, not-implemented)
    left in JavaScript/TypeScript source files.
    """
    if not file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
        return []

    stub_regex = re.compile(
        r"(?i)(//\s*(todo|fixme|hack|xxx)\b"
        r"|/\*\s*(todo|fixme|hack|xxx)\b"
        r"|\bnot[\s_]?implemented\b"
        r"|throw\s+new\s+Error\(\s*['\"]((todo|not implemented|unimplemented))"
        r"|return\s+true\s*;?\s*//\s*(todo|temp|placeholder|for now|skip auth)"
        r"|\bplaceholder\b|\bdummy(data|user|token|value)?\b)"
    )

    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_number, line in enumerate(file, 1):
                if stub_regex.search(line):
                    findings.append({
                        "type": "Placeholder / stub code left in source",
                        "line": line_number,
                        "content": line.strip()[:100]
                    })
    except Exception:
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
    total_plaintext_pwds_found = 0
    total_storage_flaws_found = 0
    total_sql_injects_found = 0
    
    # Loop through the files we found and scan them
    for file_path in files:
        secrets_found = scan_for_secrets(file_path)
        weak_config_found = scan_jwt_config(file_path)
        route_flaw_found = scan_route_logic(file_path)
        plaintext_pwd_found = scan_plaintext_passwords(file_path)
        storage_flaw_found = scan_insecure_storage(file_path)
        sql_inject_found = scan_sql_injection(file_path)
        stub_found = scan_stub_code(file_path)

        
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

        if plaintext_pwd_found:
            print(f"\n[!] WARNING: Plaintext password logic found in: {file_path}")
            for pwd in plaintext_pwd_found:
                print(f"    -> Line {pwd['line']} | Type: {pwd['type']}")
                total_plaintext_pwds_found += 1

        if storage_flaw_found:
            print(f"\n[!] WARNING: Insecure client-side storage found in: {file_path}")
            for flaw in storage_flaw_found:
                print(f"    -> Line {flaw['line']} | Type: {flaw['type']}")
                total_storage_flaws_found += 1

        if sql_inject_found:
            print(f"\n[!] WARNING: Potential SQL Injection found in: {file_path}")
            for inject in sql_inject_found:
                print(f"    -> Line {inject['line']} | Type: {inject['type']}")
                total_sql_injects_found += 1

        if stub_found:
            print(f"\n[!] WARNING: Placeholder / stub code found in: {file_path}")
            for stub in stub_found:
                print(f"    -> Line {stub['line']} | Type: {stub['type']}")

    print(f"""\n[*] Scan complete.
        Total potential secrets found: {total_secrets_found}
        Total weak JWT configurations found: {total_weak_config_found}
        Total authorization flaws found: {total_route_flaws_found}
        Total plaintext passwords found: {total_plaintext_pwds_found}
        Total token storage flaws found: {total_storage_flaws_found}
        Total potential SQL injections found: {total_sql_injects_found}
    """)
    

if __name__ == "__main__":
    main()