import os
import argparse
import json

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

def main():
    parser = argparse.ArgumentParser(description="Vibe Fuzzer SAST Module: Static Code Scanner")
    parser.add_argument("--dir", required=True, help="Path to the application directory you want to scan")
    
    args = parser.parse_args()
    target_directory = args.dir

    if not os.path.isdir(target_directory):
        print(f"Error: The directory '{target_directory}' does not exist.")
        return

    print(f"[*] Initializing scan on directory: {target_directory}")
    
    # Load the config
    config = load_config()
    
    # Pass the config to the scanner
    files = get_files_to_scan(target_directory, config)
    
    print(f"[*] Found {len(files)} relevant files to scan.")
    for f in files:
        print(f" -> {f}")

if __name__ == "__main__":
    main()