import keyring
import argparse
import os
import json
import base64
import getpass
import hashlib
from cryptography.fernet import Fernet
import win32security
import win32api
import win32con
import toml
from datetime import datetime
from typing import Dict, Any, Optional

# Import the secure keyring wrapper for usage tracking
import secure_keyring

SERVICE_NAME = "GlobalSecrets"
EXPORT_FILE = r"path\keyring_backup.enc"
TRACKED_KEYS_FILE = r"path\tracked_keys.json"
MIGRATION_FILE = r"path\keyring_migration.enc"

def verify_windows_login(password: str) -> bool:
    try:
        domain = win32api.GetComputerName()
        username = getpass.getuser()
        handle = win32security.LogonUser(
            username,
            domain,
            password,
            win32con.LOGON32_LOGON_NETWORK,
            win32con.LOGON32_PROVIDER_DEFAULT
        )
        handle.Close()
        return True
    except Exception:
        return False

def get_encryption_key(password: str) -> bytes:
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])

def encrypt_data(data: str, password: str) -> str:
    key = get_encryption_key(password)
    cipher = Fernet(key)
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, password: str) -> str:
    key = get_encryption_key(password)
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_data.encode()).decode()

def track_key_usage(key_name: str, description: Optional[str] = None, source: Optional[str] = None):
    if not os.path.exists(TRACKED_KEYS_FILE):
        tracked_data = {}
    else:
        with open(TRACKED_KEYS_FILE, "r") as f:
            tracked_data = json.load(f)
    
    current_time = datetime.now().strftime("%Y-%m-%d_%H:%M")
    tracked_data[key_name] = {
        "description": description,
        "source": source,
        "added_date": current_time,
        "last_modified": current_time
    }
    
    with open(TRACKED_KEYS_FILE, "w") as f:
        json.dump(tracked_data, f, indent=4)

def get_tracked_keys() -> Dict[str, Any]:
    if os.path.exists(TRACKED_KEYS_FILE):
        with open(TRACKED_KEYS_FILE, "r") as f:
            return json.load(f)
    return {}

def bulk_import_json(json_file_path: str):
    windows_password = getpass.getpass("Enter your Windows login password: ")
    if not verify_windows_login(windows_password):
        print("Error: Incorrect Windows login password.")
        return

    try:
        with open(json_file_path, 'r') as f:
            data = json.load(f)
        
        def process_json(obj, current_path=""):
            for key, value in obj.items():
                if isinstance(value, dict):
                    process_json(value, f"{current_path}{key}.")
                else:
                    full_key = f"{current_path}{key}".rstrip('.')
                    description = f"Imported from JSON file: {json_file_path}"
                    source = f"JSON path: {current_path.rstrip('.')}"
                    keyring.set_password(SERVICE_NAME, full_key, str(value))
                    track_key_usage(full_key, description, source)
                    print(f"Imported: {full_key}")

        process_json(data)
        print("\nJSON import completed successfully.")
    except Exception as e:
        print(f"Error importing JSON: {str(e)}")

def bulk_import_toml(toml_file_path: str):
    windows_password = getpass.getpass("Enter your Windows login password: ")
    if not verify_windows_login(windows_password):
        print("Error: Incorrect Windows login password.")
        return

    try:
        data = toml.load(toml_file_path)
        
        def process_toml(obj, current_path=""):
            for key, value in obj.items():
                if isinstance(value, dict):
                    process_toml(value, f"{current_path}{key}.")
                else:
                    full_key = f"{current_path}{key}".rstrip('.')
                    description = f"Imported from TOML file: {toml_file_path}"
                    source = f"TOML path: {current_path.rstrip('.')}"
                    keyring.set_password(SERVICE_NAME, full_key, str(value))
                    track_key_usage(full_key, description, source)
                    print(f"Imported: {full_key}")

        process_toml(data)
        print("\nTOML import completed successfully.")
    except Exception as e:
        print(f"Error importing TOML: {str(e)}")

def export_keys(migration: bool = False):
    """Export all stored keys with Windows authentication."""
    windows_password = getpass.getpass("Enter your Windows login password: ")
    if not verify_windows_login(windows_password):
        print("Error: Incorrect Windows login password.")
        return

    encryption_password = windows_password
    output_file = EXPORT_FILE

    if migration:
        migration_password = getpass.getpass("Create a password for file keyring_migration.enc: ")
        confirm_password = getpass.getpass("Confirm password for file keyring_migration.enc: ")
        if migration_password != confirm_password:
            print("Error: Passwords do not match.")
            return
        encryption_password = migration_password
        output_file = MIGRATION_FILE
    
    tracked_data = get_tracked_keys()
    export_data = {
        "keys": {},
        "metadata": tracked_data
    }

    for key in tracked_data.keys():
        value = keyring.get_password(SERVICE_NAME, key)
        if value:
            export_data["keys"][key] = value
    
    if not export_data["keys"]:
        print("No keys found to export.")
        return

    encrypted_data = encrypt_data(json.dumps(export_data), encryption_password)
    
    with open(output_file, "w") as f:
        f.write(encrypted_data)
    
    if migration:
        print(f"\nSecrets exported for migration to: {output_file}")
        print("IMPORTANT: Save this migration password - you'll need it on the new workstation.")
    else:
        print(f"\nSecrets exported securely to: {output_file}")

def import_keys(migration: bool = False):
    """Import keys with Windows authentication."""
    windows_password = getpass.getpass("Enter your Windows login password: ")
    if not verify_windows_login(windows_password):
        print("Error: Incorrect Windows login password.")
        return

    input_file = MIGRATION_FILE if migration else EXPORT_FILE
    if not os.path.exists(input_file):
        print(f"No backup file found at: {input_file}")
        return
    
    decryption_password = (
        getpass.getpass("Enter the migration password from the original workstation: ")
        if migration else windows_password
    )

    try:
        with open(input_file, "r") as f:
            encrypted_data = f.read()
        
        decrypted_data = json.loads(decrypt_data(encrypted_data, decryption_password))
        
        # Import keys and their metadata
        for key, value in decrypted_data["keys"].items():
            keyring.set_password(SERVICE_NAME, key, value)
            metadata = decrypted_data["metadata"].get(key, {})
            track_key_usage(key, metadata.get("description"), metadata.get("source"))
            print(f"Restored: {key}")

        print("\nAll secrets restored successfully.")

        if migration and os.path.exists(input_file):
            if input("Delete migration file for security? (y/N): ").lower() == 'y':
                os.remove(input_file)
                print("Migration file deleted.")

    except Exception as e:
        print("Failed to decrypt. Incorrect password or corrupted backup.")

def view_secrets():
    """View decrypted secrets with Windows authentication."""
    windows_password = getpass.getpass("Enter your Windows login password: ")
    if not verify_windows_login(windows_password):
        print("Error: Incorrect Windows login password.")
        return

    tracked_data = get_tracked_keys()
    if not tracked_data:
        print("No secrets found.")
        return

    print("\nStored Secrets:")
    print("-" * 50)
    for key, metadata in tracked_data.items():
        value = keyring.get_password(SERVICE_NAME, key)
        if value:
            print(f"\nKey: {key}")
            print(f"Value: {value}")
            if metadata.get("description"):
                print(f"Description: {metadata['description']}")
            if metadata.get("source"):
                print(f"Source: {metadata['source']}")
            if metadata.get("added_date"):
                print(f"Added: {metadata['added_date']}")
            print("-" * 30)

    print("\nWarning: Ensure you're in a secure environment.")
    input("\nPress Enter to clear screen...")
    os.system('cls' if os.name == 'nt' else 'clear')

def list_keys():
    """List all keys with their metadata."""
    tracked_data = get_tracked_keys()
    if not tracked_data:
        print("No keys found.")
        return

    print("\nStored Keys:")
    print("-" * 50)
    for key, metadata in tracked_data.items():
        if keyring.get_password(SERVICE_NAME, key):
            print(f"\nKey: {key}")
            if metadata.get("description"):
                print(f"Description: {metadata['description']}")
            if metadata.get("source"):
                print(f"Source: {metadata['source']}")
            if metadata.get("added_date"):
                print(f"Added: {metadata['added_date']}")

def report_key_usage(key_name=None):
    """Report usage statistics for keys"""
    windows_password = getpass.getpass("Enter your Windows login password: ")
    if not verify_windows_login(windows_password):
        print("Error: Incorrect Windows login password.")
        return

    # Use secure_keyring to get metadata
    all_metadata = secure_keyring.get_key_metadata()
    if not all_metadata:
        print("No keys found.")
        return
    
    if key_name and key_name not in all_metadata:
        print(f"Key not found: {key_name}")
        return
    
    keys_to_report = [key_name] if key_name else all_metadata.keys()
    
    print("\nKey Usage Report:")
    print("=" * 60)
    
    for key in keys_to_report:
        metadata = all_metadata.get(key, {})
        print(f"\nKey: {key}")
        
        if "description" in metadata and metadata["description"]:
            print(f"Description: {metadata['description']}")
        
        # Get usage data from secure_keyring
        usage_data = secure_keyring.get_usage_data(key)
        
        print("\nUsage Statistics:")
        print("-" * 50)
        
        if not usage_data:
            print("This key has not been accessed yet.")
        else:
            # Sort files by usage count (descending)
            sorted_files = sorted(
                usage_data.items(), 
                key=lambda x: x[1]["count"], 
                reverse=True
            )
            
            total_count = sum(file_data["count"] for _, file_data in sorted_files)
            print(f"Total accesses: {total_count}")
            
            for file_path, file_data in sorted_files:
                print(f"\nFile: {file_path}")
                print(f"  Access count: {file_data['count']}")
                print(f"  First used: {file_data.get('first_used', 'Unknown')}")
                print(f"  Last used: {file_data.get('last_used', 'Unknown')}")
    
    print("\n" + "=" * 60)

def report_all_usage():
    """Generate a comprehensive report of all key usage"""
    windows_password = getpass.getpass("Enter your Windows login password: ")
    if not verify_windows_login(windows_password):
        print("Error: Incorrect Windows login password.")
        return

    # Get all usage data from secure_keyring
    all_usage = secure_keyring.get_usage_data()
    all_metadata = secure_keyring.get_key_metadata()
    
    if not all_metadata:
        print("No keys found.")
        return
    
    # Collect usage data
    file_usage = {}
    key_usage = {}
    
    for key, usage in all_usage.items():
        if usage:
            key_usage[key] = sum(file_data["count"] for file_data in usage.values())
            
            for file_path, file_data in usage.items():
                if file_path not in file_usage:
                    file_usage[file_path] = 0
                file_usage[file_path] += file_data["count"]
    
    # Sort by usage count
    sorted_keys = sorted(key_usage.items(), key=lambda x: x[1], reverse=True)
    sorted_files = sorted(file_usage.items(), key=lambda x: x[1], reverse=True)
    
    print("\nComprehensive Usage Report:")
    print("=" * 60)
    
    print("\nMost Accessed Keys:")
    print("-" * 50)
    for key, count in sorted_keys:
        description = all_metadata.get(key, {}).get("description", "")
        print(f"{key}: {count} accesses" + (f" - {description}" if description else ""))
    
    print("\nFiles Accessing Keys:")
    print("-" * 50)
    for file_path, count in sorted_files:
        print(f"{file_path}: {count} accesses")
    
    print("\n" + "=" * 60)

def show_help():
    """Display detailed help information about using the script."""
    help_text = """
Keyring CLI Help
===============

Commands:
---------
1. Store a single key:
   keyring store --key <key_name> --value <secret_value> --description "Optional description"
   Example: keyring store --key api_key --value abc123 --description "Production API key"

2. Get a key's value:
   keyring get --key <key_name>
   Example: keyring get --key api_key

3. List all stored keys:
   keyring list

4. Delete a key:
   keyring delete --key <key_name>
   Example: keyring delete --key old_api_key

5. Export keys (secured with Windows password):
   keyring export

6. Import keys:
   keyring import

7. Export for migration to new workstation:
   keyring export-migration

8. Import on new workstation:
   keyring import-migration

9. View all secrets:
   keyring view

10. Bulk import from JSON:
    keyring import-json --file <path_to_json>
    Example: keyring import-json --file config.json

11. Bulk import from TOML:
    keyring import-toml --file <path_to_toml>
    Example: keyring import-toml --file config.toml

12. Report usage for a specific key:
    keyring usage --key <key_name>
    Example: keyring usage --key api_key

13. Generate a comprehensive usage report:
    keyring usage-report

14. Show this help:
    keyring help

Using Keys in Your Scripts:
-------------------------
To use these keys in your Python scripts with usage tracking:

import secure_keyring

# Get a single key (usage will be tracked)
api_key = secure_keyring.get_password("my_api_key")

# Example with nested keys from JSON import
app_id = secure_keyring.get_password("sky_app_information.app_id")
webhook_key = secure_keyring.get_password("webhook.webhook_key")

# Example usage
requests.get("https://api.example.com", headers={"Authorization": f"Bearer {api_key}"})

Notes:
------
- All sensitive operations require Windows authentication
- Descriptions are optional but recommended for documentation
- Export files are encrypted with Windows login or migration password
- Keys from JSON/TOML files maintain their hierarchy using dot notation
- Migration allows transfer of keys between workstations
- Usage tracking records which files access each key and how often
"""
    print(help_text)

def main():
    """Entry point for the CLI script."""
    parser = argparse.ArgumentParser(description="Manage stored secrets with keyring and secure backup.")
    parser.add_argument("action", 
                       choices=["store", "get", "list", "delete", 
                               "export", "import", "export-migration", 
                               "import-migration", "view",
                               "import-json", "import-toml", "help",
                               "usage", "usage-report"],
                       help="Action to perform")
    parser.add_argument("--key", help="Key name")
    parser.add_argument("--value", help="Value to store (only for 'store' action)")
    parser.add_argument("--description", help="Description of the key's purpose")
    parser.add_argument("--file", help="File path for bulk import")
    parser.add_argument("--force", action="store_true", help="Force overwrite existing keys")

    args = parser.parse_args()

    if args.action == "help":
        show_help()
    elif args.action == "store":
        if not args.key or not args.value:
            print("Error: 'store' action requires --key and --value")
        else:
            windows_password = getpass.getpass("Enter your Windows login password: ")
            if verify_windows_login(windows_password):
                keyring.set_password(SERVICE_NAME, args.key, args.value)
                track_key_usage(args.key, args.description)
                print(f"Stored key: {args.key}")
            else:
                print("Error: Windows authentication failed.")
    elif args.action == "get":
        if not args.key:
            print("Error: 'get' action requires --key")
        else:
            windows_password = getpass.getpass("Enter your Windows login password: ")
            if verify_windows_login(windows_password):
                value = keyring.get_password(SERVICE_NAME, args.key)
                if value:
                    print(value)
                else:
                    print(f"No value found for key: {args.key}")
            else:
                print("Error: Windows authentication failed.")
    elif args.action == "list":
        list_keys()
    elif args.action == "delete":
        if not args.key:
            print("Error: 'delete' action requires --key")
        else:
            windows_password = getpass.getpass("Enter your Windows login password: ")
            if verify_windows_login(windows_password):
                try:
                    keyring.delete_password(SERVICE_NAME, args.key)
                    print(f"Deleted key: {args.key}")
                except keyring.errors.PasswordDeleteError:
                    print(f"Key not found: {args.key}")
            else:
                print("Error: Windows authentication failed.")
    elif args.action == "export":
        export_keys(migration=False)
    elif args.action == "export-migration":
        export_keys(migration=True)
    elif args.action == "import":
        import_keys(migration=False)
    elif args.action == "import-migration":
        import_keys(migration=True)
    elif args.action == "view":
        view_secrets()
    elif args.action == "import-json":
        if not args.file:
            print("Error: --file parameter required for JSON import")
        else:
            bulk_import_json(args.file)
    elif args.action == "import-toml":
        if not args.file:
            print("Error: --file parameter required for TOML import")
        else:
            bulk_import_toml(args.file)
    elif args.action == "usage":
        report_key_usage(args.key)
    elif args.action == "usage-report":
        report_all_usage()

if __name__ == "__main__":
    main()
