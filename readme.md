# Keyring CLI Setup & Usage Guide

## **1. Overview**
`keyring_cli.py` is a command-line tool for securely storing and managing API keys, tokens, and credentials using the system's keyring. This also tracks usage and where keys are used. It uses Windows Credential manager for the password to export and deycrpt the key if you need to migrate.

**New Features:**
- Windows authentication security for all sensitive operations
- Bulk import from JSON and TOML configuration files
- Detailed usage tracking and reporting
- Optional descriptions for better documentation of keys

---

## **2 Setting Up `keyring_cli.py` to be used globally (not in a venv)**
### **Change location of where files should be in thhe script `keyring_cli.py`:***
   - Backup file: `EXPORT_FILE = r"C:\.virtualenv\keyring_backup.enc"` 
   - Log to track usage: `TRACKED_KEYS_FILE = r"C:\.virtualenv\tracked_keys.json"` 
   - Used to migrate to new workstation: `MIGRATION_FILE = r"C:\.virtualenv\keyring_migration.enc"`


### **Put `keyring_cli.py` and `setup.py` together into a folder:**
   ```sh
      pip install .
   ```
### **Test to ensure it installed and is working:**
   ```sh
      keyring-cli list
   ```
---

## **3. Using `keyring_cli.py`**
### **Store a Secret**
```sh
keyring-cli store --key <key_name> --value <secret_value> --description "Optional description"
```
Example:
```sh
keyring-cli store --key api_key --value my_secret_api_key --description "Production API key"
```

### **Retrieve a Secret**
```sh
keyring-cli get --key <key_name>
```
Example:
```sh
keyring-cli get --key api_key
```

### **List Stored Keys**
```sh
keyring-cli list
```
This shows stored **key names only** (not values).

### **Delete a Secret**
```sh
keyring-cli delete --key <key_name>
```
Example:
```sh
keyring-cli delete --key api_key
```

### **View All Secrets**
```sh
keyring-cli view
```
Displays all stored keys and their values (requires Windows authentication).

---

## **4. Exporting & Importing Keys Securely**
### **Export Encrypted Secrets**
```sh
keyring-cli export
```
- Prompts for your **workstation login password** or a custom password.
- Saves an **encrypted** backup in `C:\.virtualenvs\keyring_backup.enc`.

### **Import Encrypted Secrets**
```sh
keyring-cli import
```
- Prompts for the password used to encrypt the backup.
- Restores all previously stored keys.

---

## **5. Migrating to a New Workstation**
### **Export for Migration**
```sh
keyring-cli export-migration
```
- Creates an encrypted migration backup.

### **Import on a New Machine**
```sh
keyring-cli import-migration
```
- Prompts for the migration password to restore keys.

---

## **6. Automating Key Backups**
To **schedule automatic backups** every 24 hours:
- **Windows:** Use Task Scheduler
  ```sh
  schtasks /create /tn "Keyring Backup" /tr "python C:\.virtualenvs\keyring_cli.py export" /sc daily /st 00:00
  ```

---

## **7. Using Stored Keys in Python Scripts**
### **Using the Secure Keyring Wrapper (with usage tracking)**
```python
import secure_keyring

# Get a key (usage will be tracked)
api_key = secure_keyring.get_password("api_key")

# Set a key with description
secure_keyring.set_password("new_key", "secret_value", "API key for staging env")

# Delete a key
secure_keyring.delete_password("old_key")
```

### **Retrieving Keys in Python (legacy)**
```python
import keyring

SERVICE_NAME = "GlobalSecrets"

api_key = keyring.get_password(SERVICE_NAME, "api_key")
client_id = keyring.get_password(SERVICE_NAME, "sky_app_information.app_id")
webhook_key = keyring.get_password(SERVICE_NAME, "webhook.webhook_key")
```

### **Making Authenticated API Calls**
```python
import requests
import secure_keyring

# Usage tracking enabled
api_key = secure_keyring.get_password("api_key")

response = requests.get("https://api.example.com", headers={"Authorization": f"Bearer {api_key}"})
print(response.json())
```

---

## **8. Bulk Import from Configuration Files**
### **Import from JSON**
```sh
keyring-cli import-json --file <path_to_json_file>
```
Example:
```sh
keyring-cli import-json --file config.json
```
- Preserves nested structure with dot notation (e.g., `database.password`)
- Adds metadata about source and import date

### **Import from TOML**
```sh
keyring-cli import-toml --file <path_to_toml_file>
```
Example:
```sh
keyring-cli import-toml --file config.toml
```
- Preserves nested structure with dot notation (e.g., `aws.credentials.secret_key`)
- Adds metadata about source and import date

---

## **9. Usage Tracking and Reporting**
### **Generate Usage Report for a Key**
```sh
keyring-cli usage --key <key_name>
```
Example:
```sh
keyring-cli usage --key api_key
```
Shows which files access the key, how many times, and when.

### **Generate Comprehensive Usage Report**
```sh
keyring-cli usage-report
```
Provides a full analysis of all keys, including:
- Most frequently accessed keys
- Files accessing each key
- First and last usage timestamps

## **10. The secure_keyring.py Module**

The `secure_keyring.py` module provides a secure wrapper around the standard keyring functions with automatic usage tracking. This module is the recommended way to access secrets in your Python code.

### **Key Features:**
- **Automatic Usage Tracking**: Records which files access each secret and how often
- **Timestamps**: Captures first and last access times for security auditing
- **Metadata Storage**: Maintains descriptions and source information for each key
- **Simple API**: Drop-in replacement for standard keyring functions

### **Functions Available:**
```python
# Get a key with automatic usage tracking
secure_keyring.get_password(key_name)

# Store a key with optional description
secure_keyring.set_password(key_name, value, description=None)

# Delete a key and its tracking data
secure_keyring.delete_password(key_name)

# Get usage statistics for a key or all keys
secure_keyring.get_usage_data(key_name=None)

# Get metadata about keys
secure_keyring.get_key_metadata(key_name=None)
```

### **Example: Tracking Secret Usage**
```python
import secure_keyring

# Get a key (automatically tracks this access)
api_key = secure_keyring.get_password("production_api_key")

# Use the key in your application
response = requests.post(
    "https://api.example.com/v1/data",
    headers={"Authorization": f"Bearer {api_key}"},
    json=payload
)
```

The usage of this key will be recorded with:
- The filename making the request
- Timestamp of the access
- Incrementing the access counter

This data is then available through the CLI commands:
```sh
keyring-cli usage --key production_api_key
```

## **11. Help and Documentation**
```sh
keyring-cli help
```
Displays detailed help information about all commands and usage.

---

## **12. Troubleshooting**
### **Key Not Found?**
Check if the key exists:
```sh
keyring-cli list
```
If missing, re-add it:
```sh
keyring-cli store --key api_key --value my_secret_api_key
```

### **Keyring Not Working?**
Try:
```sh
python -m keyring --help
```
If needed, manually configure the backend:
```sh
python -m keyring set GlobalSecrets api_key my_secret_api_key
```

---

## **13. Summary of CLI Commands**
| **Command** | **Description** |
|------------|----------------|
| `keyring-cli store --key <key_name> --value <value> --description "desc"` | Store a key securely |
| `keyring-cli get --key <key_name>` | Retrieve a stored key |
| `keyring-cli list` | List stored keys (names only) |
| `keyring-cli delete --key <key_name>` | Delete a key from keyring |
| `keyring-cli view` | View all secrets (requires auth) |
| `keyring-cli export` | Export all keys (encrypted) |
| `keyring-cli import` | Import keys from encrypted backup |
| `keyring-cli export-migration` | Export for moving to a new workstation |
| `keyring-cli import-migration` | Import keys on a new workstation |
| `keyring-cli import-json --file <path>` | Bulk import from JSON file |
| `keyring-cli import-toml --file <path>` | Bulk import from TOML file |
| `keyring-cli usage --key <key_name>` | Show usage report for a key |
| `keyring-cli usage-report` | Show comprehensive usage report |
| `keyring-cli help` | Display detailed help information |

---
