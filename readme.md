# Keyring CLI Setup & Usage Guide

## **1. Overview**
`keyring_cli.py` is a command-line tool for securely storing and managing API keys, tokens, and credentials using the system's keyring. This also tracks usage and where keys are used. It uses Windows Credential manager for the password to export and deycrpt the key if you need to migrate..

---

## **2 Setting Up `keyring_cli.py` to be used globally (not in a venv)**
### **Change location of where files should be  in keyring_cli.py:***
   - `SERVICE_NAME = "GlobalSecrets"`
   - `EXPORT_FILE = r"C:\.virtualenv\keyring_backup.enc"`
   - `TRACKED_KEYS_FILE = r"C:\.virtualenv\tracked_keys.json"`
   - `MIGRATION_FILE = r"C:\.virtualenv\keyring_migration.enc"`

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
keyring-cli store --key <key_name> --value <secret_value>
```
Example:
```sh
keyring-cli store --key api_key --value my_secret_api_key
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

## **7 Using Stored Keys in Python Scripts**
### **Retrieving Keys in Python**
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
import keyring

SERVICE_NAME = "GlobalSecrets"
api_key = keyring.get_password(SERVICE_NAME, "api_key")

response = requests.get("https://api.example.com", headers={"Authorization": f"Bearer {api_key}"})
print(response.json())
```

---

## **8. Troubleshooting**
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

## **9. Summary of CLI Commands**
| **Command** | **Description** |
|------------|----------------|
| `keyring-cli store --key <key_name> --value <value>` | Store a key securely |
| `keyring-cli get --key <key_name>` | Retrieve a stored key |
| `keyring-cli list` | List stored keys (names only) |
| `keyring-cli delete --key <key_name>` | Delete a key from keyring |
| `keyring-cli export` | Export all keys (encrypted) |
| `keyring-cli import` | Import keys from encrypted backup |
| `keyring-cli export-migration` | Export for moving to a new workstation |
| `keyring-cli import-migration` | Import keys on a new workstation |

---
