# Keyring CLI Setup & Usage Guide

## **1. Overview**
`keyring_cli.py` is a command-line tool for securely storing and managing API keys, tokens, and credentials using the system's keyring. This guide walks you through setup and usage.

---

## **2. Installation**
### **2.1 Install Required Dependencies**
Ensure you have `pipenv` installed and set up:
```sh
pip install pipenv
```
Then navigate to your project folder and install dependencies:
```sh
pipenv install
pipenv install keyring cryptography
```

---

## **3. Setting Up `keyring_cli.py`**
1. **Move `keyring_cli.py` to a persistent location**, such as:
   ```
   C:\.virtualenvs\keyring_cli.py  (Windows)
   /usr/local/bin/keyring_cli.py      (Linux/macOS)
   ```
2. **Ensure it's executable** (Linux/macOS):
   ```sh
   chmod +x keyring_cli.py
   ```

---

## **4. Using `keyring_cli.py`**
### **4.1 Store a Secret**
```sh
python keyring_cli.py store --key <key_name> --value <secret_value>
```
Example:
```sh
python keyring_cli.py store --key api_key --value my_secret_api_key
```

### **4.2 Retrieve a Secret**
```sh
python keyring_cli.py get --key <key_name>
```
Example:
```sh
python keyring_cli.py get --key api_key
```

### **4.3 List Stored Keys**
```sh
python keyring_cli.py list
```
This shows stored **key names only** (not values).

### **4.4 Delete a Secret**
```sh
python keyring_cli.py delete --key <key_name>
```
Example:
```sh
python keyring_cli.py delete --key api_key
```

---

## **5. Exporting & Importing Keys Securely**
### **5.1 Export Encrypted Secrets**
```sh
python keyring_cli.py export
```
- Prompts for your **workstation login password** or a custom password.
- Saves an **encrypted** backup in `C:\.virtualenvs\keyring_backup.enc`.

### **5.2 Import Encrypted Secrets**
```sh
python keyring_cli.py import
```
- Prompts for the password used to encrypt the backup.
- Restores all previously stored keys.

---

## **6. Migrating to a New Workstation**
### **6.1 Export for Migration**
```sh
python keyring_cli.py export-migration
```
- Creates an encrypted migration backup.

### **6.2 Import on a New Machine**
```sh
python keyring_cli.py import-migration
```
- Prompts for the migration password to restore keys.

---

## **7. Automating Key Backups**
To **schedule automatic backups** every 24 hours:
- **Windows:** Use Task Scheduler
  ```sh
  schtasks /create /tn "Keyring Backup" /tr "python C:\.virtualenvs\keyring_cli.py export" /sc daily /st 00:00
  ```
- **Linux/macOS:** Use Cron
  ```sh
  crontab -e
  ```
  Add:
  ```
  0 0 * * * python3 /usr/local/bin/keyring_cli.py export
  ```

---

## **8. Using Stored Keys in Python Scripts**
### **8.1 Retrieving Keys in Python**
```python
import keyring

SERVICE_NAME = "GlobalSecrets"

api_key = keyring.get_password(SERVICE_NAME, "api_key")
client_id = keyring.get_password(SERVICE_NAME, "sky_app_information.app_id")
webhook_key = keyring.get_password(SERVICE_NAME, "webhook.webhook_key")
```

### **8.2 Making Authenticated API Calls**
```python
import requests
import keyring

SERVICE_NAME = "GlobalSecrets"
api_key = keyring.get_password(SERVICE_NAME, "api_key")

response = requests.get("https://api.example.com", headers={"Authorization": f"Bearer {api_key}"})
print(response.json())
```

---

## **9. Troubleshooting**
### **9.1 Key Not Found?**
Check if the key exists:
```sh
python keyring_cli.py list
```
If missing, re-add it:
```sh
python keyring_cli.py store --key api_key --value my_secret_api_key
```

### **9.2 Keyring Not Working?**
Try:
```sh
python -m keyring --help
```
If needed, manually configure the backend:
```sh
python -m keyring set GlobalSecrets api_key my_secret_api_key
```

---

## **10. Summary of CLI Commands**
| **Command** | **Description** |
|------------|----------------|
| `python keyring_cli.py store --key <key_name> --value <value>` | Store a key securely |
| `python keyring_cli.py get --key <key_name>` | Retrieve a stored key |
| `python keyring_cli.py list` | List stored keys (names only) |
| `python keyring_cli.py delete --key <key_name>` | Delete a key from keyring |
| `python keyring_cli.py export` | Export all keys (encrypted) |
| `python keyring_cli.py import` | Import keys from encrypted backup |
| `python keyring_cli.py export-migration` | Export for moving to a new workstation |
| `python keyring_cli.py import-migration` | Import keys on a new workstation |

---

## **11. Need Help?**
For additional support, run:
```sh
python keyring_cli.py help
```
