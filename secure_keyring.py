import keyring
import os
import json
import inspect
import datetime
from typing import Optional, Dict, Any

SERVICE_NAME = "GlobalSecrets"
TRACKED_KEYS_FILE = r"path\tracked_keys.json"

def get_password(key_name: str) -> Optional[str]:
    """
    Wrapper around keyring.get_password that tracks usage
    """
    # Get the calling file's path
    frame = inspect.stack()[1]
    calling_file = os.path.abspath(frame.filename)
    
    # Get the value from keyring
    value = keyring.get_password(SERVICE_NAME, key_name)
    
    if value:
        # Record the usage
        track_key_usage(key_name, calling_file)
    
    return value

def set_password(key_name: str, value: str, description: Optional[str] = None):
    """Wrapper around keyring.set_password that updates tracking"""
    keyring.set_password(SERVICE_NAME, key_name, value)
    
    # Update tracking information
    if os.path.exists(TRACKED_KEYS_FILE):
        with open(TRACKED_KEYS_FILE, "r") as f:
            tracked_data = json.load(f)
    else:
        tracked_data = {}
    
    current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M")
    
    if key_name not in tracked_data:
        tracked_data[key_name] = {
            "description": description,
            "source": None,
            "added_date": current_time,
            "last_modified": current_time,
            "usage": {}
        }
    else:
        tracked_data[key_name]["last_modified"] = current_time
        if description:
            tracked_data[key_name]["description"] = description
    
    with open(TRACKED_KEYS_FILE, "w") as f:
        json.dump(tracked_data, f, indent=4)
    
    return True

def delete_password(key_name: str):
    """Wrapper around keyring.delete_password"""
    keyring.delete_password(SERVICE_NAME, key_name)
    
    # Update tracking information
    if os.path.exists(TRACKED_KEYS_FILE):
        with open(TRACKED_KEYS_FILE, "r") as f:
            tracked_data = json.load(f)
            
        if key_name in tracked_data:
            del tracked_data[key_name]
            
            with open(TRACKED_KEYS_FILE, "w") as f:
                json.dump(tracked_data, f, indent=4)

def track_key_usage(key_name: str, calling_file: str):
    """
    Track the usage of a key by a specific file
    """
    # Load current tracking data
    if os.path.exists(TRACKED_KEYS_FILE):
        with open(TRACKED_KEYS_FILE, "r") as f:
            tracked_data = json.load(f)
    else:
        tracked_data = {}
    
    # Initialize key entry if it doesn't exist
    if key_name not in tracked_data:
        tracked_data[key_name] = {
            "description": None,
            "source": None,
            "added_date": datetime.datetime.now().strftime("%Y-%m-%d_%H:%M"),
            "last_modified": datetime.datetime.now().strftime("%Y-%m-%d_%H:%M"),
            "usage": {}
        }
    
    # Initialize or update file usage count
    if "usage" not in tracked_data[key_name]:
        tracked_data[key_name]["usage"] = {}
    
    if calling_file not in tracked_data[key_name]["usage"]:
        tracked_data[key_name]["usage"][calling_file] = {
            "count": 1,
            "first_used": datetime.datetime.now().strftime("%Y-%m-%d_%H:%M"),
            "last_used": datetime.datetime.now().strftime("%Y-%m-%d_%H:%M")
        }
    else:
        tracked_data[key_name]["usage"][calling_file]["count"] += 1
        tracked_data[key_name]["usage"][calling_file]["last_used"] = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M")
    
    # Save updated tracking data
    with open(TRACKED_KEYS_FILE, "w") as f:
        json.dump(tracked_data, f, indent=4)

def get_usage_data(key_name=None) -> Dict[str, Any]:
    """
    Get usage data for a specific key or all keys
    
    Args:
        key_name: Optional key name to get usage for. If None, returns all usage data.
        
    Returns:
        Dictionary of usage data by file for the specified key or all keys
    """
    if os.path.exists(TRACKED_KEYS_FILE):
        with open(TRACKED_KEYS_FILE, "r") as f:
            tracked_data = json.load(f)
        
        if key_name:
            return tracked_data.get(key_name, {}).get("usage", {})
        else:
            return {k: v.get("usage", {}) for k, v in tracked_data.items()}
    
    return {} if key_name else {}

def get_key_metadata(key_name=None) -> Dict[str, Any]:
    """
    Get metadata for a specific key or all keys
    
    Args:
        key_name: Optional key name to get metadata for. If None, returns all metadata.
        
    Returns:
        Dictionary of metadata for the specified key or all keys
    """
    if os.path.exists(TRACKED_KEYS_FILE):
        with open(TRACKED_KEYS_FILE, "r") as f:
            tracked_data = json.load(f)
        
        if key_name:
            return tracked_data.get(key_name, {})
        else:
            return tracked_data
    
    return {} if key_name else {}
