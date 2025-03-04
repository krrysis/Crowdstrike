#V1.1 Introduces Advanced Logging
import requests
import pandas as pd
import json
import logging

# Configure logging
logging.basicConfig(filename='usb_exceptions.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Function to generate bearer token
def generate_bearer_token(client_id, client_secret, member_cid):
    url = "https://api.eu-1.crowdstrike.com/oauth2/token"
    headers = {
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "member_cid": member_cid
    }
    response = requests.post(url, headers=headers, data=data)
    response.raise_for_status()
    token = response.json()["access_token"]
    logging.info(f"Generated bearer token for CID {member_cid}")
    print(f"Generated bearer token for CID {member_cid}")
    return token

# Function to retrieve policy details by ID
def get_policy_details(bearer_token, policy_id):
    url = f"https://api.eu-1.crowdstrike.com/policy/entities/device-control/v1?ids={policy_id}"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json().get("resources", [])[0]

# Function to retrieve policy ID by name
def get_policy_id(bearer_token, policy_name):
    url = f"https://api.eu-1.crowdstrike.com/policy/queries/device-control/v1"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    policy_ids = response.json().get("resources", [])
    for policy_id in policy_ids:
        policy_details = get_policy_details(bearer_token, policy_id)
        if policy_details.get("name") == policy_name:
            return policy_id
    return None

# Function to create USB device control exceptions
def create_usb_exceptions(bearer_token, policy_id, combined_ids):
    url = f"https://api.eu-1.crowdstrike.com/policy/entities/device-control/v1"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json"
    }
    exceptions = [{"combined_id": device_id, "action": "FULL_ACCESS", "description": "added by API on 28-FEB-2025"} for device_id in combined_ids]
    payload = {
        "resources": [
            {
                "id": policy_id,
                "name": "CyberSOC Windows-USB Block",
                "description": "Updated policy with exceptions",
                "settings": {
                    "classes": [
                        {
                            "id": "MASS_STORAGE",
                            "exceptions": exceptions
                        }
                    ],
                    "custom_notifications": {
                        "blocked_notification": {
                            "custom_message": "Blocked by policy",
                            "use_custom": True
                        },
                        "restricted_notification": {
                            "custom_message": "Restricted by policy",
                            "use_custom": True
                        }
                    },
                    "delete_exceptions": [],
                    "end_user_notification": "SILENT",
                    "enforcement_mode": "MONITOR_ONLY",
                    "enhanced_file_metadata": True
                }
            }
        ]
    }
    response = requests.patch(url, headers=headers, data=json.dumps(payload))
    response.raise_for_status()
    logging.info(f"Created USB exceptions for policy {policy_id} with combined IDs: {combined_ids}")
    print(f"Created USB exceptions for policy {policy_id} with combined IDs: {combined_ids}")
    return response.json()

# Read combined IDs from CSV
combined_ids_df = pd.read_csv("combined_ids.csv")
combined_ids = combined_ids_df["device_id"].tolist()

# Read target CIDs from CSV
target_cids_df = pd.read_csv("target_cids.csv")
target_cids = target_cids_df["cid"].tolist()

# Home CID credentials
home_cid_client_id = ""
home_cid_client_secret = ""

# Policy name to target
policy_name = "CyberSOC Windows-USB Block"

# Process each target CID
for target_cid in target_cids:
    try:
        # Generate bearer token for the target CID
        bearer_token = generate_bearer_token(home_cid_client_id, home_cid_client_secret, target_cid)
        
        # Retrieve the policy ID
        policy_id = get_policy_id(bearer_token, policy_name)
        if not policy_id:
            logging.warning(f"Policy '{policy_name}' not found for CID {target_cid}")
            print(f"Policy '{policy_name}' not found for CID {target_cid}")
            continue
        
        # Create exceptions for the target CID
        response = create_usb_exceptions(bearer_token, policy_id, combined_ids)
        logging.info(f"Exceptions created for CID {target_cid} under policy '{policy_name}': {response}")
        print(f"Exceptions created for CID {target_cid} under policy '{policy_name}': {response}")
    except requests.exceptions.HTTPError as err:
        logging.error(f"HTTP error occurred for CID {target_cid}: {err}")
        print(f"HTTP error occurred for CID {target_cid}: {err}")

logging.info("USB device control exceptions creation process completed.")
print("USB device control exceptions creation process completed.")