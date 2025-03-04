import requests
import pandas as pd
import json

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
    return response.json()["access_token"]

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
    print("Policy IDs:", policy_ids)  # Debugging line
    for policy_id in policy_ids:
        policy_details = get_policy_details(bearer_token, policy_id)
        print(f"Policy ID: {policy_id}, Policy Name: {policy_details.get('name')}")  # Debugging line
        if policy_details.get("name") == policy_name:
            return policy_id
    return None

# Function to update USB device control exceptions with FULL_ACCESS action
def update_usb_exceptions(bearer_token, policy_id, combined_ids):
    url = f"https://api.eu-1.crowdstrike.com/policy/entities/device-control/v1"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json"
    }
    
    # Retrieve current policy details
    policy_details = get_policy_details(bearer_token, policy_id)
    
    # Update the exceptions with FULL_ACCESS action
    for device_id in combined_ids:
        for device_class in policy_details["settings"]["classes"]:
            if device_class["id"] == "MASS_STORAGE":
                for exception in device_class["exceptions"]:
                    if exception["combined_id"] == device_id:
                        exception["action"] = "FULL_ACCESS"
    
    payload = {
        "resources": [
            {
                "id": policy_id,
                "name": policy_details["name"],
                "description": policy_details["description"],
                "settings": policy_details["settings"]
            }
        ]
    }
    
    print(f"Payload for policy {policy_id}: {json.dumps(payload, indent=2)}")  # Debugging line
    response = requests.patch(url, headers=headers, data=json.dumps(payload))
    if response.status_code != 200:
        print(f"Error response: {response.text}")  # Debugging line
    response.raise_for_status()
    return response.json()

# Read combined IDs from CSV
combined_ids_df = pd.read_csv("combined_ids.csv")
print("Columns in combined_ids.csv:", combined_ids_df.columns)  # Debugging line
combined_ids = combined_ids_df["device_id"].tolist()

# Read target CIDs from CSV
target_cids_df = pd.read_csv("target_cids.csv")
target_cids = target_cids_df["cid"].tolist()

# Home CID credentials
home_cid_client_id = ""
home_cid_client_secret = ""

# Policy name to target
policy_name = "CyberSOC Windows-USB Monitor"

# Process each target CID
for target_cid in target_cids:
    try:
        # Generate bearer token for the target CID
        bearer_token = generate_bearer_token(home_cid_client_id, home_cid_client_secret, target_cid)
        
        # Retrieve the policy ID
        policy_id = get_policy_id(bearer_token, policy_name)
        if not policy_id:
            print(f"Policy '{policy_name}' not found for CID {target_cid}")
            continue
        
        # Update exceptions for the target CID
        response = update_usb_exceptions(bearer_token, policy_id, combined_ids)
        print(f"Exceptions updated for CID {target_cid} under policy '{policy_name}': {response}")
    except requests.exceptions.HTTPError as err:
        print(f"HTTP error occurred for CID {target_cid}: {err}")

print("USB device control exceptions update process completed.")