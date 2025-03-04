#V1.2 introduces skipping of existing exceptions
import requests
import pandas as pd
import json
import logging
import os

# Configure logging
logging.basicConfig(filename='usb_exceptions.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s', filemode='a')

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
    policy_details = response.json().get("resources", [])[0]
    return policy_details

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

# Function to get existing combined IDs from policy
def get_existing_combined_ids(bearer_token, policy_id):
    policy_details = get_policy_details(bearer_token, policy_id)
    exceptions = policy_details.get("settings", {}).get("classes", [])
    existing_combined_ids = []
    for device_class in exceptions:
        if device_class["id"] == "MASS_STORAGE":
            existing_combined_ids = [exception["combined_id"] for exception in device_class.get("exceptions", [])]
            break
    return existing_combined_ids

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
                "settings": {
                    "classes": [
                        {
                            "id": "MASS_STORAGE",
                            "exceptions": exceptions
                        }
                    ]
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
excluded_ids = []
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
        
        # Get existing combined IDs from the policy
        existing_combined_ids = get_existing_combined_ids(bearer_token, policy_id)
        
        # Save existing exceptions to a JSON file
        os.makedirs("existingExceptions", exist_ok=True)
        with open(f"existingExceptions/{target_cid}-EE.json", "w") as f:
            json.dump(existing_combined_ids, f, indent=4)
        
        # Filter out combined IDs that already exist in the policy
        new_combined_ids = [cid for cid in combined_ids if cid not in existing_combined_ids]
        excluded_combined_ids = [cid for cid in combined_ids if cid in existing_combined_ids]
        
        # Log and save excluded combined IDs
        for excluded_id in excluded_combined_ids:
            excluded_ids.append({"combined_id": excluded_id, "cid": target_cid})
        
        # Create exceptions for the target CID
        if new_combined_ids:
            response = create_usb_exceptions(bearer_token, policy_id, new_combined_ids)
            #logging.info(f"Exceptions created for CID {target_cid} under policy '{policy_name}': {response}")
            logging.info(f"Exceptions created for CID {target_cid} under policy '{policy_name}'")
            #print(f"Exceptions created for CID {target_cid} under policy '{policy_name}': {response}")
            print(f"Exceptions created for CID {target_cid} under policy '{policy_name}'")
        else:
            logging.info(f"No new exceptions to add for CID {target_cid} under policy '{policy_name}'")
            print(f"No new exceptions to add for CID {target_cid} under policy '{policy_name}'")
        
        # Log and print summary for the target CID
        logging.info(f"Summary for CID {target_cid}: {len(new_combined_ids)} new exceptions added, {len(excluded_combined_ids)} existing exceptions excluded")
        print(f"Summary for CID {target_cid}: {len(new_combined_ids)} new exceptions added, {len(excluded_combined_ids)} existing exceptions excluded")
    except requests.exceptions.HTTPError as err:
        logging.error(f"HTTP error occurred for CID {target_cid}: {err}")
        print(f"HTTP error occurred for CID {target_cid}: {err}")
        print("Response content:", err.response.content)  # Print the response content for debugging

# Save excluded combined IDs to CSV
excluded_ids_df = pd.DataFrame(excluded_ids)
if not os.path.isfile("excluded_combined_ids.csv"):
    excluded_ids_df.to_csv("excluded_combined_ids.csv", index=False)
else:
    excluded_ids_df.to_csv("excluded_combined_ids.csv", mode='a', header=False, index=False)

# Log and print final completion message
logging.info("USB device control exceptions creation process completed.")
print("USB device control exceptions creation process completed.")