import requests
import pandas as pd
import json
import logging
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging to append to the log file
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
            existing_combined_ids = [exception["combined_id"] for exception in device_class.get("exceptions", []) if "combined_id" in exception]
            break
    return existing_combined_ids, policy_details.get("name")

# Read target CIDs from CSV
target_cids_df = pd.read_csv("target_cids.csv")
target_cids = target_cids_df["cid"].tolist()

# Home CID credentials
home_cid_client_id = os.getenv("HOME_CID_CLIENT_ID")
home_cid_client_secret = os.getenv("HOME_CID_CLIENT_SECRET")

# Policy names to target
policy_names = ["CyberSOC Windows-USB Monitor", "CyberSOC Windows-USB Block"]

# Process each target CID for each policy
for target_cid in target_cids:
    try:
        # Generate bearer token for the target CID
        bearer_token = generate_bearer_token(home_cid_client_id, home_cid_client_secret, target_cid)
        
        for policy_name in policy_names:
            # Retrieve the policy ID
            policy_id = get_policy_id(bearer_token, policy_name)
            if not policy_id:
                logging.warning(f"Policy '{policy_name}' not found for CID {target_cid}")
                print(f"Policy '{policy_name}' not found for CID {target_cid}")
                continue
            
            # Get existing combined IDs from the policy
            existing_combined_ids, policy_name = get_existing_combined_ids(bearer_token, policy_id)
            
            # Save existing exceptions to a CSV file
            os.makedirs("SuperExistingExceptions", exist_ok=True)
            existing_exceptions_df = pd.DataFrame({"combined_id": existing_combined_ids, "policy_name": policy_name})
            existing_exceptions_df.to_csv(f"SuperExistingExceptions/{target_cid}-{policy_name.replace(' ', '_')}-EE.csv", index=False)
            
            # Log and print summary for the target CID and policy
            logging.info(f"Exported existing exceptions for CID {target_cid} under policy '{policy_name}'")
            print(f"Exported existing exceptions for CID {target_cid} under policy '{policy_name}'")
    except requests.exceptions.HTTPError as err:
        logging.error(f"HTTP error occurred for CID {target_cid}: {err}")
        print(f"HTTP error occurred for CID {target_cid}: {err}")
        print("Response content:", err.response.content)  # Print the response content for debugging

# Log and print final completion message
logging.info("Export of existing exceptions completed.")
print("Export of existing exceptions completed.")