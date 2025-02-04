import requests
import csv
import logging

# --- Configuration ---
client_id = ""  # Replace with your actual client ID
client_secret = ""  # Replace with your actual client secret
base_url = "https://api.eu-1.crowdstrike.com"  # You can change this if you're using a different CrowdStrike region
auth_url = "https://api.crowdstrike.com/oauth2/token"
devices_url = f"{base_url}/devices/entities/devices-actions/v2?action_name=unhide_host"
csv_file_path = "host_ids.csv"  # Replace with the path to your CSV file
log_file_path = "host_hiding.log"  # Path to the log file

# --- Logging setup ---
logging.basicConfig(filename=log_file_path, level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# --- Functions ---

def get_access_token():
    """Retrieves an access token from the CrowdStrike API."""

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "client_id": client_id,
        "client_secret": client_secret
    }

    try:
        response = requests.post(auth_url, headers=headers, data=data)
        response.raise_for_status()
        access_token = response.json()["access_token"]
        logging.info("Access token obtained successfully.")
        return access_token
    except requests.exceptions.RequestException as e:
        logging.error(f"Error getting access token: {e}")
        raise  # Re-raise the exception after logging

def hide_hosts(access_token, host_ids):
    """Hides a batch of hosts and logs the results."""

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    data = {"ids": host_ids}

    try:
        print(f"Hiding {len(host_ids)} hosts...")  # Added print statement
        response = requests.post(devices_url, headers=headers, json=data)
        response.raise_for_status()
        for host_id in host_ids:
            if response.status_code == 202:  # Log success with 202 status
                logging.info(f"Host hidden successfully: {host_id}")
            else:
                logging.warning(f"Unexpected status code for {host_id}: {response.status_code}")
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error hiding hosts: {e}")
        raise

def process_csv(access_token, file_path, batch_size=100):
    """Reads host IDs from a CSV and hides them in batches."""

    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        host_ids = [row[0] for row in reader]

    total_hosts = len(host_ids)
    print(f"Processing {total_hosts} hosts from CSV...")  # Added print statement

    for i in range(0, total_hosts, batch_size):
        batch_ids = host_ids[i: i + batch_size]
        hide_hosts(access_token, batch_ids)

    print("Host hiding completed.")  # Added print statement

# --- Main execution ---
if __name__ == "__main__":
    try:
        access_token = get_access_token()
        process_csv(access_token, csv_file_path)
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
