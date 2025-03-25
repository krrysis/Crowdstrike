import requests
import re
from oauth.csoauth import get_bearer
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import getpass

# Set up logging
logging.basicConfig(
    filename="ioa_migration_multithread.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Configuration
CONFIG = {
    "max_workers": 10,  # Number of threads (adjust based on rate limits)
    "batch_delay": 0.1,  # Delay between batches in seconds
    "max_retries": 3,  # Number of retries for failed API calls
    "retry_backoff_factor": 1,  # Backoff factor for retries
}

# Function to validate UUID format
def is_uuid(value):
    return bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value))

# Function to get custom IOA rule groups
def get_custom_ioa_rule_groups(bearer_token):
    url = "https://api.eu-1.crowdstrike.com/ioarules/queries/rule-groups/v1"
    headers = {"Authorization": f"Bearer {bearer_token}"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    logging.info(f"Fetched rule groups: {response.json()['resources']}")
    return response.json()["resources"]

# Function to get specific custom IOA rule group details
def get_custom_ioa_rule_group_details(bearer_token, rule_group_id):
    url = f"https://api.eu-1.crowdstrike.com/ioarules/entities/rule-groups/v1?ids={rule_group_id}"
    headers = {"Authorization": f"Bearer {bearer_token}"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    logging.info(f"Fetched rule group details for {rule_group_id}: {response.json()}")
    return response.json()["resources"][0]

# Function to transform a rule object for creating a new rule
def transform_rule_for_creation(rule):
    return {
        "name": rule["name"],
        "description": rule["description"],
        "pattern_severity": rule["pattern_severity"],
        "disposition_id": rule["disposition_id"],
        "field_values": rule["field_values"],
        "ruletype_id": rule["ruletype_id"],
        "comment": rule.get("comment", "")
    }

# Function to fetch a single rule with retry logic
def fetch_rule(bearer_token, rule_id):
    details_url = "https://api.eu-1.crowdstrike.com/ioarules/entities/rules/v1"
    headers = {"Authorization": f"Bearer {bearer_token}"}
    params = {"ids": rule_id}
    
    # Set up retry strategy
    session = requests.Session()
    retries = Retry(
        total=CONFIG["max_retries"],
        backoff_factor=CONFIG["retry_backoff_factor"],
        status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    
    try:
        response = session.get(details_url, headers=headers, params=params)
        response.raise_for_status()
        rules = response.json().get("resources", [])
        logging.info(f"Fetched rule {rule_id}: {rules}")
        return rules
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch rule {rule_id} after {CONFIG['max_retries']} retries: {e}")
        logging.error(f"Failed to fetch rule {rule_id} after {CONFIG['max_retries']} retries: {e}")
        return []

# Function to get specific custom IOA rules using multi-threading
def get_custom_ioa_rules(bearer_token, rule_group_id):
    # Step 1: Fetch all rule IDs
    query_url = "https://api.eu-1.crowdstrike.com/ioarules/queries/rules/v1"
    headers = {"Authorization": f"Bearer {bearer_token}"}
    all_rule_ids = []
    offset = 0
    limit = 100

    while True:
        params = {"offset": str(offset), "limit": str(limit)}
        try:
            query_response = requests.get(query_url, headers=headers, params=params)
            query_response.raise_for_status()
            query_json = query_response.json()
            print(f"Full JSON response from queries/rules/v1 (offset={offset}): {query_json}")
            logging.info(f"Queried rule IDs (offset={offset}): {query_json}")
            
            rule_ids = query_json.get("resources", [])
            all_rule_ids.extend(rule_ids)
            
            total = query_json.get("meta", {}).get("pagination", {}).get("total", 0)
            offset += limit
            if offset >= total or not rule_ids:
                break
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch rule IDs: {e}")
            logging.error(f"Failed to fetch rule IDs: {e}")
            return []

    print(f"All Rule IDs in tenant: {all_rule_ids}")
    logging.info(f"All Rule IDs in tenant: {all_rule_ids}")
    
    if not all_rule_ids:
        print("No rules found in tenant")
        logging.warning("No rules found in tenant")
        return []
    
    # Step 2: Fetch rule details using multi-threading
    start_time = time.time()  # Start timing
    all_rules = []
    max_workers = CONFIG["max_workers"]
    batch_size = max_workers
    for i in range(0, len(all_rule_ids), batch_size):
        batch_ids = all_rule_ids[i:i + batch_size]
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_rule_id = {executor.submit(fetch_rule, bearer_token, rule_id): rule_id for rule_id in batch_ids}
            for future in as_completed(future_to_rule_id):
                rule_id = future_to_rule_id[future]
                try:
                    rules = future.result()
                    print(f"Completed fetching rule {rule_id}")
                    all_rules.extend(rules)
                except Exception as e:
                    print(f"Error fetching rule {rule_id}: {e}")
                    logging.error(f"Error fetching rule {rule_id}: {e}")
        time.sleep(CONFIG["batch_delay"])  # Add delay between batches to avoid rate limits
    
    end_time = time.time()  # End timing
    print(f"Time taken to fetch {len(all_rule_ids)} rules: {end_time - start_time:.2f} seconds")
    logging.info(f"Time taken to fetch {len(all_rule_ids)} rules: {end_time - start_time:.2f} seconds")
    
    # Step 3: Filter rules by rule_group_id
    filtered_rules = [rule for rule in all_rules if rule.get("rulegroup_id") == rule_group_id]
    print(f"Filtered rules for rule group {rule_group_id}: {len(filtered_rules)} rules")
    print(f"Filtered rule details: {filtered_rules}")
    logging.info(f"Filtered rules for rule group {rule_group_id}: {filtered_rules}")
    return filtered_rules

# Function to create a rule group in the destination tenant
def create_rule_group(bearer_token, rule_group):
    url = "https://api.eu-1.crowdstrike.com/ioarules/entities/rule-groups/v1"
    headers = {"Authorization": f"Bearer {bearer_token}", "Content-Type": "application/json"}
    payload = {
        "name": rule_group["name"],
        "platform": rule_group["platform"],
        "description": rule_group.get("description", ""),
        "enabled": rule_group["enabled"]
    }
    print(f"Creating rule group with payload: {payload}")
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    print(f"Create rule group response status: {response.status_code}")
    print(f"Create rule group response text: {response.text}")
    logging.info(f"Created rule group: {response.text}")
    new_rule_group_id = response.json()["resources"][0]["id"]
    print(f"Newly created rule group ID: {new_rule_group_id}")
    return new_rule_group_id

# Function to create a rule in the destination rule group
def create_rule(bearer_token, rule, rule_group_id):
    url = "https://api.eu-1.crowdstrike.com/ioarules/entities/rules/v1"
    headers = {"Authorization": f"Bearer {bearer_token}", "Content-Type": "application/json"}
    rule_payload = transform_rule_for_creation(rule)
    rule_payload["rulegroup_id"] = rule_group_id
    print(f"Creating rule with payload: {rule_payload}")
    response = requests.post(url, headers=headers, json=rule_payload)
    response.raise_for_status()
    print(f"Create rule response status: {response.status_code}")
    print(f"Create rule response text: {response.text}")
    logging.info(f"Created rule: {response.text}")
    return response.json()

# Function to copy custom IOA rule group and rules to another tenant
def copy_custom_ioa_rules(bearer_token, rule_group, rules):
    try:
        # Step 1: Create the rule group in the destination tenant
        new_rule_group_id = create_rule_group(bearer_token, rule_group)
        
        # Step 2: Create each rule in the new rule group
        for rule in rules:
            create_rule(bearer_token, rule, new_rule_group_id)
        
        return {"id": new_rule_group_id}
    except Exception as e:
        print(f"Failed to copy rule group: {e}")
        logging.error(f"Failed to copy rule group: {e}")
        raise

# Main function
def main():
    primary_client_id = input("Enter the client ID: ")
    primary_client_secret = getpass.getpass("Enter the client secret: ")
    source_member_cid = input("Enter the source member CID: ")
    destination_member_cid = input("Enter the destination member CID: ")

    try:
        # Generate bearer tokens
        source_bearer_token = get_bearer(primary_client_id, primary_client_secret, source_member_cid)
        destination_bearer_token = get_bearer(primary_client_id, primary_client_secret, destination_member_cid)
        
        # Get custom IOA rule groups from source CID
        rule_group_ids = get_custom_ioa_rule_groups(source_bearer_token)
        
        # List available rule groups
        print("Available Rule Groups:")
        rule_groups = []
        for idx, rule_group_id in enumerate(rule_group_ids):
            rule_group_details = get_custom_ioa_rule_group_details(source_bearer_token, rule_group_id)
            rule_groups.append(rule_group_details)
            print(f"{idx + 1}. {rule_group_details['name']} (ID: {rule_group_details['id']})")
        
        # Select rule groups to copy
        selected_indices = input("Enter the indices of the rule groups you want to copy (comma-separated): ")
        selected_indices = [int(idx.strip()) - 1 for idx in selected_indices.split(",")]
        
        # Copy selected rule groups to destination CID
        for idx in selected_indices:
            rule_group_id = rule_groups[idx]['id']
            rule_group_details = get_custom_ioa_rule_group_details(source_bearer_token, rule_group_id)
            rules = get_custom_ioa_rules(source_bearer_token, rule_group_id)
            copy_result = copy_custom_ioa_rules(destination_bearer_token, rule_group_details, rules)
            print(f"Copied rule group: {rule_group_details['name']} (New ID: {copy_result.get('id', 'N/A')})")
    except Exception as e:
        print(f"Script failed: {e}")
        logging.error(f"Script failed: {e}")

if __name__ == "__main__":
    main()