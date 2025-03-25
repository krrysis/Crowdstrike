import requests
import re
from oauth.csoauth import get_bearer

# Function to validate UUID format
def is_uuid(value):
    # Checks for UUID format: 8-4-4-4-12 hex characters
    return bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value))

# Function to get custom IOA rule groups
def get_custom_ioa_rule_groups(bearer_token):
    url = "https://api.eu-1.crowdstrike.com/ioarules/queries/rule-groups/v1"
    headers = {
        "Authorization": f"Bearer {bearer_token}"
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()["resources"]

# Function to get specific custom IOA rule group details
def get_custom_ioa_rule_group_details(bearer_token, rule_group_id):
    url = f"https://api.eu-1.crowdstrike.com/ioarules/entities/rule-groups/v1?ids={rule_group_id}"
    headers = {
        "Authorization": f"Bearer {bearer_token}"
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
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

# Function to get specific custom IOA rules
def get_custom_ioa_rules(bearer_token, rule_group_id):
    # Step 1: Fetch all rule IDs
    query_url = "https://api.eu-1.crowdstrike.com/ioarules/queries/rules/v1"
    headers = {"Authorization": f"Bearer {bearer_token}"}
    all_rule_ids = []
    offset = 0
    limit = 100

    while True:
        params = {
            "offset": str(offset),
            "limit": str(limit)
        }
        query_response = requests.get(query_url, headers=headers, params=params)
        query_response.raise_for_status()
        query_json = query_response.json()
        print(f"Full JSON response from queries/rules/v1 (offset={offset}): {query_json}")
        
        rule_ids = query_json.get("resources", [])
        all_rule_ids.extend(rule_ids)
        
        # Check pagination
        total = query_json.get("meta", {}).get("pagination", {}).get("total", 0)
        offset += limit
        if offset >= total or not rule_ids:
            break

    print(f"All Rule IDs in tenant: {all_rule_ids}")
    
    if not all_rule_ids:
        print(f"No rules found in tenant")
        return []
    
    # Step 2: Fetch rule details individually
    all_rules = []
    details_url = "https://api.eu-1.crowdstrike.com/ioarules/entities/rules/v1"
    for rule_id in all_rule_ids:
        params = {"ids": rule_id}
        print(f"Fetching rule: {rule_id}")
        details_response = requests.get(details_url, headers=headers, params=params)
        print(f"Response Status: {details_response.status_code}")
        if details_response.status_code != 200:
            print(f"Response Text: {details_response.text}")
            continue  # Skip this rule if it fails
        batch_rules = details_response.json().get("resources", [])
        all_rules.extend(batch_rules)
    
    # Step 3: Filter rules by rule_group_id
    filtered_rules = [rule for rule in all_rules if rule.get("rulegroup_id") == rule_group_id]
    print(f"Filtered rules for rule group {rule_group_id}: {len(filtered_rules)} rules")
    print(f"Filtered rule details: {filtered_rules}")
    return filtered_rules

# Function to create a rule group in the destination tenant
def create_rule_group(bearer_token, rule_group):
    url = "https://api.eu-1.crowdstrike.com/ioarules/entities/rule-groups/v1"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "name": rule_group["name"],
        "platform": rule_group["platform"],
        "description": rule_group.get("description", ""),
        "enabled": rule_group["enabled"]
    }
    print(f"Creating rule group with payload: {payload}")
    response = requests.post(url, headers=headers, json=payload)
    print(f"Create rule group response status: {response.status_code}")
    print(f"Create rule group response text: {response.text}")
    response.raise_for_status()
    new_rule_group_id = response.json()["resources"][0]["id"]
    print(f"Newly created rule group ID: {new_rule_group_id}")
    return new_rule_group_id

# Function to create a rule in the destination rule group
def create_rule(bearer_token, rule, rule_group_id):
    url = "https://api.eu-1.crowdstrike.com/ioarules/entities/rules/v1"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json"
    }
    rule_payload = transform_rule_for_creation(rule)
    rule_payload["rulegroup_id"] = rule_group_id
    print(f"Creating rule with payload: {rule_payload}")
    response = requests.post(url, headers=headers, json=rule_payload)
    print(f"Create rule response status: {response.status_code}")
    print(f"Create rule response text: {response.text}")
    response.raise_for_status()
    return response.json()

# Function to copy custom IOA rule group and rules to another tenant
def copy_custom_ioa_rules(bearer_token, rule_group, rules):
    # Step 1: Create the rule group in the destination tenant
    new_rule_group_id = create_rule_group(bearer_token, rule_group)
    
    # Step 2: Create each rule in the new rule group using the new rulegroup_id
    for rule in rules:
        create_rule(bearer_token, rule, new_rule_group_id)
    
    return {"id": new_rule_group_id}

# Main function
def main():
    primary_client_id = ""
    primary_client_secret = ""
    source_member_cid = ""
    destination_member_cid = ""

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

if __name__ == "__main__":
    main()