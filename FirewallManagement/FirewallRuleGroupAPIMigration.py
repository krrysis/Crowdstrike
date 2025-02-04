import requests
import json
import logging
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Replace these with your actual base URL
BASE_URL = 'https://api.eu-1.crowdstrike.com'

# Configure logging
logging.basicConfig(filename='firewall_migration.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_headers(api_key):
    return {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

def get_bearer_token(client_id, client_secret):
    url = f'{BASE_URL}/oauth2/token'
    data = {
        'client_id': client_id,
        'client_secret': client_secret
    }
    response = requests.post(url, data=data)
    response.raise_for_status()
    return response.json()['access_token']

def list_rule_group_ids(api_token):
    headers = {
        'Authorization': f'Bearer {api_token}'
    }
    response = requests.get(f'{BASE_URL}/fwmgr/queries/rule-groups/v1', headers=headers)
    response.raise_for_status()
    return response.json()['resources']

def get_rule_group_details(api_token, rule_group_ids):
    headers = {
        'Authorization': f'Bearer {api_token}'
    }
    params = {
        'ids': rule_group_ids
    }
    response = requests.get(f'{BASE_URL}/fwmgr/entities/rule-groups/v1', headers=headers, params=params)
    response.raise_for_status()
    return response.json()['resources']

def export_rule_group(source_cid_api_key, rule_group_id):
    url = f'{BASE_URL}/fwmgr/entities/rule-groups/v1?ids={rule_group_id}'
    headers = get_headers(source_cid_api_key)
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()['resources'][0]

def export_rule_details(source_cid_api_key, rule_ids):
    url = f'{BASE_URL}/fwmgr/entities/rules/v1?ids=' + '&ids='.join(rule_ids)
    headers = get_headers(source_cid_api_key)
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()['resources']

def import_rule_group(target_cid_api_key, rule_group_data):
    url = f'{BASE_URL}/fwmgr/entities/rule-groups/v1'
    headers = get_headers(target_cid_api_key)
    response = requests.post(url, headers=headers, data=json.dumps(rule_group_data))
    response.raise_for_status()
    return response.json()

def main():
    # Get client IDs and secrets from environment variables
    SOURCE_CLIENT_ID = os.getenv('SOURCE_CLIENT_ID')
    SOURCE_CLIENT_SECRET = os.getenv('SOURCE_CLIENT_SECRET')
    TARGET_CLIENT_ID = os.getenv('TARGET_CLIENT_ID')
    TARGET_CLIENT_SECRET = os.getenv('TARGET_CLIENT_SECRET')
    
    # Get bearer tokens for both source and target CIDs
    source_bearer_token = get_bearer_token(SOURCE_CLIENT_ID, SOURCE_CLIENT_SECRET)
    target_bearer_token = get_bearer_token(TARGET_CLIENT_ID, TARGET_CLIENT_SECRET)
    
    # List rule group IDs from the source CID
    rule_group_ids = list_rule_group_ids(source_bearer_token)
    rule_group_details = get_rule_group_details(source_bearer_token, rule_group_ids)
    
    # Display rule groups and allow user to select one
    print("Available Rule Groups:")
    for idx, rule_group in enumerate(rule_group_details):
        print(f"{idx + 1}. {rule_group['name']} (ID: {rule_group['id']})")
    
    selected_index = int(input("Enter the number of the rule group you want to migrate: ")) - 1
    selected_rule_group_id = rule_group_details[selected_index]['id']
    selected_rule_group_name = rule_group_details[selected_index]['name']
    
    logging.info(f'Starting migration of rule group {selected_rule_group_name} (ID: {selected_rule_group_id}) from source CID {SOURCE_CLIENT_ID} to target CID {TARGET_CLIENT_ID}')
    
    # Export the selected rule group from the source CID
    rule_group_data = export_rule_group(source_bearer_token, selected_rule_group_id)
    logging.info(f'Exported rule group: {rule_group_data["name"]} (ID: {selected_rule_group_id}) from source CID {SOURCE_CLIENT_ID}')
    
    # Export individual rule details
    rule_ids = rule_group_data['rule_ids']
    rules = export_rule_details(source_bearer_token, rule_ids)
    rule_names = [rule['name'] for rule in rules]
    logging.info(f'Exported rules: {rule_names}')
    
    # Prepare the data for the new rule group
    new_rule_group_data = {
        "description": rule_group_data['description'],
        "enabled": rule_group_data['enabled'],
        "name": rule_group_data['name'],
        "platform": rule_group_data['platform'],
        "rules": rules
    }
    
    # Import the rule group to the target CID
    import_response = import_rule_group(target_bearer_token, new_rule_group_data)
    logging.info(f'Imported rule group: {new_rule_group_data["name"]} to target CID {TARGET_CLIENT_ID}')
    
    print('Rule group copied successfully:', import_response)

if __name__ == '__main__':
    main()