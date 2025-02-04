import requests
import os
from dotenv import load_dotenv

load_dotenv()

client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
base_url = 'https://api.eu-1.crowdstrike.com'

def get_bearer_token():
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'client_id': client_id,
        'client_secret': client_secret
    }
    response = requests.post(f'{base_url}/oauth2/token', headers=headers, data=data)
    if response.status_code == 201:
        return response.json()['access_token']
    else:
        raise Exception(f"Failed to get token: {response.status_code} {response.text}")

# Example usage
try:
    token = get_bearer_token()
    #print(f"Bearer token: {token}")
except Exception as e:
    print(e)

# Define your API credentials and endpoints
api_token = token 

# Function to list rule group IDs
def list_rule_group_ids():
    headers = {
        'Authorization': f'Bearer {api_token}'
    }
    response = requests.get(f'{base_url}/fwmgr/queries/rule-groups/v1', headers=headers)
    if response.status_code == 200:
        return response.json()['resources']
    else:
        raise Exception(f"Failed to list rule group IDs: {response.status_code} {response.text}")

# Function to get rule group details by ID
def get_rule_group_details(rule_group_ids):
    headers = {
        'Authorization': f'Bearer {api_token}'
    }
    params = {
        'ids': rule_group_ids
    }
    response = requests.get(f'{base_url}/fwmgr/entities/rule-groups/v1', headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to get rule group details: {response.status_code} {response.text}")

# Example usage
try:
    rule_group_ids = list_rule_group_ids()
    output_text = f"Rule Group IDs: {rule_group_ids}"
    print(output_text)
    
    with open("RuleGroupIDs.txt", "a") as file:
        file.write(output_text + "\n")
    
    rule_group_details = get_rule_group_details(rule_group_ids)
    for rule_group in rule_group_details['resources']:
        output_text = f"Rule Group ID: {rule_group['id']}, Name: {rule_group['name']}"
        print(output_text)
        
        with open("RuleGroupIDs.txt", "a") as file:
            file.write(output_text + "\n")
except Exception as e:
    print(e)
    with open("RuleGroupIDs.txt", "a") as file:
        file.write(str(e) + "\n")