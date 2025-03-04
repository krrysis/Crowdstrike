import requests

# Define the URL and headers for the token request
token_url = "https://api.eu-1.crowdstrike.com/oauth2/token"
token_headers = {
    "accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded"
}

# Define the payload for the token request
token_payload = {
    "client_id": "",
    "client_secret": "",
    "member_cid": ""
}

# Make the POST request to get the bearer token
token_response = requests.post(token_url, headers=token_headers, data=token_payload)

# Extract the bearer token from the response
bearer_token = token_response.json().get("access_token")

# Function to list USB exceptions using the bearer token
def list_usb_exceptions(bearer_token):
    url = f"https://api.eu-1.crowdstrike.com/policy/queries/device-control/v1"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    return response.json()

# Call the function and print the response
usb_exceptions_response = list_usb_exceptions(bearer_token)
print(usb_exceptions_response)