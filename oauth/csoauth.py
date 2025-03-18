import requests
def get_bearer(client_id, client_secret, member_cid):
    client_id = client_id
    client_secret = client_secret
    member_cid = member_cid
    token_url = "https://api.eu-1.crowdstrike.com/oauth2/token"
    token_headers = {
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    if "09a068" in member_cid:
        token_response = requests.post(token_url, headers=token_headers, data={"client_id": client_id,"client_secret": client_secret})
    else:
        token_response = requests.post(token_url, headers=token_headers, data={"client_id": client_id,"client_secret": client_secret,"member_cid": member_cid})
    bearer_token = token_response.json().get("access_token")
    return bearer_token
