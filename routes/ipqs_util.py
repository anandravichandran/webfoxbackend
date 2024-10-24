import requests
import urllib.parse
import hashlib

def check_url_reputation(url, api_key):
    encoded_url = urllib.parse.quote(url, safe='')
    endpoint = f"https://ipqualityscore.com/api/json/url/{api_key}/{encoded_url}"
    response = requests.get(endpoint)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: Received status code {response.status_code}")
        print(f"Response content: {response.text}")
        return None



IPQS_URL = "https://www.ipqualityscore.com/api/v1/file"

def get_file_hash(file_path):
    """Generates SHA-256 hash for the uploaded file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()



def analyze_file_url(file_url, api_key):
    """Send file URL to IPQS for malware analysis with better error handling."""
    try:
        params = {
            'url': file_url,
            'user_id': api_key
        }
        response = requests.get(IPQS_URL, params=params)

        # Check if the response is empty or status code is not 200
        if response.status_code != 200:
            return {'error': f'Error from IPQS: {response.status_code} - {response.text}'}

        # Try parsing JSON; if it fails, handle the exception
        try:
            return response.json()
        except requests.exceptions.JSONDecodeError:
            return {'error': 'Received an invalid JSON response from IPQS'}
    except requests.exceptions.RequestException as e:
        return {'error': f'An error occurred during the request: {str(e)}'}
