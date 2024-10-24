# # functions.py

# import os
# import tempfile
# import base64
# from flask import Blueprint, request, jsonify
# from ipqs_util import check_url_reputation
# from vt_util import scan_url, get_scan_results, format_scan_results, scan_file
# from pii_util import analyze_pii, anonymize_text
# from auth import token_required

# function_routes = Blueprint('functions', __name__)

# def download_base64_images(image_data, output_dir):
#     os.makedirs(output_dir, exist_ok=True)
#     try:
#         encoded_data = image_data.split(',')[1]
#         decoded_data = base64.b64decode(encoded_data)
#         extension = image_data.split(';')[0].split('/')[-1]
#         filename = os.path.join(output_dir, f'uploaded_image.{extension}')
#         with open(filename, 'wb') as file:
#             file.write(decoded_data)
#         scan_results = scan_downloaded_file(filename)
#         return scan_results
#     except IndexError:
#         return {'error': f'Invalid format for image data: {image_data}'}
#     except Exception as e:
#         return {'error': f'Failed to process image data: {str(e)}'}

# def scan_downloaded_file(file_path):
#     file_id = scan_file(file_path)
#     if file_id:
#         scan_results = get_scan_results(file_id)
#         if scan_results:
#             formatted_results = format_scan_results(scan_results)
#             return {'scan_results': formatted_results}
#         else:
#             return {'error': 'Failed to retrieve scan results'}
#     else:
#         return {'error': 'File scan failed'}

# @function_routes.route('/scan', methods=['POST'])
# @token_required
# def scan(current_user):
#     if 'file' in request.json:
#         file_data = request.json['file']
#         output_directory = 'downloaded_images'
#         response = download_base64_images(file_data, output_directory)
#         if 'error' in response:
#             return jsonify(response), 400
#         return jsonify(response), 200
#     elif 'url' in request.json:
#         url = request.json['url']
#         reputation_results = check_url_reputation(url, IPQS_API_KEY)
#         url_id = scan_url(url)
#         if url_id:
#             vt_scan_results = get_scan_results(url_id)
#             if vt_scan_results:
#                 formatted_vt_results = format_scan_results(vt_scan_results)
#             else:
#                 return jsonify({'error': 'Failed to retrieve VirusTotal scan results'}), 500
#         else:
#             return jsonify({'error': 'URL submission to VirusTotal failed'}), 500
#         combined_results = {'ipqs': reputation_results, 'virustotal': formatted_vt_results}
#         return jsonify(combined_results)
#     elif 'url_reputation' in request.json:
#         url = request.json['url_reputation']
#         reputation_results = check_url_reputation(url, IPQS_API_KEY)
#         url_id = scan_url(url)
#         if url_id:
#             vt_scan_results = get_scan_results(url_id)
#             if vt_scan_results:
#                 formatted_vt_results = format_scan_results(vt_scan_results)
#             else:
#                 return jsonify({'error': 'Failed to retrieve VirusTotal scan results'}), 500
#         else:
#             return jsonify({'error': 'URL submission to VirusTotal failed'}), 500
#         combined_results = {'ipqs': reputation_results, 'virustotal': formatted_vt_results}
#         return jsonify(combined_results)
#     elif 'pii_text' in request.json:
#         text = request.json['pii_text']
#         results = analyze_pii(text)
#         detected_entities = [{'entity': result.entity_type, 'start': result.start, 'end': result.end, 'score': result.score} for result in results]
#         return jsonify({'detected_entities': detected_entities})
#     elif 'anonymize_text' in request.json:
#         text = request.json['anonymize_text']
#         results = analyze_pii(text)
#         anonymized_text = anonymize_text(text, results)
#         return jsonify({'anonymized_text': anonymized_text})
#     else:
#         return jsonify({'error': 'No file, URL, URL reputation, PII text, or anonymize text provided'}), 400


'''
from flask import Blueprint, request, jsonify
from routes.auth import token_required
from routes.ipqs_util import check_url_reputation
from routes.vt_util import scan_url, get_scan_results, format_scan_results, scan_file
from routes.pii_util import analyze_pii, anonymize_text

function_routes = Blueprint('functions', __name__)


IPQS_API_KEY = 'w0REndl0EIym4aly4naTP21ATEq1p335'
VT_API_KEY = '4e342ae597b2aedd2f9882b959cd3e749497f6bd6621d2c0b2a18e51f426797c'



def download_base64_images(image_data, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # Split the data URL to extract the base64 encoded part
        encoded_data = image_data.split(',')[1]
        
        # Decode the base64 data
        decoded_data = base64.b64decode(encoded_data)
        
        # Determine the file extension (e.g., jpeg, png)
        extension = image_data.split(';')[0].split('/')[-1]
        
        # Save the image to a file
        filename = os.path.join(output_dir, f'uploaded_image.{extension}')
        with open(filename, 'wb') as file:
            file.write(decoded_data)
        
        print(f"Downloaded image to {filename}")
        
        # Perform file scanning after saving
        scan_results = scan_downloaded_file(filename)
        
        return scan_results
        
    except IndexError:
        return {'error': f'Invalid format for image data: {image_data}'}
    except Exception as e:
        return {'error': f'Failed to process image data: {str(e)}'}

def scan_downloaded_file(file_path):
    # Implement your file scanning logic here
    # For example, using the scan_file function
    file_id = scan_file(file_path)
    if file_id:
        scan_results = get_scan_results(file_id)
        if scan_results:
            formatted_results = format_scan_results(scan_results)
            return {'scan_results': formatted_results}
        else:
            return {'error': 'Failed to retrieve scan results'}
    else:
        return {'error': 'File scan failed'}

@function_routes.route('/scan', methods=['POST'])
@token_required
def scan():
    if 'file' in request.json:
        file_data = request.json['file']
        
        # Output directory where files will be saved
        output_directory = 'downloaded_images'
        
        response = download_base64_images(file_data, output_directory)
        
        if 'error' in response:
            return jsonify(response), 400
        
        return jsonify(response), 200

    elif 'url' in request.json:
        url = request.json['url']
        
        # IPQS Analysis
        reputation_results = check_url_reputation(url, IPQS_API_KEY)
        
        # VirusTotal Analysis
        url_id = scan_url(url)
        if url_id:
            vt_scan_results = get_scan_results(url_id)
            if vt_scan_results:
                formatted_vt_results = format_scan_results(vt_scan_results)
            else:
                return jsonify({'error': 'Failed to retrieve VirusTotal scan results'}), 500
        else:
            return jsonify({'error': 'URL submission to VirusTotal failed'}), 500
        
        # Combined Results
        combined_results = {
            'ipqs': reputation_results,
            'virustotal': formatted_vt_results
        }
        return jsonify(combined_results)

    elif 'url_reputation' in request.json:
        url = request.json['url_reputation']
        
        # IPQS Analysis
        reputation_results = check_url_reputation(url, IPQS_API_KEY)
        
        # VirusTotal Analysis
        url_id = scan_url(url)
        if url_id:
            vt_scan_results = get_scan_results(url_id)
            if vt_scan_results:
                formatted_vt_results = format_scan_results(vt_scan_results)
            else:
                return jsonify({'error': 'Failed to retrieve VirusTotal scan results'}), 500
        else:
            return jsonify({'error': 'URL submission to VirusTotal failed'}), 500
        
        # Combined Results
        combined_results = {
            'ipqs': reputation_results,
            'virustotal': formatted_vt_results
        }
        return jsonify(combined_results)

    elif 'pii_text' in request.json:
        text = request.json['pii_text']
        results = analyze_pii(text)
        
        detected_entities = [
            {
                'entity': result.entity_type,
                'start': result.start,
                'end': result.end,
                'score': result.score
            } for result in results
        ]
        return jsonify({'detected_entities': detected_entities})

    elif 'anonymize_text' in request.json:
        text = request.json['anonymize_text']
        results = analyze_pii(text)
        anonymized_text = anonymize_text(text, results)
        return jsonify({'anonymized_text': anonymized_text})

    
    else:
        return jsonify({'error': 'No file, URL, URL reputation, PII text, or anonymize text provided'}), 400
'''


# import os
# import base64
# import requests
# from flask import Blueprint, request, jsonify
# from routes.auth import token_required
# from routes.ipqs_util import check_url_reputation
# from routes.vt_util import scan_url, get_scan_results, format_scan_results, scan_file
# from routes.pii_util import analyze_pii, anonymize_text

# function_routes = Blueprint('functions', __name__)

# IPQS_API_KEY = 'w0REndl0EIym4aly4naTP21ATEq1p335'
# VT_API_KEY = '4e342ae597b2aedd2f9882b959cd3e749497f6bd6621d2c0b2a18e51f426797c'
# HIBP_API_KEY = '2442b3cf4bb84e6a99934d6d93d89742'




# def download_base64_images(image_data, output_dir):
#     os.makedirs(output_dir, exist_ok=True)
    
#     try:
#         # Split the data URL to extract the base64 encoded part
#         encoded_data = image_data.split(',')[1]
        
#         # Decode the base64 data
#         decoded_data = base64.b64decode(encoded_data)
        
#         # Determine the file extension (e.g., jpeg, png)
#         extension = image_data.split(';')[0].split('/')[-1]
        
#         # Save the image to a file
#         filename = os.path.join(output_dir, f'uploaded_image.{extension}')
#         with open(filename, 'wb') as file:
#             file.write(decoded_data)
        
#         print(f"Downloaded image to {filename}")
        
#         # Perform file scanning after saving
#         scan_results = scan_downloaded_file(filename)
        
#         return scan_results
        
#     except IndexError:
#         return {'error': f'Invalid format for image data: {image_data}'}
#     except Exception as e:
#         return {'error': f'Failed to process image data: {str(e)}'}

# def scan_downloaded_file(file_path):
#     # Implement your file scanning logic here
#     # For example, using the scan_file function
#     file_id = scan_file(file_path)
#     if file_id:
#         scan_results = get_scan_results(file_id)
#         if scan_results:
#             formatted_results = format_scan_results(scan_results)
#             return {'scan_results': formatted_results}
#         else:
#             return {'error': 'Failed to retrieve scan results'}
#     else:
#         return {'error': 'File scan failed'}

# def check_email_breach(email):
#     url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
#     headers = {
#         'hibp-api-key': HIBP_API_KEY,
#         'User-Agent': 'FlaskApp',
#         'Content-Type': 'application/json'
#     }
    
#     try:
#         response = requests.get(url, headers=headers)
        
#         if response.status_code == 200:
#             breaches = response.json()
#             detailed_breaches = []

#             for breach in breaches:
#                 breach_details_url = f"https://haveibeenpwned.com/api/v3/breach/{breach.get('Name', '')}"
#                 breach_details_response = requests.get(breach_details_url, headers=headers)

#                 if breach_details_response.status_code == 200:
#                     breach_details = breach_details_response.json()
#                     breach_info = {
#                         'Name': breach.get('Name', 'N/A'),
#                         'Title': breach_details.get('Title', 'N/A'),
#                         'Description': breach_details.get('Description', 'N/A'),
#                         'BreachDate': breach_details.get('BreachDate', 'N/A'),
#                         'DataClasses': breach_details.get('DataClasses', []),
#                         'AddedDate': breach_details.get('AddedDate', 'N/A'),
#                         'ModifiedDate': breach_details.get('ModifiedDate', 'N/A'),
#                         'PwnCount': breach_details.get('PwnCount', 0),
#                         'IsVerified': breach_details.get('IsVerified', False),
#                         'IsFabricated': breach_details.get('IsFabricated', False),
#                         'IsSensitive': breach_details.get('IsSensitive', False),
#                         'IsSpamList': breach_details.get('IsSpamList', False)
#                     }
#                     detailed_breaches.append(breach_info)
#                 else:
#                     detailed_breaches.append({
#                         'Name': breach.get('Name', 'N/A'),
#                         'Title': 'N/A',
#                         'Error': 'Failed to fetch detailed information'
#                     })

#             return detailed_breaches
#         elif response.status_code == 404:
#             return {'message': 'Email not found in any breaches'}
#         elif response.status_code == 401:
#             return {'error': 'Unauthorized. Check your API key.'}
#         elif response.status_code == 403:
#             return {'error': 'Forbidden. You are not allowed to access this resource.'}
#         elif response.status_code == 429:
#             return {'error': 'Too many requests. You are being rate limited.'}
#         else:
#             return {'error': f'Unexpected error: {response.status_code}'}
#     except requests.exceptions.RequestException as e:
#         return {'error': f'Request error: {str(e)}'}

# @function_routes.route('/scan', methods=['POST'])
# @token_required
# def scan(current_user):
#     if 'file' in request.json:
#         file_data = request.json['file']
#         output_directory = 'downloaded_images'
#         response = download_base64_images(file_data, output_directory)
        
#         if 'error' in response:
#             return jsonify(response), 400
        
#         return jsonify(response), 200

#     elif 'url' in request.json:
#         url = request.json['url']
#         reputation_results = check_url_reputation(url, IPQS_API_KEY)
#         url_id = scan_url(url)
#         if url_id:
#             vt_scan_results = get_scan_results(url_id)
#             if vt_scan_results:
#                 formatted_vt_results = format_scan_results(vt_scan_results)
#             else:
#                 return jsonify({'error': 'Failed to retrieve VirusTotal scan results'}), 500
#         else:
#             return jsonify({'error': 'URL submission to VirusTotal failed'}), 500

#         combined_results = {'ipqs': reputation_results, 'virustotal': formatted_vt_results}
#         return jsonify(combined_results)

#     elif 'url_reputation' in request.json:
#         url = request.json['url_reputation']
#         reputation_results = check_url_reputation(url, IPQS_API_KEY)
#         url_id = scan_url(url)
#         if url_id:
#             vt_scan_results = get_scan_results(url_id)
#             if vt_scan_results:
#                 formatted_vt_results = format_scan_results(vt_scan_results)
#             else:
#                 return jsonify({'error': 'Failed to retrieve VirusTotal scan results'}), 500
#         else:
#             return jsonify({'error': 'URL submission to VirusTotal failed'}), 500

#         combined_results = {'ipqs': reputation_results, 'virustotal': formatted_vt_results}
#         return jsonify(combined_results)

#     elif 'pii_text' in request.json:
#         text = request.json['pii_text']
#         results = analyze_pii(text)
#         detected_entities = [
#             {
#                 'entity': result.entity_type,
#                 'start': result.start,
#                 'end': result.end,
#                 'score': result.score
#             } for result in results
#         ]
        
#         email_entities = [entity for entity in detected_entities if entity['entity'] == "EMAIL_ADDRESS"]
#         email_breach_results = []

#         for email_entity in email_entities:
#             email = text[email_entity['start']:email_entity['end']]
#             breach_results = check_email_breach(email)
#             email_breach_results.append({
#                 'email': email,
#                 'breaches': breach_results
#             })

#         return jsonify({'detected_entities': detected_entities, 'email_breach_results': email_breach_results})

#     elif 'anonymize_text' in request.json:
#         text = request.json['anonymize_text']
#         results = analyze_pii(text)
#         anonymized_text = anonymize_text(text, results)
#         return jsonify({'anonymized_text': anonymized_text})
    
#     else:
#         return jsonify({'error': 'No file, URL, URL reputation, PII text, or anonymize text provided'}), 400




import os
import base64
import re
import requests
from flask import Blueprint, request, jsonify
from routes.auth import token_required
from routes.ipqs_util import check_url_reputation
from routes.vt_util import scan_url, get_scan_results, format_scan_results, scan_file
from routes.pii_util import analyze_pii, anonymize_text


function_routes = Blueprint('functions', __name__)

IPQS_API_KEY = 'w0REndl0EIym4aly4naTP21ATEq1p335'
VT_API_KEY = '4e342ae597b2aedd2f9882b959cd3e749497f6bd6621d2c0b2a18e51f426797c'
HIBP_API_KEY = '2442b3cf4bb84e6a99934d6d93d89742'

def download_base64_images(image_data, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        encoded_data = image_data.split(',')[1]
        decoded_data = base64.b64decode(encoded_data)
        extension = image_data.split(';')[0].split('/')[-1]
        filename = os.path.join(output_dir, f'uploaded_image.{extension}')
        with open(filename, 'wb') as file:
            file.write(decoded_data)
        
        scan_results = scan_downloaded_file(filename)
        return scan_results
        
    except IndexError:
        return {'error': f'Invalid format for image data: {image_data}'}
    except Exception as e:
        return {'error': f'Failed to process image data: {str(e)}'}

def scan_downloaded_file(file_path):
    file_id = scan_file(file_path)
    if file_id:
        scan_results = get_scan_results(file_id)
        if scan_results:
            formatted_results = format_scan_results(scan_results)
            return {'scan_results': formatted_results}
        else:
            return {'error': 'Failed to retrieve scan results'}
    else:
        return {'error': 'File scan failed'}

def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

# def check_email_breach(emails):
#     breaches = {}
#     for email in emails:
#         if is_valid_email(email):
#             url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
#             headers = {
#                 'hibp-api-key': HIBP_API_KEY,
#                 'User-Agent': 'FlaskApp',
#                 'Content-Type': 'application/json'
#             }

#             try:
#                 response = requests.get(url, headers=headers)
                
#                 if response.status_code == 200:
#                     breaches[email] = response.json()
#                 elif response.status_code == 404:
#                     breaches[email] = {'message': 'Email not found in any breaches'}
#                 elif response.status_code == 401:
#                     breaches[email] = {'error': 'Unauthorized. Check your API key.'}
#                 elif response.status_code == 403:
#                     breaches[email] = {'error': 'Forbidden. You are not allowed to access this resource.'}
#                 elif response.status_code == 429:
#                     breaches[email] = {'error': 'Too many requests. You are being rate limited.'}
#                 else:
#                     breaches[email] = {'error': f'Unexpected error: {response.status_code}'}
#             except requests.exceptions.RequestException as e:
#                 breaches[email] = {'error': f'Request error: {str(e)}'}
#         else:
#             breaches[email] = {'error': 'Invalid email format'}
    
#     return breaches


def check_email_breach(emails):
    breaches = {}
    
    for email in emails:
        if is_valid_email(email):
            url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
            headers = {
                'hibp-api-key': HIBP_API_KEY,
                'User-Agent': 'FlaskApp',
                'Content-Type': 'application/json'
            }
            try:
                response = requests.get(url, headers=headers)
                
                if response.status_code == 200:
                    breach_list = response.json()
                    detailed_breaches = []
                    
                    for breach in breach_list:
                        breach_name = breach.get('Name', 'N/A')
                        breach_details_url = f"https://haveibeenpwned.com/api/v3/breach/{breach_name}"
                        breach_details_response = requests.get(breach_details_url, headers=headers)
                        
                        if breach_details_response.status_code == 200:
                            breach_details = breach_details_response.json()
                            detailed_breach_info = {
                                'Name': breach.get('Name', 'N/A'),
                                'Title': breach_details.get('Title', 'N/A'),
                                'Description': breach_details.get('Description', 'N/A'),
                                'BreachDate': breach_details.get('BreachDate', 'N/A'),
                                'DataClasses': breach_details.get('DataClasses', []),
                                'AddedDate': breach_details.get('AddedDate', 'N/A'),
                                'ModifiedDate': breach_details.get('ModifiedDate', 'N/A'),
                                'PwnCount': breach_details.get('PwnCount', 0),
                                'IsVerified': breach_details.get('IsVerified', False),
                                'IsFabricated': breach_details.get('IsFabricated', False),
                                'IsSensitive': breach_details.get('IsSensitive', False),
                                'IsSpamList': breach_details.get('IsSpamList', False)
                            }
                            detailed_breaches.append(detailed_breach_info)
                        else:
                            detailed_breaches.append({
                                'Name': breach.get('Name', 'N/A'),
                                'Title': 'N/A',
                                'Error': 'Failed to fetch detailed information'
                            })
                    
                    breaches[email] = detailed_breaches
                
                elif response.status_code == 404:
                    breaches[email] = [{'message': 'Email not found in any breaches'}]
                
                elif response.status_code == 401:
                    breaches[email] = [{'error': 'Unauthorized. Check your API key.'}]
                
                elif response.status_code == 403:
                    breaches[email] = [{'error': 'Forbidden. You are not allowed to access this resource.'}]
                
                elif response.status_code == 429:
                    breaches[email] = [{'error': 'Too many requests. You are being rate limited.'}]
                
                else:
                    breaches[email] = [{'error': f'Unexpected error: {response.status_code}'}]
            
            except requests.exceptions.RequestException as e:
                breaches[email] = [{'error': f'Request error: {str(e)}'}]
            
        else:
            breaches[email] = [{'error': 'Invalid email format'}]
    
    return breaches


@function_routes.route('/scan', methods=['POST'])
@token_required
def scan(current_user):
    if 'file' in request.json:
        file_data = request.json['file']
        output_directory = 'downloaded_images'
        response = download_base64_images(file_data, output_directory)
        
        if 'error' in response:
            return jsonify(response), 400
        
        return jsonify(response), 200

    elif 'url' in request.json:
        url = request.json['url']
        reputation_results = check_url_reputation(url, IPQS_API_KEY)
        url_id = scan_url(url)
        if url_id:
            vt_scan_results = get_scan_results(url_id)
            if vt_scan_results:
                formatted_vt_results = format_scan_results(vt_scan_results)
            else:
                return jsonify({'error': 'Failed to retrieve VirusTotal scan results'}), 500
        else:
            return jsonify({'error': 'URL submission to VirusTotal failed'}), 500

        combined_results = {'ipqs': reputation_results, 'virustotal': formatted_vt_results}
        return jsonify(combined_results)

    elif 'url_reputation' in request.json:
        url = request.json['url_reputation']
        reputation_results = check_url_reputation(url, IPQS_API_KEY)
        url_id = scan_url(url)
        if url_id:
            vt_scan_results = get_scan_results(url_id)
            if vt_scan_results:
                formatted_vt_results = format_scan_results(vt_scan_results)
            else:
                return jsonify({'error': 'Failed to retrieve VirusTotal scan results'}), 500
        else:
            return jsonify({'error': 'URL submission to VirusTotal failed'}), 500

        combined_results = {'ipqs': reputation_results, 'virustotal': formatted_vt_results}
        return jsonify(combined_results)

    elif 'pii_text' in request.json:
        text = request.json['pii_text']
        results = analyze_pii(text)
        detected_entities = [
            {
                'entity': result.entity_type,
                'start': result.start,
                'end': result.end,
                'score': result.score
            } for result in results
        ]
        
        email_entities = [entity for entity in detected_entities if entity['entity'] == "EMAIL_ADDRESS"]
        emails = [text[email_entity['start']:email_entity['end']] for email_entity in email_entities]
        
        if emails:
            breach_results = check_email_breach(emails)
            email_breach_results = [{'email': email, 'breaches': breach_results[email]} for email in emails]
        else:
            email_breach_results = []

        return jsonify({'detected_entities': detected_entities, 'email_breach_results': email_breach_results})

    elif 'anonymize_text' in request.json:
        text = request.json['anonymize_text']
        results = analyze_pii(text)
        anonymized_text = anonymize_text(text, results)
        return jsonify({'anonymized_text': anonymized_text})
    
    else:
        return jsonify({'error': 'No file, URL, URL reputation, PII text, or anonymize text provided'}), 400

@function_routes.route('/check_email_breach', methods=['POST'])
@token_required
def check_email_breach_endpoint(current_user):
    if 'emails' not in request.json:
        return jsonify({'error': 'No emails provided'}), 400
    
    emails = request.json['emails']
    
    if not isinstance(emails, list):
        return jsonify({'error': 'Emails should be provided as a list'}), 400

    breach_results = check_email_breach(emails)
    email_breach_results = [{'email': email, 'breaches': breach_results[email]} for email in emails]

    return jsonify({'email_breach_results': email_breach_results})

