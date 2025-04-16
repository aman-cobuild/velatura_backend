import os
import requests,boto3
import base64
import json
import time
import logging
import tempfile
from urllib.parse import urlparse
from docusign_webforms import ApiClient as webformApi
from docusign_esign import ApiClient, EnvelopesApi, EnvelopeDefinition, Document, Signer, SignHere, Tabs, Recipients
from docusign_webforms import FormInstanceManagementApi, FormManagementApi, CreateInstanceRequestBody,WebFormInstance
from config import (
    DOCUSIGN_INTEGRATION_KEY,
    DOCUSIGN_SECRET_KEY,
    DOCUSIGN_BASE_URL,
    DOCUSIGN_AUTH_SERVER,
    DOCUSIGN_WEBFORM_URL,
    DOCUSIGN_OAUTH_BASE_URL,
    REDIRECT_URI,
    SCOPES
)
from docusign_esign import (
    ApiClient, EnvelopesApi, EnvelopeDefinition, Document, 
    Signer, SignHere, Tabs, Recipients, TemplatesApi, 
    TemplateRole, Text, 
    RadioGroup, Radio, 
    Checkbox
)


# Configure logging
logger = logging.getLogger(__name__)

def get_consent_url():
    """Generate the URL for the consent page"""
    # Construct the URL for the DocuSign consent page
    consent_url = f"{DOCUSIGN_OAUTH_BASE_URL}/auth"
    params = {
        'response_type': 'code',
        'scope': ' '.join(SCOPES),
        'client_id': DOCUSIGN_INTEGRATION_KEY,
        'redirect_uri': REDIRECT_URI
    }
    
    # Add parameters to URL
    consent_url += '?' + '&'.join([f"{key}={value}" for key, value in params.items()])
    
    return consent_url

def get_access_token(code):
    """Exchange authorization code for access token"""
    try:
        # Prepare headers and body for token request
        auth_str = f"{DOCUSIGN_INTEGRATION_KEY}:{DOCUSIGN_SECRET_KEY}"
        base64_auth = base64.b64encode(auth_str.encode()).decode()
        
        headers = {
            'Authorization': f'Basic {base64_auth}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI
        }
        
        # Make request to DocuSign
        response = requests.post(
            f"{DOCUSIGN_OAUTH_BASE_URL}/token",
            headers=headers,
            data=data
        )
        
        if response.status_code != 200:
            logger.error(f"DocuSign token request failed: {response.status_code} - {response.text}")
            return None
        
        token_data = response.json()
        
        # Get user info to extract account ID
        user_info = get_user_info(token_data['access_token'])
        if user_info:
            account_id = user_info.get('accounts', [{}])[0].get('account_id')
            token_data['account_id'] = account_id
        
        return token_data
    except Exception as e:
        logger.error(f"Error getting access token: {str(e)}")
        return None

def get_user_info(access_token):
    """Get user information from DocuSign"""
    try:
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        response = requests.get(
            f"{DOCUSIGN_OAUTH_BASE_URL}/userinfo",
            headers=headers
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to get user info: {response.status_code} - {response.text}")
            return None
        
        return response.json()
    except Exception as e:
        logger.error(f"Error getting user info: {str(e)}")
        return None

def create_envelope(access_token, account_id, document_path, document_name, recipient_name, recipient_email):
    """Create an envelope with a document for signing"""
    try:
        # Initialize API client
        api_client = ApiClient()
        api_client.host = DOCUSIGN_BASE_URL
        api_client.set_default_header("Authorization", f"Bearer {access_token}")
        
        # Read file content
        with open(document_path, "rb") as file:
            file_bytes = file.read()
        
        # Encode the file as base64
        base64_file_content = base64.b64encode(file_bytes).decode('utf-8')
        
        # Create the document model
        document = Document(
            document_base64=base64_file_content,
            name=document_name,
            file_extension=document_name.split('.')[-1],
            document_id="1"
        )
        
        # Create the signer model with clientUserId for embedded signing
        signer = Signer(
            email=recipient_email,
            name=recipient_name,
            recipient_id="1",
            routing_order="1",
            client_user_id="1000"  # This must match the clientUserId in get_document_for_signing
        )
        
        # Create a sign_here tab
        sign_here = SignHere(
            anchor_string="/sn1/",
            anchor_units="pixels",
            anchor_x_offset="20",
            anchor_y_offset="10"
        )
        
        # If document doesn't have anchor string, use coordinates

        width = str(194.68 - 173.0)
        height = str(651.99 - 638.25) 
        if "/sn1/" not in str(file_bytes):
            sign_here = SignHere(
                document_id="1",
                page_number="2",
                x_position="173",
                y_position="639",
                width=width,
                height=height
            )
        
        # Add the tab to the signer
        signer.tabs = Tabs(sign_here_tabs=[sign_here])
        
        # Add the recipient to the envelope and set status
        recipients = Recipients(signers=[signer])
        envelope_definition = EnvelopeDefinition(
            email_subject="Please sign this document",
            documents=[document],
            recipients=recipients,
            status="sent"
        )
        
        # Create the envelope
        envelopes_api = EnvelopesApi(api_client)
        results = envelopes_api.create_envelope(account_id, envelope_definition=envelope_definition)
        
        return results.envelope_id
    except Exception as e:
        logger.error(f"Error creating envelope: {str(e)}")
        raise

def create_envelope_from_web_form(access_token, account_id, web_form_url, recipient_name, recipient_email):
    """Create an envelope for signing based on an existing DocuSign Web Form URL."""
    try:
        # Initialize API client
        api_client = ApiClient()
        api_client.host = DOCUSIGN_BASE_URL
        api_client.set_default_header("Authorization", f"Bearer {access_token}")
        envelopes_api = EnvelopesApi(api_client)

        # Create the signer model with clientUserId for embedded signing
        signer = Signer(
            email=recipient_email,
            name=recipient_name,
            recipient_id="1",
            routing_order="1",
            client_user_id="1000"  
            # Must match in get_document_for_signing
        )

        # Define the recipients for the envelope
        recipients = Recipients(signers=[signer])

        # Create the envelope definition
        envelope_definition = EnvelopeDefinition(
            email_subject="Please complete this form",
            recipients=recipients,
            status="sent",
            web_form_url=web_form_url,
            documents=[]# Set the web form URL here
        )

        # Create the envelope
        results = envelopes_api.create_envelope(account_id, envelope_definition=envelope_definition)

        return results.envelope_id
    except Exception as e:
        logger.error(f"Error creating envelope from Web Form: {str(e)}")
        raise

# def create_web_form(access_token, account_id, form_data, recipient_name, recipient_email):
#     """Create a web form (without PDF) for signing"""
#     try:
#         # Initialize API client
#         api_client = ApiClient()
#         api_client.host = DOCUSIGN_BASE_URL
#         api_client.set_default_header("Authorization", f"Bearer {access_token}")
        
#         # Create signer object
#         signer = Signer(
#             email=recipient_email,
#             name=recipient_name,
#             recipient_id="1",
#             routing_order="1",
#             # This must match the clientUserId in get_document_for_signing
#         )
        
#         # Create form fields based on the form_data
#         text_tabs = []
#         checkbox_tabs = []
#         radio_group_tabs = []
        
#         # Create form fields based on the form data structure
#         for field in form_data:
#             field_type = field.get('type')
#             field_name = field.get('name')
#             field_label = field.get('label')
#             field_value = field.get('value', '')
#             field_required = field.get('required', False)
            
#             if field_type == 'text':
#                 text_tab = Text(
#                     tab_label=field_name,
#                     name=field_name,
#                     value=field_value,
#                     width=300,
#                     required=field_required,
#                     font="helvetica",
#                     font_size="size14",
#                     document_id="1",
#                     page_number="1",
#                     x_position=str(field.get('x_position', 50)),
#                     y_position=str(field.get('y_position', 100 + len(text_tabs) * 50))
#                 )
#                 text_tabs.append(text_tab)
                
#             elif field_type == 'checkbox':
#                 checkbox = Checkbox(
#                     tab_label=field_name,
#                     name=field_name,
#                     selected=field.get('checked', False),
#                     required=field_required,
#                     document_id="1",
#                     page_number="1",
#                     x_position=str(field.get('x_position', 50)),
#                     y_position=str(field.get('y_position', 100 + len(checkbox_tabs) * 50))
#                 )
#                 checkbox_tabs.append(checkbox)
                
#             elif field_type == 'radio':
#                 # For radio buttons, we group them by group_name
#                 group_name = field.get('group_name', 'group1')
                
#                 # Check if we already have this group
#                 existing_group = next((g for g in radio_group_tabs if g.group_name == group_name), None)
                
#                 if existing_group:
#                     # Add radio button to existing group
#                     radio = Radio(
#                         value=field_value,
#                         selected=field.get('selected', False),
#                         document_id="1",
#                         page_number="1",
#                         x_position=str(field.get('x_position', 50)),
#                         y_position=str(field.get('y_position', 100 + len(radio_group_tabs) * 50))
#                     )
#                     existing_group.radios.append(radio)
#                 else:
#                     # Create a new radio group
#                     radio = Radio(
#                         value=field_value,
#                         selected=field.get('selected', False),
#                         document_id="1",
#                         page_number="1",
#                         x_position=str(field.get('x_position', 50)),
#                         y_position=str(field.get('y_position', 100 + len(radio_group_tabs) * 50))
#                     )
                    
#                     radio_group = RadioGroup(
#                         group_name=group_name,
#                         radios=[radio],
#                         document_id="1",
#                         page_number="1"
#                     )
#                     radio_group_tabs.append(radio_group)
                    
#         # Add signature field
#         sign_here = SignHere(
#             document_id="1",
#             page_number="1",
#             x_position="200",
#             y_position="400"
#         )
        
#         # Create tabs instance with all form fields
#         signer.tabs = Tabs(
#             text_tabs=text_tabs,
#             checkbox_tabs=checkbox_tabs,
#             radio_group_tabs=radio_group_tabs,
#             sign_here_tabs=[sign_here]
#         )
        
#         # Create a document for the web form
#         html_content = "<html><body><h1>Web Form</h1><p>Please fill out this form.</p></body></html>"
#         base64_html = base64.b64encode(html_content.encode('utf-8')).decode('utf-8')
        
#         document = Document(
#             document_base64=base64_html,
#             name="Web Form",
#             file_extension="html",
#             document_id="1",
#             transform_pdf_fields=True
#         )
        
#         # Add the recipient to the envelope and set status
#         recipients = Recipients(signers=[signer])
        
#         # Create the envelope definition
#         envelope_definition = EnvelopeDefinition(
#             email_subject="Please complete this web form",
#             email_blurb="Please complete this web form",
#             documents=[document],
#             recipients=recipients,
#             status="sent"
#         )
        
#         # Create the envelope
#         envelopes_api = EnvelopesApi(api_client)
#         results = envelopes_api.create_envelope(account_id, envelope_definition=envelope_definition)
        
#         return results.envelope_id
#     except Exception as e:
#         logger.error(f"Error creating web form: {str(e)}")
#         raise

def create_web_form_instance(access_token, account_id, form_id, client_user_id, form_values=None, expiration_offset=24, return_url=None, tags=None):
    """
    Creates a DocuSign Web Form instance using the Python SDK and returns the URL.

    Args:
        access_token (str): Valid OAuth access token with 'webforms_instance_write' scope.
        account_id (str): The DocuSign account ID.
        form_id (str): The ID of the pre-configured Web Form.
        client_user_id (str): A unique identifier for the user session from your application.
        form_values (dict, optional): Key-value pairs to pre-fill form fields. Defaults to None. [1]
        expiration_offset (int, optional): Hours until the instance URL expires. Defaults to 24. [1]
        return_url (str, optional): URL to redirect user after signing (for embedded signing). Defaults to None. [3]
        tags (dict, optional): Key-value pairs for categorization. Defaults to None.

    Returns:
        str: The unique URL for the user to access the Web Form instance, or None if an error occurs.
    """
   
    # 1. Initialize API Client for Web Forms API
    api_client = webformApi()
    api_client.set_default_header("Authorization", f"Bearer {access_token}")
    api_client.host=DOCUSIGN_WEBFORM_URL
    # Determine the correct base path for the Web Forms API
    # It's often the base_uri *without* the /restapi suffix
    # user_info = get_user_info(access_token)
    # web_forms_api_host = None
    # if user_info:
    #         default_account = next((acc for acc in user_info.get('accounts',) if acc.get('is_default')), user_info.get('accounts', [{}]) if user_info.get('accounts') else None)
    #         if default_account and default_account.get('base_uri'):
    #             web_forms_api_host = default_account['base_uri'] # Use the domain directly

    # if not web_forms_api_host:
    #         # Fallback: Parse from config (less reliable)
    #         parsed_uri = urlparse(DOCUSIGN_BASE_URL) # Or DOCUSIGN_AUTH_SERVER
    #         web_forms_api_host = f"{parsed_uri.scheme}://{parsed_uri.netloc}"
    #         logger.warning(f"Could not determine Web Forms API host from user info, falling back to derived host: {web_forms_api_host}")

    # api_client.host = web_forms_api_host # Set the host for the Web Forms API

    # 2. Construct Request Body using SDK Model [1]
    instance_request_body = CreateInstanceRequestBody(
        client_user_id=client_user_id,
        form_values=form_values if form_values else None, # SDK might handle None or require empty dict {}
        expiration_offset=expiration_offset,
        return_url=return_url if return_url else None,
        tags=tags if tags else None
        # Add other optional parameters supported by CreateInstanceRequestBody model if needed
    )

    # 3. Instantiate the Web Forms API Service
    # Use the imported class name (e.g., FormInstanceManagementApi)
    web_forms_api = FormInstanceManagementApi(api_client)

    logger.info(f"Calling Web Forms SDK: create_form_instance for form {form_id}")
    logger.debug(f"Request Body Model: {instance_request_body}")

    # 4. Call the SDK method to create the instance [1, 3]
    # Method name might be create_instance, create_form_instance, etc. Adjust if needed.
    # The SDK method handles constructing the correct endpoint path internally.
    instance_response = web_forms_api.create_instance(
        account_id,
        form_id,
        create_instance_body=instance_request_body
    )

    # 5. Process the SDK Response Model (e.g., WebFormInstance) [1, 4]
    if isinstance(instance_response, WebFormInstance) and instance_response.form_url and instance_response.instance_token:
        form_url = instance_response.form_url
        instance_token = instance_response.instance_token

        # Construct the final URL [1, 4]
        final_instance_url = f"{form_url}#instanceToken={instance_token}"
        logger.info(f"Successfully created Web Form instance via SDK. URL: {final_instance_url}")
        return final_instance_url
    else:
        logger.error(f"Web Forms SDK response missing formUrl or instanceToken, or unexpected type. Response: {instance_response}")
        return None

def send_invitation_email(to_address: str, instance_url: str):
    ses = boto3.client("ses")
    ses.send_email(
        Source="no‑reply@yourdomain.com",
        Destination={"ToAddresses":[to_address]},
        Message={
            "Subject": {"Data":"Please complete your form"},
            "Body": {
                "Text": {"Data": f"Hello,\n\nPlease fill out your form here:\n{instance_url}"}
            }
        }
    )
def list_web_forms(access_token: str, account_id: str):
    api_client = webformApi()
    api_client.host = DOCUSIGN_WEBFORM_URL
    api_client.set_default_header("Authorization", f"Bearer {access_token}")
    forms_api = FormManagementApi(api_client)
    return forms_api.get_forms(account_id)
    
def get_envelope_recipients(access_token, account_id, envelope_id):
    """Get recipient information for an envelope"""
    try:
        # Initialize API client
        api_client = ApiClient()
        api_client.host = DOCUSIGN_BASE_URL
        api_client.set_default_header("Authorization", f"Bearer {access_token}")
        
        # Get recipients
        envelopes_api = EnvelopesApi(api_client)
        recipients = envelopes_api.list_recipients(account_id, envelope_id)
        
        return recipients
    except Exception as e:
        logger.error(f"Error getting recipients: {str(e)}")
        return None

def get_document_for_signing(access_token, account_id, envelope_id, recipient_email, recipient_name):
    """Get a URL that allows a recipient to sign a document"""
    try:
        # Initialize API client
        api_client = ApiClient()
        api_client.host = DOCUSIGN_BASE_URL
        api_client.set_default_header("Authorization", f"Bearer {access_token}")
        
        # Prepare the request body
        from config import REDIRECT_URI
        
        # Get base URL from the redirect URI
        redirect_base = '/'.join(REDIRECT_URI.split('/')[:3])
        
        recipient_view_request = {
            "returnUrl": f"{redirect_base}/status",
            "authenticationMethod": "none",
            "email": recipient_email,
            "userName": recipient_name,
            "clientUserId": "1000"  # This matches the client_user_id in create_envelope
        }
        print("recipient_view_request",recipient_view_request)
        
        # Make request to get signing URL
        envelopes_api = EnvelopesApi(api_client)
        recipient_view = envelopes_api.create_recipient_view(
            account_id, 
            envelope_id, 
            recipient_view_request=recipient_view_request
        )
        
        return recipient_view.url
    except Exception as e:
        logger.error(f"Error getting signing URL2: {str(e)}")
        raise

def get_envelope_status(access_token, account_id, envelope_id):
    """Get the status of an envelope"""
    try:
        # Initialize API client
        api_client = ApiClient()
        api_client.host = DOCUSIGN_BASE_URL
        api_client.set_default_header("Authorization", f"Bearer {access_token}")
        
        # Get envelope status
        envelopes_api = EnvelopesApi(api_client)
        envelope = envelopes_api.get_envelope(account_id, envelope_id)
        
        return envelope.status
    except Exception as e:
        logger.error(f"Error getting envelope status: {str(e)}")
        return None

def download_signed_document(access_token, account_id, envelope_id):
    """Download the signed document as a PDF"""
    # try:
        # Initialize API client
    api_client = ApiClient()
    api_client.host = DOCUSIGN_BASE_URL
    api_client.set_default_header("Authorization", f"Bearer {access_token}")
    
    # Get documents from envelope
    envelopes_api = EnvelopesApi(api_client)
    document_list = envelopes_api.list_documents(account_id, envelope_id)
    
    if document_list and document_list.envelope_documents:
        # Get the first document
        document_id = document_list.envelope_documents[0].document_id
        
        # Download the document
        print("document_id",document_id)
        print("envelope_id",envelope_id)
        document_content = envelopes_api.get_document(account_id,document_id,envelope_id)
        print("document_content",document_content)
        # Save to temporary file
        # temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        # temp_file.write(document_content.encode('utf-8'))
        # temp_file.close()
        
        return document_content
    else:
        logger.error("No documents found in envelope")
        return None
    # except Exception as e:
    #     logger.error(f"Error downloading document: {str(e)}")
    #     return None
