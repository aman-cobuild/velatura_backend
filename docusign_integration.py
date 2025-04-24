import os
import requests,boto3
import base64
import fitz
import string 
from typing import List, Tuple, Optional
import json
import time,datetime
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
from botocore.exceptions import ClientError
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

def locate_all_signature_keywords(pdf_path: str,
                                  keyword: str = "signature",
                                  dash_width: float = 200,
                                  pad_x: float = 10,
                                  pad_y: float = 5) -> List[Tuple[int, float, float, float, float]]:
    """
    Search every page’s words for ALL occurrences of a specific keyword
    (case-insensitive), stripping common leading/trailing punctuation.
    """
    locations = []
    doc = None # Initialize doc to None
    # Define punctuation to remove from ends (includes parentheses, periods, commas, semicolons)
    punctuation_to_strip = string.punctuation # '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
    try:
        doc = fitz.open(pdf_path)
        keyword_lower = keyword.strip().lower()
        if not keyword_lower:
            print("Error: Keyword cannot be empty.")
            return []

        for p_idx, page in enumerate(doc):
            page_num = p_idx + 1
            words = page.get_text("words")

            for (x0, y0, x1, y1, text, *_) in words:
                # Process text: strip whitespace, convert to lower, strip punctuation from ends
                processed_text = text.strip().lower().strip(punctuation_to_strip)

                if processed_text == keyword_lower:
                    # Found an occurrence
                    box_x = x1 + pad_x
                    box_y = y0 - pad_y
                    box_w = dash_width
                    box_h = (y1 - y0) + (pad_y * 2)
                    locations.append((page_num, box_x, box_y, box_w, box_h))

        if not locations:
          print(f"Keyword '{keyword}' not found in the document.")

        return locations

    except Exception as e:
        print(f"An error occurred while processing the PDF: {e}")
        return [] # Return empty list on error
    finally:
        if doc:
            doc.close() 
def annotate_all_signature_boxes(pdf_path: str,
                                 output_path: str,
                                 keyword: str = "signature",
                                 dash_width: float = 200,
                                 pad_x: float = 10,
                                 pad_y: float = 5) -> Optional[str]:
    """
    Detects ALL occurrences of the keyword in the PDF, draws a
    red rectangle annotation next to each one, and saves the result.
    """
    all_locations = locate_all_signature_keywords(pdf_path, keyword, dash_width, pad_x, pad_y)

    if not all_locations:
        return None

    doc = None
    annotated = False
    try:
        doc = fitz.open(pdf_path)
        for location in all_locations:
            page_num, x, y, w, h = location
            if 0 < page_num <= doc.page_count:
                page = doc[page_num - 1]
                rect = fitz.Rect(x, y, x + w, y + h)
                annot = page.add_rect_annot(rect)
                annot.set_colors(stroke=(1, 0, 0))
                annot.set_border(width=1.5)
                annot.update()
                annotated = True
            else:
                print(f"Warning: Invalid page number {page_num} encountered.")

        if annotated:
            doc.save(output_path, garbage=4, deflate=True, clean=True)
            return output_path
        else:
            print("No valid locations found to annotate.")
            return None
    except Exception as e:
        print(f"An error occurred during annotation or saving: {e}")
        return None
    finally:
        if doc:
            doc.close()
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
        
        #NEW WAY OF SIGNING WITHOUT COORDINATES NEEDED--WORKING
        # If document doesn't have anchor string, use coordinates
        # pdf_path = "sample2.pdf"
        # output_pdf = "annotated_all_signatures_final.pdf"
        # keyword_to_find = "signature"

        # # Annotate the PDF with all found locations
        # annotated_file_path = annotate_all_signature_boxes(
        #     pdf_path,
        #     output_pdf,
        #     keyword=keyword_to_find
        # )

        # if annotated_file_path:
        #     print(f"Annotation successful. Annotated PDF saved to: {annotated_file_path}")
        #     locations_info = locate_all_signature_keywords(pdf_path, keyword=keyword_to_find)
        #     if locations_info:
        #         print(f"\nFound {len(locations_info)} instance(s) of '{keyword_to_find}':")
        #         for i, loc in enumerate(locations_info):
        #             page, x, y, w, h = loc
        #             print(f"  {i+1}. Page {page}: Box coordinates: x={x:.1f}, y={y:.1f}, width={w:.1f}, height={h:.1f}")
        # else:
        #     print(f"\nFailed to annotate PDF. Keyword '{keyword_to_find}' might be missing or an error occurred.")

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


def send_invitation_email(to_address: str, instance_url: str, sender_email: str = "sai@cobuild.tech"):
    """
    Sends a professionally designed HTML email invitation with a "Sign Here" button using AWS SES.

    Args:
        to_address: The recipient's email address.
        instance_url: The URL the "Sign Here" button should link to.
        sender_email: The email address to send the email from (must be verified in SES).
    """
    ses = boto3.client("ses")

    # --- HTML Email Body ---
    # Uses inline CSS for maximum compatibility across email clients.
    html_body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Form Completion Request</title>
        <style>
            /* Basic styles for email body */
            body {{
                font-family: Arial, Helvetica, sans-serif;
                line-height: 1.6;
                color: #333333;
                margin: 0;
                padding: 0;
                background-color: #f4f4f4;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                padding: 30px;
                background-color: #ffffff;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .header {{
                text-align: center;
                padding-bottom: 20px;
                border-bottom: 1px solid #eeeeee;
            }}
            .content {{
                padding: 20px 0;
            }}
            .button-container {{
                text-align: center;
                padding-top: 20px;
            }}
            /* Professional button style */
            .button {{
                display: inline-block;
                padding: 12px 25px;
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                background-color: #007bff; /* Professional blue */
                border: none;
                border-radius: 5px;
                text-decoration: none;
                cursor: pointer;
                transition: background-color 0.3s ease;
            }}
            .button:hover {{
                background-color: #0056b3; /* Darker blue on hover */
            }}
            .footer {{
                text-align: center;
                font-size: 12px;
                color: #777777;
                padding-top: 20px;
                border-top: 1px solid #eeeeee;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>Action Required: Please Complete Your Form</h2>
            </div>
            <div class="content">
                <p>Hello,</p>
                <p>You have a form that requires your attention. Please click the button below to access and complete it:</p>
                <div class="button-container">
                    <a href="{instance_url}" class="button">Sign Here</a>
                </div>
                <p>Thank you for your prompt attention to this matter.</p>
            </div>
            <div class="footer">
                <p>This email was sent from our automated system. Please do not reply directly.</p>
                <p>&copy; {datetime.datetime.now().year} Velatura</p>
            </div>
        </div>
    </body>
    </html>
    """

    # --- Plain Text Fallback ---
    text_body = f"""
    Hello,

    You have a form that requires your attention.
    Thank you for your prompt attention to this matter.

    This email was sent from our automated system. Please do not reply directly.
    """

    try:
        response = ses.send_email(
            Source=sender_email,
            Destination={"ToAddresses": [to_address]},
            Message={
                "Subject": {"Data": "Action Required: Please Complete Your Form"},
                "Body": {
                    "Text": {"Data": text_body},
                    "Html": {"Data": html_body}
                }
            }
        )
        print(f"Email sent! Message ID: {response['MessageId']}")
        return response['MessageId']
    except ClientError as e:
        print(f"Error sending email: {e.response['Error']['Message']}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


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
