import os

# DocuSign Integration Settings
# These should be set as environment variables in production
DOCUSIGN_INTEGRATION_KEY = os.environ.get(
    'DOCUSIGN_INTEGRATION_KEY', '819ec0f4-3444-4979-85c1-8d6cdcfad891')
DOCUSIGN_SECRET_KEY = os.environ.get('DOCUSIGN_SECRET_KEY',
                                     'de22fd79-48fc-47c6-992a-1fb6ff246dd4')
DOCUSIGN_ACCOUNT_ID = os.environ.get('DOCUSIGN_ACCOUNT_ID',
                                     '0464c541-774e-4da4-bfa4-8cb03c7e56b3')
DOCUSIGN_USER_ID = os.environ.get('DOCUSIGN_USER_ID',
                                  '5cf9513e-3f63-4ca3-8cce-18d7da314dea')
DOCUSIGN_AUTH_SERVER = 'https://account-d.docusign.com'
DOCUSIGN_OAUTH_BASE_URL = 'https://account-d.docusign.com/oauth'
DOCUSIGN_BASE_URL = 'https://demo.docusign.net/restapi'
DOCUSIGN_WEBFORM_URL = 'https://apps-d.docusign.com/api/webforms'

# This should be your actual application URL in production
# REDIRECT_URI = os.environ.get('REDIRECT_URI', 'https://is258vntuc.execute-api.us-east-1.amazonaws.com/dev/callback')# REDIRECT_URI = os.environ.get('REDIRECT_URI', 'https://is258vntuc.execute-api.us-east-1.amazonaws.com/dev/callback')
REDIRECT_URI = os.environ.get('REDIRECT_URI', 'https://is258vntuc.execute-api.us-east-1.amazonaws.com/dev/callback')# REDIRECT_URI = os.environ.get('REDIRECT_URI', 'https://is258vntuc.execute-api.us-east-1.amazonaws.com/dev/callback')
# S3_SESSION_BUCKET = os.environ.get('S3_SESSION_BUCKET', 'velatura')
# Configure the S3 session interface.
s3_bucket = os.environ.get("S3_SESSION_BUCKET",'velatura')
# Settings from env
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID","us-east-1_GN0S7Oros")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID","55nkktiap583bo6ng8rc700t5p")
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET","1umkqmmbscithgmna55bd87v5kn633puiktvclf66bi75m12vqr8")
MONGO_URL= os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME= os.getenv("DB_NAME", "vela")
JWKS_URL = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"

# JWT scope for DocuSign
SCOPES =  ['signature', 'impersonation','webforms_read','webforms_instance_read','webforms_instance_write']

# Check if environment variables are set
if not all([DOCUSIGN_INTEGRATION_KEY, DOCUSIGN_SECRET_KEY]):
    print(
        "WARNING: DocuSign credentials are not set. Please set the appropriate environment variables."
    )
