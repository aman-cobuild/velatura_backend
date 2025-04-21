import os
import logging
import tempfile
import uuid,time,requests
import json,hmac
import hashlib
import base64
from datetime import timedelta
import boto3
from functools import wraps
from flask_cors import CORS
from flask import Flask, request, redirect, url_for, session, jsonify, send_file,abort
from werkzeug.utils import secure_filename
from flask.sessions import SessionInterface, SessionMixin
from pymongo import MongoClient, ASCENDING
from jose import jwt,jwk
from bson import ObjectId
from jose.utils import base64url_decode
from jose.exceptions import JWTError


from config import COGNITO_CLIENT_ID,COGNITO_CLIENT_SECRET,COGNITO_USER_POOL_ID,MONGO_URL,DB_NAME,s3_bucket,JWKS_URL,AWS_REGION
# Import your DocuSign integration functions
from docusign_integration import (
    get_consent_url,
    get_access_token,
    create_envelope,create_web_form_instance,
    get_envelope_recipients,
    get_document_for_signing,
    get_envelope_status,
    download_signed_document,send_invitation_email
)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)



###############################################################################
# Custom S3 Session Interface Implementation with Manual Session ID Support
###############################################################################

class S3Session(dict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        self.sid = sid
        self.new = new
        super().__init__(initial or {})

class S3SessionInterface(SessionInterface):
    session_cookie_name = "s3session"

    def __init__(self, bucket, prefix="sessions", expiration=timedelta(days=1)):
        self.bucket = bucket
        self.prefix = prefix
        self.expiration = expiration
        self.s3_client = boto3.client("s3")

    def _get_s3_key(self, sid):
        """Construct the S3 key for storing session data."""
        return f"{self.prefix}/{sid}.json"

    def open_session(self, app, request):
        # Try to get session id from cookie; if not, look in header or query parameter.
        sid = request.cookies.get(self.session_cookie_name)
        if not sid:
            sid = request.headers.get("X-Session-Id") or request.args.get("session_id")
        if not sid:
            # Create a new session id if none is provided.
            sid = str(uuid.uuid4())
            return S3Session(sid=sid, new=True)

        key = self._get_s3_key(sid)
        try:
            response = self.s3_client.get_object(Bucket=self.bucket, Key=key)
            session_data = response["Body"].read().decode("utf-8")
            data = json.loads(session_data)
            return S3Session(data, sid=sid)
        except self.s3_client.exceptions.NoSuchKey:
            return S3Session(sid=sid, new=True)
        except Exception as e:
            app.logger.error(f"Error reading session from S3: {e}")
            return S3Session(sid=sid, new=True)

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        if not session:
            response.delete_cookie(self.session_cookie_name, domain=domain)
            return

        sid = session.sid
        key = self._get_s3_key(sid)
        session_data = json.dumps(dict(session))
        try:
            self.s3_client.put_object(Bucket=self.bucket, Key=key, Body=session_data)
        except Exception as e:
            app.logger.error(f"Error saving session to S3: {e}")
            return

        expires = self.get_expiration_time(app, session)
        # Only set the cookie if no custom handling is done on the client.
        if domain:
            response.set_cookie(
                self.session_cookie_name,
                sid,
                expires=expires,
                httponly=True,
                domain=domain,
            )
        else:
            response.set_cookie(
                self.session_cookie_name, sid, expires=expires, httponly=True
            )

###############################################################################
# Flask App Setup and Routes
###############################################################################

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.url_map.strict_slashes = False

if not s3_bucket:
    raise Exception("Please set the 'S3_SESSION_BUCKET' environment variable.")
app.session_interface = S3SessionInterface(bucket=s3_bucket, prefix="sessions", expiration=timedelta(days=1))

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt"}
cognito_client = boto3.client("cognito-idp", region_name=AWS_REGION)

mongo_client = MongoClient(MONGO_URL)
db = mongo_client[DB_NAME]
db.patients.create_index("name", unique=True)
jwks = requests.get(JWKS_URL).json()


# Ensure upload directory exists
UPLOAD_FOLDER = tempfile.mkdtemp()
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max upload

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS



# Utility functions
def get_secret_hash(username: str) -> str:
    msg = username + COGNITO_CLIENT_ID
    dig = hmac.new(
        COGNITO_CLIENT_SECRET.encode('utf-8'),
        msg.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', None)
        if not auth or not auth.startswith('Bearer '):
            abort(401, description="Authorization header missing or malformed")
        token = auth.split()[1]
        user = verify_jwt(token)
        return f(user,*args,**kwargs)
    return decorated

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json() or {}
    u, p, e, r = data.get('username'), data.get('password'), data.get('email'), data.get('role')
    if not all([u, p, e, r]):
        return jsonify({'error':'username,password,email,role required'}),400
    secret_hash = get_secret_hash(u)
    cognito_client.sign_up(
        ClientId=COGNITO_CLIENT_ID,
        SecretHash=secret_hash,
        Username=u, Password=p,
        UserAttributes=[{'Name':'email','Value':e},{'Name':'custom:role','Value':r}]
    )
    cognito_client.admin_confirm_sign_up(UserPoolId=COGNITO_USER_POOL_ID, Username=u)
    cognito_client.admin_add_user_to_group(
        UserPoolId=COGNITO_USER_POOL_ID, Username=u, GroupName=r
    )
    return jsonify({'message':'User signed up'}),201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    u, p = data.get('username'), data.get('password')
    if not u or not p:
        return jsonify({'error':'username,password required'}),400
    secret_hash = get_secret_hash(u)
    resp = cognito_client.initiate_auth(
        ClientId=COGNITO_CLIENT_ID,
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={'USERNAME':u,'PASSWORD':p,'SECRET_HASH':secret_hash}
    )
    auth = resp['AuthenticationResult']
    # store in session
    session['username']      = u
    session['access_token']  = auth['AccessToken']
    session['id_token']      = auth['IdToken']
    session['refresh_token'] = auth['RefreshToken']
    # decode id_token to get sub
    # payload = jwt.decode(auth['IdToken'], options={"verify_signature": False})
    # session['sub'] = payload['sub']
    return jsonify(resp.get('AuthenticationResult',{}))


# @app.route('/logout')
# def logout():
#     session.clear()
#     return 
@app.route("/")
def index():
    # Return the authentication status as a JSON response.
    is_authenticated = "docusign_access_token" in session
    return jsonify({"authenticated": is_authenticated})

# Inside app.py

@app.route("/upload", methods=['POST'])
@token_required
def upload_method(user):
    if "docusign_access_token" not in session:
        return jsonify({
            "error": "Please authenticate with DocuSign first",
            "authorize_url": url_for("authorize", _external=True),
        }), 401
    
    #TODO- Dynamic Handling of filename
    filename = "P11GA_26634068-consent-to-bill-and-treat.pdf"
    filepath = os.path.join("samples", filename)

    # Get recipient details from the request form data
    recipient_name = request.form.get("recipient_name")
    recipient_email = request.form.get("recipient_email")
    method = request.form.get("method")
    session["method"] = method


    if not recipient_name or not recipient_email:
        return jsonify({"error": "Recipient name and email are required"}), 400

    client_user_id = str(uuid.uuid4())

    form_values_to_prefill = {
        # Add prefill fields if needed, matching API reference names
    }
    if not form_values_to_prefill:
         form_values_to_prefill = None

    # try:
    #     post_signing_return_url = url_for('success', _external=True) + f"?session_id={session.sid}&client_user_id={client_user_id}"
    # except RuntimeError:
    #     post_signing_return_url = f"https://{request.host}/success?session_id={session.sid}&client_user_id={client_user_id}"

   
    DOCUSIGN_FORM_ID = "1bd7a348-f83f-4ccd-96a7-deaf727c1b6e" # Hardcoded from your previous code
    if not DOCUSIGN_FORM_ID or DOCUSIGN_FORM_ID == "YOUR_WEB_FORM_CONFIGURATION_ID":
         logger.error("DOCUSIGN_FORM_ID is not configured correctly.")
         return jsonify({"error": "Server configuration error: Web Form ID not set."}), 500

    # --- ADD LOGGING ---
    print("session-",session)
    account_id_to_use = session.get("docusign_account_id")
    logger.info(f"Attempting to create Web Form instance:")
    logger.info(f"  Account ID: {account_id_to_use}")
    logger.info(f"  Form ID: {DOCUSIGN_FORM_ID}")
    # sign_link ="http://localhost:8080/patient/sign/"+f"?session_id={session.sid}"
    sign_link ="https://velatura.app/patient/sign/"+f"?session_id={session.sid}"
    # --- END LOGGING ---

    if not account_id_to_use:
         logger.error("Account ID not found in session.")
         return jsonify({"error": "Authentication error: Account ID missing."}), 401

    if method.lower()=="webform":
        instance_url = create_web_form_instance(
        access_token=session["docusign_access_token"],
        account_id=account_id_to_use, # Use the logged variable
        form_id=DOCUSIGN_FORM_ID,
        client_user_id=client_user_id,
        form_values=form_values_to_prefill
    )

        if instance_url:
            session["instance_url"] = instance_url
            session["client_user_id"] = client_user_id
            session["recipient_name"] = recipient_name
            session["recipient_email"] = recipient_email
            session.pop("envelope_id", None)
            session.pop("document_name", None)
            session.pop("web_form_url", None)

            logger.info(f"Web Form instance created successfully. URL: {instance_url}")
            send_invitation_email(recipient_email, sign_link)
            return jsonify({
                "message": "Web Form instance created."
            })
        else:
            logger.error("Failed to create Web Form instance (instance_url was None).")
            return jsonify({"error": "Failed to create Web Form instance"}), 500
    else:
        try:
            envelope_id = create_envelope(
                session["docusign_access_token"],
                session["docusign_account_id"],
                filepath,
                filename,
                recipient_name,
                recipient_email,
            )

            if envelope_id:
                session["envelope_id"] = envelope_id
                session["document_name"] = filename
                session["recipient_name"] = recipient_name
                session["recipient_email"] = recipient_email
                
                send_invitation_email(recipient_email, sign_link)
                return jsonify({
                   "message": "Document created."
                })
            else:
                return jsonify({"error": "Failed to create envelope"}), 500
        except Exception as e:
            logger.error(f"Error creating envelope: {str(e)}")
            return jsonify({"error": f"Error creating envelope: {str(e)}"}), 500
    

@app.route("/sign")
def sign_document():
    # This route is likely NOT needed in the standard Web Forms flow.
    # The user is redirected to the instance_url from /upload.
    # Signing happens within the DocuSign UI after form submission (for template-based forms).
    # Embedded signing via get_document_for_signing is typically used when *you* create the envelope via API.
    logger.warning("Route /sign accessed, but may not be applicable for Web Forms flow.")

    if session["method"]=="webform":
        # Optionally, just return the instance URL again if the frontend needs it
        return jsonify({
            "url": session["instance_url"]

        }),200
    else:
        if "envelope_id" not in session:
            return jsonify({"error": "No document to sign"}), 400
        try:
            signing_url = get_document_for_signing(
            session["docusign_access_token"],
            session["docusign_account_id"],
            session["envelope_id"],
            session["recipient_email"],
            session["recipient_name"],
        )
            return jsonify({
            "url": signing_url

        }),200

        except Exception as e:
            logger.error(f"Error getting signing URL: {str(e)}")
            return jsonify({"error": f"Error getting signing URL: {str(e)}"}), 500
    
@app.route("/authorize")
def authorize():
    # Return the DocuSign consent URL so the client can redirect the user.
    auth_url = get_consent_url()
    return jsonify({"auth_url": auth_url})

@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return jsonify({"error": "Authorization failed. No code received."}), 400

    try:
        token_info = get_access_token(code)
        if token_info and "access_token" in token_info and "account_id" in token_info:
            session["docusign_access_token"] = token_info["access_token"]
            session["docusign_account_id"] = token_info["account_id"]

            # Instead of a redirect, return the session id so that the frontend can save it.
            # return redirect(f'http://localhost:8080/?code={token_info["access_token"]}&session={session.sid}')
            return redirect(f'https://velatura.app/?code={token_info["access_token"]}&session={session.sid}')
        else:
            return jsonify({"error": "Failed to get access token from DocuSign"}), 500
    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        return jsonify({"error": f"Authentication error: {str(e)}"}), 500


@app.route("/status")
def check_status():
    # Checking status immediately after creating an instance isn't useful,
    # as the envelope doesn't exist yet.
    # This endpoint would need to be called *after* the user submits the form.
    # You'd need the envelope_id, which isn't stored in the session initially.
    # A robust solution uses DocuSign Connect (webhooks) to get notified when the
    # envelope is created and its status changes.
    # Alternatively, you could poll using instance/user identifiers if the API supports it,
    # or store the envelope ID received via Connect/polling.

    logger.warning("Route /status accessed. Requires envelope_id obtained *after* Web Form submission (e.g., via Connect).")

    # Example: Check if we received an envelope ID (e.g., from Connect updating the session)
    envelope_id = request.args.get("envelopeId")
    if not envelope_id or "docusign_access_token" not in session:
         # Check if client_user_id exists, indicating a form was likely started
         if "client_user_id" in session:
              return jsonify({
                   "message": "Web Form instance initiated. Envelope status can be checked after user submission.",
                   "status": "instance_initiated" # Custom status for frontend
              }), 202 # Accepted
         else:
              return jsonify({"error": "No active signing session or envelope ID provided"}), 400


    try:
        status = get_envelope_status(
            session["docusign_access_token"],
            session["docusign_account_id"],
            envelope_id, # Use the ID obtained post-submission
        )
        logger.info(f"Checked status for envelope {envelope_id}: {status}")
        return jsonify({"message": f"Document status: {status}", "status": status, "envelope_id": envelope_id})

    except Exception as e:
        logger.exception(f"Error checking status for envelope {envelope_id}: {str(e)}")
        return jsonify({"error": f"Error checking status: {str(e)}"}), 500

# --- MODIFIED /download route ---
@app.route("/download")
def download():
    # Similar to /status, this requires the envelope_id obtained *after* submission.
    logger.warning("Route /download accessed. Requires envelope_id obtained *after* Web Form submission.")

    envelope_id = request.args.get("envelopeId") # Expect envelope ID as query param
    if not envelope_id or "docusign_access_token" not in session:
        return jsonify({"error": "Envelope ID required and user must be authenticated"}), 400

    try:
        # Assuming download_signed_document returns bytes
        doc_bytes = download_signed_document(
            session["docusign_access_token"],
            session["docusign_account_id"],
            envelope_id,
            # document_id='combined' # Or 'archive' or specific ID
        )

        if doc_bytes:
            # Create a temporary file to send
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
                temp_file.write(doc_bytes)
                temp_file_path = temp_file.name

            # Use send_file and clean up afterwards
            response = send_file(
                temp_file_path,
                as_attachment=True,
                download_name=f"signed_document_{envelope_id}.pdf", # Generic name
                mimetype="application/pdf",
            )
            # Ensure the file is removed after sending
            # Use response.call_on_close() if available or handle cleanup carefully
            try:
                 os.remove(temp_file_path)
            except OSError as e:
                 logger.error(f"Error removing temporary file {temp_file_path}: {e}")

            return response
        else:
            logger.error(f"Failed to download document for envelope {envelope_id} (doc_bytes is None).")
            # Check if envelope status is 'completed' before attempting download
            status = get_envelope_status(session["docusign_access_token"], session["docusign_account_id"], envelope_id)
            if status!= 'completed':
                 return jsonify({"error": f"Cannot download document. Envelope status is '{status}'."}), 400
            else:
                 return jsonify({"error": "Failed to download document"}), 500
    except Exception as e:
        logger.exception(f"Error downloading document for envelope {envelope_id}: {str(e)}")
        return jsonify({"error": f"Error downloading document: {str(e)}"}), 500

def verify_jwt(token: str) -> dict:
    try:
        # 1) Pull the kid from the unverified header
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")

        # 2) Find the matching JWK
        key_dict = next((k for k in jwks["keys"] if k["kid"] == kid), None)
        if not key_dict:
            abort(401, description="Invalid JWT header key")

        # 3) Build a jwk.RSAKey
        rsa_key = jwk.construct(key_dict)

        # 4) Verify the cryptographic signature yourself
        message, encoded_sig = token.rsplit(".", 1)
        decoded_sig = base64url_decode(encoded_sig.encode("utf-8"))
        if not rsa_key.verify(message.encode("utf-8"), decoded_sig):
            abort(401, description="JWT signature verification failed")

        # 5) Finally decode the payload (audience check, expiry, etc.)
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=[key_dict["alg"]],
            audience=COGNITO_CLIENT_ID
        )
        print("payload",payload)
        return payload

    except JWTError:
        abort(401, description="Token validation error")
def requires_auth(f):
    """
    Decorator to protect a route with Cognito JWT.
    Puts the token payload onto flask.g.current_user.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", None)
        if not auth:
            return jsonify({"error": "Missing Authorization header"}), 401

        parts = auth.split()
        if parts[0].lower() != "bearer" or len(parts) != 2:
            return jsonify({"error": "Invalid Authorization header"}), 401

        token = parts[1]
        try:
            payload = verify_jwt(token)
        except JWTError:
            return jsonify({"error": "Invalid or expired token"}), 401

        g.current_user = payload
        return f(*args, **kwargs)

    return wrapper


@app.route("/patients", methods=["POST"])
@token_required
def create_patient(user):
    """
    POST /patients
    JSON body must include: first_name, last_name, email
    Optional: phone, address, date_of_birth
    """
    data = request.get_json(force=True)
    for field in ("first_name", "last_name", "email"):
        if not data.get(field):
            return jsonify({"error": f"{field} is required"}), 400
    print("user",user)
    patient = {
        "first_name":data["first_name"],
        "last_name": data["last_name"],
        "ssn":data["ssn"],
        "mrn":data["mrn"],
        "mrn_oid": data["mrn_oid"],
        "address":data.get("address"),
        "date_of_birth":data.get("date_of_birth"),
        "created_by":user["sub"],
        "created_at":time.time(),
    }

    try:
        res = db.patients.insert_one(patient)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    patient["_id"] = str(res.inserted_id)
    return jsonify(patient), 201


@app.route("/patients", methods=["GET"])
@token_required
def list_patients(user):
    """
    GET /patients
    Return all patients (you can filter by created_by if you prefer).
    """
    docs = db.patients.find({})
    patients = []
    for p in docs:
        p["_id"] = str(p["_id"])
        patients.append(p)
    return jsonify(patients)


@app.route("/patients/<string:pid>", methods=["GET"])
@token_required
def get_patient(user,pid):
    """
    GET /patients/<pid>
    """
    try:
        p = db.patients.find_one({"_id": ObjectId(pid)})
    except:
        return jsonify({"error": "Invalid patient ID"}), 400

    if not p:
        return jsonify({"error": "Not found"}), 404

    p["_id"] = str(p["_id"])
    return jsonify(p)


@app.route("/patients/<string:pid>", methods=["PUT"])
@token_required
def update_patient(user,pid):
    """
    PUT /patients/<pid>
    Body may include any of: first_name, last_name, email, phone, address, date_of_birth
    """
    data = request.get_json(force=True)
    allowed = {"first_name","last_name","email","phone","address","date_of_birth"}
    update = {k: v for k, v in data.items() if k in allowed}

    if not update:
        return jsonify({"error": "No valid fields to update"}), 400

    try:
        res = db.patients.update_one(
            {"_id": ObjectId(pid)},
            {"$set": update}
        )
    except:
        return jsonify({"error": "Invalid patient ID"}), 400

    if res.matched_count == 0:
        return jsonify({"error": "Not found"}), 404

    p = db.patients.find_one({"_id": ObjectId(pid)})
    p["_id"] = str(p["_id"])
    return jsonify(p)


@app.route("/patients/<string:pid>", methods=["DELETE"])
@token_required
def delete_patient(user,pid):
    """
    DELETE /patients/<pid>
    """
    try:
        res = db.patients.delete_one({"_id": ObjectId(pid)})
    except:
        return jsonify({"error": "Invalid patient ID"}), 400

    if res.deleted_count == 0:
        return jsonify({"error": "Not found"}), 404

    return jsonify({"message": "Patient deleted"}), 200


# Inside app.py
# @app.route("/forms")
# def get_forms():
#     if "docusign_access_token" not in session:
#         return jsonify(error="Not authenticated"), 401
#     forms = list_web_forms(session["docusign_access_token"],
#                            session["docusign_account_id"])
#     # Return only the fields you need
#     return jsonify([
#         {"id": f.form_id, "name": f.name}
#         for f in forms.form_summaries or []
#     ])

@app.route("/success")
def success():
    # This page is redirected to from DocuSign after signing (if configured in returnUrl)
    # It confirms the user completed the DocuSign part of the flow.
    client_user_id = request.args.get("client_user_id")
    event = request.args.get("event") # DocuSign appends event query param (e.g., signing_complete)
    envelope_id_returned = request.args.get("envelopeId") # DocuSign might return this

    logger.info(f"Success/Return URL accessed. Event: {event}, ClientUserID: {client_user_id}, EnvelopeID: {envelope_id_returned}, SessionID: {session.sid}")

    # You might want to trigger a status check here using envelope_id_returned if available,
    # or update UI based on the event.
    message = f"DocuSign process event: {event or 'completed'}."
    if client_user_id:
         message += f" Associated User ID: {client_user_id}."
    if envelope_id_returned:
         message += f" Envelope ID: {envelope_id_returned}."
         # Optionally store the envelope ID in the session now if needed later
         # session['last_envelope_id'] = envelope_id_returned

    # Clear specific session data if the flow is considered complete for this instance
    # session.pop("instance_url", None)
    # session.pop("client_user_id", None)

    return jsonify({"message": message, "status": event}) # Return the event status
@app.route("/logout")
def logout():
    session.clear()
    return jsonify({"message": "You have been logged out"})

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"error": str(e)}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    # For local testing. When deploying with Zappa, use the WSGI adapter.
    app.run(debug=True, port=8080)
