import os
import logging
import tempfile
from flask import Flask, request, redirect, url_for, session, jsonify, send_file
from werkzeug.utils import secure_filename
from docusign_integration import (
    get_consent_url,
    get_access_token,
    create_envelope,
    get_envelope_recipients,
    get_document_for_signing,
    get_envelope_status,
    download_signed_document,
)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

# Allowed file extensions
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt"}

# Ensure upload directory exists
UPLOAD_FOLDER = tempfile.mkdtemp()
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max upload


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/")
def index():
    # Return the authentication status as a JSON response
    is_authenticated = "docusign_access_token" in session
    return jsonify({"authenticated": is_authenticated})


@app.route("/upload", methods=["POST"])
def upload():
    if "docusign_access_token" not in session:
        # Return 401 and a URL to authenticate if not logged in
        return (
            jsonify({
                "error": "Please authenticate with DocuSign first",
                "authorize_url": url_for("authorize", _external=True),
            }),
            401,
        )

    # For demonstration, using a fixed file from the samples directory.
    # Replace this with actual file upload handling if needed.
    filename = "pic_sub.pdf"
    filepath = os.path.join("samples", filename)

    recipient_name = request.form.get("recipient_name", "")
    recipient_email = request.form.get("recipient_email", "")

    try:
        # Create envelope with the document
        envelope_id = create_envelope(
            session["docusign_access_token"],
            session["docusign_account_id"],
            filepath,
            filename,
            recipient_name,
            recipient_email,
        )

        if envelope_id:
            # Store envelope info in session for later use
            session["envelope_id"] = envelope_id
            session["document_name"] = filename
            session["recipient_name"] = recipient_name
            session["recipient_email"] = recipient_email

            return jsonify({
                "envelope_id": envelope_id,
                "document_name": filename,
                "recipient_name": recipient_name,
                "recipient_email": recipient_email,
            })
        else:
            return jsonify({"error": "Failed to create envelope"}), 500
    except Exception as e:
        logger.error(f"Error creating envelope: {str(e)}")
        return jsonify({"error": f"Error creating envelope: {str(e)}"}), 500


@app.route("/sign")
def sign_document():
    if "envelope_id" not in session:
        return jsonify({
            "error": "No document to sign",
            "signing_url": "",
            "document_name": ""
        }), 400

    logger.info(f"Getting signing URL for envelope: {session['envelope_id']}")
    app_url = request.host
    logger.info(f"Current app URL: {app_url}")

    try:
        # Get the recipient view URL for signing
        recipient_view_url = get_document_for_signing(
            session["docusign_access_token"],
            session["docusign_account_id"],
            session["envelope_id"],
            session["recipient_email"],
            session["recipient_name"],
        )
        if recipient_view_url:
            return jsonify({
                "signing_url": recipient_view_url,
                "document_name": session["document_name"],
            })
        else:
            return jsonify({
                "error": "Failed to get signing URL",
                "signing_url": "",
                "document_name": ""
            }), 500
    except Exception as e:
        logger.error(f"Error getting signing URL: {str(e)}")
        return jsonify({"error": f"Error getting signing URL: {str(e)}"}), 500


@app.route("/authorize")
def authorize():
    # Generate the DocuSign consent URL and return it in JSON response.
    auth_url = get_consent_url()
    return jsonify({"auth_url": auth_url})


@app.route("/callback")
def callback():
    # Handle callback from DocuSign OAuth process.
    code = request.args.get("code")
    if not code:
        return jsonify({"error": "Authorization failed. No code received."}), 400

    try:
        # Exchange code for an access token
        token_info = get_access_token(code)
        if token_info and "access_token" in token_info and "account_id" in token_info:
            session["docusign_access_token"] = token_info["access_token"]
            session["docusign_account_id"] = token_info["account_id"]
            return jsonify({
                "message": "Successfully authenticated with DocuSign!",
                "access_token": token_info["access_token"],
            })
        else:
            return jsonify({"error": "Failed to get access token from DocuSign"}), 500
    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        return jsonify({"error": f"Authentication error: {str(e)}"}), 500


@app.route("/status")
def check_status():
    if "envelope_id" not in session or "docusign_access_token" not in session:
        return jsonify({"error": "No active signing session"}), 400

    try:
        # Get envelope status
        status = get_envelope_status(
            session["docusign_access_token"],
            session["docusign_account_id"],
            session["envelope_id"],
        )

        if status == "completed":
            return jsonify({"message": "Document has been signed!", "status": status})
        else:
            return jsonify({"message": f"Document status: {status}", "status": status})
    except Exception as e:
        logger.error(f"Error checking status: {str(e)}")
        return jsonify({"error": f"Error checking status: {str(e)}"}), 500


@app.route("/download")
def download():
    if "envelope_id" not in session or "docusign_access_token" not in session:
        return jsonify({"error": "No document to download"}), 400

    try:
        # Download the signed document
        doc_path = download_signed_document(
            session["docusign_access_token"],
            session["docusign_account_id"],
            session["envelope_id"],
        )

        if doc_path:
            return send_file(
                doc_path,
                as_attachment=True,
                download_name=f"signed_{session.get('document_name', 'document')}",
                mimetype="application/pdf",
            )
        else:
            return jsonify({"error": "Failed to download document"}), 500
    except Exception as e:
        logger.error(f"Error downloading document: {str(e)}")
        return jsonify({"error": f"Error downloading document: {str(e)}"}), 500


@app.route("/success")
def success():
    if "envelope_id" not in session:
        return jsonify({"error": "No success information available"}), 400
    return jsonify({"message": "Document signing process completed successfully!"})


@app.route("/logout")
def logout():
    # Clear session data and return success message.
    session.clear()
    return jsonify({"message": "You have been logged out"})


# JSON error handlers
@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"error": str(e)}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # For local testing only. When deploying on Lambda, use a WSGI adapter like Zappa or AWS Serverless WSGI.
    app.run(debug=True, port=8080)
