import os
import re
import base64
import requests
import Levenshtein
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import json # <-- NEW IMPORT
from fastapi import FastAPI, Request, Response, BackgroundTasks # <-- NEW IMPORT
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import firebase_admin
from firebase_admin import credentials, firestore

# --- Configuration ---
app = FastAPI()

# --- 1. Firebase Admin Setup ---
try:
    cred = credentials.Certificate("firebase-service-key.json")
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print("Firebase Admin SDK initialized successfully.")
except Exception as e:
    print(f"CRITICAL ERROR: Could not initialize Firebase Admin. Is 'firebase-service-key.json' in the folder? Error: {e}")
    db = None

# --- 2. Session Cookie Setup ---
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", "default_secret_key_for_local_testing")
signer = URLSafeTimedSerializer(SESSION_SECRET_KEY)
SESSION_COOKIE_NAME = "phishshield_session"

# --- 3. Google OAuth Setup ---
CLIENT_SECRETS_FILE = "client_secret.json" 
REDIRECT_URI = "https://phishshield-aai6.onrender.com/auth/callback" 
TOPIC_NAME = "projects/phishshield-main-477212/topics/gmail-push" # <-- NEW: Your "Pager" name

SCOPES = sorted([
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/gmail.readonly' # This scope is enough for watch()
])

try:
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
except FileNotFoundError:
    print("CRITICAL ERROR: 'client_secret.json' not found.")
    flow = None

# --- 4. College-Specific & API Keys ---
COLLEGE_TRUSTED_DOMAINS = { "srmist.edu.in" }
SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# --- 5. Helper Functions (Unchanged) ---
def get_domain_from_email(sender_email):
    match = re.search(r'<(.+?)>', sender_email)
    email = match.group(1) if match else sender_email.strip()
    try:
        return email.split('@')[1]
    except IndexError:
        return None
def get_sender_name(sender_email):
    return sender_email.split('<')[0].strip().replace('"', '')
def get_domain_from_url(url):
    try:
        return urlparse(url).netloc.replace('www.', '')
    except Exception:
        return None
def get_email_body(msg_payload):
    if 'parts' in msg_payload:
        for part in msg_payload['parts']:
            if part['mimeType'] == 'text/html':
                return part['body'].get('data')
            if part['mimeType'] == 'text/plain':
                return part['body'].get('data')
            body_data = get_email_body(part)
            if body_data:
                return body_data
    elif 'body' in msg_payload and msg_payload['body'].get('data'):
        return msg_payload['body'].get('data')
    return None
def extract_links_and_text(body_data):
    if not body_data:
        return []
    links_data = []
    try:
        decoded_data = base64.urlsafe_b64decode(body_data).decode('utf-8')
        soup = BeautifulSoup(decoded_data, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            link_url = a_tag['href']
            link_text = a_tag.get_text().strip()
            if link_url.startswith('http'):
                links_data.append((link_text, link_url))
        raw_links = re.findall(r'https://?[^\s"<>\']+', decoded_data)
        for raw_link in raw_links:
            links_data.append(("Raw Link", raw_link))
        return list(set(links_data))
    except Exception as e:
        print(f"Error decoding body or extracting links: {e}")
        return []

# --- 6. Security Analysis Functions (Unchanged) ---
def check_external_apis(links_to_check):
    if not links_to_check or not SAFE_BROWSING_API_KEY: 
        if not SAFE_BROWSING_API_KEY: print("Warning: SAFE_BROWSING_API_KEY is not set. Skipping API check.")
        return {}
    
    payload = {
        "client": {"clientId": "phishshield", "clientVersion": "2.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": link} for link in links_to_check]
        }
    }
    params = {'key': SAFE_BROWSING_API_KEY}
    api_threats = {}
    try:
        response = requests.post(SAFE_BROWSING_URL, json=payload, params=params)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data:
                for match in data["matches"]:
                    reason = f"Flagged as {match['threatType']} by Google"
                    api_threats[match["threat"]["url"]] = reason
        else:
            print(f"Error from Safe Browsing API: {response.text}")
    except requests.RequestException as e:
        print(f"Request error checking links: {e}")
    return api_threats
def check_sender_impersonation(sender_email, sender_name, sender_domain):
    if not sender_domain: return None
    if sender_domain in COLLEGE_TRUSTED_DOMAINS:
        return {"status": "verified", "reason": f"College Verified: Sender is from trusted domain '{sender_domain}'."}
    for trusted_domain in COLLEGE_TRUSTED_DOMAINS:
        dist = Levenshtein.distance(sender_domain, trusted_domain)
        if 0 < dist <= 2:
            return {"status": "danger", "reason": f"Impersonation Alert: Sender domain '{sender_domain}' is suspiciously similar to trusted domain '{trusted_domain}'."}
    college_name_keywords = ["srmist", "srm", "registrar", "it support", "admin"]
    for keyword in college_name_keywords:
        if keyword in sender_name.lower():
            return {"status": "danger", "reason": f"Impersonation Alert: Sender name is '{sender_name}' but is from untrusted domain '{sender_domain}'."}
    return None
def check_link_mismatch_and_ips(links_data):
    for link_text, link_url in links_data:
        if re.match(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', link_url):
            return {"status": "danger", "reason": f"Dangerous Link: Link '{link_url[:30]}...' is a raw IP address."}
        if link_text == "Raw Link" or not link_text:
            continue
        link_text_domain = get_domain_from_url("http://" + link_text.split('/')[0])
        link_url_domain = get_domain_from_url(link_url)
        if not link_text_domain or not link_url_domain:
            continue
        if ('.com' in link_text_domain or '.edu' in link_text_domain or '.org' in link_text_domain) and (link_text_domain != link_url_domain):
            return {"status": "danger", "reason": f"Link-Text Mismatch: Link says it's '{link_text_domain}' but actually goes to '{link_url_domain}'."}
    return None

# --- 7. Auth Helper Functions ---
async def get_current_user_id(request: Request):
    session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_cookie:
        return None
    try:
        user_id = signer.loads(session_cookie, max_age=86400 * 14)
        return user_id
    except (BadSignature, SignatureExpired):
        return None

# --- NEW: Helper function to start the Gmail watch ---
def start_watch_on_gmail(creds):
    """
    Tells Gmail to start sending "pings" for this user to our Pub/Sub topic.
    """
    try:
        service = build('gmail', 'v1', credentials=creds)
        request = {
            'labelIds': ['INBOX'], # Watch the Inbox
            'topicName': TOPIC_NAME  # Send pings to our "pager"
        }
        # This is the one-time API call that "subscribes" the user
        response = service.users().watch(userId='me', body=request).execute()
        print(f"Gmail watch started successfully for user. History ID: {response['historyId']}")
        return response
    except HttpError as error:
        # This will happen if the watch is already active, which is fine.
        print(f"An error occurred starting the watch: {error}")
        return None

# --- 8. FastAPI Endpoints (Main app) ---
@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open("phishshield.html") as f:
        return HTMLResponse(content=f.read(), status_code=200)

@app.get("/api/get_login_url")
async def get_login_url():
    if not flow:
        return JSONResponse({'error': 'OAuth client_secret.json not found'}, status_code=500)
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent' # This is CRITICAL to get a refresh_token
    )
    response = JSONResponse({'url': authorization_url})
    response.set_cookie(key="oauth_state", value=state, max_age=600, httponly=True)
    return response

@app.get("/api/check_auth", response_class=JSONResponse)
async def check_auth(request: Request):
    user_id = await get_current_user_id(request)
    if user_id:
        return JSONResponse({'logged_in': True})
    return JSONResponse({'logged_in': False})

@app.get("/auth/callback")
async def auth_callback(request: Request):
    """
    This is the redirect URI.
    *** UPDATED: Now also starts the Gmail watch ***
    """
    state = request.cookies.get("oauth_state")
    if not state:
        return RedirectResponse(url='/')
    
    if not flow or not db:
        return RedirectResponse(url='/?error=server_not_configured')

    try:
        # --- THE HTTPS FIX ---
        auth_response_url = str(request.url)
        if auth_response_url.startswith("http://"):
            auth_response_url = "https://" + auth_response_url[7:]
        # --- END OF FIX ---

        flow.fetch_token(
            authorization_response=auth_response_url, 
            state=state
        )
        creds = flow.credentials
        token_request = google_requests.Request()
        
        # --- THE CLOCK SKEW FIX ---
        id_info = id_token.verify_oauth2_token(
            creds.id_token, 
            token_request, 
            flow.client_config['client_id'],
            clock_skew_in_seconds=10 
        )
        
        user_id = id_info['sub']
        user_email = id_info['email']
        
        if not creds.refresh_token:
            print("Warning: No refresh_token found. User may need to re-consent.")
        
        user_doc_ref = db.collection("users").document(user_id)
        user_data = {
            'email': user_email,
            'google_user_id': user_id
        }
        if creds.refresh_token:
            user_data['refresh_token'] = creds.refresh_token
        
        user_doc_ref.set(user_data, merge=True)
        print(f"User {user_id} ({user_email}) data saved to Firestore.")

        # --- NEW: START THE GMAIL WATCH ---
        # After we've saved the token, we tell Gmail to start "watching" this user.
        start_watch_on_gmail(creds)
        # --- END OF NEW PART ---

        session_cookie = signer.dumps(user_id)
        response = RedirectResponse(url='/')
        response.set_cookie(key=SESSION_COOKIE_NAME, value=session_cookie, httponly=True, max_age=86400 * 14)
        
        response.delete_cookie("oauth_state")
        return response

    except Exception as e:
        print(f"Error in auth_callback: {e}")
        return RedirectResponse(url='/?error=auth_failed')

@app.get("/api/logout")
async def logout():
    response = JSONResponse({'logged_out': True})
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response

# ... all your /api/get_emails and other functions are still here, unchanged ...
# (I've collapsed them for brevity, but they are identical to the last file)
@app.get("/api/get_emails")
async def get_emails(request: Request):
    user_id = await get_current_user_id(request)
    if not user_id:
        return JSONResponse({'error': 'Not authenticated. Please log in.'}, status_code=401)
    if not db or not flow:
        return JSONResponse({'error': 'Server not configured.'}, status_code=500)
    try:
        user_doc = db.collection("users").document(user_id).get()
        if not user_doc.exists:
            return JSONResponse({'error': 'User not found in database. Please re-login.'}, status_code=401)
        refresh_token = user_doc.to_dict().get('refresh_token')
        if not refresh_token:
            return JSONResponse({'error': 'No refresh token found. Please log out and log back in to re-grant permission.'}, status_code=403)
        creds = Credentials(
            token=None,
            refresh_token=refresh_token,
            token_uri=flow.client_config['token_uri'],
            client_id=flow.client_config['client_id'],
            client_secret=flow.client_config['client_secret'],
            scopes=SCOPES
        )
        creds.refresh(google_requests.Request())
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', maxResults=20, labelIds=['INBOX']).execute()
        messages = results.get('messages', [])
        if not messages:
            return JSONResponse({'emails': []})
        all_links_to_check = set()
        email_details = []
        for msg_summary in messages:
            msg = service.users().messages().get(userId='me', id=msg_summary['id'], format='full').execute()
            payload = msg.get('payload', {})
            headers = payload.get('headers', [])
            email_data = {'id': msg_summary['id'], 'snippet': msg.get('snippet', ''), 'sender': 'Unknown', 'subject': 'No Subject', 'links_data': []}
            for header in headers:
                if header['name'].lower() == 'from': email_data['sender'] = header['value']
                if header['name'].lower() == 'subject': email_data['subject'] = header['value']
            body_data = get_email_body(payload)
            email_data['links_data'] = extract_links_and_text(body_data)
            for _, link_url in email_data['links_data']:
                all_links_to_check.add(link_url)
            email_details.append(email_data)
        print(f"Checking {len(all_links_to_check)} unique links against external APIs...")
        api_threats = check_external_apis(list(all_links_to_check))
        print(f"Found {len(api_threats)} threats from APIs.")
        analyzed_emails = []
        for email in email_details:
            analysis = {"status": "safe", "reason": "This email passed all checks."}
            sender_name = get_sender_name(email['sender'])
            sender_domain = get_domain_from_email(email['sender'])
            impersonation_check = check_sender_impersonation(email['sender'], sender_name, sender_domain)
            if impersonation_check:
                analysis = impersonation_check
            if analysis['status'] == 'safe':
                link_tricks_check = check_link_mismatch_and_ips(email['links_data'])
                if link_tricks_check:
                    analysis = link_tricks_check
            if analysis['status'] == 'safe':
                for _, link_url in email['links_data']:
                    if link_url in api_threats:
                        analysis['status'] = 'danger'
                        analysis['reason'] = api_threats[link_url]
                        break
            if analysis['status'] == 'safe':
                 if "urgent" in email['snippet'].lower() and "password" in email['snippet'].lower():
                    analysis['status'] = 'danger'
                    analysis['reason'] = "Suspicious Keywords: Email contains 'urgent' and 'password'."
            email['status'] = analysis['status']
            email['reason'] = analysis['reason']
            analyzed_emails.append(email)
        return JSONResponse({'emails': analyzed_emails})
    except HttpError as error:
        print(f'An error occurred: {error}')
        if error.resp.status in [401, 403]:
            response = JSONResponse({'error': 'Authentication expired. Please log in again.'}, status_code=401)
            response.delete_cookie(SESSION_COOKIE_NAME)
            return response
        return JSONResponse({'error': str(error)}, status_code=500)
    except Exception as e:
        print(f'A general error occurred: {e}')
        return JSONResponse({'error': f'An error occurred: {e}'}, status_code=500)

# --- 9. BRAND NEW: The Webhook "Ears" Endpoint ---

async def process_webhook(payload: dict):
    """
    This is the "heavy lifting" function that runs in the background.
    For now, it just decodes and prints the ping.
    """
    try:
        # 1. Decode the message from Pub/Sub
        message_data = payload.get('message', {}).get('data')
        if not message_data:
            print("Webhook received, but no message data.")
            return

        decoded_data = base64.b64decode(message_data).decode('utf-8')
        message_json = json.loads(decoded_data)
        
        email_address = message_json.get('emailAddress')
        history_id = message_json.get('historyId')

        print("--- !!! NEW EMAIL PING RECEIVED !!! ---")
        print(f"Email: {email_address}")
        print(f"History ID: {history_id}")
        print("------------------------------------------")
        
        # --- FUTURE (Step 3E) ---
        # This is where we will add the code to:
        # 1. Find this user in Firestore by their email_address
        # 2. Use their refresh_token to build a new Gmail service
        # 3. Call service.users().history().list() to get the *new* email
        # 4. Run our *full analysis* on that new email
        # 5. If it's 'danger', save it to a new 'notifications' collection
        # 6. Send the Web Push Notification
        
    except Exception as e:
        print(f"Error processing webhook: {e}")


@app.post("/api/gmail-webhook")
async def gmail_webhook_receiver(request: Request, tasks: BackgroundTasks):
    """
    This is the "Ears". It receives the "ping" from Google Pub/Sub.
    It MUST return a 200-level response *immediately*.
    """
    print("Webhook ping received from Google...")
    try:
        # Get the request body as JSON
        payload = await request.json()
        
        # Add the *real* work to a background task
        # This lets us return 204 immediately while the work runs
        tasks.add_task(process_webhook, payload)
        
        # Return "Success, No Content"
        return JSONResponse(status_code=204)
        
    except Exception as e:
        print(f"Error in webhook receiver: {e}")
        # If something goes wrong, still tell Google "OK" so it doesn't retry
        return JSONResponse(status_code=204)
