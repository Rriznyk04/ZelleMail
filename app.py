from flask import Flask, redirect, url_for, session, request, render_template
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

import os

app = Flask(__name__)
app.secret_key = '24ce13f884f9c0ef0ff9e58a22d32aec'  # Replace with a secure key

# OAuth2 Config
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Only for local development
GOOGLE_CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
REDIRECT_URI = 'https://127.0.0.1:5000/callback'


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, _ = flow.authorization_url(prompt='consent')
    return redirect(auth_url)


@app.route('/callback')
def callback():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    return redirect(url_for('home'))


@app.route('/home')
def home():
    if 'credentials' not in session:
        return redirect(url_for('index'))

    creds = session['credentials']
    service = build('gmail', 'v1', credentials=Credentials(**creds))

    # Get the user's Gmail profile
    profile = service.users().getProfile(userId='me').execute()
    email_address = profile.get('emailAddress')

    return render_template('home.html', email=email_address)


if __name__ == '__main__':
    app.run(ssl_context=('https.crt', 'https.key'), debug=True)
