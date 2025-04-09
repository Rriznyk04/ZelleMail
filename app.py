from flask import Flask, redirect, url_for, session, request, render_template
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials


import os

app = Flask(__name__)
app.secret_key = '24ce13f884f9c0ef0ff9e58a22d32aec'

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

    return redirect(url_for('summary_time'))


@app.route('/summary_time')
def summary_time():
    if 'credentials' not in session:
        return redirect(url_for('index'))
    return render_template('summary_time.html')


@app.route('/generate_summary', methods=['POST'])
def generate_summary():
    if 'credentials' not in session:
        return redirect(url_for('index'))

    creds = session['credentials']
    service = build('gmail', 'v1', credentials=Credentials(**creds))

    start_date = request.form['start_date']
    end_date = request.form['end_date']

    # Gmail format is YYYY/MM/DD
    gmail_query = f'after:{start_date} before:{end_date} ("You received money" OR "You sent money")'
    results = service.users().messages().list(userId='me', q=gmail_query).execute()
    messages = results.get('messages', [])

    summary = f"Found {len(messages)} Zelle message(s) between {start_date} and {end_date}."

    return render_template('summary_result.html', summary=summary)


if __name__ == '__main__':
    app.run(ssl_context=('https.crt', 'https.key'), debug=True)
