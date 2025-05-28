from flask import Flask, redirect, url_for, session, request, render_template
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from flask_sqlalchemy import SQLAlchemy
import base64, re, os, html, datetime

app = Flask(__name__)
app.secret_key = '24ce13f884f9c0ef0ff9e58a22d32aec'

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

GOOGLE_CLIENT_SECRETS_FILE = 'credentials.json'
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'openid'
]
REDIRECT_URI = 'http://3.83.139.121.nip.io:8080/callback'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://admin:zellemail1!@database-2.cfuhl0d69zyn.us-east-1.rds.amazonaws.com:3306/zelleDatabase'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    UserID = db.Column(db.Integer, primary_key=True)
    GoogleID = db.Column(db.String(255), unique=True, nullable=False)
    FullName = db.Column(db.String(255))
    Email = db.Column(db.String(255), unique=True, nullable=False)
    CreatedAt = db.Column(db.DateTime, default=db.func.current_timestamp())

class Transaction(db.Model):
    __tablename__ = 'transactions'
    TransactionID = db.Column(db.Integer, primary_key=True)
    UserID = db.Column(db.Integer, db.ForeignKey('users.UserID'))
    Direction = db.Column(db.Enum('sent', 'received'))
    Amount = db.Column(db.Float)
    CounterpartyName = db.Column(db.String(255))
    Date = db.Column(db.DateTime)
    SubjectLine = db.Column(db.String(500))
    RawGmailID = db.Column(db.String(255))

class OverallSummary(db.Model):
    __tablename__ = 'overall_summaries'
    SummaryID = db.Column(db.Integer, primary_key=True)
    UserID = db.Column(db.Integer, db.ForeignKey('users.UserID'))
    StartDate = db.Column(db.Date)
    EndDate = db.Column(db.Date)
    TotalSent = db.Column(db.Float, default=0.0)
    TotalReceived = db.Column(db.Float, default=0.0)
    GeneratedAt = db.Column(db.DateTime, default=db.func.current_timestamp())

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    flow = Flow.from_client_secrets_file(GOOGLE_CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    auth_url, _ = flow.authorization_url(prompt='consent')
    return redirect(auth_url)

@app.route('/callback')
def callback():
    try:
        flow = Flow.from_client_secrets_file(GOOGLE_CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI)
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
        user_service = build('oauth2', 'v2', credentials=credentials)
        user_info = user_service.userinfo().get().execute()

        user = User.query.filter_by(GoogleID=user_info['id']).first()
        if not user:
            user = User(GoogleID=user_info['id'], FullName=user_info['name'], Email=user_info['email'])
            db.session.add(user)
            db.session.commit()

        session['user_id'] = user.UserID
        return redirect(url_for('summary_time'))
    except Exception as e:
        return f"<h2>Login Error</h2><pre>{e}</pre>"

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
    query = f'after:{start_date} before:{end_date} ("You received money" OR "You sent money")'
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    user_id = session['user_id']

    total_sent = 0.0
    total_received = 0.0

    for msg in messages:
        try:
            msg_id = msg['id']
            msg_detail = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
            payload = msg_detail.get('payload', {})
            headers = payload.get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
            body_data = ''

            if 'parts' in payload:
                for part in payload['parts']:
                    if part.get('mimeType') == 'text/html':
                        body_data = part['body'].get('data', '')
                        break
            else:
                body_data = payload.get('body', {}).get('data', '')

            if body_data:
                body_data = base64.urlsafe_b64decode(body_data.encode()).decode('utf-8', errors='ignore')

            amount_match = re.search(r"\$\d+(?:\.\d{2})?", body_data)
            amount = float(amount_match.group()[1:]) if amount_match else 0.0

            direction = 'received' if 'received' in subject.lower() else 'sent'
            if direction == 'received':
                total_received += amount
            else:
                total_sent += amount

            date_match = re.search(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4}", body_data)
            parsed_date = datetime.datetime.strptime(date_match.group(), "%b %d, %Y") if date_match else datetime.datetime.utcnow()

            db.session.add(Transaction(
                UserID=user_id,
                Direction=direction,
                Amount=amount,
                CounterpartyName=None,
                Date=parsed_date,
                SubjectLine=subject,
                RawGmailID=msg_id
            ))
        except Exception as e:
            print(f"Error processing message {msg_id}: {e}")

    db.session.commit()

    db.session.add(OverallSummary(
        UserID=user_id,
        StartDate=start_date,
        EndDate=end_date,
        TotalSent=total_sent,
        TotalReceived=total_received
    ))
    db.session.commit()

    summary = f"Found {len(messages)} Zelle message(s) between {start_date} and {end_date}."
    return render_template('summary_result.html', summary=summary)

@app.route('/init_db')
def init_db():
    db.create_all()
    return "Database tables created!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)

