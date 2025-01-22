from flask import Flask, render_template, request, jsonify, send_file, redirect, session, url_for
from crew import Codesystem
import os
from pathlib import Path
from main import run_terminal
from functools import wraps
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')  # Change this in production

# GitHub OAuth Configuration
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
GITHUB_REDIRECT_URI = os.getenv('GITHUB_REDIRECT_URI', 'http://localhost:5000/github-callback')

# Configure upload folder for reports
app.config['REPORTS_FOLDER'] = Path(__file__).parent / "reports"

def login_required(f):  
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'github_token' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login')
def login():
    if 'github_token' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/github-login')
def github_login():
    github_auth_url = f'https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={GITHUB_REDIRECT_URI}&scope=user:email'
    return redirect(github_auth_url)

@app.route('/github-callback')
def github_callback():
    code = request.args.get('code')
    if not code:
        return jsonify({'error': 'Code not received'}), 400

    # Exchange code for access token
    response = requests.post(
        'https://github.com/login/oauth/access_token',
        data={
            'client_id': GITHUB_CLIENT_ID,
            'client_secret': GITHUB_CLIENT_SECRET,
            'code': code,
            'redirect_uri': GITHUB_REDIRECT_URI
        },
        headers={'Accept': 'application/json'}
    )

    if response.status_code != 200:
        return jsonify({'error': 'Failed to get access token'}), 400

    access_token = response.json().get('access_token')
    if not access_token:
        return jsonify({'error': 'Access token not received'}), 400

    # Get user info
    user_response = requests.get(
        'https://api.github.com/user',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
    )

    if user_response.status_code != 200:
        return jsonify({'error': 'Failed to get user info'}), 400

    user_data = user_response.json()
    
    # Store in session
    session['github_token'] = access_token
    session['user_data'] = {
        'username': user_data.get('login'),
        'avatar_url': user_data.get('avatar_url'),
        'name': user_data.get('name')
    }

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    user_data = session.get('user_data', {})
    return render_template('index.html', user=user_data)

@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    try:
        github_url = request.form.get('github_url')
        if not github_url:
            return jsonify({'error': 'No GitHub URL provided'}), 400

        # Run the analysis
        result = run_terminal(github_url=github_url)
        
        # Get the latest report file
        reports_dir = app.config['REPORTS_FOLDER']
        if not reports_dir.exists():
            return jsonify({'error': 'No reports generated'}), 500
            
        report_files = list(reports_dir.glob('*.docx'))
        if not report_files:
            return jsonify({'error': 'No reports found'}), 500
            
        # Get the most recent report
        latest_report = max(report_files, key=lambda x: x.stat().st_mtime)
        
        return jsonify({
            'status': 'success',
            'message': 'Analysis completed successfully',
            'report_path': str(latest_report.name)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
@login_required
def download_report(filename):
    try:
        report_path = app.config['REPORTS_FOLDER'] / filename
        return send_file(
            str(report_path),
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)