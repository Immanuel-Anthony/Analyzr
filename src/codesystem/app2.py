from flask import Flask, render_template, request, jsonify, redirect, session, url_for, send_file
from functools import wraps
import requests
import os
from dotenv import load_dotenv
from main import run_terminal  # Ensure the import path is correct
import tempfile
from pathlib import Path
import shutil

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')  # Change this in production

# GitHub OAuth Configuration
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
GITHUB_REDIRECT_URI = os.getenv('GITHUB_REDIRECT_URI', 'http://localhost:5000/github-callback')

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
        return redirect(url_for('repositories'))
    return render_template('login.html')

@app.route('/github-login')
def github_login():
    github_auth_url = f'https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={GITHUB_REDIRECT_URI}&scope=repo'
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

    return redirect(url_for('repositories'))

@app.route('/repositories')
@login_required
def repositories():
    try:
        # Get the access token from the session
        access_token = session.get('github_token')
        if not access_token:
            return jsonify({'error': 'User not authenticated'}), 401

        # Fetch repositories
        response = requests.get(
            'https://api.github.com/user/repos',
            headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
        )

        if response.status_code != 200:
            return jsonify({'error': 'Failed to fetch repositories'}), response.status_code

        repositories = response.json()  # List of repositories

        return render_template('repositories.html', repos=repositories, user=session.get('user_data'))

    except Exception as e:
        return jsonify({'error': str(e)}), 500


import logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/analyze-repo', methods=['POST'])
@login_required
def analyze_repo():
    try:
        repo_url = request.form.get('repo_url')
        if not repo_url:
            return jsonify({'error': 'No repository URL provided'}), 400

        # Analyze the repository
        output_dir = tempfile.mkdtemp()
        try:
            run_terminal(github_url=repo_url)

            # Create a dummy report file for demonstration purposes
            report_path = Path(output_dir) / "report.txt"
            with open(report_path, 'w') as report_file:
                report_file.write(f"Analysis completed for repository: {repo_url}\n")

            # Move report to a static directory
            permanent_dir = Path('static/reports')
            permanent_dir.mkdir(parents=True, exist_ok=True)
            permanent_report_path = permanent_dir / report_path.name
            shutil.move(str(report_path), str(permanent_report_path))

            # Store the path in the session for downloading
            session['report_path'] = str(permanent_report_path)

            return jsonify({
                'status': 'success',
                'message': f'Analysis completed for {repo_url}.',
                'download_url': url_for('download_report')
            })
        finally:
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir, ignore_errors=True)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download-report')
@login_required
def download_report():
    try:
        report_path = session.get('report_path')
        if not report_path or not os.path.exists(report_path):
            return jsonify({'error': 'No report available for download'}), 400

        return send_file(
            report_path,
            as_attachment=True,
            download_name=os.path.basename(report_path)
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)


#Added repositories.html file to try and make a list of the repositories along with an analyze button. No frontend
#app2 is the testing version of the program
#DO NOT make changes to app.py . Use app2.py


#Fixes to be done
#Repositories needs a bit of frontend
#The download-report url is not being redirected to
#Download button not showing up , have to change the url manually
#No landing page in the new program
#Output is not proper. its downloading a text file, not a docx file
