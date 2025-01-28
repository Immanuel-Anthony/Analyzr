from flask import Flask, render_template, request, jsonify, redirect, session, url_for, send_file
from functools import wraps
import requests
import os
from dotenv import load_dotenv
from datetime import datetime
from main import run_terminal  # Ensure the import path is correct
import tempfile
from pathlib import Path
import shutil
import threading
import time
import logging

# Load environment variables
load_dotenv()

# Dictionary to track analysis statuses
analysis_status = {}

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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

def analyze_repository(repo_name, repo_url):
    global analysis_status
    analysis_status[repo_name] = "in_progress"
    try:
        run_terminal(github_url=repo_url)
        analysis_status[repo_name] = "completed"
    except Exception as e:
        print(f"Error analyzing {repo_name}: {e}")
        analysis_status[repo_name] = "failed"

def get_latest_docx():
    """
    Find the most recently created .docx file in the reports directory
    """
    try:
        # Get the current file's directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Go directly to the reports directory
        reports_dir = os.path.join(current_dir, 'reports')
        
        logger.debug(f"Looking for .docx files in: {reports_dir}")
        
        if not os.path.exists(reports_dir):
            logger.error(f"Reports directory not found: {reports_dir}")
            return None
            
        docx_files = []
        # Walk through the reports directory
        for root, _, files in os.walk(reports_dir):
            for file in files:
                if file.endswith('.docx'):
                    full_path = os.path.join(root, file)
                    docx_files.append((full_path, os.path.getctime(full_path)))
                    logger.debug(f"Found docx file: {full_path}")
        
        if not docx_files:
            logger.warning("No .docx files found in reports directory")
            return None
        
        # Sort by creation time and get the most recent
        latest_file = max(docx_files, key=lambda x: x[1])[0]
        logger.info(f"Latest docx file found: {latest_file}")
        return latest_file
        
    except Exception as e:
        logger.error(f"Error in get_latest_docx: {str(e)}")
        return None

@app.route('/download-report')
@login_required
def download_report():
    try:
        latest_docx = get_latest_docx()
        
        if latest_docx is None:
            logger.error("No report file found")
            return "No report found", 404
            
        if not os.path.exists(latest_docx):
            logger.error(f"Report file does not exist: {latest_docx}")
            return "Report file not found", 404
            
        logger.info(f"Attempting to send file: {latest_docx}")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"code_analysis_report_{timestamp}.docx"
        
        try:
            return send_file(
                latest_docx,
                as_attachment=True,
                download_name=filename,
                mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            )
        except Exception as e:
            logger.error(f"Error sending file: {str(e)}")
            return f"Error sending file: {str(e)}", 500
            
    except Exception as e:
        logger.error(f"Error in download_report: {str(e)}")
        return f"Error downloading report: {str(e)}", 500


@app.route('/login')
def login():
    if 'github_token' in session:
        return redirect(url_for('repositories'))
    return render_template('login.html')

@app.route('/github-login')
def github_login():
    github_auth_url = f'https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={GITHUB_REDIRECT_URI}&scope=repo'
    return redirect(github_auth_url)

@app.route('/')
@login_required
def index():
    user_data = session.get('user_data', {})
    return render_template('index.html', user=user_data)


@app.route('/analyze_repo', methods=['POST'])
@login_required
def analyze_repo():
    data = request.json
    repo_url = data.get('repo_url')
    if not repo_url:
        return jsonify({'status': 'error', 'error': 'No repository URL provided'}), 400

    repo_name = repo_url.split('/')[-1].replace('.git', '')

    if repo_name not in analysis_status or analysis_status[repo_name] in ["not_started", "failed"]:
        try:
            # Pass repo_name and repo_url to the thread
            thread = threading.Thread(target=analyze_repository, args=(repo_name, repo_url))
            thread.start()
            return jsonify({'status': 'success', 'message': f'Analysis started for {repo_name}.'})
        except Exception as e:
            print(f"Error starting analysis thread: {e}")
            return jsonify({'status': 'error', 'error': 'Failed to start analysis'}), 500

    return jsonify({'status': 'error', 'error': 'Analysis already in progress or completed'}), 400


@app.route('/analyzing')
@login_required
def analyzing():
    repo_name = request.args.get('repo', 'repository')
    return render_template('analysis.html', repo_name=repo_name)

@app.route('/analysis-status')
@login_required
def analysis_status_endpoint():
    repo_name = request.args.get('repo')
    status = analysis_status.get(repo_name, "not_started")
    return jsonify({"status": status})

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

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
