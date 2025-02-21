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
report_files = {}

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
    global analysis_status, report_files
    analysis_status[repo_name] = "in_progress"
    logger.debug(f"Starting analysis for {repo_name} with URL {repo_url}")
    
    try:
        run_terminal(github_url=repo_url)
        # After analysis is complete, store the latest report file
        latest_docx = get_latest_docx()
        logger.debug(f"Analysis complete. Latest report file: {latest_docx}")
        
        if latest_docx:
            report_files[repo_name] = latest_docx
            logger.debug(f"Stored report path {latest_docx} for repo {repo_name}")
        else:
            logger.error(f"No report file found after analysis for {repo_name}")
            
        logger.debug(f"Current report_files dictionary: {report_files}")
        analysis_status[repo_name] = "completed"
        
    except Exception as e:
        logger.error(f"Error analyzing {repo_name}: {e}")
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

@app.route('/analyzing')
@login_required
def analyzing():
    repo_name = request.args.get('repo', 'repository')
    return render_template('analysis.html', repo_name=repo_name)

@app.route('/analyzing-guest')
def analyzing_guest():
    repo_name = request.args.get('repo', 'repository')
    return render_template('guest_analysis.html', repo_name=repo_name)

@app.route('/download-report')
def download_report():
    try:
        repo_name = request.args.get('repo')
        logger.debug(f"Requested report for repo: {repo_name}")
        
        if not repo_name:
            logger.error("No repository name provided")
            return "Repository name not provided", 400

        report_path = report_files.get(repo_name)
        
        if not report_path:
            logger.error(f"No report found for repository: {repo_name}")
            return "No report found for this repository", 404

        if not os.path.exists(report_path):
            logger.error(f"Report file does not exist: {report_path}")
            return "Report file not found", 404

        filename = f"{repo_name}_Analysis.docx"
        
        response = send_file(
            report_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        )
        
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    except Exception as e:
        logger.error(f"Error in download_report: {str(e)}")
        return f"Error downloading report: {str(e)}", 500

@app.route('/login')
def login():
    if 'github_token' in session:
        return redirect(url_for('repositories'))
    return render_template('index.html')

# @app.route('/github-login')
# def github_login():
#     github_auth_url = f'https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={GITHUB_REDIRECT_URI}&scope=repo'
#     return redirect(github_auth_url)

@app.route('/')
@login_required
def index():
    user_data = session.get('user_data', {})
    return render_template('index.html', user=user_data)


# Keep the existing authenticated route
@app.route('/analyze_repo', methods=['POST'])
@login_required
def analyze_repo():
    data = request.json
    repo_url = data.get('repo_url')
    if not repo_url:
        return jsonify({'status': 'error', 'error': 'No repository URL provided'}), 400

    repo_name = repo_url.split('/')[-1].replace('.git', '')

    # Check if repo has already been analyzed and has a report
    if repo_name in report_files and os.path.exists(report_files[repo_name]):
        return jsonify({
            'status': 'already_analyzed',
            'message': 'Repository was previously analyzed',
            'repo_name': repo_name
        })

    # If repo is currently being analyzed
    if repo_name in analysis_status and analysis_status[repo_name] == "in_progress":
        return jsonify({
            'status': 'in_progress',
            'message': 'Analysis already in progress',
            'repo_name': repo_name
        })

    # Start new analysis
    try:
        thread = threading.Thread(target=analyze_repository, args=(repo_name, repo_url))
        thread.start()
        return jsonify({
            'status': 'started',
            'message': f'Analysis started for {repo_name}.',
            'repo_name': repo_name
        })
    except Exception as e:
        print(f"Error starting analysis thread: {e}")
        return jsonify({'status': 'error', 'error': 'Failed to start analysis'}), 500

# Add new route for guest analysis
@app.route('/analyze_guest', methods=['POST'])
def analyze_guest():
    data = request.json
    repo_url = data.get('repo_url')
    if not repo_url:
        return jsonify({'status': 'error', 'error': 'No repository URL provided'}), 400

    # Basic validation of GitHub URL
    if 'github.com/' not in repo_url:
        return jsonify({'status': 'error', 'error': 'Invalid GitHub repository URL'}), 400

    repo_name = repo_url.split('/')[-1].replace('.git', '')

    # Check if repo has already been analyzed and has a report
    if repo_name in report_files and os.path.exists(report_files[repo_name]):
        return jsonify({
            'status': 'already_analyzed',
            'message': 'Repository was previously analyzed',
            'repo_name': repo_name
        })

    # If repo is currently being analyzed
    if repo_name in analysis_status and analysis_status[repo_name] == "in_progress":
        return jsonify({
            'status': 'in_progress',
            'message': 'Analysis already in progress',
            'repo_name': repo_name
        })

    # Start new analysis
    try:
        thread = threading.Thread(target=analyze_repository, args=(repo_name, repo_url))
        thread.start()
        return jsonify({
            'status': 'started',
            'message': f'Analysis started for {repo_name}.',
            'repo_name': repo_name
        })
    except Exception as e:
        print(f"Error starting analysis thread: {e}")
        return jsonify({'status': 'error', 'error': 'Failed to start analysis'}), 500



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
         return redirect(url_for('index'))

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


@app.route('/github-login')
def github_login():
    github_auth_url = (
        f'https://github.com/login/oauth/authorize'
        f'?client_id={GITHUB_CLIENT_ID}'
        f'&redirect_uri={GITHUB_REDIRECT_URI}'
        f'&scope=repo'
        f'&prompt=consent'  # This forces GitHub to show the authorization screen again
    )
    return redirect(github_auth_url)


@app.route('/logout')
def logout():
    # Get the access token before clearing session
    access_token = session.get('github_token')
    
    if access_token:
        try:
            # Revoke the GitHub OAuth token
            requests.delete(
                f'https://api.github.com/applications/{GITHUB_CLIENT_ID}/token',
                auth=(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET),
                headers={'Accept': 'application/vnd.github.v3+json'},
                json={'access_token': access_token}
            )
        except Exception as e:
            print(f"Error revoking token: {e}")
    
    # Clear all session data
    session.clear()
    
    # Redirect to login page with a cache-busting parameter
    return redirect(url_for('login', t=int(time.time())))


# @app.route('/github-callback')
# def github_callback():
#     # First check if user denied access
#     if 'error' in request.args:
#         error_message = request.args.get('error_description', 'Authorization was denied')
#         # Redirect back to login page with an error message
#         return redirect(url_for('login', error=error_message))

#     code = request.args.get('code')
#     if not code:
#         return redirect(url_for('login', error='Authorization failed'))

#     # Rest of the existing callback code...
#     response = requests.post(
#         'https://github.com/login/oauth/access_token',
#         data={
#             'client_id': GITHUB_CLIENT_ID,
#             'client_secret': GITHUB_CLIENT_SECRET,
#             'code': code,
#             'redirect_uri': GITHUB_REDIRECT_URI
#         },
#         headers={'Accept': 'application/json'}
#     )

#     if response.status_code != 200:
#         return redirect(url_for('login', error='Failed to get access token'))

#     access_token = response.json().get('access_token')
#     if not access_token:
#         return redirect(url_for('login', error='Access token not received'))

#     # Get user info
#     user_response = requests.get(
#         'https://api.github.com/user',
#         headers={
#             'Authorization': f'Bearer {access_token}',
#             'Accept': 'application/json'
#         }
#     )

#     if user_response.status_code != 200:
#         return redirect(url_for('login', error='Failed to get user info'))

#     user_data = user_response.json()
    
#     # Store in session
#     session['github_token'] = access_token
#     session['user_data'] = {
#         'username': user_data.get('login'),
#         'avatar_url': user_data.get('avatar_url'),
#         'name': user_data.get('name')
#     }

#     return redirect(url_for('repositories'))


if __name__ == '__main__':
    app.run(debug=True)
