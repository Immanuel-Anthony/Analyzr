import sys
import re
from pathlib import Path
from crew import Codesystem  # Ensure this import points to the correct path for Codesystem
from docx import Document  # Import the python-docx library
import git
import tempfile
import os
from dotenv import load_dotenv  # Import dotenv for .env file loading

# Load environment variables from .env
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY is not set. Please define it in your .env file.")

def clone_github_repo(github_url):
    """
    Clone a GitHub repository and return the local path.
    """
    temp_dir = tempfile.mkdtemp()
    try:
        git.Repo.clone_from(github_url, temp_dir)
        return temp_dir
    except Exception as e:
        raise Exception(f"Error cloning repository: {e}")

def get_code_files(repo_path):
    """
    Recursively get all code files from the repository.
    """
    code_extensions = {'.py', '.js', '.java', '.cpp', '.c', '.h', '.hpp', '.cs', '.rb', '.go', '.rs', '.php'}
    code_files = []
    
    for root, _, files in os.walk(repo_path):
        for file in files:
            file_path = Path(root) / file
            if file_path.suffix in code_extensions:
                code_files.append(file_path)
    
    return code_files

def read_code_file(file_path):
    """
    Read code from a file.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        return f"Error reading file {file_path}: {e}"

def prepare_inputs(file_path, code_content, agent_outputs):
    """
    Prepare inputs for report generation with the real outputs.
    """
    return {
        'code_to_analyze': code_content,
        'file_name': str(file_path),
        'code_analysis_output': agent_outputs.get('code_analysis_output', 'No output available'),
        'security_analysis_output': agent_outputs.get('security_analysis_output', 'No output available'),
        'performance_analysis_output': agent_outputs.get('performance_analysis_output', 'No output available'),
        'code_test_coverage': agent_outputs.get('code_test_output', 'No output available'),
        'best_practices_output': agent_outputs.get('best_practices_output', 'No output available')
    }

def clean_text(text):
    """
    Cleans text by replacing escape sequences with appropriate formatting.
    """
    if not isinstance(text, str):
        text = str(text)
    text = re.sub(r'\\n', ' ', text)
    text = re.sub(r'\\t', '    ', text)
    text = re.sub(r'\n+', '\n', text)
    text = text.replace('\r', '')
    return text.strip()

def run_terminal(github_url=None, file_path=None):
    repo_path = None
    try:
        if github_url is None and file_path is None:
            raise ValueError("Please provide either a GitHub URL or a path to the code file")
        
        codesystem = Codesystem()
        
        if github_url:
            # Clone the repository
            repo_path = clone_github_repo(github_url)
            
            # Get all code files
            code_files = get_code_files(repo_path)
            
            # Process each file
            for file_path in code_files:
                print(f"\nProcessing: {file_path}")
                code_content = read_code_file(file_path)
                
                if code_content:
                    initial_inputs = {
                        'code_to_analyze': code_content,
                        'file_name': str(file_path)
                    }
                    
                    # Process the file
                    result = codesystem.kickoff(inputs=initial_inputs)
                    print(f"Result for {file_path}: {result}")
        else:
            # Original single file processing
            file_path = Path(file_path)
            code_content = read_code_file(file_path)
            if not code_content:
                raise ValueError(f"Unable to read the file: {file_path}")
            initial_inputs = {
                'code_to_analyze': code_content,
                'file_name': str(file_path)
            }
            result = codesystem.kickoff(inputs=initial_inputs)
            print(f"Result for {file_path}: {result}")
        
    finally:
        # Cleanup temporary directory with error handling
        if repo_path and os.path.exists(repo_path):
            import shutil
            try:
                shutil.rmtree(repo_path, ignore_errors=True)
            except Exception as e:
                print(f"Warning: Could not fully remove temporary directory {repo_path}. You may need to remove it manually.")
                print(f"Error details: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <github_url_or_file_path>")
        sys.exit(1)

    input_path = sys.argv[1]
    if input_path.startswith(('http://', 'https://', 'git://')):
        run_terminal(github_url=input_path)
    else:
        run_terminal(file_path=input_path)
