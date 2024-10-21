"""
Title: Chair Demon

Desc: Scan XSS Cross Site Scripting vulnerability across github.

Date: Oct 21 2024
===
Copyright (C) Ujjawal K. Panchal
"""
import os
import dotenv
import requests

dotenv.load_dotenv()

# GitHub personal access token (replace with your token)
TOKEN = os.getenv('TOKEN')#'your_github_token_here'
# GitHub API base URL
BASE_URL = os.getenv('BASE_URL')#'https://api.github.com/search/code'

# Headers for the API request with token for authentication
HEADERS = {
    'Authorization': f'token {TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

# Function to search for code patterns on GitHub
def search_github_code(query, language='javascript', per_page=10):
    params = {
        'q': f'{query} language:{language}',
        'per_page': per_page,
    }
    response = requests.get(BASE_URL, headers=HEADERS, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

# Function to check for XSS patterns
def find_potential_xss_vulnerabilities():
    # Common XSS-prone patterns in JavaScript
    patterns = [
        'innerHTML',
        'document.write',
        'outerHTML',
        'eval(',
        'setTimeout(',
        'setInterval(',
    ]
    
    for pattern in patterns:
        print(f"Searching for potential XSS vulnerabilities using pattern: {pattern}")
        result = search_github_code(query=pattern)
        if result:
            print(f"Found {len(result['items'])} results for pattern: {pattern}")
            for item in result['items']:
                repo_name = item['repository']['full_name']
                file_name = item['name']
                file_url = item['html_url']
                print(f"- Repo: {repo_name}, File: {file_name}, URL: {file_url}")
        print("\n" + "="*50 + "\n")

if __name__ == "__main__":
    find_potential_xss_vulnerabilities()