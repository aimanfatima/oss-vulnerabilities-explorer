"""
Title: columbus the Explorer

Desc: Scan XSS Cross Site Scripting vulnerability across GitHub.

Date: Oct 21 2024
===
Copyright (C) Ujjawal K. Panchal
"""

import os
import dotenv
import requests

dotenv.load_dotenv()

class Columbus:
    def __init__(self, token=None, base_url=None, raw_base_url=None, results_per_search=10, language = 'javascript'):
        """
        Initialize the Columbus class with the required configurations.
        """
        self.TOKEN = token or os.getenv('TOKEN')  # GitHub personal access token
        self.BASE_URL = base_url or os.getenv('BASE_URL')  # GitHub API base URL
        self.RAW_BASE_URL = raw_base_url or 'https://raw.githubusercontent.com/'  # Raw URL for file content
        self.results_per_search = results_per_search
        self.language = 'javascript'
        self.HEADERS = {
            'Authorization': f'token {self.TOKEN}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.patterns = {
            'innerHTML': {
                'description': 'innerHTML allows direct injection of untrusted input into the DOM, enabling attackers to insert malicious scripts.',
            },
            'document.write': {
                'description': 'document.write injects content into the DOM, which can be exploited to add malicious JavaScript code.',
            },
            'outerHTML': {
                'description': 'outerHTML injects HTML into the DOM, allowing attackers to replace elements with malicious code.',
            },
            'eval(': {
                'description': 'eval() executes strings as JavaScript code, making it highly susceptible to code injection.',
            },
            'setTimeout(': {
                'description': 'setTimeout can execute a string of code after a delay, providing an opportunity for injecting malicious scripts.',
            },
            'setInterval(': {
                'description': 'setInterval can execute untrusted code repeatedly, making it vulnerable to persistent XSS attacks.',
            }
        }
        # Add SQL injection patterns
        self.sql_patterns = {
            'execute(': {
                'description': 'Direct execution of SQL queries with string concatenation can lead to SQL injection.',
                'example': "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
            },
            '.format(': {
                'description': 'Using .format() for SQL queries can be vulnerable to SQL injection if user input is not properly sanitized.',
                'example': "cursor.execute('SELECT * FROM users WHERE id = {}'.format(user_id))"
            },
            '% %': {
                'description': 'Using % string formatting in SQL queries can lead to SQL injection vulnerabilities.',
                'example': "cursor.execute('SELECT * FROM users WHERE id = %s' % user_id)"
            },
            '+': {
                'description': 'String concatenation in SQL queries is a common source of SQL injection vulnerabilities.',
                'example': "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"
            }
        }
        return

    # Function to search for code patterns on GitHub
    def search_github_code(self, query):
        params = {
            'q': f'{query} language:{self.language}',
            'per_page': self.results_per_search,
        }
        response = requests.get(self.BASE_URL, headers=self.HEADERS, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None

    # Function to get the default branch of a repository
    def get_default_branch(self, repo):
        repo_url = f"https://api.github.com/repos/{repo}"
        response = requests.get(repo_url, headers=self.HEADERS)
        if response.status_code == 200:
            repo_data = response.json()
            return repo_data['default_branch']
        else:
            print(f"Error fetching repo info: {response.status_code} - {response.text}")
            return 'main'  # Fallback to 'main' if default branch can't be retrieved

    # Function to fetch raw file content from GitHub
    def fetch_raw_file_content(self, repo, file_path):
        # Get the default branch of the repository
        default_branch = self.get_default_branch(repo)
        # Construct the raw URL for the file content
        raw_url = f"{self.RAW_BASE_URL}{repo}/{default_branch}/{file_path}"
        response = requests.get(raw_url)
        if response.status_code == 200:
            return response.text
        else:
            print(f"Error fetching file content: {response.status_code} - {response.text}")
            return None

    # Function to get code snippet where the vulnerable pattern was found
    def get_vulnerable_code_snippet(self, file_content, pattern, lines_before=5, lines_after=5):
        lines = file_content.splitlines()
        vulnerable_lines = []
        for idx, line in enumerate(lines):
            if pattern in line:
                # Collect context around the vulnerable line
                start_idx = max(0, idx - lines_before)
                end_idx = min(len(lines), idx + lines_after + 1)
                vulnerable_lines = lines[start_idx:end_idx]
                break
        return '\n'.join(vulnerable_lines)

    # Function to get code snippet with injected malicious payload
    def inject_payload_into_snippet(self, code_snippet, pattern, payload="<script>alert(\"XSS\")</script>"):
        """
        Injects a malicious payload into the vulnerable code snippet where the pattern is found.
        """
        if pattern in ["document.write", "innerHTML", "outerHTML"]:
            # Find the first instance of a string inside document.write or innerHTML and insert the payload into it
            return code_snippet.replace('">', f'">{payload}', 1)  # Correctly inject payload at the end of the first tag
        elif pattern in ["eval(", "setTimeout(", "setInterval("]:
            # Insert payload as part of the argument passed to eval(), setTimeout(), or setInterval()
            return code_snippet.replace("(", f"('{payload}',", 1)
        else:
            # As fallback, inject payload into the pattern as a comment
            return code_snippet.replace(pattern, f"{pattern} /* {payload} */")

    # Function to search for XSS vulnerabilities
    def search_XSS(self):
        findings = []
        for pattern, details in self.patterns.items():
            print(f"Searching for potential XSS vulnerabilities using pattern: {pattern}")
            result = self.search_github_code(query=pattern)
            if result:
                print(f"Found {len(result['items'])} results for pattern: {pattern}")
                for item in result['items']:
                    repo_name = item['repository']['full_name']
                    file_name = item['path']  # Fetching the file path where the vulnerability exists
                    file_url = item['html_url']
                    # Fetch the raw file content to analyze further
                    file_content = self.fetch_raw_file_content(repo_name, file_name)
                    if file_content:
                        code_snippet = self.get_vulnerable_code_snippet(file_content, pattern)
                        # Inject payload into code snippet for Step 3
                        injected_code_snippet = self.inject_payload_into_snippet(code_snippet, pattern)
                        attack_steps = [
                            f"1. The vulnerable code is found in the following file:\n{code_snippet}",
                            f"2. An attacker could inject a malicious script where the `{pattern}` pattern is used, exploiting this specific function in the code.",
                            f"3. For instance, an attacker might craft a payload like `<script>alert('XSS')</script>`, which would get injected here:\n{injected_code_snippet}",
                            f"4. When the browser renders this code, the malicious script executes, leading to an XSS attack."
                        ]
                        findings.append({
                            "vulnerability": "XSS",
                            "repo": repo_name,
                            "file": file_name,
                            "url": file_url,
                            "pattern": pattern,
                            "description": details['description'],
                            "attack_steps": attack_steps,
                            "code_snippet": code_snippet
                        })
                    print(f"- Repo: {repo_name}, File: {file_name}, URL: {file_url}, Pattern: {pattern}")
            print("\n" + "="*50 + "\n")
        return findings

    # New function to search for .env file leaks
    def search_env(self):
        print(f"Searching for committed .env files in public repositories.")
        query = 'extension:.env'
        findings = []
        
        # Use the search_github_code function to search for .env files
        result = self.search_github_code(query=query)
        
        if result:
            print(f"Found {len(result['items'])} results for .env files")
            for item in result['items']:
                repo_name = item['repository']['full_name']
                file_name = item['path']
                file_url = item['html_url']
                # Fetch the raw file content to analyze further
                file_content = self.fetch_raw_file_content(repo_name, file_name)

                # Skip empty or non-standard .env files (e.g., those without any '=' character)
                if file_content and '=' not in file_content:
                    print(f"Skipping {file_name} in repo {repo_name} as it does not contain any environment variables.")
                    continue

                if file_content:
                    findings.append({
                        "vulnerability": "env-leak",
                        "repo": repo_name,
                        "file": file_name,
                        "url": file_url,
                        "code_snippet": file_content
                    })
                print(f"- Repo: {repo_name}, File: {file_name}, URL: {file_url}")
        else:
            print("No results found or there was an error in the query.")
        print("\n" + "="*50 + "\n")
        
        return findings

    def search_openai_api_key(self):
        print(f"Searching for potential OpenAI API keys in repositories.")
        query = "openai_api_key = 'sk-"
        findings = []

        # Use the search_github_code function to search for the specific pattern
        result = self.search_github_code(query=query)

        if result:
            print(f"Found {len(result['items'])} results for OpenAI API key leaks")
            for item in result['items']:
                repo_name = item['repository']['full_name']
                file_name = item['path']
                file_url = item['html_url']
                # Fetch the raw file content to analyze further
                file_content = self.fetch_raw_file_content(repo_name, file_name)

                if file_content:
                    findings.append({
                        "vulnerability": "openai-api-key-leak",
                        "repo": repo_name,
                        "file": file_name,
                        "url": file_url,
                        "code_snippet": file_content
                    })
                print(f"- Repo: {repo_name}, File: {file_name}, URL: {file_url}")
        else:
            print("No results found or there was an error in the query.")
        print("\n" + "="*50 + "\n")
        return findings

    def search_sql_injection(self):
        """
        Search for potential SQL injection vulnerabilities in Python API code.
        Focuses on common patterns that might indicate unsafe SQL query construction.
        """
        findings = []
        print("Searching for potential SQL injection vulnerabilities in Python code...")
        
        # Temporarily change language to Python for this search
        original_language = self.language
        self.language = 'python'
        
        for pattern, details in self.sql_patterns.items():
            print(f"Searching for SQL injection vulnerabilities using pattern: {pattern}")
            query = f'{pattern} execute cursor.execute'
            result = self.search_github_code(query=pattern)
            
            if result:
                print(f"Found {len(result['items'])} results for pattern: {pattern}")
                for item in result['items']:
                    repo_name = item['repository']['full_name']
                    file_name = item['path']
                    file_url = item['html_url']
                    
                    # Fetch the raw file content
                    file_content = self.fetch_raw_file_content(repo_name, file_name)
                    if file_content:
                        code_snippet = self.get_vulnerable_code_snippet(file_content, pattern)
                        exploit_example = self.get_sql_exploit_example(code_snippet, pattern)
                        
                        attack_steps = [
                            f"1. The vulnerable code is found in the following file:\n{code_snippet}",
                            f"2. An attacker could inject malicious SQL commands where the `{pattern}` pattern is used.",
                            f"3. For example, an attacker might craft a payload like:\n{exploit_example}",
                            "4. When this malicious input is processed, the SQL query structure would be altered, potentially exposing or modifying sensitive data."
                        ]
                        
                        findings.append({
                            "vulnerability": "sql-injection",
                            "repo": repo_name,
                            "file": file_name,
                            "url": file_url,
                            "pattern": pattern,
                            "description": details['description'],
                            "attack_steps": attack_steps,
                            "code_snippet": code_snippet
                        })
                    print(f"- Repo: {repo_name}, File: {file_name}, URL: {file_url}, Pattern: {pattern}")
            print("\n" + "="*50 + "\n")
        
        # Restore original language setting
        self.language = original_language
        return findings

    def get_sql_exploit_example(self, code_snippet, pattern):
        """
        Generate an example of how the SQL injection vulnerability could be exploited.
        Returns a formatted string showing original vs malicious input scenarios.
        """
        if "SELECT" in code_snippet.upper():
            return """Original intended input:
    user_id = "123"

    Malicious input that could expose all users:
    user_id = "123 OR 1=1"

    Resulting query:
    SELECT * FROM users WHERE id = 123 OR 1=1
    # This would return all users instead of just user 123"""

        elif "INSERT" in code_snippet.upper():
            return """Original intended input:
    username = "john"

    Malicious input that could inject additional SQL:
    username = "john'); DROP TABLE users;--"

    Resulting query:
    INSERT INTO users (username) VALUES ('john'); DROP TABLE users;--
    # This would insert the user and then drop the entire users table"""

        else:
            return """Original intended input:
    user_input = "valid_input"

    Malicious input example:
    user_input = "' OR '1'='1"

    Resulting query transformation:
    Original: SELECT * FROM table WHERE field = 'valid_input'
    Malicious: SELECT * FROM table WHERE field = '' OR '1'='1'
    # This would bypass authentication or return all records"""

    # Function to report findings for all vulnerabilities
    def report_findings(self, findings: list = []):
        print(f"Columbus found the following vulnerabilities:\n===")
        for i, finding in enumerate(findings):
            vulnerability_type = finding['vulnerability']
            file_name = f"{finding['repo'].replace('/', '-')}-{vulnerability_type}.log"
            # Ensure the directory exists
            if not os.path.exists(f"findings/columbus/{vulnerability_type}/"):
                os.makedirs(f"findings/columbus/{vulnerability_type}/")
            # Skip if the file already exists
            if os.path.exists(f"findings/columbus/{vulnerability_type}/{file_name}"):
                print(f"Skipping {file_name} as it already exists.")
                continue
            # Write to file
            with open(f"findings/columbus/{vulnerability_type}/{file_name}", "wt") as file:
                print(f"{i+1}. Repo: {finding['repo']}")
                file.write(f"{i+1}. Repo: {finding['repo']}\n")
                file.write(f"\tFile: {finding['file']}\n")
                file.write(f"\tURL: {finding['url']}\n")
                if vulnerability_type == "XSS":
                    file.write(f"\tVulnerable Pattern: {finding['pattern']}\n")
                    file.write(f"\tAttack Description: {finding['description']}\n")
                    file.write(f"\tVulnerable Code Snippet:\n{finding['code_snippet']}\n")
                    file.write(f"Step-by-Step Attack Scenario:\n")
                    for step in finding['attack_steps']:
                        file.write(f"\t\t\t{step}\n")
                elif vulnerability_type == ".env Leak":
                    file.write(f"\tVulnerable Code Snippet:\n{finding['code_snippet']}\n")
                # Print to console
                elif vulnerability_type == "sql-injection":
                    file.write(f"\tVulnerable Pattern: {finding['pattern']}\n")
                    file.write(f"\tAttack Description: {finding['description']}\n")
                    file.write(f"\tVulnerable Code Snippet:\n{finding['code_snippet']}\n")
                    file.write(f"Step-by-Step Attack Scenario:\n")
                    for step in finding['attack_steps']:
                        file.write(f"\t\t\t{step}\n")
                elif vulnerability_type == ".env Leak":
                    print(f"\tVulnerable Code Snippet:\n{finding['code_snippet']}")
                # Print to console
                print(f"{i+1}. Repo: {finding['repo']}")
                if vulnerability_type == "openai-api-key-leak":
                    print(f"\tVulnerable Code Snippet:\n{finding['code_snippet']}")
                print("\n")

# If the script is being run directly, execute the main search and reporting process
if __name__ == "__main__":
    columbus = Columbus()
    
    # Search for XSS vulnerabilities
    columbus.results_per_search = 1000
    #findings_XSS = columbus.search_XSS()
    
    # Search for .env file leaks
    #findings_env = columbus.search_env()

    # Search for OpenAI API Key.
    #findings_openai = columbus.search_openai_api_key()
    
    #Search for SQL Injection.
    findings_SQL = columbus.search_sql_injection()

    # Combine both findings and report them
    findings_XSS = findings_env = []
    all_findings = findings_SQL #+ findings_XSS + findings_env + findings_openai
    columbus.report_findings(all_findings)