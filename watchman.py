import os
from github import Github
from dotenv import load_dotenv
from github import Auth
# 1. Setup Configuration
load_dotenv()
token = os.getenv('GITHUB_TOKEN')

if not token:
    raise ValueError("No GITHUB_TOKEN.")

TARGET_REPO = "psf/requests" 

def get_latest_commits(repo_name, limit=3):
    auth = Auth.Token(token)
    g = Github(auth=auth)
    repo = g.get_repo(repo_name)
    commits = repo.get_commits()

    print(f"--- Monitoring {repo_name} ---")
    
    for i in range(limit):
        commit = commits[i]
        print(f"\n[+] Analyzing Commit: {commit.sha[:7]}")
        print(f"    Author: {commit.commit.author.name}")
        
        files = commit.files
        for file in files:
            if file.patch: 
                print(f"    File changed: {file.filename}")
                analyze_with_llm(file.filename, file.patch)

def analyze_with_llm(filename, patch_data):
    print(f"    [!] Sending {filename} patch to AI Auditor...")
    print(f"    Preview: {patch_data[:100]}...")

if __name__ == "__main__":
    get_latest_commits(TARGET_REPO)