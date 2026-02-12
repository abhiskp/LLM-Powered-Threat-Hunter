import os
import re
from openai import OpenAI
from github import Github
from dotenv import load_dotenv
from github import Auth

load_dotenv()
token = os.getenv('GITHUB_TOKEN')
openai_key = os.getenv('OPENAI_API_KEY')

if not token:
    raise ValueError("No GITHUB_TOKEN.")

TARGET_REPO = "psf/requests" 
client = OpenAI(api_key=openai_key)
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
                analyze_with_gpt(file.filename, file.patch)


def save_yara_rule(rule_text, commit_sha):
    if "rule" not in rule_text.lower():
        return 
    filename = f"signatures/threat_{commit_sha}.yar"
    with open(filename, "w") as f:
        f.write(rule_text.strip())
    print(f"Signature saved to: {filename}")


def analyze_with_gpt(filename, patch_data, commit_sha="test"):
    print(f"    ... Auditing for Threats ...")
    
    user_prompt = f"""
    Analyze this GitHub patch for malicious activity.
    FILE: {filename}
    PATCH: {patch_data}
    
    RESPONSE FORMAT (Strictly follow this):
    RISK: [High/Med/Low]
    SUMMARY: [One sentence]
    YARA: [Provide a full YARA rule here if Risk is High or Med. If not, write N/A]
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a Security Researcher. Output YARA rules for high-risk code."},
                {"role": "user", "content": user_prompt}
            ]
        )
        
        report = response.choices[0].message.content
        print(f"\n    [SECURITY REPORT]\n{report}\n")
        
        # Extract YARA section and save it
        if "RISK: High" in report or "RISK: Med" in report:
            # Use regex to find the YARA rule text
            yara_match = re.search(r"YARA:\s*(rule.*?})", report, re.DOTALL | re.IGNORECASE)
            if yara_match:
                save_yara_rule(yara_match.group(1), commit_sha)

    except Exception as e:
        print(f"    [!] Error: {e}")

if __name__ == "__main__":
    # get_latest_commits(TARGET_REPO)
    from testThreat import FAKE_PATCH
    analyze_with_gpt("requests/api.py", FAKE_PATCH, commit_sha="reverse_shell_001")