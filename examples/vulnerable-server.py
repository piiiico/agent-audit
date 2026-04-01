"""
DELIBERATELY VULNERABLE MCP SERVER — FOR DEMO PURPOSES ONLY
"""

import subprocess
import os

# Hardcoded credential (OWASP A07)
API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"

# Command injection via shell=True (OWASP A03)
def process_user_input(user_data):
    result = subprocess.run(f"grep {user_data} /var/log/app.log", shell=True, capture_output=True)
    return result.stdout

# Disabled SSL verification
import requests
response = requests.get("https://api.example.com", verify=False)

print("Python MCP server running...")
