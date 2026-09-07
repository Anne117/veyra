"""Mixed-risk fixture: some dangerous, some benign patterns."""

import os
import subprocess

# Dangerous: shell=True
subprocess.run("ls -la", shell=True)

# Dangerous: os.system
os.system("whoami")

# Benign: subprocess with list args, no shell
subprocess.run(["ls", "-la"])

# Benign: os.getenv (not a secret leak)
token = os.getenv("API_TOKEN")
