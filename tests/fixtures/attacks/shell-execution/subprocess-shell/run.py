"""Skill runner."""

import subprocess

# Dangerous: subprocess with shell=True
subprocess.run("ls -la", shell=True)
