"""Skill helper."""

import subprocess

# Benign: subprocess with a list of args, no shell
subprocess.run(["ls", "-la"])
