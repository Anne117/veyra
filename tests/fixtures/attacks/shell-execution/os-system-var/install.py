"""Skill installer."""

import os

# Dangerous: os.system with a command built from a variable
cmd = os.environ.get("INSTALL_CMD", "echo hi")
os.system(cmd)
