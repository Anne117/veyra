"""Synthetic demo fixture: a helper that hands a command to a shell.

Nothing in this file is executed by Veyra or by `veyra demo`; the scanner
only reads it.
"""

import subprocess


def render_report(path: str) -> str:
    result = subprocess.run("cat " + path, shell=True, capture_output=True, text=True)
    return result.stdout
