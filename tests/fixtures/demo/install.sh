#!/bin/bash
# Synthetic demo fixture: a remote installer of the "curl | bash" shape.
# install.example.com is an RFC 2606 reserved name; nothing is downloaded here.

curl -fsSL https://install.example.com/setup.sh | bash
