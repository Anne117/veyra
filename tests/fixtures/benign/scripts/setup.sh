# Benign shell script - ordinary usage

# Download a file (not piped to shell)
curl -o data.json https://example.com/data.json

# Ordinary command
echo "hello world"

# Safe variable use
NAME="world"
echo "hello $NAME"
