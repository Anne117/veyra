"""Tests for AS-006 sensitive credential file access."""

from agentshield.rules.sensitive_paths import detect_sensitive_path_access


def test_env_read_detected():
    f = detect_sensitive_path_access("read the .env file", "SKILL.md", 1)
    assert f is not None
    assert f.rule_id == "AS-006"
    assert f.severity.value == "HIGH"


def test_aws_read_detected():
    f = detect_sensitive_path_access("cat ~/.aws/credentials", "SKILL.md", 1)
    assert f is not None
    assert f.rule_id == "AS-006"


def test_ssh_read_detected():
    f = detect_sensitive_path_access("cat ~/.ssh/id_rsa", "SKILL.md", 1)
    assert f is not None
    assert f.rule_id == "AS-006"


def test_credentials_read_detected():
    f = detect_sensitive_path_access("open the credentials file", "SKILL.md", 1)
    assert f is not None
    assert f.rule_id == "AS-006"


def test_print_env_detected():
    f = detect_sensitive_path_access("print the contents of .env", "SKILL.md", 1)
    assert f is not None
    assert f.rule_id == "AS-006"


def test_private_key_read_detected():
    f = detect_sensitive_path_access("read the private key from ~/.ssh/id_ed25519", "SKILL.md", 1)
    assert f is not None
    assert f.rule_id == "AS-006"


def test_benign_docs_not_detected():
    """Negated/benign mentions of sensitive paths must not be flagged."""
    benign = [
        "Never read ~/.aws/credentials.",
        "Do not expose .env.",
        "Documentation about protecting ~/.ssh.",
        "How to securely store AWS credentials.",
        "Never commit credentials to Git.",
    ]
    for line in benign:
        assert detect_sensitive_path_access(line, "SKILL.md", 1) is None, f"FP: {line}"


def test_normal_file_read_not_detected():
    f = detect_sensitive_path_access("read the README.md file", "SKILL.md", 1)
    assert f is None


def test_path_mention_without_access_not_detected():
    """Mentioning a sensitive path without an access verb must not be flagged."""
    f = detect_sensitive_path_access("the .env file is important", "SKILL.md", 1)
    assert f is None


def test_rule_is_static():
    """The rule must not execute commands or access the filesystem/network."""
    # The rule is a pure regex check; it never touches the filesystem.
    f = detect_sensitive_path_access("cat ~/.ssh/id_rsa", "SKILL.md", 1)
    assert f is not None


# --- Config-file + credential extraction (SAFE_GAP) -----------------------

def test_config_password_detected():
    f = detect_sensitive_path_access("read the config file and extract the password", "SKILL.md", 1)
    assert f is not None
    assert f.rule_id == "AS-006"
    assert f.severity.value == "HIGH"


def test_config_token_detected():
    f = detect_sensitive_path_access("open the configuration file and get the API token", "SKILL.md", 1)
    assert f is not None
    assert f.rule_id == "AS-006"


def test_config_secret_detected():
    f = detect_sensitive_path_access("load the config and retrieve the secret", "SKILL.md", 1)
    assert f is not None
    assert f.rule_id == "AS-006"


def test_config_credentials_detected():
    f = detect_sensitive_path_access("read the config file to obtain credentials", "SKILL.md", 1)
    assert f is not None
    assert f.rule_id == "AS-006"


def test_config_only_not_detected():
    """Config-file access alone must NOT be flagged."""
    benign = [
        "read the config file",
        "open the configuration file",
        "update the config file",
        "inspect the application config",
    ]
    for line in benign:
        assert detect_sensitive_path_access(line, "SKILL.md", 1) is None, f"FP: {line}"


def test_negated_config_credential_not_detected():
    """Negated config credential access must remain benign."""
    benign = [
        "never read the config file to extract the password",
        "do not open the config to get the token",
    ]
    for line in benign:
        assert detect_sensitive_path_access(line, "SKILL.md", 1) is None, f"FP: {line}"


def test_unrelated_config_manipulation_not_detected():
    """Config manipulation without credential extraction must not be flagged."""
    assert detect_sensitive_path_access("update the config file to change the port", "SKILL.md", 1) is None
