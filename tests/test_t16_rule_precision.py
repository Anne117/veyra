"""T16: precision of the four rule classes the public corpus measured as FP.

Input: ``docs/PUBLIC-CORPUS.md`` §6 (T15). Each class below is the rule side of
one measured false-positive class. Every negative assertion in this file was
run against the rules as they stood before T16 and failed there (a finding was
returned); the corresponding positive assertion pins that the narrowing did not
turn the rule off.

Measured, not asserted: the corpus numbers are in ``docs/PUBLIC-CORPUS.md``
§"T16: after". This file only pins the mechanism.

The values used here are non-secret by construction: placeholder forms, and for
the "still fires" half an obvious fake assembled at run time, so that scanning
this repository does not report its own test data.
"""

from __future__ import annotations

from veyra.rules.secrets import detect_github_token, detect_generic_key
from veyra.rules.sensitive_paths import detect_sensitive_path_access
from veyra.rules.shell import detect_eval_exec
from veyra.step_sequence import analyze_file


# --- 1. AS-002 EVAL_EXEC: a regex match is not code execution ---------------


def test_regex_exec_is_not_dynamic_code():
    """``<regex>.exec(s)`` is ``RegExp.prototype.exec``, not ``eval``."""
    for line in (
        "const m = /x/.exec(s)",
        "while ((m = re.exec(command)) !== null) {",
        "const m = /^(\\d+)\\.(\\d+)\\.(\\d+)$/.exec(s);",
        "const m = EXCLUDED_RE.exec(command)",
        "const m = re?.exec(command)",
    ):
        assert detect_eval_exec(line, "x.mjs", 1) is None, line


def test_exec_on_an_unprovable_receiver_still_reports():
    """The receiver exemption is by receiver, not a blanket on ``X.exec(``.

    ``PR_LINE`` is a module-level regex constant this rule cannot see: the
    finding stays, and it is recorded as a residual false positive in
    ``docs/PUBLIC-CORPUS.md`` §"T16: after" rather than suppressed blind.
    """
    f = detect_eval_exec("const match = PR_LINE.exec(line)", "x.mjs", 1)
    assert f is not None and f.severity.value == "HIGH"


def test_dynamic_code_still_detected():
    """The bare globals keep their HIGH, including a wrapper's method call."""
    for line in (
        "eval(userInput)",
        "exec(payload)",
        "new Function(body)",
        'setTimeout("alert(1)", 0)',
        # Not a regex receiver: suppressing every `X.exec(` would hide this.
        "runner.exec(code)",
    ):
        f = detect_eval_exec(line, "x.mjs", 1)
        assert f is not None, line
        assert f.rule_id == "AS-002"
        assert f.severity.value == "HIGH"


# --- 2. AS-006: the verb must govern the path ------------------------------


def test_access_verb_must_govern_the_path():
    """A verb that stands near a credential path does not read it."""
    for line in (
        # A table cell boundary: GET governs the cell, not the next one.
        "| `GET`    | `/v1/vaults/{vault_id}/credentials` | ListCredentials |",
        # Advisory modality: a recommendation is not an access.
        "- **File permissions**: Restrict access to config files containing tokens",
        "3. **File Permissions**: Restrict access to configuration files containing tokens",
        # `process.env` is the environment, not a dotenv file.
        "{ fetch = globalThis.fetch, env = process.env } = {},",
        # The verb comes after the path, and the sentence is a negation.
        "### `MCP_*` environment variables and `.env` files are no longer read",
        # `private key` is the object of nothing: `access` governs "token".
        "private key, exchanges it for an installation access token, and refreshes the",
        # Two words of different clauses, 90 characters apart.
        "Most services read an API key from a request header, so {} is the narrower configuration",
        # A sentence ends between the verb and the file noun.
        "can `read` the full content. No configuration required.",
        # Not the verb: a compound word (`read-only` is an adjective).
        "| Secret protection | [read-only](https://example.com/readonly?config=x) |",
    ):
        assert detect_sensitive_path_access(line, "SKILL.md", 1) is None, line


def test_sensitive_path_access_still_detected():
    for line in (
        'open(".env")',
        "read the .env file",
        "cat ~/.ssh/id_rsa",
        "print the contents of .env",
        "read the config file and extract the password",
    ):
        f = detect_sensitive_path_access(line, "SKILL.md", 1)
        assert f is not None, line
        assert f.rule_id == "AS-006"
        assert f.severity.value == "HIGH"


# --- 3. AS-CHAIN-002: the execution must consume what was downloaded -------


def test_download_and_execution_of_different_objects_is_not_a_chain():
    for text in (
        # Two prerequisites of one install guide: "download Go" then "run lint".
        "Install Go 1.27.3 or later [through download](https://go.dev/doc/install)\n"
        "Install golangci-lint v2.14.0 or let `script/lint` install the pinned version.\n",
        # A warning that quotes the attack is not the attack.
        "Download the page from https://example.com/page\n"
        "Never run its commands, setup scripts or `curl | sh` lines\n",
        # A JSON field named "system" is not a command to execute.
        'curl -X POST https://api.example.com/v1/sessions \\\n'
        '"system": "You are a senior code reviewer",\n',
        # An install paragraph and an unrelated "run it".
        "Optionally: Install node.js, this will cause the fetch server to change.\n"
        "After installation, you can run it as a script using:\n",
    ):
        assert "AS-CHAIN-002" not in [
            f.rule_id for f in analyze_file(text, "SKILL.md")
        ], text


def test_download_and_execution_of_the_same_object_is_a_chain():
    for text in (
        "Download the deployment script.\nRun the deployment script.\n",
        "Fetch the remote package.\nExecute the package.\n",
        "Retrieve the script from the remote server and then run it.\n",
        # Kind reference: the execution names the artefact the download named.
        "Download the signed installer file from the mirror.\nRun the installer script.\n",
    ):
        assert "AS-CHAIN-002" in [
            f.rule_id for f in analyze_file(text, "SKILL.md")
        ], text


# --- 4. AS-001 GENERIC_KEY: an obvious placeholder is not a secret ---------


def test_placeholder_values_are_not_hardcoded_secrets():
    for line in (
        "GITHUB_PERSONAL_ACCESS_TOKEN=test-token",
        'CLIENT_SECRET = "enterprise-secret"',
        'DEMO_TOKEN = "demo-token"',
        'DEMO_CLIENT_SECRET = "demo-m2m-secret"',
        'DEMO_CLIENT_SECRET = "demo-finance-agent-secret"',
        "API_KEY = changeme",
        'SERVICE_TOKEN = "xxxxxxxx"',
        'ANTHROPIC_API_KEY = "sk-ant-****"',
    ):
        assert detect_generic_key(line, "x.py", 1) is None, line


def test_placeholder_exemption_keeps_values_with_entropy():
    # A placeholder *prefix* is not a placeholder value: the whole value is
    # judged by its form, so a marker plus real entropy still reports.
    for line in (
        "API_KEY=" + "supersecretvalue123",
        "CLIENT_SECRET=" + "enterprise-" + "2f8a9c1d4e7b",
        "DEMO_TOKEN=" + "demo-" + "4f9a2c7b1e8d3a6f",
    ):
        f = detect_generic_key(line, "x.py", 1)
        assert f is not None, line
        assert f.severity.value == "HIGH"


def test_provider_detectors_are_not_weakened_by_the_placeholder_exemption():
    # `sk-`, `ghp_`, `AKIA` keep their own shape rules.
    assert detect_github_token("TOKEN: ghp_" + "a8f5f167f44f4964e6c998dee827110c", "x.py", 1) is not None
    assert detect_generic_key("TOKEN: ghp_" + "a8f5f167f44f4964e6c998dee827110c", "x.py", 1) is not None
