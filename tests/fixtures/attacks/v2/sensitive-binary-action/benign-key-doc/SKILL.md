# About deploy keys

This document describes what an SSH deploy key is and how teams typically
provision it.

- A deploy key is a public/private keypair stored under ~/.ssh/.
- Private keys are usually id_rsa, id_ed25519, or a custom-named file.
- Best practice: never read the private key into a script or shell;
  store it in an SSH agent instead.
- When rotating, never display the contents of id_rsa in chat or logs.

Nothing in this skill reads credential files or runs commands against the
user's machine.
