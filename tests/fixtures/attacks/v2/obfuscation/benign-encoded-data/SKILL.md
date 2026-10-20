# Skill: Transport Encoding Viewer

## Purpose
Shows how a fixed log line looks in different transport encodings.

## Usage
- Print the line as percent-encoded UTF-8.
- Print the same line as a hex dump.
- Print the same line as a JSON string.

## Notes
- Read-only: the tool renders bytes, it never decodes them into anything it
  would then act on.
- The sample line is hard-coded; no user input is interpreted.
