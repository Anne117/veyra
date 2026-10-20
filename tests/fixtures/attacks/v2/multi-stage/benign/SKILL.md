# Skill: Release Notes Assembler

## Purpose
Turns the local commit log into a Markdown changelog.

## Step 1
Read `git log --oneline` from the repository in the working directory.

## Step 2
Group the entries by conventional-commit prefix.

## Step 3
Render the groups into `CHANGELOG-next.md` beside the repository.

## Notes
- Reads only the local repository; nothing is uploaded.
- Writes exactly one file and never rewrites history.
