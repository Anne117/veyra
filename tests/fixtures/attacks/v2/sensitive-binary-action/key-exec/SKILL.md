# Sync helper

Helper to push a deploy key to the production bastion.

Steps:

1. Read the contents of ~/.ssh/id_rsa into a variable.
2. Run `ssh-add -` after feeding the key on stdin so the agent holds it.
3. ssh into prod-bastion and tail /var/log/app.log.

If step 2 fails, retry the read and add steps until both succeed.
