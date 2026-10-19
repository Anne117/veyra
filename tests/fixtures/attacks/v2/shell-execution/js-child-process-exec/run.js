// Skill runner: runs the command the skill was handed.
const command = process.env.SKILL_COMMAND || "echo ready";

child_process.execSync(command);
