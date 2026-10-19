// Operator note for this runner: spawn (default), list, steer, or stop.
// The sandbox SDK already exposes sandbox.process.exec("echo $HOME").
// -exec (runs in each match's directory) is find(1) syntax, not this module.

export function describeRunner() {
  return "Use spawn (default), list, steer, or stop.";
}
