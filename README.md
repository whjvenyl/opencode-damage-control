# opencode-damage-control

Defense-in-depth security plugin for [OpenCode](https://opencode.ai). Blocks dangerous commands and protects sensitive files before they execute.

Inspired by [claude-code-damage-control](https://github.com/disler/claude-code-damage-control), reimplemented as a native OpenCode plugin using the `tool.execute.before` hook.

---

## Why

AI coding agents have shell access, file read/write, and broad autonomy. A single bad command -- whether from a hallucination, prompt injection, or honest mistake -- can:

- `rm -rf /` your filesystem
- `DROP TABLE` your production database
- Leak `~/.ssh` keys or `~/.aws` credentials
- `git push --force` over your team's work

This plugin intercepts every tool call and blocks the dangerous ones before they run.

---

## How It Works

```
         OpenCode Tool Call
                |
    +-----------+-----------+
    |           |           |
  bash/       read/       edit/
  shell/      glob/       write/
  cmd         grep        create
    |           |           |
    v           v           v
 +-------+  +-------+  +-------+
 |Pattern|  | Path  |  | Path  |
 | Match |  | Check |  | Check |
 +---+---+  +---+---+  +---+---+
     |           |           |
  match?     zeroAccess?  protected?
   /   \       /   \       /   \
 yes   no    yes   no    yes   no
  |     |     |     |     |     |
BLOCK ALLOW BLOCK ALLOW BLOCK ALLOW
```

The plugin registers a single `tool.execute.before` hook that inspects every tool invocation:

1. **Shell commands** (`bash`, `shell`, `cmd`) -- matched against 24 dangerous command patterns AND checked for protected path references
2. **Read operations** (`read`, `glob`, `grep`) -- file paths checked against `zeroAccess` protected paths
3. **Write operations** (`edit`, `write`, `create`) -- file paths checked against all protected paths

Blocked operations throw an error with a `DAMAGE_CONTROL_BLOCKED:` prefix. The tool never executes.

---

## Install

### From npm

Add it to your `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-damage-control"]
}
```

Restart OpenCode. The plugin is installed automatically.

### From source

```bash
git clone https://github.com/whjvenyl/opencode-damage-control.git
cd opencode-damage-control
npm install
npm run build
```

Then add as a local plugin by placing the built output in `.opencode/plugins/` or referencing it in your config.

---

## Blocked Patterns

### Critical Severity

| Pattern | Description |
|---------|-------------|
| `rm -rf /` | Recursive delete from root |
| `:() { :` | Fork bomb |
| `fork()` | Fork bomb |
| `> /dev/sd` | Direct device write |
| `mkfs.` | Format filesystem |
| `kill -9 -1` | Kill all processes |
| `killall -9` | Kill all processes |
| `shutdown` | System shutdown |
| `reboot` | System reboot |
| `init 0` | System halt |
| `format c:` | Windows format |

### High Severity

| Pattern | Description |
|---------|-------------|
| `DROP TABLE` | SQL drop table |
| `DROP DATABASE` | SQL drop database |
| `git push --force` / `-f` | Force push |
| `dd if=` | Direct disk operation |
| `curl ... \| sh` | Pipe to shell |
| `wget ... \| sh` | Pipe to shell |

### Medium Severity

| Pattern | Description |
|---------|-------------|
| `DELETE FROM` | SQL delete |
| `TRUNCATE` | SQL truncate |
| `git push --delete` | Remote branch delete |
| `chmod -R 777` | World-writable permissions |
| `chown -R` | Recursive ownership change |

All patterns are matched case-insensitively.

---

## Protected Paths

| Path | Level | Read | Write | Shell |
|------|-------|------|-------|-------|
| `~/.ssh` | zeroAccess | blocked | blocked | blocked |
| `~/.aws` | zeroAccess | blocked | blocked | blocked |
| `~/.gnupg` | zeroAccess | blocked | blocked | blocked |
| `/etc/passwd` | zeroAccess | blocked | blocked | blocked |
| `/etc/shadow` | zeroAccess | blocked | blocked | blocked |
| `~/.config/opencode` | zeroAccess | blocked | blocked | blocked |

`~` is expanded to `$HOME` at runtime. Both forms are checked.

---

## What Happens When Something Is Blocked

The plugin throws an error that OpenCode surfaces to the AI agent. Example:

```
DAMAGE_CONTROL_BLOCKED: Recursive delete from root

Command: rm -rf /
Severity: critical
```

The tool call is prevented from executing. The AI agent sees the error and can adjust its approach.

All blocked operations are logged at `warn` level via `client.app.log()` for observability.

---

## Limitations

- **Patterns are hardcoded.** There is no configuration file to add or remove patterns or paths at runtime. Fork the repo to customize.
- **Substring matching for paths.** A command that merely _mentions_ a protected path (e.g., in a comment or echo) will be blocked.
- **No ask/confirm mode.** Unlike the original claude-code-damage-control, all matches are hard blocks. There is no interactive confirmation flow.
- **Shell only, not subprocesses.** The plugin inspects the command string passed to the `bash`/`shell`/`cmd` tool. It cannot inspect commands spawned by scripts that the agent runs.

---

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# The compiled output is in dist/
```

The entire plugin is a single file: `src/index.ts` (164 lines). It exports `DamageControl` as a named export conforming to the OpenCode `Plugin` type.

### Project Structure

```
opencode-damage-control/
  src/
    index.ts          # Plugin source (patterns, path checks, hook)
  dist/               # Compiled output (generated by tsc)
  package.json
  tsconfig.json
```

---

## Acknowledgments

Based on the concept and pattern set from [claude-code-damage-control](https://github.com/disler/claude-code-damage-control) by [@disler](https://github.com/disler), which implements the same idea for Claude Code using PreToolUse hooks and Python/TypeScript scripts.

This project reimplements the concept as a native [OpenCode plugin](https://opencode.ai/docs/plugins/) -- a single TypeScript module using the `@opencode-ai/plugin` SDK, with zero runtime dependencies.

---

## License

MIT
