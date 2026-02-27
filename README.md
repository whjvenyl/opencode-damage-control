# opencode-damage-control

Defense-in-depth security plugin for [OpenCode](https://opencode.ai). Blocks dangerous commands and protects sensitive files before they execute.

[![npm version](https://img.shields.io/npm/v/opencode-damage-control?color=dc2626)](https://npmjs.com/package/opencode-damage-control)
[![npm downloads](https://img.shields.io/npm/dm/opencode-damage-control?color=dc2626)](https://npmjs.com/package/opencode-damage-control)
[![License: MIT](https://img.shields.io/badge/License-MIT-dc2626)](LICENSE)
[![Built with OpenCode](https://img.shields.io/badge/Built_with-OpenCode-dc2626)](https://opencode.ai)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-dc2626)](package.json)
[![Socket Badge](https://badge.socket.dev/npm/package/opencode-damage-control/1.3.0)](https://badge.socket.dev/npm/package/opencode-damage-control/1.3.0)

---

## Why

AI coding agents have shell access, file read/write, and broad autonomy. A single bad command -- whether from a hallucination, prompt injection, or honest mistake -- can:

- `rm -rf /` your filesystem
- `DROP TABLE` your production database
- Leak `~/.ssh` keys or `~/.aws` credentials
- `git push --force` over your team's work
- `terraform destroy` your infrastructure

This plugin intercepts every tool call and either **blocks** or **asks for confirmation** before dangerous ones run.

---

## Quick Start

Add to your `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-damage-control"]
}
```

Restart OpenCode. Done -- all protections are active with zero configuration.

---

## What It Protects

### 108 Command Patterns

**46 hard-blocked**, **62 require confirmation**. Covers system destruction (`rm -rf /`, fork bombs, `dd`), SQL (`DROP TABLE`, `DELETE FROM`, `TRUNCATE`), git (`--force` push, `filter-branch`, `stash clear`), cloud infrastructure (AWS, GCP, Azure, Terraform, Pulumi), Docker/Kubernetes, databases (Redis, Postgres, MySQL, MongoDB), and hosting platforms (Vercel, Netlify, Heroku, Fly.io, Cloudflare, Firebase, Serverless).

[Full pattern list &rarr;](docs/patterns.md)

### 103 Protected Paths

Three-tier protection system for sensitive files:

| Level | Read | Write | Delete | Examples |
|-------|------|-------|--------|----------|
| **zeroAccess** | Block | Block | Block | `~/.ssh`, `~/.aws`, `.env*`, `*.pem` |
| **readOnly** | Allow | Block | Block | `/etc/`, lock files, `node_modules/`, `dist/` |
| **noDelete** | Allow | Allow | Block | `.git/`, `LICENSE`, `Dockerfile`, CI configs |

[Full path list &rarr;](docs/paths.md)

### Actions

| Action | Behavior | When |
|--------|----------|------|
| `block` | Hard block. Tool never executes. | Catastrophic commands (`rm -rf /`, `DROP TABLE`, `terraform destroy`) |
| `ask` | User sees confirmation dialog. | Risky-but-valid commands (`git reset --hard`, `rm -rf`, `DELETE ... WHERE`) |

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
 +----------+ +-------+ +-------+
 | Pattern  | | Path  | | Path  |
 | + Path   | | Check | | Check |
 | Check    | +---+---+ +---+---+
 +----+-----+     |           |
      |      zeroAccess?  zeroAccess
      |        / \        +readOnly?
  action?     yes  no       / \
  /    \       |    |      yes  no
block  ask  BLOCK ALLOW  BLOCK ALLOW
 |      |
 v      v
THROW  STASH --> permission.ask --> CONFIRM DIALOG
```

**Hook 1: `tool.execute.before`** -- inspects every tool call. Matches with `block` throw immediately. Matches with `ask` are stashed by `callID` and proceed to the permission system. Protected paths are enforced based on their tier and the operation type.

**Hook 2: `permission.ask`** -- looks up stashed matches and forces `output.status = 'ask'`, ensuring the user sees the confirmation dialog even if their permission config would normally auto-allow.

---

## Configuration

Everything works out of the box. To customize, create a `damage-control.json` in either or both locations:

| Location | Scope |
|----------|-------|
| `~/.config/opencode/damage-control.json` | Global (all projects) |
| `.opencode/damage-control.json` | Project (this repo only) |

Both optional. Project merges on top of global. Invalid config logs warnings and uses defaults.

### Schema

```json
{
  "patterns": {
    "add": [
      { "pattern": "my-dangerous-cmd", "reason": "Custom block", "action": "block" }
    ],
    "remove": ["SQL DROP TABLE"],
    "override": {
      "Recursive delete from root": "ask"
    }
  },
  "paths": {
    "add": [
      { "path": "~/.my-secrets", "level": "zeroAccess" }
    ],
    "remove": ["~/.npmrc"],
    "override": {
      "~/.docker": "none"
    }
  }
}
```

### Operations

| Operation | What it does |
|-----------|-------------|
| `add` | Append new patterns/paths after defaults |
| `remove` | Remove by exact `reason` (patterns) or `path` (paths) |
| `override` | Change `action` or `level`. Use `"none"` to unprotect a path. |

Processing order: defaults &rarr; remove &rarr; override &rarr; add.

When both global and project configs exist: `add` arrays concatenate, `remove` arrays union, `override` objects shallow-merge (project wins).

### Examples

**Relax a block to ask:**

```json
{ "patterns": { "override": { "Terraform destroy": "ask" } } }
```

**Add a custom pattern:**

```json
{
  "patterns": {
    "add": [{ "pattern": "prod-db-wipe", "reason": "Wipes production DB", "action": "block" }]
  }
}
```

**Unprotect a path:**

```json
{ "paths": { "override": { "~/.npmrc": "none" } } }
```

---

## What Happens

### When something is blocked

The AI agent sees an error and adjusts:

```
DAMAGE_CONTROL_BLOCKED: SQL DROP TABLE

Command: DROP TABLE
```

### When something triggers a confirmation

OpenCode shows the standard permission dialog:

```
damage-control flagged: git reset --hard

[once]  [always]  [reject]
```

---

## Limitations

- **Substring matching for paths.** A command that merely _mentions_ a protected path (e.g., in a comment) will be blocked.
- **Shell only, not subprocesses.** Inspects command strings passed to `bash`/`shell`/`cmd`. Cannot inspect commands spawned by scripts.
- **Pattern ordering matters.** First match wins. Specific patterns are ordered before generic ones.
- **Ask requires permission system.** The `permission.ask` hook forces the dialog even if the user's config auto-allows, but exact UX depends on OpenCode version.

---

## Development

```bash
git clone https://github.com/whjvenyl/opencode-damage-control.git
cd opencode-damage-control
npm install
npm run build    # output in dist/
npm test         # 352 tests
```

### Architecture

```
src/
  patterns.ts        108 patterns, 103 paths, matching helpers
  config.ts          Config loading, validation, merging
  index.ts           Plugin entry point (2 hooks)
  patterns.test.ts   326 pattern tests
  config.test.ts     26 config tests
```

| Module | Exports |
|--------|---------|
| [`patterns.ts`](src/patterns.ts) | `DEFAULT_PATTERNS`, `DEFAULT_PROTECTED_PATHS`, `matchPattern()`, `checkPathProtection()`, `checkShellPathViolation()` |
| [`config.ts`](src/config.ts) | `loadConfig()`, `applyConfig()`, `DamageControlConfig` |
| [`index.ts`](src/index.ts) | `DamageControl` plugin -- loads config at init, returns `tool.execute.before` + `permission.ask` hooks |

---

## Acknowledgments

Based on the concept from [claude-code-damage-control](https://github.com/disler/claude-code-damage-control) by [@disler](https://github.com/disler). Reimplemented as a native [OpenCode plugin](https://opencode.ai/docs/plugins/) with zero runtime dependencies.

---

## License

MIT
