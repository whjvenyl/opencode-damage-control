# opencode-damage-control

Defense-in-depth security plugin for [OpenCode](https://opencode.ai). Blocks dangerous commands and protects sensitive files before they execute.

Inspired by [claude-code-damage-control](https://github.com/disler/claude-code-damage-control), reimplemented as a native OpenCode plugin.

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

## How It Works

The plugin uses two hooks working together:

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
      |        zeroAccess? protected?
      |          / \         / \
  action?      yes  no     yes  no
  /    \        |    |      |    |
block  ask   BLOCK ALLOW BLOCK ALLOW
 |      |
 v      v
THROW  STASH ──> permission.ask ──> CONFIRM DIALOG
```

### Two-Hook Architecture

**Hook 1: `tool.execute.before`** -- inspects every tool call with full access to arguments.

- **Shell commands** (`bash`, `shell`, `cmd`) are matched against 70+ dangerous patterns. Matches with `action: 'block'` throw immediately. Matches with `action: 'ask'` are stashed and allowed to proceed to the permission system.
- **Read operations** (`read`, `glob`, `grep`) are checked against protected paths. `zeroAccess` paths are hard-blocked.
- **Write operations** (`edit`, `write`, `create`) are checked against all protected paths. Any match is hard-blocked.
- Shell commands referencing protected paths are hard-blocked.

**Hook 2: `permission.ask`** -- fires when OpenCode's permission system is consulted.

- Looks up stashed matches by `callID`.
- Forces `output.status = 'ask'` so the user sees the confirmation dialog, even if their `opencode.json` permission config would normally allow the action.

### Actions

| Action | Behavior | When |
|--------|----------|------|
| `block` | Hard block. Tool never executes. Error surfaced to the AI agent. | Catastrophic commands (`rm -rf /`, `DROP TABLE`, `terraform destroy`, etc.) |
| `ask` | User sees confirmation dialog with once/always/reject options. | Risky-but-valid commands (`git reset --hard`, `rm -rf`, `DELETE ... WHERE`, etc.) |

---

## Install

### From npm

Add to your `opencode.json`:

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

Then reference it as a local plugin in `.opencode/plugins/` or your config.

---

## Blocked Patterns (action: block)

These are hard-blocked. The tool never executes.

### System Destruction

| Pattern | Description |
|---------|-------------|
| `rm -rf /` | Recursive delete from root |
| Fork bombs | `:() { :` and `fork()` |
| `> /dev/sd*` | Direct device write |
| `dd ... of=/dev/` | dd writing to device |
| `mkfs.*` | Format filesystem |
| `kill -9 -1` | Kill all processes |
| `killall -9` | Kill all processes |
| `shutdown` / `reboot` / `init 0` | System shutdown/reboot/halt |
| `format c:` | Windows format |
| `sudo rm` | sudo rm |

### SQL (no WHERE clause)

| Pattern | Description |
|---------|-------------|
| `DROP TABLE` | SQL DROP TABLE |
| `DROP DATABASE` | SQL DROP DATABASE |
| `DELETE FROM ... ;` | DELETE without WHERE clause |
| `TRUNCATE TABLE` | SQL TRUNCATE TABLE |

### Git (irreversible)

| Pattern | Description |
|---------|-------------|
| `git push --force` | Force push (blocks `--force` but NOT `--force-with-lease`) |
| `git push -f` | Force push shorthand |
| `git stash clear` | Deletes ALL stashes |
| `git filter-branch` | Rewrites entire history |

### Infrastructure

| Pattern | Description |
|---------|-------------|
| `terraform destroy` | Destroys all infrastructure |
| `pulumi destroy` | Destroys all resources |
| `aws s3 rm --recursive` | Deletes all S3 objects |
| `aws s3 rb --force` | Force removes S3 bucket |
| `gcloud projects delete` | Deletes entire GCP project |
| `kubectl delete all --all` | Deletes all K8s resources |

### Databases / Services

| Pattern | Description |
|---------|-------------|
| `redis-cli FLUSHALL` | Wipes ALL Redis data |
| `dropdb` | PostgreSQL drop database |
| `mysqladmin drop` | MySQL drop database |
| `mongosh ... dropDatabase` | MongoDB drop database |
| `npm unpublish` | Removes package from registry |
| `gh repo delete` | Deletes GitHub repository |

### Shell

| Pattern | Description |
|---------|-------------|
| `curl ... \| sh` | Pipe to shell |
| `wget ... \| sh` | Pipe to shell |

---

## Confirmed Patterns (action: ask)

These prompt the user for confirmation. The user can approve once, approve always, or reject.

### File Operations

| Pattern | Description |
|---------|-------------|
| `rm -rf` / `rm -f` / `rm --force` | rm with recursive or force flags |

### Git (recoverable but risky)

| Pattern | Description |
|---------|-------------|
| `git reset --hard` | Hard reset (suggest --soft or stash) |
| `git clean -fd` | Clean with force/directory flags |
| `git checkout -- .` | Discard all uncommitted changes |
| `git restore .` | Discard all uncommitted changes |
| `git stash drop` | Permanently delete a stash |
| `git branch -D` | Force delete branch (even if unmerged) |
| `git push --delete` | Delete remote branch |

### SQL (targeted)

| Pattern | Description |
|---------|-------------|
| `DELETE FROM ... WHERE` | SQL DELETE with WHERE clause |

### Permissions

| Pattern | Description |
|---------|-------------|
| `chmod 777` / `chmod -R 777` | World-writable permissions |
| `chown -R` | Recursive ownership change |

### Cloud / Infrastructure

| Pattern | Description |
|---------|-------------|
| `aws ec2 terminate-instances` | Terminate EC2 instances |
| `aws rds delete-db-instance` | Delete RDS instance |
| `aws cloudformation delete-stack` | Delete CloudFormation stack |
| `gcloud compute instances delete` | Delete GCE instances |
| `gcloud sql instances delete` | Delete Cloud SQL instances |
| `gcloud container clusters delete` | Delete GKE clusters |
| `docker system prune -a` | Remove all unused Docker data |
| `docker volume prune` | Remove unused Docker volumes |
| `kubectl delete namespace` | Delete K8s namespace |
| `helm uninstall` | Uninstall Helm release |
| `redis-cli FLUSHDB` | Wipe Redis database |

### Hosting / Deployment

| Pattern | Description |
|---------|-------------|
| `vercel remove --yes` | Remove Vercel deployment |
| `vercel projects rm` | Delete Vercel project |
| `netlify sites:delete` | Delete Netlify site |
| `heroku apps:destroy` | Destroy Heroku app |
| `heroku pg:reset` | Reset Heroku Postgres |
| `fly apps destroy` | Destroy Fly.io app |
| `wrangler delete` | Delete Cloudflare Worker |

### Other

| Pattern | Description |
|---------|-------------|
| `history -c` | Clear shell history |

---

## Protected Paths

These paths are hard-blocked for all tool types. Shell commands, reads, and writes referencing them are prevented.

| Path | What It Protects |
|------|------------------|
| `~/.ssh` | SSH keys and config |
| `~/.aws` | AWS credentials |
| `~/.gnupg` | GPG keys |
| `~/.config/gcloud` | GCP credentials |
| `~/.azure` | Azure credentials |
| `~/.kube` | Kubernetes config |
| `~/.docker` | Docker config |
| `/etc/passwd` | System user database |
| `/etc/shadow` | System password hashes |
| `~/.config/opencode` | OpenCode config (prevents self-modification) |
| `~/.netrc` | Network credentials |
| `~/.npmrc` | npm auth tokens |
| `~/.git-credentials` | Git credentials |

`~` is expanded to `$HOME` at runtime. Both forms are checked.

---

## What Happens

### When something is blocked

The AI agent sees an error and adjusts its approach:

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

- **once** -- approve this specific invocation
- **always** -- approve future matches for this pattern (current session)
- **reject** -- deny the action

---

## Limitations

- **Patterns are hardcoded.** No runtime configuration. Fork the repo to customize.
- **Substring matching for paths.** A command that merely _mentions_ a protected path (e.g., in a comment) will be blocked.
- **Shell only, not subprocesses.** The plugin inspects command strings passed to the `bash`/`shell`/`cmd` tool. It cannot inspect commands spawned by scripts.
- **Ask requires permission system.** The confirmation dialog for `ask` patterns relies on OpenCode's permission system being active. If a user's config has `bash: "allow"`, the `permission.ask` hook forces the dialog anyway -- but the exact UX depends on the OpenCode version.

---

## Development

```bash
npm install
npm run build    # output in dist/
npm test         # run tests
```

[`src/index.ts`](src/index.ts) exports `DamageControl` as a named export conforming to the OpenCode `Plugin` type. Patterns, protected paths, and helpers live in [`src/patterns.ts`](src/patterns.ts).

### Architecture

```
src/patterns.ts
  |
  +-- DEFAULT_PATTERNS[]           70+ patterns with action (block | ask)
  +-- DEFAULT_PROTECTED_PATHS[]    13 sensitive paths
  +-- matchPattern()               regex matching against pattern list
  +-- checkPathProtection()        path substring matching
  +-- expandHome()                 ~ -> $HOME expansion

src/index.ts
  |
  +-- DamageControl                Plugin function returning two hooks:
       +-- tool.execute.before     inspect + block or stash
       +-- permission.ask          force confirmation for stashed items
```

### Project Structure

```
opencode-damage-control/
  src/
    index.ts              # Plugin entry point
    patterns.ts           # Patterns, paths, and helpers
    patterns.test.ts      # Tests (node:test)
  dist/                   # Compiled output (generated by tsc)
  package.json
  tsconfig.json
```

---

## Acknowledgments

Based on the concept and pattern set from [claude-code-damage-control](https://github.com/disler/claude-code-damage-control) by [@disler](https://github.com/disler), which implements the same idea for Claude Code using PreToolUse hooks and Python/TypeScript scripts.

This project reimplements the concept as a native [OpenCode plugin](https://opencode.ai/docs/plugins/) using the `@opencode-ai/plugin` SDK, with zero runtime dependencies.

---

## License

MIT
