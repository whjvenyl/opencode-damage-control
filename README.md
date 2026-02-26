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

**108 command patterns** (46 block, 62 ask) and **103 protected paths** across three protection levels.

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

### Two-Hook Architecture

**Hook 1: `tool.execute.before`** -- inspects every tool call with full access to arguments.

- **Shell commands** (`bash`, `shell`, `cmd`) are matched against 108 dangerous patterns. Matches with `action: 'block'` throw immediately. Matches with `action: 'ask'` are stashed and proceed to the permission system. Shell commands referencing protected paths are also checked, with enforcement varying by protection level.
- **Read operations** (`read`, `glob`, `grep`) are checked against protected paths. Only `zeroAccess` paths are hard-blocked (secrets should never be read).
- **Write/edit operations** (`edit`, `write`, `create`) are checked against `zeroAccess` and `readOnly` paths.
- **Delete operations** are checked against all protection levels.

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
| `pkill -9` | pkill with SIGKILL |
| `shutdown` / `reboot` / `init 0` | System shutdown/reboot/halt |
| `format c:` | Windows format |
| `sudo rm` | sudo rm |

### SQL (no WHERE clause)

| Pattern | Description |
|---------|-------------|
| `DROP TABLE` | SQL DROP TABLE |
| `DROP DATABASE` | SQL DROP DATABASE |
| `DELETE FROM ... ;` | DELETE without WHERE clause |
| `DELETE * FROM` | DELETE * (will delete ALL rows) |
| `TRUNCATE TABLE` | SQL TRUNCATE TABLE |

### Git (irreversible)

| Pattern | Description |
|---------|-------------|
| `git push --force` | Force push (blocks `--force` but NOT `--force-with-lease`) |
| `git push -f` | Force push shorthand |
| `git stash clear` | Deletes ALL stashes |
| `git filter-branch` | Rewrites entire history |
| `git reflog expire` | Destroys recovery mechanism |
| `git gc --prune=now` | Can lose dangling commits |

### Shell

| Pattern | Description |
|---------|-------------|
| `curl ... \| sh` | Pipe to shell |
| `wget ... \| sh` | Pipe to shell |

### Docker / Containers

| Pattern | Description |
|---------|-------------|
| `docker rm -f $(docker ps)` | Force removes all running containers |
| `kubectl delete all --all` | Deletes all K8s resources |
| `kubectl delete --all --all-namespaces` | Deletes across all namespaces |

### Infrastructure

| Pattern | Description |
|---------|-------------|
| `terraform destroy` | Destroys all infrastructure |
| `pulumi destroy` | Destroys all resources |
| `aws s3 rm --recursive` | Deletes all S3 objects |
| `aws s3 rb --force` | Force removes S3 bucket |
| `gcloud projects delete` | Deletes entire GCP project |
| `firebase projects:delete` | Deletes Firebase project |
| `firebase firestore:delete --all-collections` | Wipes all Firestore data |

### Databases / Services

| Pattern | Description |
|---------|-------------|
| `redis-cli FLUSHALL` | Wipes ALL Redis data |
| `dropdb` | PostgreSQL drop database |
| `mysqladmin drop` | MySQL drop database |
| `mongosh ... dropDatabase` | MongoDB drop database |
| `mongo ... dropDatabase` | MongoDB drop database (legacy shell) |
| `npm unpublish` | Removes package from registry |
| `gh repo delete` | Deletes GitHub repository |

---

## Confirmed Patterns (action: ask)

These prompt the user for confirmation. The user can approve once, approve always, or reject.

### File Operations

| Pattern | Description |
|---------|-------------|
| `rm -rf` / `rm -f` / `rm -R` | rm with recursive or force flags |
| `rm --recursive` / `rm --force` | rm with long flag variants |
| `rmdir --ignore-fail-on-non-empty` | rmdir ignore-fail |

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
| `git push origin :branch` | Delete remote branch (refspec syntax) |

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
| `aws dynamodb delete-table` | Delete DynamoDB table |
| `aws eks delete-cluster` | Delete EKS cluster |
| `aws lambda delete-function` | Delete Lambda function |
| `aws iam delete-role` / `delete-user` | Delete IAM role or user |
| `gcloud compute instances delete` | Delete GCE instances |
| `gcloud sql instances delete` | Delete Cloud SQL instances |
| `gcloud container clusters delete` | Delete GKE clusters |
| `gcloud storage rm -r` | Recursive cloud storage delete |
| `gcloud functions delete` | Delete Cloud Function |
| `gcloud iam service-accounts delete` | Delete service account |

### Docker / Kubernetes

| Pattern | Description |
|---------|-------------|
| `docker system prune -a` | Remove all unused Docker data |
| `docker rmi -f` | Force remove Docker images |
| `docker volume rm` / `docker volume prune` | Remove Docker volumes |
| `kubectl delete namespace` | Delete K8s namespace |
| `helm uninstall` | Uninstall Helm release |

### Databases

| Pattern | Description |
|---------|-------------|
| `redis-cli FLUSHDB` | Wipe Redis database |
| `firebase database:remove` | Remove Firebase Realtime Database data |

### Hosting / Deployment

| Pattern | Description |
|---------|-------------|
| `vercel remove --yes` / `vercel projects rm` | Remove Vercel deployment or project |
| `vercel env rm --yes` | Remove Vercel environment variable |
| `netlify sites:delete` / `netlify functions:delete` | Delete Netlify site or function |
| `heroku apps:destroy` / `heroku pg:reset` | Destroy Heroku app or reset Postgres |
| `fly apps destroy` / `fly destroy` | Destroy Fly.io app |
| `wrangler delete` | Delete Cloudflare Worker |
| `wrangler r2 bucket delete` | Delete R2 bucket |
| `wrangler kv:namespace delete` | Delete KV namespace |
| `wrangler d1 delete` / `wrangler queues delete` | Delete D1 database or Queue |
| `firebase hosting:disable` / `firebase functions:delete` | Disable Firebase hosting or delete function |
| `serverless remove` / `sls remove` | Remove Serverless Framework stack |
| `sam delete` | Delete SAM application |
| `doctl compute droplet delete` / `doctl databases delete` | Delete DigitalOcean resources |
| `supabase db reset` | Reset Supabase database |

### Other

| Pattern | Description |
|---------|-------------|
| `history -c` | Clear shell history |

---

## Protected Paths

Paths are organized into three protection levels. Enforcement varies by tool type and operation.

### Protection Matrix

| Level | Read | Write/Edit | Delete | Shell |
|-------|------|------------|--------|-------|
| **zeroAccess** | Block | Block | Block | Block if path referenced |
| **readOnly** | Allow | Block | Block | Block if writing or deleting |
| **noDelete** | Allow | Allow | Block | Block if deleting |

Shell commands are analyzed for write operators (`>`, `>>`, `tee`, `sed -i`, `cp`, `mv`, `chmod`, `touch`, `mkdir`, etc.) and delete operators (`rm`, `unlink`, `rmdir`, `shred`) to determine the actual operation being performed.

### zeroAccess (36 paths)

Secrets and credentials. No tool can read, write, or delete these.

| Path | What It Protects |
|------|------------------|
| `~/.ssh` | SSH keys and config |
| `~/.aws` | AWS credentials |
| `~/.gnupg` | GPG keys |
| `~/.config/gcloud` | GCP credentials |
| `~/.azure` | Azure credentials |
| `~/.kube` | Kubernetes config |
| `~/.docker` | Docker config |
| `/etc/passwd` / `/etc/shadow` | System user database and password hashes |
| `~/.config/opencode` | OpenCode config (prevents self-modification) |
| `~/.netrc` / `~/.npmrc` / `~/.pypirc` | Network and registry credentials |
| `~/.git-credentials` / `.git-credentials` | Git credentials |
| `.env*` | Environment variable files (glob) |
| `*.pem` / `*.key` / `*.p12` / `*.pfx` | Cryptographic keys and certificates |
| `*.tfstate*` / `.terraform/` | Terraform state |
| `*-credentials.json` | Cloud credential files |
| `*serviceAccount*.json` / `*service-account*.json` | Service account keys |
| `serviceAccountKey.json` | Firebase/GCP service account key |
| `kubeconfig` | Kubernetes config file |
| `*-secret.yaml` / `secrets.yaml` | Kubernetes/app secrets |
| `.vercel/` / `.netlify/` / `.supabase/` | Deployment platform configs |
| `firebase-adminsdk*.json` | Firebase admin SDK key |
| `dump.sql` / `backup.sql` / `*.dump` | Database dumps |

### readOnly (43 paths)

System directories, shell configs, lock files, and build artifacts. Tools can read but not modify.

| Path | What It Protects |
|------|------------------|
| `/etc/` / `/usr/` / `/bin/` / `/sbin/` / `/boot/` / `/root/` | System directories |
| `~/.bash_history` / `~/.zsh_history` / `~/.node_repl_history` | Shell history |
| `~/.bashrc` / `~/.zshrc` / `~/.profile` / `~/.bash_profile` | Shell configs |
| `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` | JS lock files |
| `Gemfile.lock` / `Cargo.lock` / `poetry.lock` / `composer.lock` | Other lock files |
| `go.sum` / `Pipfile.lock` / `flake.lock` / `bun.lockb` / `uv.lock` | More lock files |
| `npm-shrinkwrap.json` / `*.lock` / `*.lockb` | Generic lock files |
| `*.min.js` / `*.min.css` / `*.bundle.js` / `*.chunk.js` | Minified/bundled output |
| `dist/` / `build/` / `out/` / `.next/` / `.nuxt/` / `.output/` | Build output directories |
| `node_modules/` / `__pycache__/` / `.venv/` / `venv/` / `target/` | Dependency/build directories |

### noDelete (24 paths)

Project infrastructure. Tools can read and edit but not delete.

| Path | What It Protects |
|------|------------------|
| `~/.claude/` / `CLAUDE.md` | Claude Code config |
| `LICENSE*` / `COPYING*` / `NOTICE` / `PATENTS` | License files |
| `README*` / `CONTRIBUTING.md` / `CHANGELOG.md` | Project docs |
| `CODE_OF_CONDUCT.md` / `SECURITY.md` | Community docs |
| `.git/` / `.gitignore` / `.gitattributes` / `.gitmodules` | Git infrastructure |
| `.github/` / `.gitlab-ci.yml` / `.circleci/` | CI/CD configs |
| `Jenkinsfile` / `.travis.yml` / `azure-pipelines.yml` | CI/CD configs |
| `Dockerfile*` / `docker-compose*.yml` / `.dockerignore` | Container configs |

`~` is expanded to `$HOME` at runtime. Glob patterns (`*`) match against the file basename. Non-glob patterns use prefix/substring matching.

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

## Configuration

All 108 patterns and 103 protected paths work out of the box with zero configuration. To customize, create a `damage-control.json` file in either or both locations:

| Location | Scope |
|----------|-------|
| `~/.config/opencode/damage-control.json` | Global (all projects) |
| `.opencode/damage-control.json` | Project (this repo only) |

Both are optional. When both exist, project config merges on top of global. Invalid config logs warnings and falls back to defaults -- the plugin never crashes on bad config.

### Schema

```json
{
  "$schema": "https://raw.githubusercontent.com/whjvenyl/opencode-damage-control/main/schema.json",
  "patterns": {
    "add": [
      { "pattern": "my-dangerous-cmd", "reason": "Custom dangerous command", "action": "block" }
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
      "/etc/hosts": "noDelete",
      "~/.docker": "none"
    }
  }
}
```

### Config operations

| Operation | Key | What it does |
|-----------|-----|-------------|
| **Add** | `patterns.add` / `paths.add` | Append new entries after defaults |
| **Remove** | `patterns.remove` / `paths.remove` | Remove by exact `reason` (patterns) or `path` (paths) string |
| **Override** | `patterns.override` / `paths.override` | Change `action` or `level` of existing entries. Use `"none"` in paths to unprotect. |

### Processing order

1. Start with built-in defaults
2. **Remove** matching entries
3. **Override** remaining entries
4. **Add** new entries at the end

### Merge semantics (global + project)

| Field | Merge strategy |
|-------|----------------|
| `add` arrays | Concatenate (global first, then project) |
| `remove` arrays | Union (both lists apply) |
| `override` objects | Shallow merge (project wins on conflict) |

### Examples

**Relax a block to ask** -- allow `terraform destroy` with confirmation instead of hard-blocking:

```json
{
  "patterns": {
    "override": { "Terraform destroy": "ask" }
  }
}
```

**Add a custom pattern** -- block a company-specific dangerous CLI:

```json
{
  "patterns": {
    "add": [
      { "pattern": "prod-db-wipe", "reason": "Wipes production database", "action": "block" }
    ]
  }
}
```

**Unprotect a path** -- allow writes to `.npmrc`:

```json
{
  "paths": {
    "override": { "~/.npmrc": "none" }
  }
}
```

**Protect additional paths** -- add company secrets directory:

```json
{
  "paths": {
    "add": [
      { "path": "~/.company-secrets", "level": "zeroAccess" }
    ]
  }
}
```

---

## Limitations

- **Substring matching for paths.** A command that merely _mentions_ a protected path (e.g., in a comment) will be blocked.
- **Shell only, not subprocesses.** The plugin inspects command strings passed to the `bash`/`shell`/`cmd` tool. It cannot inspect commands spawned by scripts.
- **Pattern ordering matters.** When a command matches multiple patterns, the first match wins. Specific patterns (e.g., `docker rm`, `gcloud storage rm`) are ordered before generic ones (e.g., `rm -rf`) to ensure the right action and reason are applied.
- **Ask requires permission system.** The confirmation dialog for `ask` patterns relies on OpenCode's permission system being active. If a user's config has `bash: "allow"`, the `permission.ask` hook forces the dialog anyway -- but the exact UX depends on the OpenCode version.

---

## Development

```bash
npm install
npm run build    # output in dist/
npm test         # run 352 tests
```

[`src/index.ts`](src/index.ts) exports `DamageControl` as a named export conforming to the OpenCode `Plugin` type. Patterns, protected paths, and helpers live in [`src/patterns.ts`](src/patterns.ts). Configuration loading and merging live in [`src/config.ts`](src/config.ts).

### Architecture

```
src/patterns.ts
  |
  +-- DEFAULT_PATTERNS[]           108 patterns with action (block | ask)
  +-- DEFAULT_PROTECTED_PATHS[]    103 paths across 3 protection levels
  +-- matchPattern()               first-match regex against pattern list
  +-- checkPathProtection()        glob + prefix/substring path matching
  +-- checkShellPathViolation()    shell command operation detection
  +-- isShellWrite()               detects write operators (17 patterns)
  +-- isShellDelete()              detects delete operators (4 patterns)
  +-- expandHome()                 ~ -> $HOME expansion
  +-- globToRegex()                zero-dependency glob-to-regex conversion

src/config.ts
  |
  +-- loadConfig()                 reads global + project JSON, validates, merges
  +-- applyConfig()               pure function: remove -> override -> add
  +-- DamageControlConfig          config type (patterns + paths sections)

src/index.ts
  |
  +-- DamageControl                Plugin function returning two hooks:
       +-- loadConfig + applyConfig   at init, customizes defaults
       +-- tool.execute.before        inspect + block or stash
       +-- permission.ask             force confirmation for stashed items
```

### Project Structure

```
opencode-damage-control/
  src/
    index.ts              # Plugin entry point
    config.ts             # Config loading, validation, and merging
    patterns.ts           # Patterns, paths, and helpers
    config.test.ts        # 26 config tests (node:test)
    patterns.test.ts      # 326 pattern tests (node:test)
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
