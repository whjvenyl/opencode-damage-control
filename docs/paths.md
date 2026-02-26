# Protected Paths

[Back to README](../README.md)

**103 paths** across three protection levels. Enforcement varies by tool type and operation.

## Protection Matrix

| Level | Read | Write/Edit | Delete | Shell |
|-------|------|------------|--------|-------|
| **zeroAccess** | Block | Block | Block | Block if path referenced |
| **readOnly** | Allow | Block | Block | Block if writing or deleting |
| **noDelete** | Allow | Allow | Block | Block if deleting |

Shell commands are analyzed for write operators (`>`, `>>`, `tee`, `sed -i`, `cp`, `mv`, `chmod`, `touch`, `mkdir`, etc.) and delete operators (`rm`, `unlink`, `rmdir`, `shred`) to determine the actual operation being performed.

---

## zeroAccess (36 paths)

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

## readOnly (43 paths)

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

## noDelete (24 paths)

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

---

## Path Matching

- `~` is expanded to `$HOME` at runtime
- **Glob patterns** (`*`) match against the file basename (e.g., `*.pem` matches `/any/path/server.pem`)
- **Directory paths** (ending in `/`) match any file under that directory
- **Non-glob paths** use prefix/substring matching
