// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Action = 'block' | 'ask'

export interface Pattern {
  pattern: string
  reason: string
  action: Action
}

export type ProtectionLevel = 'zeroAccess' | 'readOnly' | 'noDelete'

export interface ProtectedPath {
  path: string
  level: ProtectionLevel
}

// ---------------------------------------------------------------------------
// Dangerous command patterns
// ---------------------------------------------------------------------------
// action: 'block' = hard block, never executes
// action: 'ask'   = prompt user for confirmation via OpenCode permission dialog
// ---------------------------------------------------------------------------
export const DEFAULT_PATTERNS: Pattern[] = [
  // -- System destruction (block) --
  { pattern: 'rm\\s+-rf\\s+/', reason: 'Recursive delete from root', action: 'block' },
  { pattern: ':\\(\\)\\ \\{:', reason: 'Fork bomb', action: 'block' },
  { pattern: 'fork\\(\\)', reason: 'Fork bomb', action: 'block' },
  { pattern: '>\\s*/dev/sd', reason: 'Direct device write', action: 'block' },
  { pattern: 'mkfs\\.', reason: 'Format filesystem', action: 'block' },
  { pattern: 'kill\\s+-9\\s+-1', reason: 'Kill all processes', action: 'block' },
  { pattern: 'killall\\s+-9', reason: 'Kill all processes', action: 'block' },
  { pattern: 'pkill\\s+-9', reason: 'pkill -9', action: 'block' },
  { pattern: 'shutdown', reason: 'System shutdown', action: 'block' },
  { pattern: 'reboot', reason: 'System reboot', action: 'block' },
  { pattern: 'init\\s+0', reason: 'System halt', action: 'block' },
  { pattern: 'format\\s+[a-z]:', reason: 'Windows format', action: 'block' },
  { pattern: 'dd\\s+.*of=/dev/', reason: 'dd writing to device', action: 'block' },

  // -- SQL (block catastrophic, ask targeted) --
  { pattern: 'DROP\\s+TABLE', reason: 'SQL DROP TABLE', action: 'block' },
  { pattern: 'DROP\\s+DATABASE', reason: 'SQL DROP DATABASE', action: 'block' },
  { pattern: 'DELETE\\s+FROM\\s+\\w+\\s*;', reason: 'SQL DELETE without WHERE clause', action: 'block' },
  { pattern: 'DELETE\\s+FROM\\s+\\w+\\s*$', reason: 'SQL DELETE without WHERE clause', action: 'block' },
  { pattern: 'DELETE\\s+\\*\\s+FROM', reason: 'SQL DELETE * (will delete ALL rows)', action: 'block' },
  { pattern: 'TRUNCATE\\s+TABLE', reason: 'SQL TRUNCATE TABLE', action: 'block' },
  { pattern: 'DELETE\\s+FROM\\s+\\w+\\s+WHERE\\b', reason: 'SQL DELETE with WHERE clause', action: 'ask' },

  // -- Shell piping (block) --
  { pattern: 'curl.*\\|\\s*sh', reason: 'Pipe curl to shell', action: 'block' },
  { pattern: 'wget.*\\|\\s*sh', reason: 'Pipe wget to shell', action: 'block' },

  // -- Git (block irreversible, ask recoverable) --
  { pattern: 'git\\s+push\\s+.*--force(?!-with-lease)', reason: 'git push --force (use --force-with-lease)', action: 'block' },
  { pattern: 'git\\s+push\\s+(-[^\\s]*)*-f\\b', reason: 'git push -f (use --force-with-lease)', action: 'block' },
  { pattern: 'git\\s+stash\\s+clear', reason: 'git stash clear (deletes ALL stashes)', action: 'block' },
  { pattern: 'git\\s+filter-branch', reason: 'git filter-branch (rewrites entire history)', action: 'block' },
  { pattern: 'git\\s+reflog\\s+expire', reason: 'git reflog expire (destroys recovery mechanism)', action: 'block' },
  { pattern: 'git\\s+gc\\s+.*--prune=now', reason: 'git gc --prune=now (can lose dangling commits)', action: 'block' },
  { pattern: 'git\\s+reset\\s+--hard', reason: 'git reset --hard (use --soft or stash)', action: 'ask' },
  { pattern: 'git\\s+clean\\s+(-[^\\s]*)*-[fd]', reason: 'git clean with force/directory flags', action: 'ask' },
  { pattern: 'git\\s+checkout\\s+--\\s*\\.', reason: 'Discard all uncommitted changes', action: 'ask' },
  { pattern: 'git\\s+restore\\s+\\.', reason: 'Discard all uncommitted changes', action: 'ask' },
  { pattern: 'git\\s+stash\\s+drop', reason: 'Permanently deletes a stash', action: 'ask' },
  { pattern: 'git\\s+branch\\s+(-[^\\s]*)*-D', reason: 'Force delete branch (even if unmerged)', action: 'ask' },
  { pattern: 'git\\s+push\\s+--delete', reason: 'Delete remote branch', action: 'ask' },
  { pattern: 'git\\s+push\\s+\\S+\\s+:\\S+', reason: 'Delete remote branch (refspec syntax)', action: 'ask' },

  // -- File operations (block sudo, ask rm -rf) --
  // NOTE: specific rm patterns (docker, gcloud) must come before generic rm
  { pattern: 'docker\\s+rm\\s+.*-f.*\\$\\(docker\\s+ps', reason: 'docker rm -f $(docker ps) (force removes containers)', action: 'block' },
  { pattern: 'gcloud\\s+storage\\s+rm\\s+.*-r', reason: 'gcloud storage rm -r (recursive delete)', action: 'ask' },
  { pattern: 'sudo\\s+rm\\b', reason: 'sudo rm', action: 'block' },
  { pattern: '\\brm\\s+(-[^\\s]*)*-[rRf]', reason: 'rm with recursive or force flags', action: 'ask' },
  { pattern: '\\brm\\s+--recursive', reason: 'rm with --recursive flag', action: 'ask' },
  { pattern: '\\brm\\s+--force', reason: 'rm with --force flag', action: 'ask' },
  { pattern: '\\brmdir\\s+--ignore-fail-on-non-empty', reason: 'rmdir ignore-fail', action: 'ask' },

  // -- Permissions (ask) --
  { pattern: 'chmod\\s+(-[^\\s]+\\s+)*777', reason: 'chmod 777 (world writable)', action: 'ask' },
  { pattern: 'chmod\\s+-[Rr].*777', reason: 'Recursive chmod 777', action: 'ask' },
  { pattern: 'chown\\s+-[Rr]', reason: 'Recursive ownership change', action: 'ask' },

  // -- Cloud / Infrastructure --
  { pattern: 'terraform\\s+destroy', reason: 'terraform destroy', action: 'block' },
  { pattern: 'pulumi\\s+destroy', reason: 'pulumi destroy', action: 'block' },
  { pattern: 'aws\\s+s3\\s+rm\\s+.*--recursive', reason: 'aws s3 rm --recursive', action: 'block' },
  { pattern: 'aws\\s+s3\\s+rb\\s+.*--force', reason: 'aws s3 rb --force', action: 'block' },
  { pattern: 'aws\\s+ec2\\s+terminate-instances', reason: 'aws ec2 terminate-instances', action: 'ask' },
  { pattern: 'aws\\s+rds\\s+delete-db-instance', reason: 'aws rds delete-db-instance', action: 'ask' },
  { pattern: 'aws\\s+cloudformation\\s+delete-stack', reason: 'aws cloudformation delete-stack', action: 'ask' },
  { pattern: 'aws\\s+dynamodb\\s+delete-table', reason: 'aws dynamodb delete-table', action: 'ask' },
  { pattern: 'aws\\s+eks\\s+delete-cluster', reason: 'aws eks delete-cluster', action: 'ask' },
  { pattern: 'aws\\s+lambda\\s+delete-function', reason: 'aws lambda delete-function', action: 'ask' },
  { pattern: 'aws\\s+iam\\s+delete-role', reason: 'aws iam delete-role', action: 'ask' },
  { pattern: 'aws\\s+iam\\s+delete-user', reason: 'aws iam delete-user', action: 'ask' },
  { pattern: 'gcloud\\s+projects\\s+delete', reason: 'gcloud projects delete', action: 'block' },
  { pattern: 'gcloud\\s+compute\\s+instances\\s+delete', reason: 'gcloud compute instances delete', action: 'ask' },
  { pattern: 'gcloud\\s+sql\\s+instances\\s+delete', reason: 'gcloud sql instances delete', action: 'ask' },
  { pattern: 'gcloud\\s+container\\s+clusters\\s+delete', reason: 'gcloud container clusters delete', action: 'ask' },
  { pattern: 'gcloud\\s+functions\\s+delete', reason: 'gcloud functions delete', action: 'ask' },
  { pattern: 'gcloud\\s+iam\\s+service-accounts\\s+delete', reason: 'gcloud iam service-accounts delete', action: 'ask' },

  // -- Docker / Kubernetes --
  { pattern: 'docker\\s+system\\s+prune\\s+.*-a', reason: 'docker system prune -a', action: 'ask' },
  { pattern: 'docker\\s+rmi\\s+.*-f', reason: 'docker rmi -f (force removes images)', action: 'ask' },
  { pattern: 'docker\\s+volume\\s+rm', reason: 'docker volume rm (data loss)', action: 'ask' },
  { pattern: 'docker\\s+volume\\s+prune', reason: 'docker volume prune', action: 'ask' },
  { pattern: 'kubectl\\s+delete\\s+namespace', reason: 'kubectl delete namespace', action: 'ask' },
  { pattern: 'kubectl\\s+delete\\s+all\\s+--all', reason: 'kubectl delete all --all', action: 'block' },
  { pattern: 'kubectl\\s+delete\\s+.*--all\\s+--all-namespaces', reason: 'kubectl delete across all namespaces', action: 'block' },
  { pattern: 'helm\\s+uninstall', reason: 'helm uninstall', action: 'ask' },

  // -- Database CLIs --
  { pattern: 'redis-cli\\s+FLUSHALL', reason: 'redis FLUSHALL', action: 'block' },
  { pattern: 'redis-cli\\s+FLUSHDB', reason: 'redis FLUSHDB', action: 'ask' },
  { pattern: 'dropdb\\b', reason: 'PostgreSQL dropdb', action: 'block' },
  { pattern: 'mysqladmin\\s+drop', reason: 'MySQL drop database', action: 'block' },
  { pattern: 'mongosh.*dropDatabase', reason: 'MongoDB dropDatabase', action: 'block' },
  { pattern: 'mongo.*dropDatabase', reason: 'MongoDB dropDatabase (legacy shell)', action: 'block' },

  // -- Hosting / Deployment --
  { pattern: 'vercel\\s+remove\\s+.*--yes', reason: 'vercel remove --yes', action: 'ask' },
  { pattern: 'vercel\\s+projects\\s+rm', reason: 'vercel projects rm', action: 'ask' },
  { pattern: 'vercel\\s+env\\s+rm\\s+.*--yes', reason: 'vercel env rm --yes', action: 'ask' },
  { pattern: 'netlify\\s+sites:delete', reason: 'netlify sites:delete', action: 'ask' },
  { pattern: 'netlify\\s+functions:delete', reason: 'netlify functions:delete', action: 'ask' },
  { pattern: 'heroku\\s+apps:destroy', reason: 'heroku apps:destroy', action: 'ask' },
  { pattern: 'heroku\\s+pg:reset', reason: 'heroku pg:reset', action: 'ask' },
  { pattern: 'fly\\s+apps\\s+destroy', reason: 'fly apps destroy', action: 'ask' },
  { pattern: 'fly\\s+destroy', reason: 'fly destroy', action: 'ask' },
  { pattern: 'wrangler\\s+delete', reason: 'wrangler delete (Cloudflare Worker)', action: 'ask' },
  { pattern: 'wrangler\\s+r2\\s+bucket\\s+delete', reason: 'wrangler r2 bucket delete', action: 'ask' },
  { pattern: 'wrangler\\s+kv:namespace\\s+delete', reason: 'wrangler kv:namespace delete', action: 'ask' },
  { pattern: 'wrangler\\s+d1\\s+delete', reason: 'wrangler d1 delete', action: 'ask' },
  { pattern: 'wrangler\\s+queues\\s+delete', reason: 'wrangler queues delete', action: 'ask' },

  // -- Firebase --
  { pattern: 'firebase\\s+projects:delete', reason: 'firebase projects:delete', action: 'block' },
  { pattern: 'firebase\\s+firestore:delete\\s+.*--all-collections', reason: 'firebase firestore:delete --all-collections', action: 'block' },
  { pattern: 'firebase\\s+database:remove', reason: 'firebase database:remove', action: 'ask' },
  { pattern: 'firebase\\s+hosting:disable', reason: 'firebase hosting:disable', action: 'ask' },
  { pattern: 'firebase\\s+functions:delete', reason: 'firebase functions:delete', action: 'ask' },

  // -- Serverless / SAM --
  { pattern: 'serverless\\s+remove', reason: 'serverless remove (removes stack)', action: 'ask' },
  { pattern: 'sls\\s+remove', reason: 'sls remove (removes stack)', action: 'ask' },
  { pattern: 'sam\\s+delete', reason: 'sam delete (deletes SAM application)', action: 'ask' },

  // -- DigitalOcean --
  { pattern: 'doctl\\s+compute\\s+droplet\\s+delete', reason: 'doctl droplet delete', action: 'ask' },
  { pattern: 'doctl\\s+databases\\s+delete', reason: 'doctl databases delete', action: 'ask' },

  // -- Supabase --
  { pattern: 'supabase\\s+db\\s+reset', reason: 'supabase db reset', action: 'ask' },

  // -- Package Registries / GitHub --
  { pattern: 'npm\\s+unpublish', reason: 'npm unpublish', action: 'block' },
  { pattern: 'gh\\s+repo\\s+delete', reason: 'gh repo delete', action: 'block' },

  // -- History --
  { pattern: 'history\\s+-c', reason: 'Clear shell history', action: 'ask' },
]

// ---------------------------------------------------------------------------
// Protected paths
// ---------------------------------------------------------------------------
//
// Protection matrix:
//   zeroAccess  = block read + write + edit + delete (secrets, credentials)
//   readOnly    = allow read, block write + edit + delete (system dirs, configs)
//   noDelete    = allow read + write + edit, block delete only (project infra)
//
// Path syntax:
//   - Literal prefix match: '~/.ssh', '/etc/'
//   - Glob wildcards:  '*' matches any characters except '/'
//                      '**' is not needed — we match basename or full path
//   - Tilde is expanded to $HOME at match time
//
// ---------------------------------------------------------------------------

export const DEFAULT_PROTECTED_PATHS: ProtectedPath[] = [
  // -- zeroAccess: secrets and credentials -----------------------------------
  { path: '~/.ssh', level: 'zeroAccess' },
  { path: '~/.aws', level: 'zeroAccess' },
  { path: '~/.gnupg', level: 'zeroAccess' },
  { path: '~/.config/gcloud', level: 'zeroAccess' },
  { path: '~/.azure', level: 'zeroAccess' },
  { path: '~/.kube', level: 'zeroAccess' },
  { path: '~/.docker', level: 'zeroAccess' },
  { path: '/etc/passwd', level: 'zeroAccess' },
  { path: '/etc/shadow', level: 'zeroAccess' },
  { path: '~/.config/opencode', level: 'zeroAccess' },
  { path: '~/.netrc', level: 'zeroAccess' },
  { path: '~/.npmrc', level: 'zeroAccess' },
  { path: '~/.pypirc', level: 'zeroAccess' },
  { path: '~/.git-credentials', level: 'zeroAccess' },
  { path: '.git-credentials', level: 'zeroAccess' },
  // Glob-style patterns (matched against basename)
  { path: '.env*', level: 'zeroAccess' },
  { path: '*.pem', level: 'zeroAccess' },
  { path: '*.key', level: 'zeroAccess' },
  { path: '*.p12', level: 'zeroAccess' },
  { path: '*.pfx', level: 'zeroAccess' },
  { path: '*.tfstate*', level: 'zeroAccess' },
  { path: '.terraform/', level: 'zeroAccess' },
  { path: '*-credentials.json', level: 'zeroAccess' },
  { path: '*serviceAccount*.json', level: 'zeroAccess' },
  { path: '*service-account*.json', level: 'zeroAccess' },
  { path: 'serviceAccountKey.json', level: 'zeroAccess' },
  { path: 'kubeconfig', level: 'zeroAccess' },
  { path: '*-secret.yaml', level: 'zeroAccess' },
  { path: 'secrets.yaml', level: 'zeroAccess' },
  { path: '.vercel/', level: 'zeroAccess' },
  { path: '.netlify/', level: 'zeroAccess' },
  { path: 'firebase-adminsdk*.json', level: 'zeroAccess' },
  { path: '.supabase/', level: 'zeroAccess' },
  { path: 'dump.sql', level: 'zeroAccess' },
  { path: 'backup.sql', level: 'zeroAccess' },
  { path: '*.dump', level: 'zeroAccess' },

  // -- readOnly: system directories and generated files ----------------------
  { path: '/etc/', level: 'readOnly' },
  { path: '/usr/', level: 'readOnly' },
  { path: '/bin/', level: 'readOnly' },
  { path: '/sbin/', level: 'readOnly' },
  { path: '/boot/', level: 'readOnly' },
  { path: '/root/', level: 'readOnly' },
  // Shell history
  { path: '~/.bash_history', level: 'readOnly' },
  { path: '~/.zsh_history', level: 'readOnly' },
  { path: '~/.node_repl_history', level: 'readOnly' },
  // Shell configs
  { path: '~/.bashrc', level: 'readOnly' },
  { path: '~/.zshrc', level: 'readOnly' },
  { path: '~/.profile', level: 'readOnly' },
  { path: '~/.bash_profile', level: 'readOnly' },
  // Lock files
  { path: 'package-lock.json', level: 'readOnly' },
  { path: 'yarn.lock', level: 'readOnly' },
  { path: 'pnpm-lock.yaml', level: 'readOnly' },
  { path: 'Gemfile.lock', level: 'readOnly' },
  { path: 'Cargo.lock', level: 'readOnly' },
  { path: 'poetry.lock', level: 'readOnly' },
  { path: 'composer.lock', level: 'readOnly' },
  { path: 'go.sum', level: 'readOnly' },
  { path: 'Pipfile.lock', level: 'readOnly' },
  { path: 'flake.lock', level: 'readOnly' },
  { path: 'bun.lockb', level: 'readOnly' },
  { path: 'uv.lock', level: 'readOnly' },
  { path: 'npm-shrinkwrap.json', level: 'readOnly' },
  // Generic lock file globs
  { path: '*.lock', level: 'readOnly' },
  { path: '*.lockb', level: 'readOnly' },
  // Minified / bundled
  { path: '*.min.js', level: 'readOnly' },
  { path: '*.min.css', level: 'readOnly' },
  { path: '*.bundle.js', level: 'readOnly' },
  { path: '*.chunk.js', level: 'readOnly' },
  // Build output directories
  { path: 'dist/', level: 'readOnly' },
  { path: 'build/', level: 'readOnly' },
  { path: 'out/', level: 'readOnly' },
  { path: '.next/', level: 'readOnly' },
  { path: '.nuxt/', level: 'readOnly' },
  { path: '.output/', level: 'readOnly' },
  { path: 'node_modules/', level: 'readOnly' },
  { path: '__pycache__/', level: 'readOnly' },
  { path: '.venv/', level: 'readOnly' },
  { path: 'venv/', level: 'readOnly' },
  { path: 'target/', level: 'readOnly' },

  // -- noDelete: project infrastructure files --------------------------------
  { path: '~/.claude/', level: 'noDelete' },
  { path: 'CLAUDE.md', level: 'noDelete' },
  { path: 'LICENSE*', level: 'noDelete' },
  { path: 'COPYING*', level: 'noDelete' },
  { path: 'NOTICE', level: 'noDelete' },
  { path: 'PATENTS', level: 'noDelete' },
  { path: 'README*', level: 'noDelete' },
  { path: 'CONTRIBUTING.md', level: 'noDelete' },
  { path: 'CHANGELOG.md', level: 'noDelete' },
  { path: 'CODE_OF_CONDUCT.md', level: 'noDelete' },
  { path: 'SECURITY.md', level: 'noDelete' },
  { path: '.git/', level: 'noDelete' },
  { path: '.gitignore', level: 'noDelete' },
  { path: '.gitattributes', level: 'noDelete' },
  { path: '.gitmodules', level: 'noDelete' },
  { path: '.github/', level: 'noDelete' },
  { path: '.gitlab-ci.yml', level: 'noDelete' },
  { path: '.circleci/', level: 'noDelete' },
  { path: 'Jenkinsfile', level: 'noDelete' },
  { path: '.travis.yml', level: 'noDelete' },
  { path: 'azure-pipelines.yml', level: 'noDelete' },
  { path: 'Dockerfile*', level: 'noDelete' },
  { path: 'docker-compose*.yml', level: 'noDelete' },
  { path: '.dockerignore', level: 'noDelete' },
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function matchPattern(command: string, patterns: Pattern[]) {
  for (const p of patterns) {
    const regex = new RegExp(p.pattern, 'i')
    if (regex.test(command)) {
      return { match: command.match(regex)?.[0] || p.pattern, pattern: p }
    }
  }
  return null
}

/**
 * Convert a simple glob pattern (supporting only `*`) into a RegExp.
 * Used to match path entries like `*.pem`, `.env*`, `*-credentials.json`
 * against a filename or path segment.
 */
function globToRegex(glob: string): RegExp {
  // Escape regex metacharacters, then convert `*` (now `\\*`) back to `.*`
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  const pattern = escaped.replace(/\*/g, '.*')
  return new RegExp(`^${pattern}$`)
}

/**
 * Returns true if `glob` contains wildcard characters and should be matched
 * against the basename (filename) of a path rather than as a prefix/substring.
 */
function isGlobPattern(path: string): boolean {
  return path.includes('*')
}

/**
 * Extract the basename from a file path. Handles trailing slashes.
 * e.g. '/home/user/.env.local' -> '.env.local'
 *      '/home/user/dist/'      -> 'dist'
 */
function basename(filePath: string): string {
  const trimmed = filePath.replace(/\/+$/, '')
  const idx = trimmed.lastIndexOf('/')
  return idx === -1 ? trimmed : trimmed.slice(idx + 1)
}

export function expandHome(p: string): string {
  return p.replace('~', process.env.HOME || '')
}

/**
 * Check if a file path is protected. Returns the matching ProtectedPath or null.
 *
 * Matching strategy:
 *   1. Glob patterns (contain `*`): match against the basename of `filePath`
 *   2. Directory patterns (end with `/`): check if `filePath` starts with or contains the dir
 *   3. Literal patterns: substring match against the full path
 *
 * For all strategies, `~` is expanded to $HOME before matching.
 */
export function checkPathProtection(filePath: string, protectedPaths: ProtectedPath[]) {
  const home = process.env.HOME || ''

  for (const p of protectedPaths) {
    if (isGlobPattern(p.path)) {
      // Glob: match against basename of the file path
      const name = basename(filePath)
      const regex = globToRegex(p.path)
      if (regex.test(name)) return p
      continue
    }

    // Non-glob: expand home and do prefix/substring matching
    const expandedPath = p.path.replace('~', home)
    if (filePath.includes(expandedPath) || filePath.includes(p.path)) {
      return p
    }
  }

  return null
}

// ---------------------------------------------------------------------------
// Shell operation classifiers
// ---------------------------------------------------------------------------
// Detect whether a shell command performs a write or delete operation
// targeting a specific path. Used to enforce readOnly and noDelete levels
// on bash/shell tool invocations.
// ---------------------------------------------------------------------------

/** Patterns that indicate a shell command writes/modifies files */
const SHELL_WRITE_OPS = [
  /(?:^|[;&|]\s*)(?:>|>>)\s*/,                          // redirect: > file, >> file
  /\btee\s+(?:-a\s+)?/,                                 // tee file, tee -a file
  /\bsed\s+(-[^\s]*\s+)*-i/,                            // sed -i (in-place edit)
  /\bsed\s+--in-place/,                                 // sed --in-place
  /\bcp\s+/,                                             // cp (copy to target)
  /\bmv\s+/,                                             // mv (rename/move = write target)
  /\bchmod\s+/,                                          // chmod (modify perms)
  /\bchown\s+/,                                          // chown (modify owner)
  /\bln\s+/,                                             // ln (create link)
  /\binstall\s+/,                                        // install (copy + set perms)
  /\bpatch\s+/,                                          // patch (modify file)
  /\btruncate\s+/,                                       // truncate (modify file)
  /\bdd\s+/,                                             // dd (write to target)
  /\btouch\s+/,                                          // touch (create/modify timestamp)
  /\bmkdir\s+/,                                          // mkdir (create dir)
  /\becho\s+.*(?:>|>>)\s*/,                              // echo ... > file
  /\bprintf\s+.*(?:>|>>)\s*/,                            // printf ... > file
  /\bcat\s+.*(?:>|>>)\s*/,                               // cat ... > file (writing, not reading)
]

/** Patterns that indicate a shell command deletes files */
const SHELL_DELETE_OPS = [
  /\brm\s+/,                                             // rm
  /\bunlink\s+/,                                         // unlink
  /\brmdir\s+/,                                          // rmdir
  /\bshred\s+/,                                          // shred (secure delete)
]

/**
 * Check if a path reference appears in the command. Expands `~` and checks
 * both the raw and expanded forms. For glob-pattern protected paths,
 * extracts all path-like tokens from the command and matches basenames.
 */
function commandReferencesPath(command: string, protPath: string): boolean {
  const home = process.env.HOME || ''

  if (isGlobPattern(protPath)) {
    // Extract path-like tokens and match basenames against the glob
    const regex = globToRegex(protPath)
    const tokens = command.split(/\s+/)
    for (const token of tokens) {
      const name = basename(token)
      if (name && regex.test(name)) return true
    }
    return false
  }

  const expanded = protPath.replace('~', home)
  return command.includes(expanded) || command.includes(protPath)
}

/**
 * Check if a shell command performs a write operation on a specific path.
 * Returns true if any write operator is detected AND the protected path
 * appears in the command.
 */
export function isShellWrite(command: string, protPath: string): boolean {
  if (!commandReferencesPath(command, protPath)) return false
  for (const op of SHELL_WRITE_OPS) {
    if (op.test(command)) return true
  }
  return false
}

/**
 * Check if a shell command performs a delete operation on a specific path.
 * Returns true if any delete operator is detected AND the protected path
 * appears in the command.
 */
export function isShellDelete(command: string, protPath: string): boolean {
  if (!commandReferencesPath(command, protPath)) return false
  for (const op of SHELL_DELETE_OPS) {
    if (op.test(command)) return true
  }
  return false
}

/**
 * Check all protected paths against a shell command and return the first
 * violation, or null if the command is safe.
 *
 * Enforcement rules:
 *   zeroAccess: block if path appears anywhere in command
 *   readOnly:   block if command writes or deletes the path
 *   noDelete:   block if command deletes the path
 */
export function checkShellPathViolation(
  command: string,
  protectedPaths: ProtectedPath[],
): { protectedPath: ProtectedPath; operation: 'access' | 'write' | 'delete' } | null {
  for (const p of protectedPaths) {
    switch (p.level) {
      case 'zeroAccess':
        if (commandReferencesPath(command, p.path)) {
          return { protectedPath: p, operation: 'access' }
        }
        break

      case 'readOnly':
        if (isShellWrite(command, p.path)) {
          return { protectedPath: p, operation: 'write' }
        }
        if (isShellDelete(command, p.path)) {
          return { protectedPath: p, operation: 'delete' }
        }
        break

      case 'noDelete':
        if (isShellDelete(command, p.path)) {
          return { protectedPath: p, operation: 'delete' }
        }
        break
    }
  }
  return null
}
