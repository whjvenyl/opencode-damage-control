// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Action = 'block' | 'ask'

export interface Pattern {
  pattern: string
  reason: string
  action: Action
}

export interface ProtectedPath {
  path: string
  level: 'zeroAccess' | 'readOnly'
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
  { pattern: 'git\\s+reset\\s+--hard', reason: 'git reset --hard (use --soft or stash)', action: 'ask' },
  { pattern: 'git\\s+clean\\s+(-[^\\s]*)*-[fd]', reason: 'git clean with force/directory flags', action: 'ask' },
  { pattern: 'git\\s+checkout\\s+--\\s*\\.', reason: 'Discard all uncommitted changes', action: 'ask' },
  { pattern: 'git\\s+restore\\s+\\.', reason: 'Discard all uncommitted changes', action: 'ask' },
  { pattern: 'git\\s+stash\\s+drop', reason: 'Permanently deletes a stash', action: 'ask' },
  { pattern: 'git\\s+branch\\s+(-[^\\s]*)*-D', reason: 'Force delete branch (even if unmerged)', action: 'ask' },
  { pattern: 'git\\s+push\\s+--delete', reason: 'Delete remote branch', action: 'ask' },
  { pattern: 'git\\s+push\\s+\\S+\\s+:\\S+', reason: 'Delete remote branch (refspec syntax)', action: 'ask' },

  // -- File operations (block sudo, ask rm -rf) --
  { pattern: 'sudo\\s+rm\\b', reason: 'sudo rm', action: 'block' },
  { pattern: '\\brm\\s+(-[^\\s]*)*-[rRf]', reason: 'rm with recursive or force flags', action: 'ask' },
  { pattern: '\\brm\\s+--recursive', reason: 'rm with --recursive flag', action: 'ask' },
  { pattern: '\\brm\\s+--force', reason: 'rm with --force flag', action: 'ask' },

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
  { pattern: 'gcloud\\s+projects\\s+delete', reason: 'gcloud projects delete', action: 'block' },
  { pattern: 'gcloud\\s+compute\\s+instances\\s+delete', reason: 'gcloud compute instances delete', action: 'ask' },
  { pattern: 'gcloud\\s+sql\\s+instances\\s+delete', reason: 'gcloud sql instances delete', action: 'ask' },
  { pattern: 'gcloud\\s+container\\s+clusters\\s+delete', reason: 'gcloud container clusters delete', action: 'ask' },

  // -- Docker / Kubernetes --
  { pattern: 'docker\\s+system\\s+prune\\s+.*-a', reason: 'docker system prune -a', action: 'ask' },
  { pattern: 'docker\\s+volume\\s+prune', reason: 'docker volume prune', action: 'ask' },
  { pattern: 'kubectl\\s+delete\\s+namespace', reason: 'kubectl delete namespace', action: 'ask' },
  { pattern: 'kubectl\\s+delete\\s+all\\s+--all', reason: 'kubectl delete all --all', action: 'block' },
  { pattern: 'helm\\s+uninstall', reason: 'helm uninstall', action: 'ask' },

  // -- Database CLIs --
  { pattern: 'redis-cli\\s+FLUSHALL', reason: 'redis FLUSHALL', action: 'block' },
  { pattern: 'redis-cli\\s+FLUSHDB', reason: 'redis FLUSHDB', action: 'ask' },
  { pattern: 'dropdb\\b', reason: 'PostgreSQL dropdb', action: 'block' },
  { pattern: 'mysqladmin\\s+drop', reason: 'MySQL drop database', action: 'block' },
  { pattern: 'mongosh.*dropDatabase', reason: 'MongoDB dropDatabase', action: 'block' },

  // -- Hosting / Deployment --
  { pattern: 'vercel\\s+remove\\s+.*--yes', reason: 'vercel remove --yes', action: 'ask' },
  { pattern: 'vercel\\s+projects\\s+rm', reason: 'vercel projects rm', action: 'ask' },
  { pattern: 'netlify\\s+sites:delete', reason: 'netlify sites:delete', action: 'ask' },
  { pattern: 'heroku\\s+apps:destroy', reason: 'heroku apps:destroy', action: 'ask' },
  { pattern: 'heroku\\s+pg:reset', reason: 'heroku pg:reset', action: 'ask' },
  { pattern: 'fly\\s+apps\\s+destroy', reason: 'fly apps destroy', action: 'ask' },
  { pattern: 'wrangler\\s+delete', reason: 'wrangler delete (Cloudflare Worker)', action: 'ask' },

  // -- Package Registries / GitHub --
  { pattern: 'npm\\s+unpublish', reason: 'npm unpublish', action: 'block' },
  { pattern: 'gh\\s+repo\\s+delete', reason: 'gh repo delete', action: 'block' },

  // -- History --
  { pattern: 'history\\s+-c', reason: 'Clear shell history', action: 'ask' },
]

// ---------------------------------------------------------------------------
// Protected paths
// ---------------------------------------------------------------------------
export const DEFAULT_PROTECTED_PATHS: ProtectedPath[] = [
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
  { path: '~/.git-credentials', level: 'zeroAccess' },
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

export function checkPathProtection(filePath: string, protectedPaths: ProtectedPath[]) {
  const home = process.env.HOME || ''
  for (const p of protectedPaths) {
    const expandedPath = p.path.replace('~', home)
    if (filePath.includes(expandedPath) || filePath.includes(p.path)) {
      return p
    }
  }
  return null
}

export function expandHome(p: string): string {
  return p.replace('~', process.env.HOME || '')
}
