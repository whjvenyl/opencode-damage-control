import type { Plugin } from "@opencode-ai/plugin"

type Action = 'block' | 'ask'

interface Pattern {
  pattern: string
  reason: string
  action: Action
}

interface ProtectedPath {
  path: string
  level: 'zeroAccess' | 'readOnly'
}

interface PendingAsk {
  reason: string
  match: string
  tool: string
}

// ---------------------------------------------------------------------------
// Dangerous command patterns
// ---------------------------------------------------------------------------
// action: 'block' = hard block, never executes
// action: 'ask'   = prompt user for confirmation via OpenCode permission dialog
// ---------------------------------------------------------------------------
const DEFAULT_PATTERNS: Pattern[] = [
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
const DEFAULT_PROTECTED_PATHS: ProtectedPath[] = [
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

function matchPattern(command: string, patterns: Pattern[]) {
  for (const p of patterns) {
    const regex = new RegExp(p.pattern, 'i')
    if (regex.test(command)) {
      return { match: command.match(regex)?.[0] || p.pattern, pattern: p }
    }
  }
  return null
}

function checkPathProtection(filePath: string, protectedPaths: ProtectedPath[]) {
  const home = process.env.HOME || ''
  for (const p of protectedPaths) {
    const expandedPath = p.path.replace('~', home)
    if (filePath.includes(expandedPath) || filePath.includes(p.path)) {
      return p
    }
  }
  return null
}

function expandHome(p: string): string {
  return p.replace('~', process.env.HOME || '')
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const DamageControl: Plugin = async ({ client, directory }) => {
  await client.app.log({
    body: {
      service: 'damage-control',
      level: 'info',
      message: 'Plugin initialized',
      extra: { directory },
    },
  })

  // Pending asks keyed by callID -- set in tool.execute.before,
  // consumed in permission.ask to force the confirmation dialog.
  const pendingAsks = new Map<string, PendingAsk>()

  return {
    // -----------------------------------------------------------------------
    // Hook 1: Inspect tool calls before execution
    //
    // - action:'block' -> throw immediately (hard block)
    // - action:'ask'   -> stash match, return void (proceed to permission
    //                     system where hook 2 forces the confirmation dialog)
    // -----------------------------------------------------------------------
    'tool.execute.before': async (input, output) => {
      const tool = input.tool
      const args = output.args

      await client.app.log({
        body: {
          service: 'damage-control',
          level: 'debug',
          message: 'tool.execute.before',
          extra: { tool, args: JSON.stringify(args).slice(0, 200) },
        },
      })

      // -- Shell commands --
      if (tool === 'bash' || tool === 'shell' || tool === 'cmd') {
        const command = args.command as string
        if (!command) return

        const result = matchPattern(command, DEFAULT_PATTERNS)
        if (result) {
          const { match, pattern } = result

          if (pattern.action === 'block') {
            await client.app.log({
              body: {
                service: 'damage-control',
                level: 'warn',
                message: 'Blocked dangerous command',
                extra: { command: command.slice(0, 100), reason: pattern.reason },
              },
            })
            throw new Error(
              `DAMAGE_CONTROL_BLOCKED: ${pattern.reason}\n\n` +
              `Command: ${match}`
            )
          }

          // action === 'ask' -- stash for permission.ask hook
          await client.app.log({
            body: {
              service: 'damage-control',
              level: 'warn',
              message: 'Flagged command for confirmation',
              extra: { command: command.slice(0, 100), reason: pattern.reason },
            },
          })
          pendingAsks.set(input.callID, {
            reason: pattern.reason,
            match,
            tool,
          })
          return // proceed to permission system
        }

        // Check protected paths in shell commands
        for (const prot of DEFAULT_PROTECTED_PATHS) {
          const expandedPath = expandHome(prot.path)
          if (command.includes(expandedPath) || command.includes(prot.path)) {
            await client.app.log({
              body: {
                service: 'damage-control',
                level: 'warn',
                message: 'Blocked access to protected path in command',
                extra: { command: command.slice(0, 100), path: prot.path },
              },
            })
            throw new Error(
              `DAMAGE_CONTROL_BLOCKED: Protected path "${prot.path}" cannot be accessed\n` +
              `Protection level: ${prot.level}`
            )
          }
        }
      }

      // -- Read operations --
      if (tool === 'read' || tool === 'glob' || tool === 'grep') {
        const filePath = args.filePath as string
        if (!filePath) return

        const prot = checkPathProtection(filePath, DEFAULT_PROTECTED_PATHS)
        if (prot && prot.level === 'zeroAccess') {
          await client.app.log({
            body: {
              service: 'damage-control',
              level: 'warn',
              message: 'Blocked read of protected path',
              extra: { filePath, path: prot.path },
            },
          })
          throw new Error(
            `DAMAGE_CONTROL_BLOCKED: Cannot read protected path "${prot.path}"`
          )
        }
      }

      // -- Write operations --
      if (tool === 'edit' || tool === 'write' || tool === 'create') {
        const filePath = args.filePath as string
        if (!filePath) return

        const prot = checkPathProtection(filePath, DEFAULT_PROTECTED_PATHS)
        if (prot) {
          await client.app.log({
            body: {
              service: 'damage-control',
              level: 'warn',
              message: `Blocked ${tool} on protected path`,
              extra: { filePath, path: prot.path, level: prot.level },
            },
          })
          throw new Error(
            `DAMAGE_CONTROL_BLOCKED: Cannot ${tool} protected path "${prot.path}"\n` +
            `Protection level: ${prot.level}`
          )
        }
      }
    },

    // -----------------------------------------------------------------------
    // Hook 2: Force confirmation dialog for ask-flagged operations
    //
    // When tool.execute.before stashes a match, this hook ensures the
    // user sees the interactive confirmation dialog -- even if their
    // permission config would normally allow the action.
    // -----------------------------------------------------------------------
    'permission.ask': async (input, output) => {
      const callID = input.callID
      if (!callID) return

      const pending = pendingAsks.get(callID)
      if (!pending) return

      // Clean up
      pendingAsks.delete(callID)

      await client.app.log({
        body: {
          service: 'damage-control',
          level: 'warn',
          message: 'Forcing confirmation dialog',
          extra: { reason: pending.reason, match: pending.match },
        },
      })

      // Force the confirmation dialog
      output.status = 'ask'
    },
  }
}
