import type { Plugin } from "@opencode-ai/plugin"

const DEFAULT_PATTERNS = [
  { pattern: 'rm\\s+-rf\\s+/', reason: 'Recursive delete from root', severity: 'critical' },
  { pattern: ':\\(\\)\\ \{:', reason: 'Fork bomb', severity: 'critical' },
  { pattern: 'fork\\(\\)', reason: 'Fork bomb', severity: 'critical' },
  { pattern: 'DROP\\s+TABLE', reason: 'SQL drop table', severity: 'high' },
  { pattern: 'DROP\\s+DATABASE', reason: 'SQL drop database', severity: 'high' },
  { pattern: 'DELETE\\s+FROM', reason: 'SQL delete all', severity: 'medium' },
  { pattern: 'TRUNCATE\\s+', reason: 'SQL truncate', severity: 'medium' },
  { pattern: 'git\\s+push\\s+--force', reason: 'Force push', severity: 'high' },
  { pattern: 'git\\s+push\\s+-f', reason: 'Force push', severity: 'high' },
  { pattern: 'git\\s+push\\s+--delete', reason: 'Remote delete', severity: 'medium' },
  { pattern: '\\>\\s*/dev/sd', reason: 'Direct device write', severity: 'critical' },
  { pattern: 'dd\\s+if=', reason: 'Direct disk operation', severity: 'high' },
  { pattern: 'mkfs\\.', reason: 'Format filesystem', severity: 'critical' },
  { pattern: 'chmod\\s+-R\\s+777', reason: 'World-writable permissions', severity: 'medium' },
  { pattern: 'chown\\s+-R', reason: 'Recursive ownership change', severity: 'medium' },
  { pattern: 'kill\\s+-9\\s+-1', reason: 'Kill all processes', severity: 'critical' },
  { pattern: 'killall\\s+-9', reason: 'Kill all processes', severity: 'critical' },
  { pattern: 'shutdown', reason: 'System shutdown', severity: 'critical' },
  { pattern: 'reboot', reason: 'System reboot', severity: 'critical' },
  { pattern: 'init\\s+0', reason: 'System halt', severity: 'critical' },
  { pattern: 'curl.*\\|\\s*sh', reason: 'Pipe to shell', severity: 'high' },
  { pattern: 'wget.*\\|\\s*sh', reason: 'Pipe to shell', severity: 'high' },
  { pattern: 'format\\s+[a-z]:', reason: 'Windows format', severity: 'critical' },
]

const DEFAULT_PROTECTED_PATHS = [
  { path: '~/.ssh', level: 'zeroAccess' },
  { path: '~/.aws', level: 'zeroAccess' },
  { path: '~/.gnupg', level: 'zeroAccess' },
  { path: '/etc/passwd', level: 'zeroAccess' },
  { path: '/etc/shadow', level: 'zeroAccess' },
  { path: '~/.config/opencode', level: 'zeroAccess' },
]

function matchPattern(command: string, patterns: typeof DEFAULT_PATTERNS) {
  for (const p of patterns) {
    const regex = new RegExp(p.pattern, 'i')
    if (regex.test(command)) {
      return { match: command.match(regex)?.[0] || p.pattern, pattern: p }
    }
  }
  return null
}

function checkPathProtection(filePath: string, protectedPaths: typeof DEFAULT_PROTECTED_PATHS) {
  for (const p of protectedPaths) {
    const expandedPath = p.path.replace('~', process.env.HOME || '')
    if (filePath.includes(expandedPath) || filePath.includes(p.path)) {
      return p
    }
  }
  return null
}

export const DamageControl: Plugin = async ({ client, directory }) => {
  await client.app.log({
    body: {
      service: 'damage-control',
      level: 'info',
      message: 'Plugin initialized',
      extra: { directory },
    },
  })

  return {
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

      if (tool === 'bash' || tool === 'shell' || tool === 'cmd') {
        const command = args.command as string
        if (!command) return

        const match = matchPattern(command, DEFAULT_PATTERNS)
        if (match) {
          await client.app.log({
            body: {
              service: 'damage-control',
              level: 'warn',
              message: 'Blocked dangerous command',
              extra: { command: command.slice(0, 100), pattern: match.pattern.reason },
            },
          })
          throw new Error(
            `DAMAGE_CONTROL_BLOCKED: ${match.pattern.reason}\n\n` +
            `Command: ${match.match}\n` +
            `Severity: ${match.pattern.severity}`
          )
        }

        for (const prot of DEFAULT_PROTECTED_PATHS) {
          const expandedPath = prot.path.replace('~', process.env.HOME || '')
          if (command.includes(expandedPath) || command.includes(prot.path)) {
            await client.app.log({
              body: {
                service: 'damage-control',
                level: 'warn',
                message: 'Blocked access to protected path',
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
  }
}
