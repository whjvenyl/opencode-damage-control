import type { Plugin } from "@opencode-ai/plugin"
import {
  DEFAULT_PATTERNS,
  DEFAULT_PROTECTED_PATHS,
  matchPattern,
  checkPathProtection,
  expandHome,
} from "./patterns.js"

interface PendingAsk {
  reason: string
  match: string
  tool: string
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
