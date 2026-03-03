import type { Plugin } from "@opencode-ai/plugin"
import {
  DEFAULT_PATTERNS,
  DEFAULT_PROTECTED_PATHS,
  matchPattern,
  checkPathProtection,
  checkShellPathViolation,
  unwrapShellCommand,
} from "./patterns.js"
import { loadConfig, applyConfig } from "./config.js"

interface PendingAsk {
  reason: string
  match: string
  tool: string
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const DamageControl: Plugin = async ({ client, directory }) => {
  // Load and apply custom configuration
  const { config, warnings } = loadConfig(directory)
  const { patterns, paths } = applyConfig(config, DEFAULT_PATTERNS, DEFAULT_PROTECTED_PATHS)

  const hasCustomConfig =
    config.patterns !== undefined || config.paths !== undefined

  await client.app.log({
    body: {
      service: 'damage-control',
      level: 'info',
      message: 'Plugin initialized',
      extra: {
        directory,
        customConfig: hasCustomConfig,
        patterns: patterns.length,
        paths: paths.length,
      },
    },
  })

  // Log any config validation warnings
  for (const warning of warnings) {
    await client.app.log({
      body: {
        service: 'damage-control',
        level: 'warn',
        message: warning,
      },
    })
  }

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

        // Unwrap shell wrappers (e.g. bash -c "rm -rf /") to inspect
        // the inner commands. The original command is checked first.
        const commandsToCheck = [command, ...unwrapShellCommand(command)]

        // 1. Check dangerous command patterns
        for (const cmd of commandsToCheck) {
          const result = matchPattern(cmd, patterns)
          if (result) {
            const { match, pattern } = result

            if (pattern.action === 'block') {
              await client.app.log({
                body: {
                  service: 'damage-control',
                  level: 'warn',
                  message: cmd === command
                    ? 'Blocked dangerous command'
                    : 'Blocked dangerous command (unwrapped from shell wrapper)',
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
                message: cmd === command
                  ? 'Flagged command for confirmation'
                  : 'Flagged command for confirmation (unwrapped from shell wrapper)',
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
        }

        // 2. Check three-tier path protection for shell commands
        //    zeroAccess: block if path appears in command at all
        //    readOnly:   block only writes/deletes (cat ~/.bashrc is fine)
        //    noDelete:   block only deletes (echo >> .gitignore is fine)
        for (const cmd of commandsToCheck) {
          const violation = checkShellPathViolation(cmd, paths)
          if (violation) {
            const { protectedPath: prot, operation } = violation
            const verb = operation === 'access' ? 'access'
              : operation === 'write' ? 'write to'
              : 'delete'
            await client.app.log({
              body: {
                service: 'damage-control',
                level: 'warn',
                message: cmd === command
                  ? `Blocked ${operation} on protected path in command`
                  : `Blocked ${operation} on protected path (unwrapped from shell wrapper)`,
                extra: { command: command.slice(0, 100), path: prot.path, level: prot.level },
              },
            })
            throw new Error(
              `DAMAGE_CONTROL_BLOCKED: Cannot ${verb} protected path "${prot.path}"\n` +
              `Protection level: ${prot.level}`
            )
          }
        }
      }

      // -- Read operations --
      // Only zeroAccess paths block reads. readOnly and noDelete allow reading.
      if (tool === 'read' || tool === 'glob' || tool === 'grep') {
        const filePath = args.filePath as string
        if (!filePath) return

        const prot = checkPathProtection(filePath, paths)
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

      // -- Write/edit operations --
      // zeroAccess and readOnly block writes. noDelete allows writes.
      if (tool === 'edit' || tool === 'write' || tool === 'create') {
        const filePath = args.filePath as string
        if (!filePath) return

        const prot = checkPathProtection(filePath, paths)
        if (prot && (prot.level === 'zeroAccess' || prot.level === 'readOnly')) {
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

      // -- Delete operations --
      // All three levels block deletes.
      if (tool === 'delete' || tool === 'remove') {
        const filePath = args.filePath as string
        if (!filePath) return

        const prot = checkPathProtection(filePath, paths)
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
