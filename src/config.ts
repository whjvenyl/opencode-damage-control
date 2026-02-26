import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Action, Pattern, ProtectedPath, ProtectionLevel } from './patterns.js'

// ---------------------------------------------------------------------------
// Config types
// ---------------------------------------------------------------------------

export interface DamageControlConfig {
  patterns?: {
    /** Extra patterns appended after defaults */
    add?: Pattern[]
    /** Remove default patterns by exact reason string */
    remove?: string[]
    /** Change the action of existing patterns by reason string */
    override?: Record<string, Action>
  }
  paths?: {
    /** Extra protected paths appended after defaults */
    add?: ProtectedPath[]
    /** Remove default paths by exact path string */
    remove?: string[]
    /** Change protection level of existing paths, or 'none' to unprotect */
    override?: Record<string, ProtectionLevel | 'none'>
  }
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

function globalConfig(): string {
  return join(process.env.HOME || '', '.config', 'opencode', 'damage-control.json')
}

function projectConfig(directory: string): string {
  return join(directory, '.opencode', 'damage-control.json')
}

function readJsonFile(path: string): unknown | null {
  try {
    return JSON.parse(readFileSync(path, 'utf-8'))
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const VALID_ACTIONS: ReadonlySet<string> = new Set(['block', 'ask'])
const VALID_LEVELS: ReadonlySet<string> = new Set(['zeroAccess', 'readOnly', 'noDelete', 'none'])

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function isValidPattern(v: unknown): v is Pattern {
  return (
    isObject(v) &&
    typeof v.pattern === 'string' &&
    typeof v.reason === 'string' &&
    VALID_ACTIONS.has(v.action as string)
  )
}

function isValidProtectedPath(v: unknown): v is ProtectedPath {
  return (
    isObject(v) &&
    typeof v.path === 'string' &&
    VALID_LEVELS.has(v.level as string) &&
    v.level !== 'none'
  )
}

/**
 * Validate and sanitize a raw parsed config object.
 * Returns a clean DamageControlConfig plus any warnings.
 */
function validateConfig(
  raw: unknown,
  source: string,
): { config: DamageControlConfig; warnings: string[] } {
  const warnings: string[] = []
  const config: DamageControlConfig = {}

  if (!isObject(raw)) {
    warnings.push(`${source}: config is not an object, ignoring`)
    return { config, warnings }
  }

  // -- patterns --
  if (raw.patterns !== undefined) {
    if (!isObject(raw.patterns)) {
      warnings.push(`${source}: "patterns" is not an object, ignoring`)
    } else {
      const p = raw.patterns
      config.patterns = {}

      // patterns.add
      if (p.add !== undefined) {
        if (!Array.isArray(p.add)) {
          warnings.push(`${source}: "patterns.add" is not an array, ignoring`)
        } else {
          const valid: Pattern[] = []
          for (let i = 0; i < p.add.length; i++) {
            if (isValidPattern(p.add[i])) {
              valid.push(p.add[i] as Pattern)
            } else {
              warnings.push(
                `${source}: "patterns.add[${i}]" is invalid (need pattern, reason, action), skipping`,
              )
            }
          }
          if (valid.length > 0) config.patterns.add = valid
        }
      }

      // patterns.remove
      if (p.remove !== undefined) {
        if (!Array.isArray(p.remove)) {
          warnings.push(`${source}: "patterns.remove" is not an array, ignoring`)
        } else {
          const valid = p.remove.filter((v: unknown) => typeof v === 'string') as string[]
          if (valid.length !== p.remove.length) {
            warnings.push(`${source}: some "patterns.remove" entries are not strings, skipping those`)
          }
          if (valid.length > 0) config.patterns.remove = valid
        }
      }

      // patterns.override
      if (p.override !== undefined) {
        if (!isObject(p.override)) {
          warnings.push(`${source}: "patterns.override" is not an object, ignoring`)
        } else {
          const valid: Record<string, Action> = {}
          for (const [key, val] of Object.entries(p.override)) {
            if (VALID_ACTIONS.has(val as string)) {
              valid[key] = val as Action
            } else {
              warnings.push(
                `${source}: "patterns.override[${JSON.stringify(key)}]" has invalid action "${val}", skipping`,
              )
            }
          }
          if (Object.keys(valid).length > 0) config.patterns.override = valid
        }
      }
    }
  }

  // -- paths --
  if (raw.paths !== undefined) {
    if (!isObject(raw.paths)) {
      warnings.push(`${source}: "paths" is not an object, ignoring`)
    } else {
      const p = raw.paths
      config.paths = {}

      // paths.add
      if (p.add !== undefined) {
        if (!Array.isArray(p.add)) {
          warnings.push(`${source}: "paths.add" is not an array, ignoring`)
        } else {
          const valid: ProtectedPath[] = []
          for (let i = 0; i < p.add.length; i++) {
            if (isValidProtectedPath(p.add[i])) {
              valid.push(p.add[i] as ProtectedPath)
            } else {
              warnings.push(
                `${source}: "paths.add[${i}]" is invalid (need path, level), skipping`,
              )
            }
          }
          if (valid.length > 0) config.paths.add = valid
        }
      }

      // paths.remove
      if (p.remove !== undefined) {
        if (!Array.isArray(p.remove)) {
          warnings.push(`${source}: "paths.remove" is not an array, ignoring`)
        } else {
          const valid = p.remove.filter((v: unknown) => typeof v === 'string') as string[]
          if (valid.length !== p.remove.length) {
            warnings.push(`${source}: some "paths.remove" entries are not strings, skipping those`)
          }
          if (valid.length > 0) config.paths.remove = valid
        }
      }

      // paths.override
      if (p.override !== undefined) {
        if (!isObject(p.override)) {
          warnings.push(`${source}: "paths.override" is not an object, ignoring`)
        } else {
          const valid: Record<string, ProtectionLevel | 'none'> = {}
          for (const [key, val] of Object.entries(p.override)) {
            if (VALID_LEVELS.has(val as string)) {
              valid[key] = val as ProtectionLevel | 'none'
            } else {
              warnings.push(
                `${source}: "paths.override[${JSON.stringify(key)}]" has invalid level "${val}", skipping`,
              )
            }
          }
          if (Object.keys(valid).length > 0) config.paths.override = valid
        }
      }
    }
  }

  // Warn about unknown top-level keys
  for (const key of Object.keys(raw)) {
    if (key !== 'patterns' && key !== 'paths' && key !== '$schema') {
      warnings.push(`${source}: unknown key "${key}", ignoring`)
    }
  }

  return { config, warnings }
}

// ---------------------------------------------------------------------------
// Merge two configs (global + project)
// ---------------------------------------------------------------------------

function mergeConfigs(
  global: DamageControlConfig,
  project: DamageControlConfig,
): DamageControlConfig {
  const merged: DamageControlConfig = {}

  // Merge patterns
  const gp = global.patterns
  const pp = project.patterns
  if (gp || pp) {
    merged.patterns = {}
    // add: concatenate (global first, then project)
    const adds = [...(gp?.add || []), ...(pp?.add || [])]
    if (adds.length > 0) merged.patterns.add = adds
    // remove: union
    const removes = [...(gp?.remove || []), ...(pp?.remove || [])]
    if (removes.length > 0) merged.patterns.remove = removes
    // override: shallow merge, project wins
    const overrides = { ...(gp?.override || {}), ...(pp?.override || {}) }
    if (Object.keys(overrides).length > 0) merged.patterns.override = overrides
  }

  // Merge paths
  const gpaths = global.paths
  const ppaths = project.paths
  if (gpaths || ppaths) {
    merged.paths = {}
    const adds = [...(gpaths?.add || []), ...(ppaths?.add || [])]
    if (adds.length > 0) merged.paths.add = adds
    const removes = [...(gpaths?.remove || []), ...(ppaths?.remove || [])]
    if (removes.length > 0) merged.paths.remove = removes
    const overrides = { ...(gpaths?.override || {}), ...(ppaths?.override || {}) }
    if (Object.keys(overrides).length > 0) merged.paths.override = overrides
  }

  return merged
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Load and merge config from global (~/.config/opencode/damage-control.json)
 * and project (.opencode/damage-control.json) locations.
 *
 * Returns the merged config plus any validation warnings. Both files are
 * optional -- returns empty config with no warnings when neither exists.
 */
export function loadConfig(directory: string): {
  config: DamageControlConfig
  warnings: string[]
} {
  const warnings: string[] = []

  // Global config
  const globalPath = globalConfig()
  const globalRaw = readJsonFile(globalPath)
  let globalCfg: DamageControlConfig = {}
  if (globalRaw !== null) {
    const v = validateConfig(globalRaw, globalPath)
    globalCfg = v.config
    warnings.push(...v.warnings)
  }

  // Project config
  const projectPath = projectConfig(directory)
  const projectRaw = readJsonFile(projectPath)
  let projConfig: DamageControlConfig = {}
  if (projectRaw !== null) {
    const v = validateConfig(projectRaw, projectPath)
    projConfig = v.config
    warnings.push(...v.warnings)
  }

  const config = mergeConfigs(globalCfg, projConfig)
  return { config, warnings }
}

/**
 * Apply custom configuration on top of default patterns and paths.
 *
 * Pure function: takes defaults + config, returns new arrays.
 * Does not mutate inputs.
 *
 * Processing order for each (patterns / paths):
 *   1. Start with defaults
 *   2. Remove entries matching `remove` list
 *   3. Apply `override` to remaining entries
 *   4. Append `add` entries at the end
 */
export function applyConfig(
  config: DamageControlConfig,
  defaultPatterns: readonly Pattern[],
  defaultPaths: readonly ProtectedPath[],
): { patterns: Pattern[]; paths: ProtectedPath[] } {
  // -- Patterns --
  let patterns = [...defaultPatterns]
  const pc = config.patterns

  if (pc) {
    // 1. Remove
    if (pc.remove) {
      const removeSet = new Set(pc.remove)
      patterns = patterns.filter((p) => !removeSet.has(p.reason))
    }

    // 2. Override
    if (pc.override) {
      patterns = patterns.map((p) => {
        const newAction = pc.override![p.reason]
        if (newAction !== undefined) {
          return { ...p, action: newAction }
        }
        return p
      })
    }

    // 3. Add
    if (pc.add) {
      patterns = [...patterns, ...pc.add]
    }
  }

  // -- Paths --
  let paths = [...defaultPaths]
  const pathc = config.paths

  if (pathc) {
    // 1. Remove
    if (pathc.remove) {
      const removeSet = new Set(pathc.remove)
      paths = paths.filter((p) => !removeSet.has(p.path))
    }

    // 2. Override
    if (pathc.override) {
      const afterOverride: ProtectedPath[] = []
      for (const p of paths) {
        const newLevel = pathc.override[p.path]
        if (newLevel === 'none') continue // remove by override
        if (newLevel !== undefined) {
          afterOverride.push({ ...p, level: newLevel })
        } else {
          afterOverride.push(p)
        }
      }
      paths = afterOverride
    }

    // 3. Add
    if (pathc.add) {
      paths = [...paths, ...pathc.add]
    }
  }

  return { patterns, paths }
}
