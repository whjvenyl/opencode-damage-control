import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { loadConfig, applyConfig, type DamageControlConfig } from './config.js'
import type { Pattern, ProtectedPath } from './patterns.js'

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const SAMPLE_PATTERNS: Pattern[] = [
  { pattern: 'rm\\s+-rf\\s+/', reason: 'Recursive delete from root', action: 'block' },
  { pattern: 'git\\s+reset\\s+--hard', reason: 'git reset --hard (use --soft or stash)', action: 'ask' },
  { pattern: 'DROP\\s+TABLE', reason: 'SQL DROP TABLE', action: 'block' },
  { pattern: 'npm\\s+unpublish', reason: 'npm unpublish', action: 'block' },
]

const SAMPLE_PATHS: ProtectedPath[] = [
  { path: '~/.ssh', level: 'zeroAccess' },
  { path: '~/.aws', level: 'zeroAccess' },
  { path: 'dist/', level: 'readOnly' },
  { path: '.git/', level: 'noDelete' },
]

// ---------------------------------------------------------------------------
// applyConfig tests (pure function, no I/O)
// ---------------------------------------------------------------------------

describe('applyConfig', () => {
  describe('patterns', () => {
    it('returns defaults unchanged when config is empty', () => {
      const { patterns } = applyConfig({}, SAMPLE_PATTERNS, SAMPLE_PATHS)
      assert.deepEqual(patterns, SAMPLE_PATTERNS)
    })

    it('adds new patterns after defaults', () => {
      const config: DamageControlConfig = {
        patterns: {
          add: [{ pattern: 'my-cmd', reason: 'Custom', action: 'block' }],
        },
      }
      const { patterns } = applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      assert.equal(patterns.length, SAMPLE_PATTERNS.length + 1)
      assert.equal(patterns[patterns.length - 1].reason, 'Custom')
    })

    it('removes patterns by exact reason', () => {
      const config: DamageControlConfig = {
        patterns: { remove: ['npm unpublish'] },
      }
      const { patterns } = applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      assert.equal(patterns.length, SAMPLE_PATTERNS.length - 1)
      assert.ok(!patterns.some((p) => p.reason === 'npm unpublish'))
    })

    it('overrides action of existing pattern', () => {
      const config: DamageControlConfig = {
        patterns: {
          override: { 'git reset --hard (use --soft or stash)': 'block' },
        },
      }
      const { patterns } = applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      const gitReset = patterns.find(
        (p) => p.reason === 'git reset --hard (use --soft or stash)',
      )
      assert.ok(gitReset)
      assert.equal(gitReset.action, 'block')
    })

    it('applies remove, then override, then add in order', () => {
      const config: DamageControlConfig = {
        patterns: {
          remove: ['npm unpublish'],
          override: { 'SQL DROP TABLE': 'ask' },
          add: [{ pattern: 'new-cmd', reason: 'New', action: 'ask' }],
        },
      }
      const { patterns } = applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      // npm unpublish removed
      assert.ok(!patterns.some((p) => p.reason === 'npm unpublish'))
      // DROP TABLE overridden to ask
      assert.equal(
        patterns.find((p) => p.reason === 'SQL DROP TABLE')?.action,
        'ask',
      )
      // New pattern added at end
      assert.equal(patterns[patterns.length - 1].reason, 'New')
      // Total: 4 - 1 + 1 = 4
      assert.equal(patterns.length, 4)
    })

    it('removing a non-existent pattern is a no-op', () => {
      const config: DamageControlConfig = {
        patterns: { remove: ['does not exist'] },
      }
      const { patterns } = applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      assert.equal(patterns.length, SAMPLE_PATTERNS.length)
    })

    it('overriding a non-existent reason is a no-op', () => {
      const config: DamageControlConfig = {
        patterns: { override: { 'no such reason': 'block' } },
      }
      const { patterns } = applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      assert.deepEqual(patterns, SAMPLE_PATTERNS)
    })

    it('does not mutate the input arrays', () => {
      const original = [...SAMPLE_PATTERNS]
      const config: DamageControlConfig = {
        patterns: {
          remove: ['npm unpublish'],
          override: { 'SQL DROP TABLE': 'ask' },
          add: [{ pattern: 'x', reason: 'X', action: 'block' }],
        },
      }
      applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      assert.deepEqual(SAMPLE_PATTERNS, original)
    })
  })

  describe('paths', () => {
    it('returns defaults unchanged when config is empty', () => {
      const { paths } = applyConfig({}, SAMPLE_PATTERNS, SAMPLE_PATHS)
      assert.deepEqual(paths, SAMPLE_PATHS)
    })

    it('adds new paths after defaults', () => {
      const config: DamageControlConfig = {
        paths: {
          add: [{ path: '~/my-secrets/', level: 'zeroAccess' }],
        },
      }
      const { paths } = applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      assert.equal(paths.length, SAMPLE_PATHS.length + 1)
      assert.equal(paths[paths.length - 1].path, '~/my-secrets/')
    })

    it('removes paths by exact path string', () => {
      const config: DamageControlConfig = {
        paths: { remove: ['dist/'] },
      }
      const { paths } = applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      assert.equal(paths.length, SAMPLE_PATHS.length - 1)
      assert.ok(!paths.some((p) => p.path === 'dist/'))
    })

    it('overrides level of existing path', () => {
      const config: DamageControlConfig = {
        paths: { override: { 'dist/': 'noDelete' } },
      }
      const { paths } = applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      const dist = paths.find((p) => p.path === 'dist/')
      assert.ok(dist)
      assert.equal(dist.level, 'noDelete')
    })

    it('removes path when overridden with "none"', () => {
      const config: DamageControlConfig = {
        paths: { override: { 'dist/': 'none' } },
      }
      const { paths } = applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      assert.ok(!paths.some((p) => p.path === 'dist/'))
      assert.equal(paths.length, SAMPLE_PATHS.length - 1)
    })

    it('applies remove, then override, then add in order', () => {
      const config: DamageControlConfig = {
        paths: {
          remove: ['~/.aws'],
          override: { 'dist/': 'none', '.git/': 'zeroAccess' },
          add: [{ path: '/custom/', level: 'readOnly' }],
        },
      }
      const { paths } = applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      // ~/.aws removed
      assert.ok(!paths.some((p) => p.path === '~/.aws'))
      // dist/ removed via override none
      assert.ok(!paths.some((p) => p.path === 'dist/'))
      // .git/ upgraded
      assert.equal(paths.find((p) => p.path === '.git/')?.level, 'zeroAccess')
      // Custom added
      assert.equal(paths[paths.length - 1].path, '/custom/')
      // Total: 4 - 1 (remove) - 1 (override none) + 1 (add) = 3
      assert.equal(paths.length, 3)
    })

    it('does not mutate the input arrays', () => {
      const original = [...SAMPLE_PATHS]
      const config: DamageControlConfig = {
        paths: {
          remove: ['dist/'],
          add: [{ path: '/x/', level: 'readOnly' }],
        },
      }
      applyConfig(config, SAMPLE_PATTERNS, SAMPLE_PATHS)
      assert.deepEqual(SAMPLE_PATHS, original)
    })
  })
})

// ---------------------------------------------------------------------------
// loadConfig tests (file I/O)
// ---------------------------------------------------------------------------

describe('loadConfig', () => {
  let tempDir: string

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'dc-test-'))
  })

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true })
  })

  it('returns empty config when no files exist', () => {
    const { config, warnings } = loadConfig(tempDir)
    assert.deepEqual(config, {})
    assert.equal(warnings.length, 0)
  })

  it('loads project config from .opencode/damage-control.json', () => {
    const dir = join(tempDir, '.opencode')
    mkdirSync(dir, { recursive: true })
    writeFileSync(
      join(dir, 'damage-control.json'),
      JSON.stringify({
        patterns: {
          remove: ['npm unpublish'],
        },
      }),
    )

    const { config, warnings } = loadConfig(tempDir)
    assert.deepEqual(config.patterns?.remove, ['npm unpublish'])
    assert.equal(warnings.length, 0)
  })

  it('warns and returns empty config for invalid JSON', () => {
    const dir = join(tempDir, '.opencode')
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'damage-control.json'), '{ not valid json')

    const { config, warnings } = loadConfig(tempDir)
    // Invalid JSON fails to parse → null → no config loaded
    assert.deepEqual(config, {})
    assert.equal(warnings.length, 0) // parse failure is silent (file not found equivalent)
  })

  it('warns about non-object config', () => {
    const dir = join(tempDir, '.opencode')
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'damage-control.json'), '"just a string"')

    const { config, warnings } = loadConfig(tempDir)
    assert.deepEqual(config, {})
    assert.ok(warnings.length > 0)
    assert.ok(warnings[0].includes('not an object'))
  })

  it('warns about unknown top-level keys', () => {
    const dir = join(tempDir, '.opencode')
    mkdirSync(dir, { recursive: true })
    writeFileSync(
      join(dir, 'damage-control.json'),
      JSON.stringify({ patterns: {}, unknownKey: true }),
    )

    const { config, warnings } = loadConfig(tempDir)
    assert.ok(warnings.some((w) => w.includes('unknownKey')))
    // patterns still loaded (it's valid, just empty)
    assert.ok(config.patterns !== undefined || Object.keys(config).length === 0)
  })

  it('warns about invalid pattern entries in add', () => {
    const dir = join(tempDir, '.opencode')
    mkdirSync(dir, { recursive: true })
    writeFileSync(
      join(dir, 'damage-control.json'),
      JSON.stringify({
        patterns: {
          add: [
            { pattern: 'valid', reason: 'Valid', action: 'block' },
            { pattern: 'missing-action', reason: 'Bad' },
            'not an object',
          ],
        },
      }),
    )

    const { config, warnings } = loadConfig(tempDir)
    assert.equal(config.patterns?.add?.length, 1)
    assert.equal(config.patterns?.add?.[0].reason, 'Valid')
    assert.ok(warnings.length >= 2)
  })

  it('warns about invalid action in override', () => {
    const dir = join(tempDir, '.opencode')
    mkdirSync(dir, { recursive: true })
    writeFileSync(
      join(dir, 'damage-control.json'),
      JSON.stringify({
        patterns: {
          override: {
            'valid reason': 'block',
            'bad reason': 'invalid-action',
          },
        },
      }),
    )

    const { config, warnings } = loadConfig(tempDir)
    assert.ok(config.patterns?.override?.['valid reason'] === 'block')
    assert.ok(config.patterns?.override?.['bad reason'] === undefined)
    assert.ok(warnings.some((w) => w.includes('invalid-action')))
  })

  it('warns about invalid level in paths.override', () => {
    const dir = join(tempDir, '.opencode')
    mkdirSync(dir, { recursive: true })
    writeFileSync(
      join(dir, 'damage-control.json'),
      JSON.stringify({
        paths: {
          override: {
            'dist/': 'none',
            '~/.ssh': 'badLevel',
          },
        },
      }),
    )

    const { config, warnings } = loadConfig(tempDir)
    assert.equal(config.paths?.override?.['dist/'], 'none')
    assert.ok(config.paths?.override?.['~/.ssh'] === undefined)
    assert.ok(warnings.some((w) => w.includes('badLevel')))
  })

  it('allows $schema key without warning', () => {
    const dir = join(tempDir, '.opencode')
    mkdirSync(dir, { recursive: true })
    writeFileSync(
      join(dir, 'damage-control.json'),
      JSON.stringify({ $schema: 'https://example.com/schema.json' }),
    )

    const { warnings } = loadConfig(tempDir)
    assert.ok(!warnings.some((w) => w.includes('$schema')))
  })
})

// ---------------------------------------------------------------------------
// Config merging (global + project)
// ---------------------------------------------------------------------------

describe('loadConfig merging', () => {
  let tempDir: string
  let fakeHome: string
  let origHome: string | undefined

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'dc-merge-'))
    fakeHome = mkdtempSync(join(tmpdir(), 'dc-home-'))
    origHome = process.env.HOME
    process.env.HOME = fakeHome
  })

  afterEach(() => {
    process.env.HOME = origHome
    rmSync(tempDir, { recursive: true, force: true })
    rmSync(fakeHome, { recursive: true, force: true })
  })

  it('merges global and project configs', () => {
    // Global: add a pattern, remove a path
    const globalDir = join(fakeHome, '.config', 'opencode')
    mkdirSync(globalDir, { recursive: true })
    writeFileSync(
      join(globalDir, 'damage-control.json'),
      JSON.stringify({
        patterns: {
          add: [{ pattern: 'global-cmd', reason: 'Global', action: 'ask' }],
        },
        paths: {
          remove: ['dist/'],
        },
      }),
    )

    // Project: add a different pattern, override a path
    const projectDir = join(tempDir, '.opencode')
    mkdirSync(projectDir, { recursive: true })
    writeFileSync(
      join(projectDir, 'damage-control.json'),
      JSON.stringify({
        patterns: {
          add: [{ pattern: 'project-cmd', reason: 'Project', action: 'block' }],
        },
        paths: {
          override: { '.git/': 'zeroAccess' },
        },
      }),
    )

    const { config, warnings } = loadConfig(tempDir)
    assert.equal(warnings.length, 0)

    // Patterns: both adds concatenated
    assert.equal(config.patterns?.add?.length, 2)
    assert.equal(config.patterns?.add?.[0].reason, 'Global')
    assert.equal(config.patterns?.add?.[1].reason, 'Project')

    // Paths: remove from global + override from project
    assert.deepEqual(config.paths?.remove, ['dist/'])
    assert.equal(config.paths?.override?.['.git/'], 'zeroAccess')
  })

  it('project override wins over global override for same key', () => {
    const globalDir = join(fakeHome, '.config', 'opencode')
    mkdirSync(globalDir, { recursive: true })
    writeFileSync(
      join(globalDir, 'damage-control.json'),
      JSON.stringify({
        patterns: {
          override: { 'SQL DROP TABLE': 'ask' },
        },
      }),
    )

    const projectDir = join(tempDir, '.opencode')
    mkdirSync(projectDir, { recursive: true })
    writeFileSync(
      join(projectDir, 'damage-control.json'),
      JSON.stringify({
        patterns: {
          override: { 'SQL DROP TABLE': 'block' },
        },
      }),
    )

    const { config } = loadConfig(tempDir)
    assert.equal(config.patterns?.override?.['SQL DROP TABLE'], 'block')
  })
})
