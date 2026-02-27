# Contributing

Thanks for your interest in contributing to opencode-damage-control.

## Prerequisites

- Node.js 22+
- npm

## Setup

```bash
git clone https://github.com/whjvenyl/opencode-damage-control.git
cd opencode-damage-control
npm install
```

## Development

```bash
npm run build    # Compile TypeScript to dist/
npm test         # Run all tests (352 tests)
```

## Architecture

```
src/
  patterns.ts        108 patterns, 103 paths, matching helpers
  config.ts          Config loading, validation, merging
  index.ts           Plugin entry point (2 hooks)
  patterns.test.ts   326 pattern tests
  config.test.ts     26 config tests
```

- **`patterns.ts`** -- all pattern/path data and matching logic. This is where new patterns and paths go.
- **`config.ts`** -- config file loading, validation, and merge semantics.
- **`index.ts`** -- thin entry point that wires hooks. Should stay small.

## Adding a pattern

1. Add the regex and metadata to `DEFAULT_PATTERNS` in `src/patterns.ts`
2. Add test cases to `src/patterns.test.ts` (both matching and non-matching)
3. Run `npm test` to verify
4. Update `docs/patterns.md` with the new entry

## Adding a protected path

1. Add the path to the appropriate tier in `DEFAULT_PROTECTED_PATHS` in `src/patterns.ts`
2. Add test cases to `src/patterns.test.ts`
3. Run `npm test` to verify
4. Update `docs/paths.md` with the new entry

## Branch naming

Use branch prefixes for automatic PR labeling:

| Prefix | Label |
|--------|-------|
| `feature/` | enhancement |
| `fix/` | bug |
| `chore/` | chore |
| `docs/` | documentation |

## Pull requests

- One concern per PR
- Include tests for new patterns/paths
- Ensure `npm test` passes and `npm run build` succeeds
- Fill out the PR template

## Code style

- Zero runtime dependencies -- keep it that way
- Tests use `node:test` (no test framework dependency)
- TypeScript strict mode
