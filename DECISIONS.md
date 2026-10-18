# Decisions

One entry per trade-off: context, options considered, decision, consequences.

## 001: Separate tsconfig for build vs. type-check
- **Context:** tests live outside `src/`, but `dist/` should contain only `src/`.
- **Decision:** `tsconfig.json` type-checks `src` + `tests` with `noEmit`; `tsconfig.build.json` extends it, sets `rootDir: src`, and emits to `dist/`.
- **Consequences:** `npm run typecheck` covers tests; `npm run build` ships only CLI code. Tests run from source via vitest.
