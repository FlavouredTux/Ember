# Ember

Context for Claude Code sessions working in this repo.

## What it is

From-scratch x86-64 decompiler + Electron UI. ELF and Mach-O loaders, own
x86-64 decoder, IR + SSA, cleanup passes, control-flow structuring, pseudo-C
emitter, QuickJS scripting surface.

**No Capstone. No Zydis. No Ghidra. No LLVM.** Stdlib only. The one
exception is QuickJS-NG (vendored in `third_party/quickjs/`, MIT, for
scripting). Don't propose adding libraries.

## Layout

```
core/    C++23 library — everything except the CLI shim
  include/ember/  public headers, mirroring src layout
  src/
    binary/       ELF + Mach-O loaders
    disasm/       x86-64 decoder
    analysis/     CFG builder, arity inference, strings scanner, pipeline helpers
    ir/           IR + x64 lifter + SSA + cleanup passes
    structure/    region builder (if/while/switch)
    decompile/    pseudo-C emitter
    script/       QuickJS runtime + bindings
    common/       annotations (project file), disk cache
cli/       command-line driver
scripts/   JS scripts consumed by `ember --script` (query.js, etc.)
ui/        Electron + React + TypeScript frontend
tests/     golden-output CTest suite
```

## Build + test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

UI:

```sh
cd ui && npm install && npm run dev
```

## Testing discipline

Goldens live in `tests/golden/`. When you intentionally change behaviour that
shifts output, **update goldens in the same commit** and narrate what changed:

```sh
UPDATE_GOLDEN=1 ctest --test-dir build -V
```

Never regenerate goldens to "make tests pass" without understanding why they
drifted.

## Scripting surface

`ember --script PATH <binary> [-- args...]` runs a JS file with these globals:

- `binary.{arch, format, entry, sections(), symbols(), findSymbol, symbolAt, bytesAt, decompile, disasm, cfg, findBytes, stringAt}`
- `xrefs.{to, callers, callees}`
- `strings.{search, xrefs}` (accept string or RegExp)
- `project.{rename, setSignature, note, diff, commit, revert}` — only when `--project PATH` is passed; mutations stage into a pending buffer, `commit()` writes back to disk. Every mutator accepts `{dryRun: true}`.
- `argv` — args after `--`
- `log.{info,warn,error}`, `print`

When adding a new script-callable binding, keep the heavy logic in
`core/src/analysis/` (or wherever) returning strings/structs, and let
`runtime.cpp` stay a thin wrapper. Don't re-implement pipeline stages inside
the runtime.

## Disk cache

`--xrefs`, `--strings`, `--arities` cache to `$XDG_CACHE_HOME/ember/<key>/<tag>`.
Key = FNV-1a-64 of `abspath|size|mtime|vN`. Bump `kVersion` in
`core/include/ember/common/cache.hpp` whenever any cached payload's on-disk
format changes — otherwise stale data will be served silently. `--no-cache`
bypasses.

## Style

- C++23, CMake, warnings-as-errors on (off only for vendored QuickJS).
- Terse and decisive. No speculative error handling, no fallbacks for cases
  that can't happen, no validation outside system boundaries.
- Don't add comments that narrate the obvious. Only note non-obvious
  invariants, workarounds, or surprises.
- Batch edits → build → ctest → show before/after.
- Say the tradeoff out loud when picking one.

## Rough edges (don't file bugs; known limits)

- Indirect calls often render as `(*(u64*)(0x...))(...)`.
- Switch cases whose default is outside the bounds check can misattribute.
- Some sub-register arithmetic corners still look clunky.
- `xrefs.to()` is aliased to `xrefs.callers()` for now; data xrefs live on
  `strings.*`.

## Gaps intentionally deferred

Domain-specific analyses (ObjC, C++ vtables/Itanium ABI, crash triage,
Roblox-specific) don't belong in Ember core — they'd live in a downstream
Selene-on-Ember layer, not here.
