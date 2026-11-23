# AGENTS.md

Builders for the files a log enricher reads. This tree is the library,
the `enrich` CLI, the on-disk formats, and the tests.

Read `docs/COMMIT.md` and `docs/BRANCHES.md` before any
commit-shaped or branch-shaped output. You do not commit, push,
or tag. The human does, using those contracts. Work branches are
`<type>/<scope>-<slug>`. Never push `main`.

## Build and test

```
make
make test
```

Requires libfastjson. Dual-arch: `x86-64-v2` with SSE4.2, and
`armv8-a+crc`, with a scalar CRC32C fallback. A change proven only
on one arch is incomplete.

## In

`src/enrich.h`, `src/enrich_lib.c`, `src/enrich_cmd.c`,
`src/enrich_version.c`, `src/thrtutil.c`, `src/thrt_cli.c`,
`src/overlay_tool.c`, `src/prev_lookup.c`, `src/enrichd.c`,
`src/enrichd_sha256.h`, the format headers, the
tests and `src/fuzz_enrich.c`, `testdata/`, `Makefile`, `docs/`.

## Not in

Host integration. An rsyslog module, a package port, and service
config do not land here.

## Must

- One write set. If the task needs a file outside it, stop.
- 4 spaces, K&R braces, snake_case, no VLA, bounded string APIs,
  check every allocation.
- Paste the command and its output. Do not claim tests passed without
  that paste.
- Format version and SONAME are frozen. Bumping them is a human
  decision (`Contract: abi|format`). The SONAME is
  `libenrich.so.<LIB_MAJOR>`. `LIB_MAJOR`, `LIB_MINOR`, `LIB_PATCH` in
  the Makefile and `enrich_version()` move together. `ENRICH_VERSION_PATCH` in
  `enrich.h` is not the published version.

## Never

- `git commit`, `git push`, `git tag`, `git rebase`, merge, force-push
- Rewrite `docs/COMMIT.md`, `.githooks/`, `scripts/check-commit-msg.sh`,
  `.github/workflows/`, or `CODEOWNERS` unless that is the write set
- Assistant attribution in comments, commits, or docs
- Em-dashes in anything that ships
