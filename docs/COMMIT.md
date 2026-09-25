# Commit message contract

Every commit uses this shape. GitHub squash-merge uses the PR title as
the subject and the PR body as the rest. Those must match too.

## Shape

```
<type>(<scope>): <subject>

Why:
<one or more lines>

Proof:
<command plus its decisive output, or "not run: <reason>">

Contract: none | abi | format
```

One blank line after the subject. `Signed-off-by:` is allowed after
`Contract:`. Nothing else.

## First line

- `<type>` is one of: `feat` `fix` `perf` `refactor` `test` `build`
  `ci` `docs` `chore`
- `<scope>` is one of: `format` `cli` `build` `github` `docs` `test`
- `<subject>` is imperative, ASCII, no trailing period, no em-dash
- The whole first line is at most 72 characters. GitHub squash-merge
  appends ` (#<n>)` to the subject on `main`. That suffix is not counted

## Contract

| Value | Surface |
|-------|---------|
| `none` | No public header change and no `.thrt` / `.ovly` / `.prev` change |
| `abi` | Exported headers, SONAME, pkg-config |
| `format` | On-disk `.thrt`, `.ovly`, or `.prev` layout |

## Forbidden

- Tool or assistant attribution
- Em-dash (U+2014)
- Trailing subject period
- A type or scope not in the lists above
- An empty Why or Proof section
