# Branch policy

`main` is the only long-lived branch. Everything else is a short-lived work
branch that dies at merge.

## main

- CI on `main` is green (`commit-msg`, `test` on the Linux and macOS jobs).
- No merge commits. Squash or rebase only.
- Squash uses the PR title as the subject and the PR body as Why / Proof /
  Contract (`docs/COMMIT.md`).
- The head branch is deleted on merge.
- Force-push and deletion of `main` are forbidden. Where the hosting plan
  allows a branch ruleset, that ruleset enforces it; the commit hook, CI, and
  this file are the gate regardless.

## Work branches

Name:

```
<type>/<scope>-<slug>
```

`<type>` and `<scope>` are the same closed lists as `docs/COMMIT.md`.
`<slug>` is lowercase ASCII, hyphens, at most 40 characters.

Examples: `fix/cli-page-fold`, `build/build-release-0.1.6`,
`docs/github-contract`.

One branch, one PR, one concern. Do not stack unrelated work.

## Tags

`N.N.N` is a human release. Tags are not rewritten. The tag has no `v`
prefix: the release workflow matches `[0-9]+.[0-9]+.[0-9]+`.

## Automated contributors

Automated contributors do not create or push `main`, do not tag, and do not
choose a branch name outside the pattern above. See `AGENTS.md`.
