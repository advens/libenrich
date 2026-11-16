# Contributing

## Commits

`docs/COMMIT.md` is the contract. It is not optional. Install the
hook before you commit:

```
git config core.hooksPath .githooks
git config commit.template .gitmessage
```

PRs squash-merge. The PR title is the subject. The PR body is Why /
Proof / Contract. CI runs `scripts/check-commit-msg.sh` on every
commit in the PR and on the squash on `main`. GitHub's squash
` (#<n>)` suffix is not part of the 72-character subject.

Author email on this repository is jeremie.jourdin@advens.fr.

## Branches

`docs/BRANCHES.md`. Work branches are `<type>/<scope>-<slug>` with
the same type and scope lists as commits. `main` is not a work
branch.

## Issues

Use the Bug or Build form. Security reports go to
jeremie.jourdin@advens.fr, not the tracker.

## Code

C11, 4 spaces, K&R, snake_case, no VLA. Dual-arch (amd64 SSE4.2,
aarch64 NEON CRC, scalar fallback). `make test` before you ask for
merge.

Do not send host-integration glue here. An rsyslog module, a package
port, and service config belong with the host.

## Releasing

`docs/RELEASING.md`, for whoever is cutting the next tag.
