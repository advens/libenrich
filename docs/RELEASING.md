# Releasing

How to cut a libenrich release: bump the version, update the changelog,
merge, tag, and let CI publish it. Tagging is the only step a human has
to do by hand; everything after the tag is automated.

## 1. Decide the version

`MAJOR.MINOR.PATCH`. The SONAME is `libenrich.so.<MAJOR>`:

- The release breaks a frozen surface (a `Contract: abi` or `format`
  commit landed, per `docs/COMMIT.md`) -> bump MAJOR. The SONAME moves
  with it.
- New, backward-compatible functionality -> bump MINOR.
- Bug fixes only -> bump PATCH. The SONAME stays.

## 2. Bump the published version

`LIB_MAJOR`, `LIB_MINOR`, and `LIB_PATCH` at the top of `Makefile` are
the source of truth for the shared-library filename and for
`enrich.pc`. `src/enrich_version.c` returns the same `MAJOR.MINOR.PATCH`
string. Edit both by hand. The git tag does not drive them.

Do not edit `ENRICH_VERSION_MAJOR`, `ENRICH_VERSION_MINOR`, or
`ENRICH_VERSION_PATCH` in `src/enrich.h`. Those macros are not the
published version.

A MAJOR change moves the SONAME, so that commit is `Contract: abi`.

## 3. Update the changelog

Add a `## [MAJOR.MINOR.PATCH] - YYYY-MM-DD` section to `CHANGELOG.md`
(move relevant `[Unreleased]` entries into it, or write new ones),
following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Update the links at the bottom:

```
[Unreleased]: https://github.com/advens/libenrich/compare/MAJOR.MINOR.PATCH...HEAD
[MAJOR.MINOR.PATCH]: https://github.com/advens/libenrich/releases/tag/MAJOR.MINOR.PATCH
```

This section is not optional decoration: the release workflow's release
notes are this section's text, verbatim. The heading match is the
prefix `## [MAJOR.MINOR.PATCH]`, so the date may follow it.

## 4. PR it, merge to main

Same as any other change: a work branch, commits that each pass
`scripts/check-commit-msg.sh`, `Contract: abi` or `format` on whichever
commit actually touches that surface, CI green, then merge.

The version commit's subject follows the earlier releases:

```
build(build): set the version to MAJOR.MINOR.PATCH
```

## 5. Tag and push

The tag points at the squash commit that contains the new `LIB_PATCH`
and the changelog section. Tagging an older commit publishes the
previous version's tree.

```
git tag MAJOR.MINOR.PATCH
git push origin MAJOR.MINOR.PATCH
```

The tag must match `[0-9]+.[0-9]+.[0-9]+` exactly
(`.github/workflows/release.yml`'s trigger) and should point at a commit
already on `main`. No `v` prefix. Tags are not rewritten
(`docs/BRANCHES.md`).

## What happens automatically

Pushing the tag fires `.github/workflows/release.yml`:

1. `make test` runs against the tagged commit.
2. `git archive --format=tar.gz --prefix=libenrich-<tag>/` produces the
   source tarball; a `.sha256` of it is computed alongside.
3. The `## [<tag>]` section of `CHANGELOG.md` is extracted as the
   release notes body.
4. A GitHub Release named `<tag>` is published with both files attached.

No local packaging step, no manual upload: the tag push is the only
trigger.

## Verifying a release

```
gh release download <tag>
sha256sum -c libenrich-<tag>.tar.gz.sha256
tar xzf libenrich-<tag>.tar.gz
cd libenrich-<tag> && make test
```
