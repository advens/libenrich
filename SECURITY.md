# Security Policy

## Reporting a vulnerability

Report privately, either way:

- GitHub: **Security > Report a vulnerability** (private advisory) on this
  repository, or
- email **jeremie.jourdin@advens.fr**.

Do not open a public issue or PR for a loader bug before a fix is released.

Please include the affected commit or tag, the architecture and OS, and a
reproducer (a hostile `.thrt`, `.ovly`, or `.prev`, or a crashing command
line).

## What to expect

- Acknowledgement within 3 business days.
- An initial assessment and a target fix window within 10 business days.
- Coordinated disclosure: we agree a publication date with you, normally within
  90 days of the report, and credit you in the advisory unless you prefer
  otherwise.

## Supported versions

Only the latest tagged release and `main` receive security fixes; older
tags do not get backports.

## Hardening invariants

- The `.thrt` reader rejects a bad magic or a version older than the one
  it writes.
- The `.thrt` builder writes no string entry 128 or more slots from its
  home slot (`THRT_PROBE_MAX`), the distance a lookup walks. A feed that
  crafts CRC32C collisions fails the build instead of hiding a value.
- The overlay reader rejects a bad magic, version, size, or trailing CRC32C.
- The prevalence map rejects a bad magic, version, or bound. A checksum of
  zero is unset and is not verified.
- A crash, over-read, or over-write on one of those files is a security bug.
