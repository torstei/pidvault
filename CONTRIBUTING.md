# Contributing

Questions, bug reports and ideas go in [GitHub issues](https://github.com/torstei/sshvault/issues).
Report vulnerabilities privately instead, as [SECURITY.md](SECURITY.md) describes.

Changes go in as pull requests against `main`. A pull request is merged once CI passes;
`main` accepts nothing else. sshvault is opinionated: it aims to be one way of working
that works, not a set of options. An issue before a larger change saves work on both
sides.

A change needs:

- **Tests.** New behaviour and fixed bugs come with tests that fail without the change:
  unit tests beside the code, end-to-end tests in `tests/end_to_end.rs` for what a user
  or another process can observe, and checks in `tests/vm/` for anything that needs
  root, systemd or the installed package. A change to what other processes can send the
  daemon belongs in a fuzz target in `fuzz/` too.
- **Clean checks.** `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and
  `cargo deny check` pass. Every `unsafe` block says why it is sound.
- **Documentation.** A line in `CHANGELOG.md` under `## Unreleased` for anything a user
  would notice, and the README where it describes the behaviour. If the change affects a
  claim or limitation in [docs/security-design.md](docs/security-design.md), update it
  there as well.

The README's "Development" section explains how to run the tests, including the VM
tests and the fuzz targets.

By submitting a contribution, you agree that it is licensed as MIT OR Apache-2.0, as the
README's "License" section states.
