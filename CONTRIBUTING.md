# Contributing to Hivemend

Thanks for helping. Hivemend is free and open source, and it gets better
through people running it on real machines and telling us what they see.

## Ways to help

- **Report a false positive.** If Hivemend flagged something that is not
  stale, that is the most valuable report you can send. Use the
  *False positive* issue template.
- **Report a bug** with the *Bug report* template.
- **Suggest a scanner or feature** with the *Feature request* template.
- **Improve the docs.** Typos, unclear wording, missing steps: small pull
  requests are welcome.
- **Send code.** See below.

Security problems go through private reporting instead; see
[SECURITY.md](SECURITY.md).

## Ground rules

These are what Hivemend is, so pull requests that change them will not be
merged:

- No network access, telemetry, analytics, ads, or update checks.
- No paid tiers, license keys, nags, or inflated counts.
- Nothing is removed without a backup that Restore can put back, unless it
  is a cache or temp file the user chose to clean.
- When in doubt, leave it alone. A missed stale entry costs nothing; a wrong
  deletion can break someone's machine.

## Working on the code

You need Rust (the version is pinned in `rust-toolchain.toml`, and `rustup`
picks it up). The release build needs Windows with the MSVC build tools; the
engine's tests also run on Linux.

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --target x86_64-pc-windows-msvc
```

CI runs the same checks on every pull request, on Linux and Windows.

- Keep pull requests focused on one change, and explain *why* in the
  description.
- Add a test for a new scanner rule or a fixed bug. The tests run against an
  in-memory hive, so they need no real registry.
- If you change `Cargo.lock`, regenerate the notices with
  `python3 scripts/third-party-notices.py`.
- New dependencies need a good reason: each one is code that runs with
  access to the registry.

## License

By contributing, you agree that your contribution is licensed under MIT or
Apache-2.0, at the user's option, like the rest of the project.
