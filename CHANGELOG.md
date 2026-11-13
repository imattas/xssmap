# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 2.8.0 predate this file; their history is in the git log.

## [Unreleased]

## [2.8.1] - 2026-11-13

Packaging release. No scanner behaviour changed.

### Added

- `LICENSE` (MIT).
- `CHANGELOG.md`.
- `xssmap/py.typed` so downstream type checkers use the project's inline
  annotations (PEP 561), shipped inside the wheel as package data.

### Changed

- `pyproject.toml` now declares the license with PEP 639 metadata
  (`license = "MIT"`, `license-files`) instead of carrying a comment saying no
  license was stated, so the wheel and sdist advertise the terms and PyPI
  renders them.
- Build backend floor raised to `setuptools>=77`, which is the first release
  that understands `license-files` and an SPDX license expression.
- Author metadata now names the maintainer instead of repeating the project
  name.

## [2.8.0] - 2026-11-13

### Added

- DOM state-store and hydration flows. A value written to
  `localStorage`/`sessionStorage` on one page and rendered as HTML on another,
  and a server-rendered state blob (`__INITIAL_STATE__`, `__NEXT_DATA__`,
  `data-*`) that a bundle re-reads after hydration, are now replayed step by
  step in the browser instead of being left as unprovable static guesses. The
  new `xssmap/domstate.py` engine drives both, and the bundled lab serves
  `/dom-state-read` and `/dom-hydrate` endpoints to exercise them.
- Splash banner in the sqlmap idiom, drawn on every interactive run and
  suppressed with `--no-color`.
- 21 tests covering the DOM state-store and hydration engine.

### Fixed

- The remaining DOM-analysis gap: storage-mediated and hydration-mediated
  source-to-sink flows that the static tracer could see but not confirm are now
  confirmed in a real browser.
