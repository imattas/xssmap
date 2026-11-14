# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 2.8.0 predate this file; their history is in the git log.

## [Unreleased]

## [2.10.0] - 2026-11-14

Discovery release. Detection behaviour is unchanged; what changed is how much
of a site gets found and how often the same shape is probed twice.

### Added

- Sitemap indexes are followed. A `<sitemapindex>` names more sitemaps, which is
  how most large sites publish their URL set, and it used to be skipped outright
  because the child files end in `.xml`. Indexes are now walked breadth-first
  with a depth cap of 2, at most 200 files and 8 files in flight, gzipped
  `.xml.gz` bodies are decoded, `&amp;` in `<loc>` is unescaped and every
  `Sitemap:` line in robots.txt is honoured (up to 10). On a 4,096-URL lab the
  crawl reached 4,096 parameterised URLs with 21 requests in 0.2 s; the same
  site crawled link by link exposed 1.
- `--url-variants N` (default 3) controls how many value variants of one
  signature (`?id=1`, `?id=2`, ...) are kept from a crawl. It is the knob to
  turn up when an id space has to be covered, and down when it does not.
- `--fast` applies a shallow preset (depth 1, 60 pages, 300 points, no JS, no
  browser) for a quick pass; flags given explicitly on the command line still
  win over the preset.
- Response profiles are shared across points that agree on method, host, path,
  parameter and context, so a catalogue of 4,000 ids sharing one template does
  not derive the same profile 4,000 times.

### Changed

- robots.txt and `/sitemap.xml` are requested at the same time instead of one
  after the other, and the root sitemap is not parsed twice when robots.txt
  already named it.
- The sitemap summary is printed once per crawl rather than once per ingestion
  path.
- The crawl logs pages per second every two seconds, so a long crawl reports
  progress instead of finishing silently.

## [2.9.1] - 2026-11-13

Speed release. Detection behaviour is unchanged.

### Changed

- Discovery has its own worker count. `--crawl-threads` defaults to 16 (or
  `--threads` when that is larger) instead of running the crawl at the payload
  width of 5; `--threads` itself now defaults to 10. On a 4,096-page lab target
  with 50 ms of latency, the same 8,252 requests finished in 85 s before and
  38 s after.
- The baseline response is fetched once per URL rather than once per parameter,
  and concurrent workers share the in-flight fetch instead of racing on it.
  Only the status is cached, never a body.

### Fixed

- Point order is deterministic. `param_urls` ties were broken by crawl
  completion order, so `--max-points` could cut at a different place on every
  run of the same target.
- A parameter that answers 500 when probed no longer re-sends the identical
  probe; the error body is still analysed for a reflection.

## [2.9.0] - 2026-11-13

### Added

- Server-stack fingerprinting. `Server`, `X-Powered-By`, `X-AspNet-Version`,
  `X-Generator`, `<meta name="generator">` and session cookie names are read
  from the seed response the crawl already fetched, so the pass sends no extra
  request. Rows are printed in the console and rendered in the Markdown and
  HTML reports under "Server stack".
- Outdated-version detection for components that advertise a version, using a
  deliberately short policy table: Apache 2.4.49/2.4.50 (CVE-2021-41773,
  CVE-2021-42013), nginx before 1.20.1 (CVE-2021-23017), PHP branches before
  8.2 (out of security support) and IIS 6.0-8.5 (shipped only with an
  end-of-life Windows Server). A flagged version is a lead for the operator,
  never a finding on its own.
- 36 tests pinning the new crawl scheduling, the transport cap, the throttle
  rules and the stack policy table.

### Changed

- Crawl scheduling is continuous instead of level-by-level. `--depth` counts
  hops from the seed and `--max-pages` is a hard stop, so one slow branch no
  longer holds back pages that are already queued behind it.
- `robots.txt` and `sitemap.xml` are fetched concurrently, turning two round
  trips into one.
- `Throttle` no longer reads an HTTP 500 as backpressure. An application error
  is not load, so only 429/503 count, and only after a short streak; a target
  that answers a fraction of URLs with 500 used to stack seconds of sleep into
  the crawl and dominate its duration.
- Binary bodies are read up to a 256 KB cap and marked truncated instead of
  being buffered whole. A truncated body drops its connection rather than
  returning a half-drained socket to the pool.

### Fixed

- Crawling a target that 500s part of its URL space is ~20x faster at the same
  page count: about 1 s instead of 20 s for 68 pages, measured by running the
  2.8.1 tree and this one against the same local server (identical page sets,
  50 ms of fixed latency, a deterministic 15% of URLs answering 500).

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
