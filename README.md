# xssmap

A context-aware cross-site scripting scanner with a crawler, built in the spirit of
sqlmap: point it at a URL, it crawls, enumerates every injection point, works out the
exact reflection context, fires payloads aimed at that context, and proves which ones
actually execute in a real browser.

- **Zero dependencies.** Pure Python 3.9+ standard library (no requests, no BeautifulSoup,
  no Playwright, no Node). Drop the folder anywhere and run it.
- **Crawler included.** Bounded BFS, robots.txt and sitemap seeding, forms, inline and
  external JavaScript endpoint extraction, JSON/AJAX hints, scope and exclusion rules.
- **Context-aware payloads.** HTML text, double/single/unquoted attributes, URL
  attributes, JS string (double/single/template), JS code, `<script>` data blocks,
  comments, `<textarea>`/`<title>`/`<style>` RCDATA, tag space.
- **Filter fingerprinting.** Each point is probed to learn which characters and keywords
  survive (`<`, `>`, quotes, space, `onerror`, `script`, `javascript:`), so payloads that
  cannot possibly work are pruned and the ones that can are preferred.
- **Mutation engine.** When a filter blocks the obvious payload, candidates are mutated
  (case, entity, nested keyword, unclosed tag, null byte, double encoding, comment
  padding, event swap) and the survivors are verified like any other payload.
- **WAF fingerprinting and evasion.** Identifies the vendor in front of each host from
  headers, block pages and probe behaviour, then routes payloads through that vendor's
  bypass vocabulary - with a bounded number of extra attempts per point. What the target
  actually lets through reorders that vocabulary for the rest of the scan: proven shapes
  first, filtered ones last.
- **Filter brute force.** For a point that reflects but mangles everything, learns which
  characters, keyword spellings and multi-character sequences survive, finds where the
  value gets truncated, and synthesises a payload from the survivors instead of guessing.
- **Hidden parameters and fuzzing.** Probes undocumented query, form and JSON-body
  parameters, confirms a hit in the same direction before adding it, and classifies what
  each one does to the response (raw, encoded, template-evaluated, stripped) against its
  own baseline, so exploration is evidence rather than noise.
- **Client-side CVE hints.** Fingerprints jQuery, Bootstrap, AngularJS, DOMPurify and
  friends from body or filename, compares versions against each advisory's affected range
  (so 2.3.2 is not blamed for a 3.4.1 fix) and can merge fresh advisories from osv.dev
  with `--osv`.
- **Server stack and outdated versions.** Reads what each host says about itself - `Server`,
  `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, `<meta name="generator">` and session
  cookie names - from the seed response the crawl already received, so the pass costs no
  extra request. Versions whose exact build is known-vulnerable or out of support (Apache
  2.4.49/2.4.50, nginx before 1.20.1, PHP before 8.2, IIS 6.0-8.5) are flagged with the
  CVE, and every row names the header it came from.
- **Leads, not silence.** A parameter that reflects but swallows every payload is recorded
  as an unconfirmed lead with the measured filter and how much of the probe survived
  (verbatim, recased, escaped, truncated), in its own report section - never presented as a
  finding and never left looking clean. Detection and measurement are separate: a sink that
  mangles the value is still reported as a sink.
- **mXSS round trip.** Parser-differential payloads are proven by serialising the DOM,
  re-parsing it and re-running it, so the proof comes from the page rather than from the
  scanner's belief about the page.
- **Multibyte charset escapes.** GBK/Shift_JIS/BIG5 trail-byte payloads are generated per
  charset and confirmed the same way, with a UTF-8 control route to catch false positives.
- **DOM XSS analysis.** Static source-to-sink taint tracing over crawled scripts
  (`location.search/hash/name`, `document.referrer`, `postMessage` into `innerHTML`,
  `eval`, `document.write`, `location`), then real browser confirmation of each flow.
  Two-step flows are followed across resources: a value written to
  `localStorage`/`sessionStorage` on one page and rendered as HTML on another, and a
  server-rendered state blob (`__INITIAL_STATE__`, `__NEXT_DATA__`, `data-*`) that the
  bundle re-reads after hydration, are replayed step by step in the browser instead of
  being left as unprovable guesses.
- **Stored and blind XSS.** Plants a uniquely marked payload in every writable form,
  finds where it reappears, and proves execution - in the page itself, a viewer URL you
  supply, or out-of-band through a built-in callback listener.
- **Browser proof.** Drives a local Chrome/Chromium/Edge over the DevTools protocol
  (stdlib WebSocket) and asks the live DOM whether the injected node was created,
  which turns "reflected" into "confirmed".
- **Exploit stage (`--verify`).** Replays the proven vector with a weaponised script and
  measures what it reaches: cookie bytes and names, anti-CSRF token readability, a
  same-origin read, or an out-of-band callback. Proven capabilities raise severity and
  CVSS; an inconclusive replay stays `unproven` with the browser's own reason.
- **Honest by construction.** Every payload ends in one of three states, and a
  verification that could not run is never reported as a clean result. CSP that blocks
  execution is detected and downgraded instead of being reported as a high-severity hit,
  and a `strict-dynamic` page is annotated with the script-creating gadgets and allowlisted
  JSONP endpoints a manual bypass review should start from.
- **Reports.** JSON, Markdown, self-contained HTML, SARIF 2.1.0 for CI, one evidence
  file per finding, CVSS 3.1 vector and a ready-to-paste `curl` reproduction.

## Install

```bash
git clone <this folder> xssmap && cd xssmap     # or just copy the directory
python run.py --help
```

Optional, for a `xssmap` command on PATH:

```bash
python -m pip install .
xssmap --version
```

Windows users can call `xssmap.cmd`, POSIX users `./xssmap.sh`. Both are thin wrappers
around `python run.py` that resolve their own directory, so they work from anywhere.
The `.cmd` wrapper skips the Microsoft Store `python` stub and propagates the real exit
code.

## Quick start

```bash
# single URL, crawl by default (depth 2, 150 pages)
python run.py -u "https://target.tld/search?q=test"

# crawl deeper, more threads, write reports (--depth is an alias)
python run.py -u https://target.tld --depth 3 --max-pages 200 --threads 8

# hand it a bare domain and let it find and test everything
python run.py --domain example.com --autonomous

# no crawling, only the URL you gave
python run.py -u "https://target.tld/page?name=x" --no-crawl

# a list of targets
python run.py -m urls.txt --threads 10

# POST body / JSON body
python run.py -u https://target.tld/api/login --data 'user=a&pass=b'
python run.py -u https://target.tld/api/login --json-body '{"user":"a","pass":"b"}'

# DOM XSS + stored XSS with an out-of-band listener, SARIF for CI
python run.py -u https://target.tld --crawl --dom --stored --callback \
  --sarif out/xssmap.sarif --evidence out/evidence

# authenticated scan, header/cookie injection points, browser proof, CI gate
python run.py -u https://target.tld \
  --cookie "sid=abc" --header "X-Api-Key: ..." \
  --headers-points --browser --fail-on-findings

# log in first, keep the session, and resume an interrupted run later
python run.py -u https://target.tld --login-url https://target.tld/login \
  --login-user bob --login-pass 's3cret' --login-check https://target.tld/account \
  --state out/scan.state --save-cookies out/cookies.txt
```

## Whole-domain scans

`--domain` takes a hostname instead of a URL: it picks a working scheme (https, falling
back to http), discovers subdomains, then crawls and tests everything it found.

```bash
# discover + crawl + scan everything under example.com
python run.py --domain example.com --autonomous

# the same sweep with explicit budgets
python run.py --domain example.com --subdomains --max-hosts 30 --depth 3 --max-pages 500

# passive discovery only: no DNS wordlist sweep
python run.py --domain example.com --no-subdomain-brute
```

Discovery uses two independent sources:

1. **Certificate transparency** via crt.sh. Passive: the target sees no traffic from it.
2. **A DNS wordlist** of roughly 80 high-signal labels (`admin`, `api`, `staging`, `dev`,
   `sso`, ...), resolved concurrently and bounded by `--max-hosts` and a wall-clock
   timeout. `--subdomain-wordlist FILE` adds your own labels.

A random name is resolved first to detect wildcard DNS. Against a wildcard every candidate
looks live, so the wordlist sweep is skipped and reported instead of inventing a hundred
phantom hosts. Discovered names that do not resolve right now are dropped, and each
survivor gets an HTTPS probe with an HTTP fallback. The page budget is shared across all
hosts, so `--max-pages` remains a real limit rather than a per-host one.

When discovery finds other hosts, scope widens from `host` to `subdomain` automatically and
says so. Pass `--scope host` explicitly to keep the crawl on one host; the discovered hosts
are then left out and the log tells you why.

### Autonomous mode

`--autonomous` is the one-flag sweep: subdomain discovery, depth-3 crawl, POST forms,
stored planting, DOM analysis, browser confirmation, header and cookie points, common
paths, screenshots, and a 30-minute soft budget. Every flag you pass yourself wins,
including the off switches:

```bash
python run.py --domain example.com --autonomous                # full sweep
python run.py --domain example.com --autonomous --no-stored    # read-only
python run.py --domain example.com --autonomous --max-pages 80 --depth 2
```

It prints what it enabled and what it kept from your command line. Because it plants
stored payloads and submits forms by default, it warns about that once at startup; use
`--no-stored` and/or `--no-forms` on anything you must not modify.

`--max-minutes N` is a wall-clock budget enforced between phases *and* inside them: the
scanner checks the deadline before every injection point, and the stored stage checks it
before every plant and every proof. Once it is reached, queued work is dropped, the points
already in flight are allowed to finish, and the log reports how many points were actually
tested ("time budget reached mid-scan; 13 point(s) tested"). The report then counts only
those points under **Points tested**, lists the run as `"partial"` in JSON, and points
skipped by the budget are deliberately kept out of `--state` so the next run re-tests them.
The remaining overshoot is bounded by a single in-flight point, not by a whole phase.

## How detection works

For every injection point the engine runs a fixed pipeline:

1. **Baseline.** Request the point with a benign value, record the response.
2. **Marker.** Send a unique alphanumeric token (`xs` + 8 hex chars) and locate every
   occurrence with the HTML parser, which tracks byte offsets, enclosing tag,
   attribute, quote style and script/comment ranges.
3. **Classify.** Each reflection gets a context and a snippet, so the payload can be
   built for that exact position rather than sprayed blindly.
4. **Fingerprint.** Probe once more to learn the filter: which break-out characters
   arrive raw and which keywords are stripped. The answer decides which payloads are
   even feasible, and it is stored on the finding as evidence of *why* it worked.
5. **Fire.** Context-matched payloads are rendered with the marker and JS variant, then
   filtered by `--level` and `--risk`. Blocked ones are retried as mutations.
6. **Verify the reflection.** The payload must appear verbatim and the break-out
   characters (`"`, `'`, space, `<`, `-->`, backtick) must survive raw. Quotes preceded
   by an odd run of backslashes are rejected as escaped, not broken out. Payloads built
   for a non-UTF-8 charset are re-encoded in that charset before this check.
7. **Stability.** The same request is re-sent; flaky or one-off reflections are dropped.
8. **Execution proof (optional).** A DOM-writing payload variant is loaded in a headless
   browser and the engine checks `document.getElementById(...)` in the live page, with
   console, network and CSP-violation observers attached. If the node exists, the payload
   really ran.

A payload that is reflected but never executes is reported as *reflected*, not as a
confirmed vulnerability, and the note says why.

### What the sink did to the value (`efficiency`)

Every reflecting point produces a verdict, not just the ones that happen to match a payload.
The last stage measures how much of the probe came back and scores it (the same idea as
XSStrike's `fuzz.partial_ratio`, made explicit instead of hidden in a 90-point special case):

| Kind | Score | Meaning |
| --- | --- | --- |
| `verbatim` | 100 | the value arrived exactly as sent; the payload ladder is worth running |
| `case` | 99 | the sink changed the case (`XS…`); executable, but payloads must be rebuilt |
| `escaped` | 90 | one character was rewritten or escaped (`\'`); a break-out may still exist |
| `partial` | 50 | only the head survived ("only the first 5 characters survive") |
| `absent` | 0 | the value is not in the body |

A point whose value is mangled is not silently dropped: it becomes a lead carrying the
measurement (`filter_profile.efficiency`, `lead_kind` in the JSON), so "filtered" and "never
reached the sink" stay distinguishable. Two details matter in practice:

- **Recased sinks are detected without an extra request.** Markers are lowercase, so the
  comparison ignores the body's case; a sink that uppercases the value used to look unreflected.
- **Digit-stripping or truncating sinks get a second, shorter probe.** When the first marker
  does not come back intact (absent, escaped or partial) and `--level 2` or higher is active,
  one letter-only marker is sent. A sink that loses exactly one character is the case that used
  to slip through: 9 of 10 characters still scores 90%, which reads as `escaped` and looks like
  a value that survived. If the short probe reflects, the point is measured and attacked with a
  marker the sink can carry instead of being written off.

`lead_kind` names why the point stayed a lead: `unproven` (reflected, nothing executed),
`partial-reflection` (the probe itself was mangled) or `non-html` (the sink returns JSON or
text, so a browser cannot execute it).

### Verification is tri-state, and "unknown" is not "clean"

This is the rule the scanner is built around. Every payload that reaches the proof stage
carries one of:

| State | Meaning |
| --- | --- |
| `confirmed` | The page itself produced the effect: artifact node present, console message seen, callback received, or CSP violation reported. |
| `not_observed` | The check genuinely ran, the page loaded and executed, and the payload produced nothing. A real negative. |
| `not_tested` | The check could not run: no browser, navigation failure, DevTools error, timeout, blocked download. **Unknown, not clean.** |

Anything that fails to observe records *why* (`verify_reason`), and `not_tested` findings
are never counted as false-positive-free evidence. A run with no browser reports
`execution reported not_tested` rather than implying the site is safe. Conflating those
two states was the single biggest honesty defect in earlier versions: a browser crash and
a blocked payload both used to look like a quiet negative, and both silently dropped a
finding from high to medium confidence.

`--fail-on-findings` exits 1 on findings. If you want a CI gate that also fails when
verification was impossible, gate on the `verify_state` counts in the JSON report.

### Mutation XSS

The mXSS stage takes a payload that a browser accepted as inert markup, serialises the
resulting DOM, re-parses that serialisation, and checks whether the second parse now
executes. The payload is only reported when the round trip itself produces execution,
so a browser that normalises differently from the server cannot manufacture a finding.
A control route that does not round-trip is asserted to stay silent.

### Multibyte charsets

Where the response declares or implies a multibyte charset in the GBK family
(`gbk`, `gb2312`, `gb18030`, `cp936`), Big5 (`big5`, `cp950`), or Shift_JIS family
(`shift_jis`, `sjis`, `cp932`, `windows-31j`), the generator produces the classic
trail-byte form: a lead byte followed by a byte that the server's encoder consumes out
of the quote or angle bracket, so `\` or `"` disappears from the byte stream and the
attribute breaks out. Payloads are encoded in the target charset rather than sent as
UTF-8, and a UTF-8 route with the same payload is used as a control: if the control
fires, the finding is a plain encoding issue rather than a charset escape.
Charsets outside those three families are not modelled and are reported as ordinary
reflection, not as an escape.

### CSP

The `Content-Security-Policy` header is parsed into directives, sources and nonces.
A payload that the policy would block is reported with `csp_blocked` and a downgraded
severity, and the report names the directive that stopped it plus any observed
weakening (`unsafe-inline`, `*`, `data:`, a missing `object-src`, report-only mode).
`Content-Security-Policy-Report-Only` is treated as *not enforced* - it changes nothing
about exploitability, so it must not silence a real finding.

### DOM XSS

Crawled scripts are parsed for sources (`location.search`, `location.hash`,
`location.pathname`, `document.referrer`, `window.name`, `postMessage`, storage,
framework router hooks and server-rendered state blobs) and sinks (`innerHTML`,
`outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `Function`,
`setTimeout(string)`, `location`). A flow is reported only when the tainted value
reaches the sink along an assignment chain, and confirmed only when the browser shows
the payload's own artifact node or the payload calls home. Flows that need the fragment
are delivered through `location.hash` with an exact reload, not by assuming a
navigation happened.

The flow does not have to live in one script or travel in one request:

- **Storage joins.** `localStorage.setItem('saved-search', term)` on one page and
  `el.innerHTML = localStorage.getItem('saved-search')` on another are joined into a
  single flow. Verification drives the real sequence - open the write page with the
  payload, confirm the value actually landed in storage, then load the read page - so a
  write that never happened is reported as "flow not exercised", not as "clean". Keys
  are origin-scoped: a write from another origin is dropped rather than replayed.
- **Hydration sources.** A state blob is not JavaScript, so it is read through the id
  of its `<script>` element (`__INITIAL_STATE__`, `__PRELOADED_STATE__`, `__NEXT_DATA__`,
  `__NUXT__`, `__APOLLO_STATE__`, `__REDUX_STATE__`) or through `el.dataset.*` /
  `getAttribute('data-…')`. The blob itself is excluded from the taint pass, and the
  parameter that feeds it is taken from the page's own query names before any guess.
- **Every inline block counts.** All executable `<script>` blocks of a page are merged
  into one virtual resource before analysis, so a variable assigned in one block and
  sunk in the next is still a flow - and a non-executable block can no longer shadow the
  script that reads it.

### Stored and blind XSS

`--stored` plants one uniquely marked payload per form field, re-fetches the crawled
pages to find where the marker reappears, then opens those pages and waits for the
payload's handler to create a node. The same handler also beacons the callback listener
when `--callback` is running, which is what makes blind XSS (payload executed by an
admin view you cannot see) provable instead of guessed.

Three refinements matter in practice:

- **`--viewer-url`** names the page that renders submitted content (a moderation queue,
  a profile page, an admin inbox). Blind stored XSS is exactly the case where the payload
  renders for someone else, so without a viewer URL it can only be proven by callback.
- **`--stored-json URL [--stored-json-field NAME]`** plants into JSON APIs, which is how
  most modern forms actually submit. Form-encoded planting misses them entirely.
- **`--capture-cookies`** makes the callback beacon include `document.cookie`. It is
  **off by default**: harvesting a session cookie is an exfiltration step, not a
  detection step, and it should be a deliberate choice on an authorised test.

### Authenticated sessions

`--login-url` submits the site's own login form (auto-detecting the username, password
and any CSRF token fields, overridable with `--login-user-field`, `--login-pass-field`
and `--login-data K=V`), keeps the resulting cookie jar for every later request, and
`--login-check URL` confirms the session really took by requiring that URL to stop
redirecting to the login page. If the check fails the scan says so instead of silently
crawling a login page.

Anti-CSRF tokens are re-read before each submission, because a token captured once is
usually stale by the third POST (`--no-csrf-refresh` disables this). `--cookie-jar`
preloads a Netscape `cookies.txt`, and `--save-cookies` writes the final jar back out;
that file holds live session secrets, and the scanner says so when it writes it.

## WAF, parameters and library intelligence

Five stages run alongside detection. They are observation-only: they decide what gets
tested and what the report explains, never what counts as a finding.

### WAF fingerprinting and evasion (`--waf`, `--evade`)

`--waf` asks the target a small fixed set of questions - four requests: a benign baseline
and three probes shaped like a script tag, a SQL injection and a traversal - then reads the
vendor from headers, cookies, block pages and probe behaviour. Evidence from every response
is kept and merged, so confidence rises only when the answers agree; one odd 403 is a
low-confidence hint, not a WAF. Detection is per host and cached for the run.

When a blocking vendor is identified, `--evade` routes payloads through that vendor's
vocabulary of variants (case, whitespace, entity and comment tricks). Every reflection gets
its own share - two to six variants, depending on the detection's confidence and whether
the vendor was seen blocking - and `--evasion-budget` (default 240) caps the total added
across the whole scan, so one hostile point cannot starve the rest. `--no-waf` and
`--no-evade` switch the stages off.

Two deliberate limits: a variant that only appears to bypass because the scanner decoded it
twice is not counted - every variant still has to pass the same reflection and execution
gates as a normal payload - and the budget is a cap, not a promise.

### Character-level brute force (`--brute`)

When a point reflects but every payload is mangled, `--brute` measures the filter instead of
guessing. Four probe families run in sequence, all marker-wrapped so a rejected value cannot
hide which part caused it:

- one probe per break-out character, to learn what survives raw, is encoded, or is stripped;
- keyword probes in every casing (`alert`, `ALERT`, `AlErT`, `script`, `svg`), so a filter
  that only blocks the lowercase spelling is measured as passable - HTML does not care about
  case even when the filter does; handlers are probed too (`onload`, `onerror` before the rest,
  because a synthesised vector needs a handler the filter actually allows);
- multi-character sequences (`<script`, `</script`, `<svg`, `onerror=`, `onload=`,
  `javascript:`, `<>`, `"><`, `=(`, `(){}`), because `<` surviving on its own says nothing
  about `<script` being blocked as a token;
- a truncation search that finds the length where the target starts cutting the value, so a
  payload silently sliced in half is not mistaken for one whose characters were removed.

The character map then drives synthesis: vectors are built only from characters that
survived, using the spelling of each keyword that came back verbatim and skipping banned
sequences, and they are tested like any other payload. A word blocked in every casing is
never emitted: if no callable or handler survives, the vector is dropped (a `<script>` block
needs no handler and is still tried). `--brute-budget` caps the probes for the whole scan
(default 40 - raise it when a scan has several hostile points); findings produced this way
carry the character map, the synthesised vector, the blocked sequences and the truncation
limit as evidence.

Brute force also runs when the reflection could not be classified at all (`inferred`): the
payload ladder is skipped, the measured survivors are synthesised, and a hit is reported as a
finding because the marker came back inside the synthesised vector - the filter was measured,
not assumed.

### Undocumented parameters (`--discover-params`)

Parameters are probed in batches with a unique alphanumeric marker. A name is reported when
its marker is reflected, or when the response contains a validation-style message naming it;
promising names are re-probed with `name=1` and their response shape compared against the
baseline so a length change alone is not mistaken for a parameter, and confirmed again in
the same direction before a name is added (a shape that flips between requests is drift, not
a parameter). JSON and form bodies are searched too: every candidate key is injected into the
body and the response is compared against a body-only baseline, so a property that is only
read by the server - and never appears in the URL - is still found, while keys the request
already documents are not reported as hidden. `--param` still filters which names may be
added to the scan. A user-supplied wordlist is tested before the built-in candidates, so a
long list cannot be silently truncated by the built-in budget.

### Fuzz mode (`--fuzz`)

Exploration rather than detection: each parameter is probed with a fixed matrix (quotes,
angle brackets, comment and script closers, backticks, parentheses, `javascript:` URLs,
template syntax) and every response is classified as raw, encoded, evaluated or stripped -
always against that parameter's own baseline, so punctuation that already exists in the page
boilerplate is not reported as a reflection. It produces no findings; it produces the table
that tells you which payload family a parameter will accept, and `--fuzz-budget` bounds the
requests (default 200).

### Client-side library CVEs (`--js-libs`)

Script sources and inline bodies are matched against a signature table (jQuery, jQuery UI,
Bootstrap, AngularJS, Lodash, Moment.js, DOMPurify, Handlebars, Underscore, Axios, React,
Vue, marked). A version is used only when it was read from the resource itself - the body
first, then the filename - and compared numerically against each advisory's affected range
(introduced version up to, but not including, the version that fixed it). Ranges matter:
Bootstrap 3.0.0-3.4.0 and 4.0.0-4.3.0 are affected by the tooltip/popover issues fixed in
3.4.1 and 4.3.1, while 2.3.2 and 3.3.7 are not, and a single "version 3.4.1" string would
get both cases wrong. `--osv` additionally asks osv.dev about every identified version and
merges the advisories it returns (lookups are capped and a failure is ignored rather than
changing a verdict). Libraries whose version could not be determined are not queried at all:
a versionless OSV query returns every advisory for the package, which would read as "this
build is vulnerable to all of them". Long advisory lists stay complete in the JSON and are
summarised in the console line (`+N more`). The output is an indicator: "CVE-2020-11022
applies to this version" is not a claim that this page is exploitable.

OSV enrichment is verified against the live service, not only against fixtures. A bounded run
(`max_lookups=3`, 0.64 s) merged advisories for jQuery 1.8.3 (5 CVEs), Bootstrap 3.3.7 (7)
and Lodash 4.17.4 (9) into the local verdicts, then stopped: the fourth library was never
queried and stayed unchanged, so the cap is visibly enforced.

### Server stack and outdated versions

The headers a host sends are also an inventory: `Server: nginx/1.18.0` is a version, not
just a name. The crawler keeps the headers and the `<meta name="generator">` value of the
first HTML response it already fetched, and the stack pass reads them without a second
request. Three things make the result usable rather than noisy:

- A row always cites its evidence (`Server`, `X-Powered-By`, `X-AspNet-Version`,
  `X-Generator`, `meta generator`, or `cookie <name>`), so a claim can be checked against
  the response that produced it.
- Versions are compared numerically, so nginx 1.20.10 is newer than 1.20.9 and is not
  blamed for a fix that shipped in 1.20.1, and the IIS rules match `8.5` without also
  matching `10.0`.
- The policy table only holds issues that are public, fixed and cheap to verify: Apache
  2.4.49/2.4.50 (CVE-2021-41773, CVE-2021-42013), nginx before 1.20.1 (CVE-2021-23017),
  PHP branches before 8.2 (out of security support) and IIS 6.0-8.5 (shipped only with an
  end-of-life Windows Server). A CMS such as WordPress is reported with its disclosed
  version and no end-of-life claim, because that judgement is not the scanner's to make.

A flagged version is a lead: it says the build has a published problem, not that this
host is exploitable through it. The finding standard for XSS is unchanged.

### Browser cost

`--browser` reuses one browser and one page per run. The report's `browser_verification`
line states how many checks ran, how many launches were needed and the average milliseconds
per check, so the price of execution proof is visible rather than implied.

## Flags

| Flag | Meaning |
| --- | --- |
| `-u URL`, `--domain DOMAIN`, `-m FILE` | single URL, a bare domain to enumerate, or a file of URLs |
| `--autonomous` | one-flag sweep; explicit flags always win |
| `--max-minutes N` | wall-clock budget, enforced between and inside phases (0 = unlimited) |
| `--crawl` / `--no-crawl` | force crawling on or off (crawl is on by default) |
| `--crawl-depth N`, `--depth N` | BFS depth (default 2) |
| `--max-pages N` | page cap for the crawl, shared across hosts (default 150) |
| `--scope {host,subdomain,any}` | how far the crawler may wander |
| `--subdomains` | discover subdomains via CT + DNS and crawl them too |
| `--no-subdomain-brute` | passive CT only, no DNS wordlist sweep |
| `--subdomain-wordlist FILE` | extra DNS labels, one per line |
| `--subdomain-base {auto,host,registrable}` | how the enumeration base is derived (default `auto`) |
| `--public-suffix-list FILE` | real PSL file to replace the built-in suffix table |
| `--max-hosts N` | cap on discovered hosts crawled per target (default 25) |
| `--exclude REGEX` / `--include REGEX` | limit what gets crawled (repeatable) |
| `--no-js`, `--robots`, `--common-paths` | JS endpoint mining off, honour robots.txt, probe conventional paths |
| `--forms` / `--no-forms` | also submit POST forms as reflected points (can create records) |
| `--stored` / `--no-stored` | plant payloads in forms and prove stored XSS (writes data) |
| `--stored-max-forms N` | cap on forms used for stored planting (default 20) |
| `--stored-json URL`, `--stored-json-field NAME` | plant stored payloads through a JSON endpoint |
| `--viewer-url URL` | page that renders stored content (moderation queue, profile) |
| `--callback [PORT]` | loopback listener for blind XSS proof (random port by default) |
| `--callback-bind ADDR` | interface the listener binds to (default `127.0.0.1`) |
| `--callback-url URL` | public URL the target should reach, when the listener is behind NAT |
| `--capture-cookies` | let the callback beacon send `document.cookie` (off by default) |
| `--method`, `--data`, `--json-body` | test a specific request body |
| `-p`, `--param`, `--param-value` | only these parameters / custom injection placeholder |
| `--headers-points` | add Referer, User-Agent, X-Forwarded-Host, Origin |
| `--cookie`, `-H`, `-A`, `--random-agent` | request identity |
| `--login-url`, `--login-user`, `--login-pass` | sign in through the site's login form first |
| `--login-user-field`, `--login-pass-field`, `--login-data K=V` | override login field names / add fields |
| `--login-check URL` | URL that must stop redirecting to login |
| `--cookie-jar FILE`, `--save-cookies FILE` | load / save a Netscape cookies.txt (secrets) |
| `--no-csrf-refresh` | do not re-read anti-CSRF tokens before each submission |
| `--level 1..3` | payload breadth: 1 classic, 2 JS/RCDATA/forms, 3 polyglots/headers/cookies |
| `--risk 1..3` | 1 non-interactive, 2 adds autofocus/onfocus, 3 adds interaction payloads |
| `--no-profile`, `--mutations N` | disable filter fingerprinting / cap mutations per point |
| `--waf` / `--no-waf` | fingerprint the WAF/CDN in front of each host (default on) |
| `--evade` / `--no-evade` | route payloads through the detected vendor's bypass vocabulary (default on) |
| `--evasion-budget N` | cap on evasion variants added across the whole scan (default 240) |
| `--brute`, `--brute-budget N` | character/keyword brute force for hostile points; probe budget for the whole scan (default 40) |
| `--discover-params` | probe for undocumented query and body parameters and add the responsive ones to the scan |
| `--fuzz`, `--fuzz-budget N` | classify what each parameter does to the response; request budget (default 200) |
| `--js-libs` / `--no-js-libs` | fingerprint client-side library versions and list applicable CVEs (default on) |
| `--osv` | merge advisories from osv.dev into the library results (capped lookups, network) |
| `--browser` / `--no-browser` | headless execution proof (auto-detects Chrome/Edge) |
| `--verify` / `--no-verify` | exploit stage: replay each finding with a weaponised payload and measure impact |
| `--verify-max N` | cap on findings replayed by `--verify` (default 10) |
| `--dom` / `--no-dom`, `--dom-flows N` | DOM analysis and its flow cap (default 15) |
| `--headless new\|old` | headless mode passed to the browser |
| `--screenshots` | capture a PNG for verified findings |
| `--threads N`, `--delay S`, `--timeout S`, `--retries N` | pacing and reliability |
| `--proxy URL`, `--insecure` | `http://`/`socks5://` proxy for scanner and browser; skip TLS verification |
| `--max-points N` | stop after N injection points |
| `--state FILE` | resume file: skip points already completed, carry findings over |
| `-o FILE`, `--html FILE`, `--markdown FILE`, `--output-dir DIR` | report destinations |
| `--sarif FILE` | SARIF 2.1.0 report for CI/code scanning integrations |
| `--evidence DIR` | one evidence file per finding |
| `-q`, `-v`, `--no-color` | verbosity |
| `--fail-on-findings` | exit code 1 when something is found (CI gate) |
| `--list-payloads` | print the payload catalogue and exit |
| `--version` | print the version and exit |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | run completed, nothing found (or findings without `--fail-on-findings`) |
| `1` | `--fail-on-findings` was set and something was found |
| `2` | usage error, bad arguments, or no usable Python interpreter (launcher) |
| `130` | interrupted (Ctrl-C) - **reports and `--state` are still written first** |

Ctrl-C used to abort mid-run and lose everything that had already been proven. It now
stops the workers, flushes reports, saves resume state and exits 130, so an interrupted
long scan is still worth something.

## Reports

Each run writes the configured files (timestamped in `--output-dir` by default):

- `*.json` - machine readable: metadata, crawl stats, statistics, filter profiles and
  every finding with payload, context, severity, confidence, `browser_verified`,
  `browser_checked`, `verify_state`, `verify_reason`, `csp_blocked`, `cvss`,
  `reproduction` and `severity_change_conditions`. Findings also carry `template`,
  `payload_name`, the recorded `request`, and an `exploit` block when `--verify` ran;
  the run's overall exploit counts sit in the top-level `verification` key.
- `*.md` - summary table plus per-finding sections for tickets and write-ups, including
  a "Exploit (proof of impact)" block with the measured capabilities. A final
  "Reconnaissance" section lists the WAF verdict and evidence, client-side libraries and
  their CVE hints, discovered parameters, the fuzzing matrix and brute-force character maps.
  Points that reflect but swallow every payload get their own "Leads (unconfirmed)" table:
  parameter, context, confidence and the measured filter, kept separate from findings so a
  hostile-but-unproven point is never read as a vulnerability or as a clean result.
- `*.html` - self-contained report with severity counters (including an "Exploit-proven"
  tally), collapsible evidence and the same Reconnaissance section as tables.
- `*.sarif` - SARIF 2.1.0, one rule per context, with parameter, payload, confidence,
  verification state and the `exploit` verdict in `properties`. The same reconnaissance
  data rides in `runs[0].properties.reconnaissance` for pipelines that read more than
  `results`. Unconfirmed leads ride along in the run's `leads` metadata (capped at 200).

`--evidence DIR` additionally writes `NNN-context-parameter.txt` per finding: target,
parameter, payload, filter profile, the request that triggered it, the response
observation that confirmed it, a CVSS 3.1 vector, and a `curl` line that reproduces it.
The captured request is reproduced with `Cookie` and `Authorization` values replaced by
`<redacted>`, and the `curl` line omits those headers entirely with a comment telling you
where to add your own session - a report is a document, not a credential spill.

## Exploit stage (`--verify`)

Detection answers "did this input reach an execution context?". `--verify` answers the
next question a report has to answer: **what could that script reach on this origin?**

It re-renders the vector that already worked -- same template, same parameter, same
request body -- with the inert DOM artifact swapped for a weaponised script, replays that
request in the same browser, and asks the live page what the script observed:

| Measured capability | What it establishes |
| --- | --- |
| `dom_control` | the injected script ran and owns the document |
| `cookie_bytes` / `cookie_names` | how much `document.cookie` the origin exposes, and which cookies (**names only, never values**) |
| `csrf_token_readable` / `csrf_token_length` | the script can read the page's anti-CSRF token, so it can script state-changing requests |
| `same_origin_status` / `same_origin_bytes` | a same-origin GET issued as the victim returned a readable response |
| callback hit | the payload reached an out-of-band listener (`--callback`) |

```bash
python -m xssmap -u "https://target.tld/search?q=1" --verify --browser
python -m xssmap -u https://target.tld --verify --verify-max 5 --callback 9000
```

Against the loopback lab used for the regression tests:

```
[*] exploit stage: replaying up to 1 of 1 finding(s) with a weaponised payload
[+] exploit proven on q (html_text): same-vector - dom_control, csrf_token_readable
[+] exploit: 1 finding(s) proven to reach cookies, tokens or same-origin data
    exploit PROVEN (same-vector): Arbitrary script execution in the target origin ...
    The script read 28 bytes of cookie data (names: sid) ...
    The script read the page's anti-CSRF token (14 chars) ...
    A same-origin GET issued as the victim returned HTTP 200 (161 bytes readable) ...
```

The stage refuses to inflate a finding: a replayed payload that produced no observable
effect stays `unproven`, with the browser's own reason quoted (CSP refusal, console
error, or "rendered but no effect"), and the finding keeps its detection severity. Only
measured capabilities upgrade severity and CVSS.

Two implementation details matter more than they look:

- The weaponised script contains **no whitespace and no angle brackets**. Most vectors
  put `{JS}` in an unquoted attribute (`<svg onload={JS}>`), where the first space or
  `>` ends the attribute value; a normal-looking script would be truncated mid-expression
  and never run. `var/**/x` keeps the parser's token separator without emitting a space,
  and the token hunt uses `indexOf(...)+1` instead of `... > -1`. As a fallback, an
  unquoted slot is quoted when a script still needs either character.
- It records cookie **names and byte counts**, never values, so the report demonstrates
  exposure without becoming a credential dump.

When the target sends CSP, `--verify` makes one bounded attempt at nonce reuse: if the
same nonce appears in two responses, an injected `<script nonce=...>` is tried. That is a
fixed, single candidate -- there is no policy brute force. Everything else about CSP is
reported as an observed block, not as an exploit.

## Verification

`tests/selftest.py` starts a purpose-built vulnerable lab (`testapp/vuln_app.py`) on a
random port, scans it over real HTTP and scores the output against the app's manifest.
It exits non-zero if any expectation fails, so it is usable as a gate.

```bash
python tests/selftest.py                             # crawl + direct scan
python tests/selftest.py --forms --stored            # no browser required
python tests/selftest.py --browser --forms --stored   # full, needs Chrome/Edge
```

Eight phases: crawl and scan, direct per-endpoint scan, POST form with CSRF token,
machine-readable outputs, mXSS round trip, multibyte charset escaping, authenticated
session with JSON planting, and resume state with viewer pages.

Latest full run (`--browser --forms --stored`):

```
phase 1 - crawl and scan (default level 2)
  TP  /attr?name            attr_double        browser-confirmed
  TP  /attr-single?name     attr_single        browser-confirmed
  TP  /attr-unquoted?q      attr_unquoted      browser-confirmed
  TP  /charset?q            charset            browser-confirmed
  TP  /comment?x            comment            browser-confirmed
  TP  /csp?q                html_text          csp-blocked-execution
  TP  /csp-report-only?q    html_text          browser-confirmed
  TP  /dom?q                dom_xss            browser-confirmed
  TP  /dom-hash?q           dom_xss            browser-confirmed
  TP  /dom-hydrate?q        dom_xss            browser-confirmed
  TP  /dom-state-read?q     dom_xss            browser-confirmed
  TP  /feedback?message     stored_xss         browser-confirmed
  TP  /filter?q             html_text          browser-confirmed
  TP  /guestbook?comment    stored_xss         browser-confirmed
  TP  /js?name              js_string_double   browser-confirmed
  TP  /js-single?name       js_string_single   browser-confirmed
  TP  /misconfig?q          html_text          browser-confirmed
  TP  /search?q             html_text          browser-confirmed
  TP  /textarea?msg         textarea           browser-confirmed
  TP  /title?q              title              browser-confirmed
  TN  /charset-safe?q       -                  utf-8 decoding keeps the escape
  TN  /encoded?q            -                  html_escape
  TN  /stripped?q           -                  character stripping
  TN  /safe?q               -                  json script escaping
  TN  /json?q               -                  json content-type + nosniff
  -> 20/20 detected (100% recall), 0 false positive(s) (100% precision)
  crawl: 43 pages, 27 parameterised URLs, 12 forms; 413 requests

phase 2 - direct per-endpoint scan (reflected only)
  -> 14/14 detected (100% recall), 0 false positive(s) (100% precision)

phase 3 - POST form with CSRF token            token handled
phase 4 - machine-readable outputs             SARIF 2.1.0 valid, evidence written
phase 5 - mutation XSS round trip              round trip re-executed, high/confirmed
phase 6 - multibyte charset escaping           trail byte proven; no-browser run not_tested
phase 7 - authenticated session, JSON planting tokens refreshed: 2, stored proven: 4
phase 8 - resume state and viewer pages        point skipped, finding carried over
all checks passed
```

The lab deliberately includes traps: HTML-escaped output, a character-stripping filter,
JSON inside a non-executable `<script type="application/json">` block, JSON served with
`nosniff`, a UTF-8 route sharing the charset payload, and a
`Content-Security-Policy-Report-Only` header that must *not* be treated as enforcement.
All of them stay clean.

### Second, independent lab

`bench/` scores the scanner against `bench/lab2/app.py`, a second vulnerable application
written separately from `testapp/`, with its own ground truth (`bench/verify_lab.py`)
and a scorer that reports precision/recall rather than a pass/fail count:

```bash
python bench/run_bench.py              # no browser
python bench/run_bench.py --browser    # with execution proof
```

Latest browser run: 9 true positives, 0 false positives, 0 false negatives, 4 true
negatives (precision 1.00, recall 1.00, F1 1.00) over 13 labelled routes. Having two
labs written independently of each other is the point: a payload tuned to one app's
response shape shows up as a miss on the other.

## Tests and CI

```bash
python -m unittest discover -s tests -p "test_*.py" -v   # 445 tests, no network
python -m ruff check .                                   # lint
python -m mypy xssmap                                    # types on shipped package
```

Units cover the parts that are hard to eyeball: the tri-state verifier and its
"exception is not a negative" rule, the CSP parser (including report-only), the mXSS
round-trip gate, charset trail-byte generation and the UTF-8 control, throttle and
`Retry-After` handling, resume state, report/SARIF rendering, subdomain parsing, suffix
derivation and scope matching, the autonomous preset's precedence rules, DOM source and
delivery inference (`location.hash`/`location.search` outranking the source table),
storage write/read joins including the cross-origin drop, hydration and `dataset`
sources, parameter guessing for flows that name none, inline-script merging across
`<script>` blocks, payload surgery and request replay for the exploit stage (including
the no-whitespace/no-angle-bracket rule), session re-login and captured-cookie
precedence, `strict-dynamic` gadget and JSONP notes, adaptive evasion ordering, the
transport deadline clip, and the bench ground truth.

`ruff` and `mypy` settings live in `pyproject.toml`; the ignores are documented inline
next to the rule they silence rather than in a bare list. mypy is scoped to `xssmap/`
(the code users run) and does not cover `tests/` or `bench/` fixtures.

`.github/workflows/ci.yml` runs five jobs: lint, types, units on a
3.9/3.12/Windows matrix, the browser-free selftest on Linux and Windows, and the full
browser harness on Linux (advisory, since headless timing on shared runners varies).

## Limitations

- DOM analysis is static taint tracing plus runtime confirmation. It recognises common
  framework sources and sinks (`useSearchParams`/`useLocation`, `dangerouslySetInnerHTML`,
  `v-html`, `bypassSecurityTrustHtml`, `createContextualFragment`, jQuery `.parseHTML`,
  `innerHTML`, `eval`, `document.write`, `location`) and follows a value across resources
  through web storage, server-rendered state blobs, `data-*` attributes, component state
  (`setState({...})`, `this.state.x`, `useState`), reducer dispatch (`dispatch({type:...})`
  joined to the matching `case` handler, including spread state updates) and a pub/sub bus
  (`emit`/`publish` joined to `on`/`subscribe` handlers). Values carried in an object
  property or an array (`holder.value`, `parts.push`, `arr.join`) are tracked to the sink
  as well. It is still not a general data-flow analysis: a flow that is rendered by a
  server template the crawler never fetches, or that is assembled by string operations the
  taint model does not name, stays a miss. A storage join also needs both pages inside the
  crawl budget (`--max-pages`, `--crawl-depth`), and a blob needs the script that reads it.
  A component-state, reducer or event-bus join is only replayed when the write and the read
  happen on the same page, because an in-memory store is reset by a second navigation; a
  cross-page join is reported as a lead with that reason. Only flows proven in the browser
  are reported, so a miss stays a gap, never a false positive.
- A lead means the parameter reflects and every payload the scanner tried was filtered,
  encoded or cut. It is recorded with the measured filter (surviving characters, blocked
  keywords and sequences, truncation limit, efficiency score) and low confidence; it is not a
  finding, and it is not proof that a bypass exists - only a reason to look by hand. The
  measurement explains *where* the value landed and how much of it survived; it cannot
  explain why an application-level filter chose to rewrite it.
- Stored scanning writes data through forms. It is opt-in (`--stored`) and should only be
  used on systems you are authorised to modify.
- Browser proof and `--verify` cover classic inline execution. CSP handling is bounded on
  purpose: one nonce-reuse attempt when the header really repeats a nonce, then the
  observed block is reported. `strict-dynamic` is analysed rather than assumed: the finding
  notes count the page's own script-creating gadgets (`createElement('script')`,
  `innerHTML`/`document.write` with `<script>`, `insertAdjacentHTML`), because that trust
  model still executes a script a trusted gadget builds from attacker data, and they list
  allowlisted JSONP endpoints that take a callback parameter (skipped under
  `strict-dynamic`, where a host allowlist does not apply). Those are leads for a manual
  gadget check, not an execution claim: the scanner does not weaponise a gadget on its own,
  so a target behind a well-built CSP will usually stay `unproven` - which is a statement
  about the measurement, not about safety.
- `--verify` replays the recorded request with the run's session. When a login was
  performed (`--login-url`/`--login-user`/`--login-pass`), the credentials are kept in
  memory only for the run: if a replay lands on a login wall (401/403 or a login path),
  the scanner logs in again once, re-syncs the browser cookies and retries, and the
  finding records `reauth`. A captured `Cookie` header from the original request is
  dropped while a session exists so the fresh cookie is the one that is sent. A replay
  still fails as `unproven` if the second login is refused, and the reason says so.
- The exploit stage proves what the script could read *at that moment*: cookie byte
  counts and names, token readability and one same-origin GET. It does not attempt
  state-changing requests, so it demonstrates capability rather than performing writes.
- `--callback` binds to loopback by default. Use `--callback-bind` for another interface,
  or `--callback-url` when the listener sits behind NAT and the target must reach a
  public address; the listener is unauthenticated by design and should be short-lived.
- mXSS and charset stages prove what the *scanner's* browser does with a payload. A
  different browser or version may round-trip differently, so treat a positive as
  "this payload executed here", not "every client is affected".
- `--save-cookies` writes live session secrets to disk in Netscape format. The file is
  created `0600` on POSIX; Windows does not enforce mode bits, so rely on NTFS ACLs there.
  Treat the file like a password either way.
- Subdomain discovery is best-effort reconnaissance, not a complete asset inventory. The
  enumeration base is public-suffix aware for the common `co.uk`/`com.au`-style suffixes
  built in, and `--public-suffix-list FILE` loads the real PSL (`*.` and `!` rules
  supported) when you need full coverage; without it, an unusual multi-label suffix falls
  back to the simple rule. Certificate transparency is queried through three independent
  providers in order (crt.sh, certspotter, hackertarget): a failing or rate-limited
  provider is recorded and skipped, the next one is asked, and the per-source yield is
  reported, so one bad day at crt.sh no longer empties the result. Coverage is still
  best-effort, and the DNS step uses a short built-in wordlist - feed your own recon in
  through `--subdomain-wordlist` for a full inventory.
- `--max-minutes` is enforced inside phases as well as between them (crawl, scan pool,
  DOM, stored and exploit stages all check a deadline), and the transport clips each
  request's socket timeout to the budget that is left, with retry sleeps and throttle
  pacing stopping at the deadline. A request already in flight can still exceed the budget
  by at most the remaining slice (floored at 0.25s), and the report is then marked
  `partial` rather than pretending the sweep finished.
- Heavy crawls against large sites should be bounded with `--max-pages`, `--delay` and
  `--threads`; the scanner honours those limits for every request it makes.
- WAF evasion is signature-driven at first and adaptive afterwards: each strategy that
  makes a payload reflect verbatim is tried first on later points, and one that only
  produces mangled or blocked responses moves to the end of the budget (the per-scan
  ranking is written to the report as `evasion_learned`). A proprietary or heavily
  customised filter may still be misidentified or missed entirely, and the vendor
  vocabulary only helps when the blocking rule is one of the known shapes. A failed bypass
  is a failed bypass, not proof that the target is safe.
- `--brute`, `--discover-params` and `--fuzz` are request-hungry by design. Each has an
  explicit budget and stops at it; the report marks a truncated fuzz run instead of
  implying it covered every parameter.
- JavaScript CVE hints are version indicators, not exploit proof, and only cover the
  libraries in the signature table. A current library can still be vulnerable through the
  application's own code, and a library version read from a filename can be wrong.

Only test systems you are authorised to test.
