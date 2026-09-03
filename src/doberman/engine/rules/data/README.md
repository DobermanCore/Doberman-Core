# Dependency admission bundled lists

Two static, offline JSON snapshots consumed only by
`doberman.engine.rules.dependency_admission` (C3, v1). Point-in-time,
refreshed per release, not a live feed — see `README.md`'s known-limitations
section for the honest caveat shipped alongside this.

## known_malicious_packages.json

`{ecosystem: [names]}` of package names with a documented public
typosquat/slopsquat/supply-chain-malware advisory. Each name below MUST be
re-verified against a live advisory before a release ships it (advisories
get superseded or retracted); never add a name without an independently
checkable public source.

Every entry below is from the 2017 npm typosquat campaign (credential-stealing
packages), all removed from the registry and all carrying a GitHub Security
Advisory. Verified against `api.osv.dev/v1/query` on 2026-09-02:

- `npm` / `crossenv` — typosquat of `cross-env`. GHSA-c2m4-w5hm-vqjw
- `npm` / `cross-env.js` — typosquat of `cross-env`. GHSA-hwhq-3hrj-v6v5
- `npm` / `d3.js` — typosquat of `d3`. GHSA-qmjg-g86h-6rc9
- `npm` / `fabric-js` — typosquat of `fabric`. GHSA-v73m-fjxv-w4rh
- `npm` / `mongose` — typosquat of `mongoose`. GHSA-894f-rw44-qrw5
- `npm` / `nodesass` — typosquat of `node-sass`. GHSA-xfmw-2vmm-579c
- `npm` / `nodesqlite` — typosquat of `node-sqlite`. GHSA-wwf2-5cj8-jx6w
- `npm` / `jquery.js` — typosquat of `jquery`. GHSA-jp27-cwp2-5qqr
- `npm` / `openssl.js` — typosquat of `openssl`. GHSA-22gq-x6pg-752j
- `npm` / `babelcli` — typosquat of `babel-cli`. GHSA-72hv-rp4q-q7f3

Verify any of the above at: https://github.com/advisories?query=ecosystem%3Anpm
(search the package name) or `api.osv.dev/v1/query`.

`pypi` ships **empty** in v1: the planner's initial candidates (`colourama`,
`python3-dateutil`, `jeIlyfish`) returned no live OSV advisory when checked
against `api.osv.dev/v1/query` on 2026-09-02, so nothing went in rather than
shipping an unverifiable claim. Add PyPI entries only once a real advisory is
found and cited the same way as the npm entries above.

Never list a legitimate package that was merely compromised in one version
(e.g. `event-stream`, `ua-parser-js`) — this is a name-only list and would
block the real package forever, not just the compromised release.

## popular_packages.json

`{ecosystem: [names]}` of well-known, high-download-count package names per
ecosystem. Used ONLY as (a) the "not itself popular" false-positive guard
and (b) the edit-distance-1 typosquat target set — never as an allowlist
that grants anything.

A name on this list is EXEMPT from the typosquat check (it can never itself be
flagged as one edit away from something popular) — so adding or omitting a name
here is a security-relevant decision, not cosmetic: a real, legitimate package
absent from this seed can be gated once (stepped up to `AUTH`) if it happens to
land one edit from an entry that IS present (e.g. `vuex` vs. `vue`, `boto` vs.
`boto3` — both fixed by adding the omitted name, see the C3 whole-branch review).

This is a STARTER seed (5-22 names per ecosystem: pypi 22, npm 22, cargo 10,
rubygems 10, go 5 — 69 names total). Expand toward the
≤2000-per-ecosystem ceiling from a real ranked snapshot before relying on
this in production — e.g. PyPI's own download-stats BigQuery dataset
(`hugovk.github.io/top-pypi-packages`), npm's registry download-count API,
or crates.io's `/api/v1/crates?sort=downloads` endpoint. Every name added
must be real and independently checkable; never invent one.
