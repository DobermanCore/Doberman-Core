# Pull Request

## Slice
- Repo: doberman-core | doberman-enterprise
- Feature / Slice: <id> — <title>
- Plan reference: doberman_implementation_plan.md

## What this PR does

## Tests added (run in CI)
-

## Changelog
- [ ] `changelog.d/<PR>.<type>.md` fragment added (one line per user-visible change, see `changelog.d/README.md`), or this change is invisible to users

## Public-release safety (doberman-core only)
- [ ] Contains nothing from the "not allowed" list: no enterprise/hosted code, no proprietary detection, no customer data, no secrets, no commercial-license code
- [ ] Core still builds/tests/runs with NO enterprise package installed

## Security checklist
- [ ] Fails closed on error / uncertainty
- [ ] No secret, full file, or unredacted prompt logged or committed
- [ ] Any guardrail/learning change is raise-only (no silent loosening)
- [ ] Every BLOCK/AUTH carries reason codes + a human explanation
- [ ] doberman-core does not import doberman_enterprise

## Edge cases covered / Deviations from plan / Risks introduced
-
