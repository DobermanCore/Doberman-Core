- Added `docs/AUTHORITY_TIERS.md`, documenting the T0-T3 authority tiers (which layer of a decision may
  `BLOCK` versus only step up to `AUTH`) and a new `tests/unit/test_authority_tiers.py` regression suite
  that keeps every `FLOOR_HARD_BLOCKS` reason code provably reachable as `BLOCK` and every BLOCK-capable
  rule's boundary a discrete predicate rather than a smoothed score.
