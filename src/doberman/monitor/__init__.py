"""The ambient monitor (FM): observe-only adapters that sit beside the live
inline gate, never on it.

``doberman.monitor`` is an adapter surface like ``doberman.proxy`` or
``doberman.dash`` — the policy core (``engine``, ``auth``, ``policy``,
``storage``, ``egress``) is forbidden from importing it (see the
import-linter contract in ``pyproject.toml``, "Policy core must not depend
on the ambient monitor"). The dependency only ever runs the other way: this
package imports the policy core to score what it observes, but nothing in
the policy core knows this package exists. A dead or misbehaving monitor
process therefore cannot change what the live gate does — it isn't wired
into that path at all.

* ``storage.activity`` (FM.1): the redacted ``ActivityEvent`` bus collectors
  write to and this package's daemon drains.
* ``monitor.daemon`` (FM.2): the warm, observe-only daemon
  (``doberman monitor run`` / ``doberman monitor status``) that polls
  collectors and scores what they see through the same ``decide()`` the
  live gate uses — recording alerts, never enforcing anything.
"""
