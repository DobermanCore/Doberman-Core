"""Recommended policy checklist (Feature 6, slice 6.1).

Generates a pre-checked policy (hard-blocks + step-ups) from the agent role and
the discovered capabilities, as an editable :class:`PolicyDoc` that persists to
``.doberman/policies.yaml``. Good defaults are the product: everything ships
**enabled** (safe-by-default), and the **core hard blocks are always present and
not removable here** — disabling one requires the Feature 10 human-approved path.

This module is policy core: it imports only ``doberman`` models/roles and never
the proxy.
"""

from dataclasses import dataclass, replace
from typing import Any

from doberman.models import Verdict
from doberman.roles.roles import RoleDefinition

CATEGORY_HARD_BLOCK = "hard_block"
CATEGORY_STEP_UP = "step_up"


@dataclass(frozen=True)
class PolicyItem:
    """One checklist item (immutable).

    ``core`` items are non-disableable here (a core hard block can only be
    removed through F10). ``applicable`` is False when the item's capability is
    not present in this repo (kept in the doc, marked N/A) — never silently
    dropped.
    """

    id: str
    description: str
    category: str
    verdict: Verdict
    enabled: bool = True
    core: bool = False
    applicable: bool = True


#: Core hard blocks — always present, always enabled, never disableable here.
_CORE_HARD_BLOCKS: tuple[PolicyItem, ...] = (
    PolicyItem(
        "hard_block.secret_exfiltration",
        "Block sending secret material to an external destination.",
        CATEGORY_HARD_BLOCK,
        Verdict.BLOCK,
        core=True,
    ),
    PolicyItem(
        "hard_block.protected_path",
        "Block writes/deletes to protected paths (.env, secrets, keys).",
        CATEGORY_HARD_BLOCK,
        Verdict.BLOCK,
        core=True,
    ),
    PolicyItem(
        "hard_block.destructive_command",
        "Block catastrophic commands (rm -rf /, disk wipes, force-push to protected branches).",
        CATEGORY_HARD_BLOCK,
        Verdict.BLOCK,
        core=True,
    ),
    PolicyItem(
        "hard_block.repo_escape",
        "Block actions whose target resolves outside the repository boundary.",
        CATEGORY_HARD_BLOCK,
        Verdict.BLOCK,
        core=True,
    ),
)

#: Tunable step-ups. ``requires_capability`` (if set) marks the item N/A when the
#: capability is absent from the discovered surface.
_STEP_UPS: tuple[tuple[PolicyItem, str | None], ...] = (
    (
        PolicyItem(
            "step_up.sensitive_path",
            "Require auth for sensitive paths (backend/auth, infra, CI).",
            CATEGORY_STEP_UP,
            Verdict.AUTH,
        ),
        None,
    ),
    (
        PolicyItem(
            "step_up.sensitive_secret_access",
            "Require auth to read/write local secret material.",
            CATEGORY_STEP_UP,
            Verdict.AUTH,
        ),
        None,
    ),
    (
        PolicyItem(
            "step_up.unknown_destination",
            "Require auth for requests to unknown external destinations.",
            CATEGORY_STEP_UP,
            Verdict.AUTH,
        ),
        "network",
    ),
    (
        PolicyItem(
            "step_up.bulk_operation",
            "Require auth for bulk deletes at/over the mode threshold.",
            CATEGORY_STEP_UP,
            Verdict.AUTH,
        ),
        None,
    ),
    (
        PolicyItem(
            "step_up.encoded_exfiltration",
            "Require auth for encoded/indirect exfiltration carriers.",
            CATEGORY_STEP_UP,
            Verdict.AUTH,
        ),
        None,
    ),
)


@dataclass(frozen=True)
class PolicyDoc:
    """The editable policy document (immutable; edits return new copies)."""

    items: tuple[PolicyItem, ...]
    mode: str = "balanced"

    def get(self, item_id: str) -> PolicyItem | None:
        return next((it for it in self.items if it.id == item_id), None)

    def with_item_enabled(self, item_id: str, enabled: bool) -> "PolicyDoc":
        """Return a copy with one item toggled.

        Refuses to disable a core item — that must go through F10 — by raising
        ``ValueError`` (never silently allow a hard block to be turned off).
        """
        target = self.get(item_id)
        if target is None:
            raise KeyError(f"unknown policy item {item_id!r}")
        if target.core and not enabled:
            raise ValueError(
                f"{item_id} is a core hard block and cannot be disabled here "
                "(requires the policy-change approval flow)"
            )
        new_items = tuple(
            replace(it, enabled=enabled) if it.id == item_id else it for it in self.items
        )
        return replace(self, items=new_items)

    def with_mode(self, mode: str) -> "PolicyDoc":
        return replace(self, mode=mode)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "items": [
                {
                    "id": it.id,
                    "description": it.description,
                    "category": it.category,
                    "verdict": it.verdict.value,
                    "enabled": it.enabled,
                    "core": it.core,
                    "applicable": it.applicable,
                }
                for it in self.items
            ],
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "PolicyDoc":
        items = tuple(
            PolicyItem(
                id=str(raw["id"]),
                description=str(raw.get("description", "")),
                category=str(raw.get("category", CATEGORY_STEP_UP)),
                verdict=Verdict(raw.get("verdict", "AUTH")),
                enabled=bool(raw.get("enabled", True)),
                core=bool(raw.get("core", False)),
                applicable=bool(raw.get("applicable", True)),
            )
            for raw in data.get("items", [])
            if isinstance(raw, dict) and raw.get("id")
        )
        return cls(items=items, mode=str(data.get("mode", "balanced")))


def recommend_policy(
    role: RoleDefinition | None = None,
    capabilities: list[Any] | None = None,
) -> PolicyDoc:
    """Build the recommended (pre-checked) policy for this repo.

    Core hard blocks are always included and enabled. Step-ups are enabled by
    default; one whose capability is absent is kept but marked not-applicable.
    If a role is active, an out-of-scope step-up is added.
    """
    present_caps = {
        getattr(c, "name", None) for c in (capabilities or []) if getattr(c, "present", False)
    }

    items: list[PolicyItem] = list(_CORE_HARD_BLOCKS)
    for item, required_cap in _STEP_UPS:
        applicable = required_cap is None or required_cap in present_caps
        items.append(replace(item, applicable=applicable))

    if role is not None:
        items.append(
            PolicyItem(
                "step_up.role_out_of_scope",
                f"Require auth for actions outside the active '{role.name}' role's scope.",
                CATEGORY_STEP_UP,
                Verdict.AUTH,
            )
        )

    return PolicyDoc(items=tuple(items), mode="balanced")
