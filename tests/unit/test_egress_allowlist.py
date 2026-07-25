"""Feature RB, slice RB.2a — the default-deny egress allowlist.

Every test here defends: (1) default-deny — nothing is trusted unless it
matches, (2) the allowlist reuses `destinations.py`'s own host parser/matcher
rather than a second, potentially-divergent implementation, and (3) the
optional `.doberman/egress_allowlist.yaml` loader is additive-only and fails
closed (never raises, never grants trust it couldn't validate).
"""

from doberman.egress.allowlist import (
    ALLOWLIST_FILE,
    EgressAllowlist,
    load_extra_allowed_hosts,
)
from doberman.engine.rules.destinations import TRUSTED_HOSTS


def test_default_deny_unknown_host():
    allowlist = EgressAllowlist()
    assert allowlist.is_allowed("https://not-a-trusted-host.example/path") is False


def test_seeded_trusted_host_is_allowed():
    allowlist = EgressAllowlist()
    assert "github.com" in TRUSTED_HOSTS
    assert allowlist.is_allowed("https://github.com/fu351/doberman") is True


def test_trusted_subdomain_is_allowed():
    allowlist = EgressAllowlist()
    assert allowlist.is_allowed("https://raw.githubusercontent.com/x/y") is True


def test_lookalike_suffix_confusable_host_is_denied():
    allowlist = EgressAllowlist()
    # Neither a prefix-confusable nor a suffix-confusable domain is trusted —
    # matches the exact adversarial cases destinations.py itself defends.
    assert allowlist.is_allowed("https://evil-github.com/x") is False
    assert allowlist.is_allowed("https://github.com.evil.test/x") is False


def test_case_and_punycode_handling_matches_destinations_module():
    allowlist = EgressAllowlist()
    # Case-insensitive.
    assert allowlist.is_allowed("https://GitHub.COM/x") is True
    # Punycode domain (same fixture as test_rule_destinations.py) — must decode
    # consistently with destinations.py and, since it never equals a real
    # trusted host once decoded, must be denied.
    assert allowlist.is_allowed("https://xn--80ak6aa92e.com/path") is False
    # Raw (non-punycode) unicode homoglyph of github.com (contains a Cyrillic
    # char) must also be denied — never accidentally string-matched as ASCII.
    assert allowlist.is_allowed("https://gхithub.com/x") is False


def test_raw_ip_literal_is_never_allowed():
    allowlist = EgressAllowlist()
    assert allowlist.is_allowed("http://140.82.112.3/") is False
    assert allowlist.is_allowed("http://[::1]:8080/") is False


def test_unparseable_destination_is_denied():
    allowlist = EgressAllowlist(extra_hosts=("example.corp",))
    assert allowlist.is_allowed("") is False


def test_constructor_extra_hosts_are_additive_to_the_builtins():
    allowlist = EgressAllowlist(extra_hosts=("internal.example.corp",))
    assert allowlist.is_allowed("https://internal.example.corp/api") is True
    # Built-ins are still present alongside the extra host.
    assert allowlist.is_allowed("https://github.com/x") is True
    # Still default-deny for anything not on either list.
    assert allowlist.is_allowed("https://not-trusted.example/") is False


# --- load_extra_allowed_hosts / EgressAllowlist.from_repo -----------------------


def test_load_extra_allowed_hosts_missing_file_returns_empty(tmp_path):
    assert load_extra_allowed_hosts(str(tmp_path)) == ()


def test_load_extra_allowed_hosts_valid_file(tmp_path):
    doberman_dir = tmp_path / ".doberman"
    doberman_dir.mkdir()
    (doberman_dir / ALLOWLIST_FILE).write_text(
        "allowed_hosts:\n  - internal.example.corp\n  - artifacts.example.corp\n",
        encoding="utf-8",
    )
    hosts = load_extra_allowed_hosts(str(tmp_path))
    assert hosts == ("internal.example.corp", "artifacts.example.corp")


def test_load_extra_allowed_hosts_malformed_yaml_fails_closed(tmp_path):
    doberman_dir = tmp_path / ".doberman"
    doberman_dir.mkdir()
    (doberman_dir / ALLOWLIST_FILE).write_text("not: valid: yaml: [", encoding="utf-8")
    assert load_extra_allowed_hosts(str(tmp_path)) == ()


def test_load_extra_allowed_hosts_not_a_mapping_fails_closed(tmp_path):
    doberman_dir = tmp_path / ".doberman"
    doberman_dir.mkdir()
    (doberman_dir / ALLOWLIST_FILE).write_text("- just\n- a\n- list\n", encoding="utf-8")
    assert load_extra_allowed_hosts(str(tmp_path)) == ()


def test_load_extra_allowed_hosts_wrong_type_for_allowed_hosts_fails_closed(tmp_path):
    doberman_dir = tmp_path / ".doberman"
    doberman_dir.mkdir()
    (doberman_dir / ALLOWLIST_FILE).write_text("allowed_hosts: not-a-list\n", encoding="utf-8")
    assert load_extra_allowed_hosts(str(tmp_path)) == ()


def test_from_repo_combines_builtins_and_extras(tmp_path):
    doberman_dir = tmp_path / ".doberman"
    doberman_dir.mkdir()
    (doberman_dir / ALLOWLIST_FILE).write_text(
        "allowed_hosts:\n  - internal.example.corp\n", encoding="utf-8"
    )
    allowlist = EgressAllowlist.from_repo(str(tmp_path))
    assert allowlist.is_allowed("https://internal.example.corp/x") is True
    assert allowlist.is_allowed("https://github.com/x") is True
    assert allowlist.is_allowed("https://not-trusted.example/") is False


def test_from_repo_with_no_config_dir_is_just_the_builtins(tmp_path):
    allowlist = EgressAllowlist.from_repo(str(tmp_path))
    assert allowlist.is_allowed("https://github.com/x") is True
    assert allowlist.is_allowed("https://not-trusted.example/") is False
