"""Slice SL2.2 — generic inference of destination, reversibility, provenance, blast.

Load-bearing properties: unknowns classify to the CONSERVATIVE class (an egress
action with no parseable destination is unknown_external, never none); an
unclear origin defaults to untrusted_data; punycode/IP-literal/credential URL
handling reuses the hardened F3 parser.
"""

from datetime import datetime, timezone

import pytest

from doberman.models import (
    ActionType,
    BlastRadius,
    DestinationClass,
    Provenance,
    Reversibility,
    SecurityObject,
    SourceContext,
)
from doberman.subjective.infer import (
    infer_algebra,
    infer_blast_radius,
    infer_destination_class,
    infer_provenance,
    infer_reversibility,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


def _action(tool_name="custom_tool", action_type=ActionType.other, **kw):
    return SecurityObject(
        id="ctx-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=action_type,
        tool_name=tool_name,
        **kw,
    )


def _net(dest):
    return _action(
        "net_get",
        action_type=ActionType.network_request,
        target=dest,
        external_destination=dest,
    )


# --- destination ----------------------------------------------------------------


def test_trusted_host_is_known_external():
    cls, conf = infer_destination_class(_net("https://github.com/org/repo"))
    assert cls is DestinationClass.known_external
    assert conf >= 0.9


def test_unrecognized_host_is_unknown_external():
    cls, _ = infer_destination_class(_net("https://evil.example/upload"))
    assert cls is DestinationClass.unknown_external


def test_loopback_and_private_hosts_are_internal():
    assert infer_destination_class(_net("http://127.0.0.1:8080/x"))[0] is DestinationClass.internal
    assert infer_destination_class(_net("http://localhost:3000"))[0] is DestinationClass.internal
    assert infer_destination_class(_net("http://10.0.0.5/api"))[0] is DestinationClass.internal


def test_public_ip_literal_is_unknown_external():
    # A PUBLIC IP literal is never trusted by name (documentation/TEST-NET
    # ranges count as private in ipaddress, so use a real public address).
    cls, _ = infer_destination_class(_net("http://8.8.8.8/x"))
    assert cls is DestinationClass.unknown_external


def test_punycode_homoglyph_is_not_trusted():
    # xn-- domain decodes to unicode and must not match an ASCII trusted host.
    cls, _ = infer_destination_class(_net("https://xn--gthub-zra.com/repo"))
    assert cls is DestinationClass.unknown_external


def test_mailbox_to_trusted_domain_is_unknown_external():
    # C2 (mailbox security-review fix pass): mail to someone @ a trusted
    # domain is not trusted egress -- must not take the TRUSTED_HOSTS branch
    # just because a mailbox destination parses with no credentials.
    cls, conf = infer_destination_class(_net("user@github.com"))
    assert cls is DestinationClass.unknown_external
    assert conf == pytest.approx(0.7)


def test_scheme_less_credentials_to_trusted_domain_is_unknown_external():
    # C1 collateral: `admin:s3cret@pypi.org` must not be read as a mailbox
    # either -- the embedded-credential signal must still win here.
    cls, _ = infer_destination_class(_net("admin:s3cret@pypi.org"))
    assert cls is DestinationClass.unknown_external


def test_file_action_with_no_destination_is_none():
    action = _action("fs_write", action_type=ActionType.file_write, target="src/a.py")
    cls, _ = infer_destination_class(action)
    assert cls is DestinationClass.none


def test_egress_action_with_unparseable_destination_is_conservative():
    # A network action whose destination cannot be determined is NOT "none".
    action = _action("net_post", action_type=ActionType.network_request, target=None)
    cls, conf = infer_destination_class(action)
    assert cls is DestinationClass.unknown_external
    assert conf <= 0.2


# --- provenance ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (SourceContext.user, Provenance.trusted_instruction),
        (SourceContext.webpage, Provenance.untrusted_data),
        (SourceContext.email, Provenance.untrusted_data),
        (SourceContext.tool_output, Provenance.mixed),
    ],
)
def test_provenance_mapping(source, expected):
    prov, _ = infer_provenance(_action(source_context=source))
    assert prov is expected


def test_unclear_origin_defaults_to_untrusted_at_low_confidence():
    prov, conf = infer_provenance(_action(source_context=SourceContext.unknown))
    assert prov is Provenance.untrusted_data
    assert conf <= 0.3


# --- blast radius ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (1, BlastRadius.single),
        (3, BlastRadius.few),
        (30, BlastRadius.many),
        (500, BlastRadius.mass),
    ],
)
def test_target_count_maps_to_tiers(count, expected):
    action = _action(
        "fs_delete",
        action_type=ActionType.file_delete,
        target="a.txt",
        metadata={"target_count": count},
    )
    blast, conf = infer_blast_radius(action, None)
    assert blast is expected
    assert conf >= 0.8


def test_recipient_list_drives_blast_radius():
    action = _action("send_email", target="newsletter")
    blast, _ = infer_blast_radius(action, {"to": [f"u{i}@example.com" for i in range(20)]})
    assert blast is BlastRadius.many


def test_recursive_shell_and_globs_imply_many():
    shell = _action("shell_exec", action_type=ActionType.shell_exec, target="rm -rf build/")
    assert infer_blast_radius(shell, None)[0] is BlastRadius.many
    globby = _action("fs_delete", action_type=ActionType.file_delete, target="src/*.py")
    assert infer_blast_radius(globby, None)[0] is BlastRadius.many


def test_non_recursive_flag_cluster_is_not_treated_as_recursive():
    # "-lart" bundles list/all/reverse/time flags — not a recursive delete.
    action = _action("shell_exec", action_type=ActionType.shell_exec, target="ls -lart")
    assert infer_blast_radius(action, None)[0] is BlastRadius.single


def test_dash_capital_r_flag_is_still_recursive():
    action = _action("shell_exec", action_type=ActionType.shell_exec, target="chmod -R ./config")
    assert infer_blast_radius(action, None)[0] is BlastRadius.many


def test_url_query_string_is_not_treated_as_a_glob():
    action = _net("https://api.example.com/search?q=foo")
    assert infer_blast_radius(action, None)[0] is BlastRadius.single


def test_single_concrete_target_is_single_and_no_target_is_unknown():
    single = _action("fs_write", action_type=ActionType.file_write, target="src/a.py")
    assert infer_blast_radius(single, None)[0] is BlastRadius.single
    blank = _action("zzz", target=None)
    blast, conf = infer_blast_radius(blank, None)
    assert blast is BlastRadius.unknown
    assert conf <= 0.2


# --- reversibility ----------------------------------------------------------------


def test_deletion_and_destructive_shell_are_low_reversibility():
    delete = _action("fs_delete", action_type=ActionType.file_delete, target="a.txt")
    assert infer_reversibility(delete) is Reversibility.low
    force_push = _action(
        "shell_exec", action_type=ActionType.shell_exec, target="git push --force origin main"
    )
    assert infer_reversibility(force_push) is Reversibility.low


def test_reads_are_high_and_writes_keep_existing_assessment():
    read = _action("fs_read", action_type=ActionType.file_read, target="a.txt")
    assert infer_reversibility(read) is Reversibility.high
    write = _action("fs_write", action_type=ActionType.file_write, target="a.txt")
    assert infer_reversibility(write) is Reversibility.medium


def test_force_push_only_forces_low_when_force_belongs_to_the_push():
    # "docker rmi --force" after "&&" must not spill into the git push's own
    # reversibility signal (the bounded clause, not a greedy `.*`).
    action = _action(
        "shell_exec",
        action_type=ActionType.shell_exec,
        target="git push origin main && docker rmi --force old-image",
    )
    assert infer_reversibility(action) is not Reversibility.low


def test_hard_reset_is_still_low_reversibility():
    action = _action(
        "shell_exec", action_type=ActionType.shell_exec, target="git reset --hard HEAD~1"
    )
    assert infer_reversibility(action) is Reversibility.low


def test_hard_links_flag_is_not_treated_as_git_reset_hard():
    action = _action(
        "shell_exec", action_type=ActionType.shell_exec, target="rsync -a --hard-links src/ dst/"
    )
    assert infer_reversibility(action) is not Reversibility.low


# --- full algebra ----------------------------------------------------------------


def test_infer_algebra_populates_every_dimension():
    action = _action(
        "send_email",
        action_type=ActionType.network_request,
        target="https://mail.evil.example/send",
        external_destination="https://mail.evil.example/send",
        source_context=SourceContext.email,
    )
    algebra = infer_algebra(action, {"to": ["a@example.com"], "body": "hi"})
    assert algebra.destination_class is DestinationClass.unknown_external
    assert algebra.provenance is Provenance.untrusted_data
    assert algebra.blast_radius is BlastRadius.single
    assert 0.0 <= algebra.classification_confidence <= 1.0
