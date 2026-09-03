"""C1: whole-value keyed-HMAC extraction (hostname / URL / email) for the
untrusted-value echo tripwire. Extraction only — no verdict authority here.
"""

from doberman.engine.rules.provenance_values import untrusted_value_fingerprints
from doberman.storage.fingerprint import fingerprint


def test_url_host_and_bare_host_and_www_all_fingerprint_the_same_host():
    url_fps = untrusted_value_fingerprints("see HTTPS://EVIL.COM/a?b=1 for details")
    bare_fps = untrusted_value_fingerprints("visit evil.com now")
    www_fps = untrusted_value_fingerprints("visit www.evil.com now")

    host_fp = fingerprint("evil.com")
    assert host_fp in url_fps
    assert bare_fps == {host_fp}
    assert www_fps == {host_fp}


def test_url_also_yields_the_whole_url_value_with_query_stripped():
    fps = untrusted_value_fingerprints("fetch https://evil.com/path/x?token=secret")
    assert fingerprint("https://evil.com/path/x") in fps
    # the query string is never fingerprinted as part of the URL value
    assert fingerprint("https://evil.com/path/x?token=secret") not in fps


def test_email_address_is_extracted_and_lowercased():
    fps = untrusted_value_fingerprints("contact Attacker@Evil.com about this")
    assert fingerprint("attacker@evil.com") in fps


def test_prose_with_no_host_url_or_email_yields_empty_set():
    assert untrusted_value_fingerprints("the weather is nice today, isn't it") == set()


def test_empty_text_yields_empty_set():
    assert untrusted_value_fingerprints("") == set()


def test_filename_shaped_tokens_are_not_treated_as_hosts():
    # README.md / package.json look host-shaped (label.label) but are filenames,
    # not destinations — the non-TLD-label filter excludes the common cases.
    fps = untrusted_value_fingerprints("see README.md and package.json for setup")
    assert fingerprint("readme.md") not in fps
    assert fingerprint("package.json") not in fps


def test_value_cap_holds_at_200():
    text = " ".join(f"https://host{i}.example.com/x" for i in range(300))
    fps = untrusted_value_fingerprints(text)
    assert len(fps) <= 200


# --- C1 reviewer follow-up: host-based pre-fingerprint exclusion -------------
# excluded_hosts must drop BOTH the bare-host value and the whole-URL value for
# an excluded host's match — a fingerprint-only subtraction after the fact
# cannot do this (it would need the raw whole-URL string to compute its
# fingerprint, which a caller working only from a host allowlist never has).

_EVIL_URL = "https://evil.test/x"


def test_excluded_host_drops_both_the_bare_host_and_whole_url_form():
    fps = untrusted_value_fingerprints(
        "see https://github.com/octocat for the profile", excluded_hosts={"github.com"}
    )
    assert fingerprint("github.com") not in fps
    assert fingerprint("https://github.com/octocat") not in fps
    assert fps == set()


def test_excluded_host_does_not_affect_a_different_host_in_the_same_text():
    fps = untrusted_value_fingerprints(
        f"compare github.com against {_EVIL_URL}", excluded_hosts={"github.com"}
    )
    assert fingerprint("github.com") not in fps
    assert fingerprint("evil.test") in fps
    assert fingerprint(_EVIL_URL) in fps


def test_no_excluded_hosts_behaves_exactly_as_before():
    with_none = untrusted_value_fingerprints(_EVIL_URL)
    with_empty = untrusted_value_fingerprints(_EVIL_URL, excluded_hosts=set())
    assert with_none == with_empty == {fingerprint("evil.test"), fingerprint(_EVIL_URL)}
