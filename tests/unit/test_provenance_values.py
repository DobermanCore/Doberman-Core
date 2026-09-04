"""C1: whole-value keyed-HMAC extraction (hostname / URL / email) for the
untrusted-value echo tripwire. Extraction only — no verdict authority here.
"""

import time

import pytest

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


# --- final review, IMPORTANT 1: excluded_hosts must use registered-domain
# suffix matching (destinations._registered_match), not exact membership -----
# _excluded_hosts (taint_floor.py) seeds this set from the SAME TRUSTED_HOSTS
# ExternalDestinationRule matches by suffix (host == d or a dotted subdomain of
# d); exact membership here would miss a subdomain like api.github.com.


def test_excluded_hosts_matches_a_subdomain_of_a_trusted_host():
    fps = untrusted_value_fingerprints(
        "see https://api.github.com/repos/x for the issue", excluded_hosts={"github.com"}
    )
    assert fps == set()


def test_excluded_hosts_suffix_matching_does_not_over_match_a_lookalike_domain():
    # github.com.evil.test merely contains "github.com" as a label sequence --
    # it is NOT a dotted subdomain of github.com (registered-domain suffix
    # matching requires host == d or host.endswith("." + d)) and must still be
    # fingerprinted. Regression guard against over-broad exclusion.
    fps = untrusted_value_fingerprints(
        "see https://github.com.evil.test/x for the payload", excluded_hosts={"github.com"}
    )
    assert fingerprint("github.com.evil.test") in fps


def test_excluded_hosts_applies_to_the_email_branchs_domain():
    # MINOR (final review): excluded_hosts previously only filtered the URL and
    # bare-host branches -- an email at a trusted domain still fingerprinted.
    fps = untrusted_value_fingerprints(
        "contact security@github.com about this", excluded_hosts={"github.com"}
    )
    assert fps == set()


def test_excluded_hosts_email_domain_check_does_not_over_exclude_a_different_domain():
    fps = untrusted_value_fingerprints(
        "contact attacker@evil.test about this", excluded_hosts={"github.com"}
    )
    assert fingerprint("attacker@evil.test") in fps


# --- final review, MINOR: IDNA/punycode normalization -----------------------
# untrusted_value_fingerprints used its own _normalize_host (lowercase + www-
# strip only, no IDNA decode) -- a punycode-encoded host and the unicode host
# it decodes to fingerprinted as two UNRELATED values, so a homoglyph/punycode-
# disguised repeat host slipped past the echo tripwire.


def test_punycode_host_and_its_unicode_form_fingerprint_the_same():
    unicode_fps = untrusted_value_fingerprints("see https://café.example/x")
    punycode_fps = untrusted_value_fingerprints("see https://xn--caf-dma.example/x")
    assert fingerprint("xn--caf-dma.example") in unicode_fps
    assert fingerprint("xn--caf-dma.example") in punycode_fps


# --- final review, MINOR: IP-literal branch ----------------------------------
# The bare-host regex requires an alpha-only final label (a TLD shape), so a
# bare IP address mentioned with no scheme was invisible to it -- a bare-IP
# mention and a later http://<ip>/ egress did not fingerprint as the same
# value.


def test_bare_ipv4_and_url_form_fingerprint_the_same_host():
    bare_fps = untrusted_value_fingerprints("reach out to 192.0.2.1 directly")
    url_fps = untrusted_value_fingerprints("fetch http://192.0.2.1/status")
    assert fingerprint("192.0.2.1") in bare_fps
    assert fingerprint("192.0.2.1") in url_fps


def test_invalid_ipv4_shaped_string_is_not_treated_as_a_host():
    # 999 is not a valid octet -- the IP-literal branch validates via
    # ipaddress, not just dotted-quad shape.
    fps = untrusted_value_fingerprints("version 999.999.999.999 released")
    assert fps == set()


def test_bracketed_ipv6_url_form_is_still_extracted_as_a_host_value():
    # Regression guard: bracketed IPv6 in a URL was already covered via
    # urlsplit().hostname (which strips the brackets) -- the new IP-literal
    # branch must not disturb that existing path.
    fps = untrusted_value_fingerprints("see http://[2001:db8::1]/status for the endpoint")
    assert fingerprint("2001:db8::1") in fps


# --- T4: mail-address de-obfuscation (bracketed / bare-word / spaced forms) --
# Attackers write an address as "user [at] host [dot] com" precisely to defeat
# literal _EMAIL_RE matching. A de-obfuscated copy of the sample is scanned
# through the SAME _EMAIL_RE + same path, so the plain address fingerprints
# the same whether it arrived literal or obfuscated.


@pytest.mark.parametrize(
    "text",
    [
        "contact [at] contact [dot] com",
        "contact ( at ) contact ( dot ) com",
        "contact (at) contact (dot) com",
        "contact{at}contact{dot}com",
        "contact <at> contact <dot> com",
        "contact AT contact DOT com",
        "contact @ contact . com",
    ],
)
def test_bracketed_at_dot_forms_fingerprint_the_plain_address(text):
    fps = untrusted_value_fingerprints(text)
    assert fingerprint("contact@contact.com") in fps


def test_plain_address_is_fingerprinted_once():
    # contact.com also matches the pre-existing bare-host branch -- the
    # assertion is that the SECOND (de-obfuscation) pass adds nothing beyond
    # what the first pass already produces for an already-plain address.
    fps = untrusted_value_fingerprints("mail contact@contact.com now")
    assert fps == {fingerprint("contact@contact.com"), fingerprint("contact.com")}


def test_prose_at_dot_words_do_not_invent_an_address():
    fps = untrusted_value_fingerprints("meet me at the cafe. dot your i's")
    assert fps == set()


def test_sentence_period_is_not_joined():
    fps = untrusted_value_fingerprints("see you at end. Next line")
    assert fps == set()


# --- T4 perf follow-up: de-obfuscation must stay linear on adversarial
# whitespace -------------------------------------------------------------
# The bracketed de-obfuscation patterns had unbounded \s* flanking a
# mandatory alternation -- on a long run of plain whitespace the regex
# engine backtracks quadratically (every start position re-tries the
# leading \s* one char shorter). Every de-obfuscation pattern's whitespace
# is now bounded (\s{0,4} / \s{1,4}), so even a worst-case _SCAN_MAX_CHARS
# (100k) payload finishes in milliseconds, not tens of seconds.


@pytest.mark.parametrize(
    "text",
    [
        " " * 100_000,
        "[ " * 30_000,
        " at " * 25_000,
        ("a" + " " * 50) * 2_000,
        "[ at " * 20_000,
    ],
    # explicit short ids: pytest's default id is the raw string, and Windows
    # caps an env var at 32767 chars -- PYTEST_CURRENT_TEST would overflow it.
    ids=[
        "all_spaces",
        "bracket_space",
        "spaced_at_word",
        "letter_plus_50_spaces",
        "near_miss_bracket",
    ],
)
def test_deobfuscation_is_linear_on_adversarial_whitespace(text):
    start = time.perf_counter()
    untrusted_value_fingerprints(text)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"took {elapsed:.2f}s on a {len(text)}-char adversarial input"
