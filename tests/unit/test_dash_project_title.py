"""Unit tests for per-project dashboard titles.

``doberman dash`` is scoped to one repo per run (``--path``, default cwd -
see ``create_app``'s ``repo_root`` param). Before this slice every dashboard
shell hardcoded ``<title>Doberman Dashboard</title>`` and the JS title update
re-hardcoded the same string, so a user running several dashboards for
several projects (one per terminal/browser tab) had no way to tell the tabs
apart. This derives the tab title, and a topbar label, from the repo folder
name instead.

Covers:

* the served ``<title>`` and topbar both carry the repo folder's name;
* the JS unread-count title update also uses the project-qualified title,
  not the old hardcoded string;
* a repo folder name containing HTML-special characters is escaped in the
  markup (``<title>``/topbar) and safely JSON-encoded in the JS string -
  never breaks out of either context;
* the bearer token still never appears in the shell (unchanged invariant).
"""

from starlette.testclient import TestClient

from doberman.dash.app import _js_string_literal, _project_display_name, create_app

_TOKEN = "test-dash-token-0123456789"  # noqa: S105 - fixture value, not a real secret


def _index_html(repo_root: str) -> str:
    client = TestClient(create_app(_TOKEN, repo_root))
    resp = client.get("/")
    assert resp.status_code == 200
    return resp.text


def test_project_display_name_is_the_repo_folder_name(tmp_path):
    project_dir = tmp_path / "widget-service"
    project_dir.mkdir()
    assert _project_display_name(str(project_dir)) == "widget-service"


def test_page_title_carries_the_project_name(tmp_path):
    project_dir = tmp_path / "widget-service"
    project_dir.mkdir()
    html = _index_html(str(project_dir))
    assert "<title>widget-service — Doberman Dashboard</title>" in html


def test_topbar_carries_the_project_name(tmp_path):
    project_dir = tmp_path / "widget-service"
    project_dir.mkdir()
    html = _index_html(str(project_dir))
    assert '<span class="project">widget-service</span>' in html


def test_js_title_update_uses_the_project_qualified_title_not_the_old_hardcode(tmp_path):
    project_dir = tmp_path / "widget-service"
    project_dir.mkdir()
    html = _index_html(str(project_dir))
    # The em dash is outside ASCII, so json.dumps's default ensure_ascii
    # renders it as — here, unlike the literal char used in <title>.
    assert '"widget-service \\u2014 Doberman Dashboard"' in html
    assert (
        'document.title = (rows.length ? "(" + rows.length + ") " : "") + DASH_BASE_TITLE;' in html
    )
    # The old form re-hardcoded the base string inline instead of a variable.
    assert '+ "Doberman Dashboard";' not in html


def test_two_different_projects_render_different_titles(tmp_path):
    a = tmp_path / "project-a"
    b = tmp_path / "project-b"
    a.mkdir()
    b.mkdir()
    html_a = _index_html(str(a))
    html_b = _index_html(str(b))
    assert "<title>project-a — Doberman Dashboard</title>" in html_a
    assert "<title>project-b — Doberman Dashboard</title>" in html_b


def test_project_name_with_html_special_characters_is_escaped(tmp_path):
    # Deliberately not .mkdir()'d: `<`/`>` are illegal in a real directory name on
    # Windows (WinError 123). _render_shell only needs the string - Path.resolve()
    # works fine on a path that was never created on disk.
    project_dir = tmp_path / "my <cool> & co"
    html = _index_html(str(project_dir))
    # Never an unescaped "<cool>" landing anywhere in the page - neither the
    # HTML-escaped markup nor the JS string (which unicode-escapes <, >, &
    # so an embedded "</script>" can never close the enclosing script tag).
    assert "<cool>" not in html
    assert "my &lt;cool&gt; &amp; co — Doberman Dashboard" in html
    assert '"my \\u003ccool\\u003e \\u0026 co \\u2014 Doberman Dashboard"' in html


def test_project_name_with_quotes_is_safe_inside_the_js_string(tmp_path):
    # Deliberately not .mkdir()'d: `"` is illegal in a real directory name on
    # Windows (WinError 123). _render_shell only needs the string - Path.resolve()
    # works fine on a path that was never created on disk.
    project_dir = tmp_path / 'weird"name'
    html = _index_html(str(project_dir))
    # json.dumps escapes the embedded quote, so the JS string literal stays
    # well-formed instead of terminating early.
    assert '"weird\\"name \\u2014 Doberman Dashboard"' in html


def test_js_string_literal_cannot_close_the_enclosing_script_tag():
    """A folder named e.g. `</script><script>alert(1)</script>` must not be
    able to break out of the inline <script> element - the browser's HTML
    tokenizer looks for the literal "</script" byte sequence in the script's
    text content, independent of JS string/quote context."""
    hostile = "</script><script>alert(1)</script>"
    literal = _js_string_literal(hostile)
    assert "</script" not in literal
    assert "<script" not in literal


def test_shell_still_never_leaks_the_token(tmp_path):
    project_dir = tmp_path / "widget-service"
    project_dir.mkdir()
    assert _TOKEN not in _index_html(str(project_dir))
