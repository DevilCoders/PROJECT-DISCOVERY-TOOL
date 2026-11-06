from io import StringIO

from rich.console import Console

from project_discovery.cli import _render_banner


def test_command_center_banner_is_clean_for_redirected_output():
    stream = StringIO()
    console = Console(file=stream, force_terminal=False, width=140)
    _render_banner(console)
    output = stream.getvalue()

    assert "PDT // DISCOVERY COMMAND CENTER" in output
    assert "ENGINE STATUS" in output
    assert "Python orchestration" in output
    assert "C++ signatures" in output
    assert "Rust walker" in output
    assert "Inventory" in output
    assert "\x1b[" not in output
