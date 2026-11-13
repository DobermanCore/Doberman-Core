"""`python -m doberman`: the CLI when the `doberman` script is not on PATH."""

from doberman.cli.main import app

app(prog_name="doberman")
