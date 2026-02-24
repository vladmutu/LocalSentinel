from __future__ import annotations

import json
from pathlib import Path

import typer

from localsentinel.core.scanner import scan_package


def create_app() -> typer.Typer:
    app = typer.Typer()

    @app.command()
    def scan(
        path: str = typer.Argument(..., help="Path to scan"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed findings"),
    ) -> None:
        """Scan a package directory before installation."""
        target_path = Path(path)
        if not target_path.exists() or not target_path.is_dir():
            typer.secho("Path does not exist or is not a directory.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        typer.secho(f"Scanning: {target_path}", fg=typer.colors.CYAN)
        result = scan_package(target_path)
        typer.secho(
            f"Risk Score: {result['risk_score']} ({result['label']})",
            fg=typer.colors.GREEN,
        )
        typer.secho(
            f"Vectors: {result['vector_counts']}",
            fg=typer.colors.YELLOW,
        )

        if verbose:
            typer.echo(json.dumps(result["details"], indent=2))

    return app


app = create_app()

if __name__ == "__main__":
    app()
