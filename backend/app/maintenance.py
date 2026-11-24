"""Safe SQLite online backup and explicit restore utilities.

Run restore only while the API and browser worker are stopped. Backups are
created atomically and are readable only by the current container user.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import tempfile
from pathlib import Path

DEFAULT_DB_PATH = Path(
    os.environ.get(
        "UNWEB_DB_PATH",
        str(Path(__file__).resolve().parents[1] / "data" / "unweb.sqlite3"),
    )
)


def _copy_database(source: Path, destination: Path, *, overwrite: bool) -> Path:
    source = Path(source).expanduser().resolve()
    destination = Path(destination).expanduser().resolve()
    if source == destination:
        raise ValueError("Source and destination must be different files.")
    if not source.is_file():
        raise FileNotFoundError(f"SQLite source database does not exist: {source}")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Destination already exists: {destination}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with sqlite3.connect(str(source), timeout=10) as source_connection:
            with sqlite3.connect(str(temporary), timeout=10) as destination_connection:
                source_connection.backup(destination_connection)
                result = destination_connection.execute("PRAGMA integrity_check").fetchone()
                if not result or result[0] != "ok":
                    raise sqlite3.DatabaseError("SQLite integrity_check failed for copied database.")
        os.chmod(temporary, 0o600)
        if overwrite:
            os.replace(temporary, destination)
        else:
            # Hard-link creation is atomic and will not overwrite a file that
            # appeared after the earlier existence check.
            os.link(temporary, destination)
            temporary.unlink()
        return destination
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def backup_database(source: Path, destination: Path, *, overwrite: bool = False) -> Path:
    """Create a consistent online SQLite backup, including committed WAL data."""
    return _copy_database(source, destination, overwrite=overwrite)


def restore_database(backup: Path, destination: Path, *, overwrite: bool = False) -> Path:
    """Restore a verified backup atomically; callers must stop DB-writing services."""
    return _copy_database(backup, destination, overwrite=overwrite)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="UnWeb SQLite backup and restore")
    commands = parser.add_subparsers(dest="command", required=True)

    backup = commands.add_parser("backup", help="Create a consistent SQLite backup")
    backup.add_argument("destination", type=Path)
    backup.add_argument("--source", type=Path, default=DEFAULT_DB_PATH)
    backup.add_argument("--overwrite", action="store_true")

    restore = commands.add_parser("restore", help="Restore a SQLite backup")
    restore.add_argument("backup", type=Path)
    restore.add_argument("--destination", type=Path, default=DEFAULT_DB_PATH)
    restore.add_argument("--overwrite", action="store_true")
    restore.add_argument("--confirm-restore", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            path = backup_database(args.source, args.destination, overwrite=args.overwrite)
        else:
            if not args.confirm_restore:
                parser.error("restore requires --confirm-restore after stopping the API and browser worker")
            path = restore_database(args.backup, args.destination, overwrite=args.overwrite)
    except (OSError, ValueError, sqlite3.DatabaseError) as exc:
        parser.exit(1, f"UnWeb database maintenance failed: {exc}\n")
    print(f"SQLite {args.command} completed: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
