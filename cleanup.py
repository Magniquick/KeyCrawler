from dataclasses import dataclass
from pathlib import Path

from check import keybox_check
from helpers import SAVE_DIR, log_error, log_info, print_section, print_summary


@dataclass
class CleanupStats:
    inspected: int = 0
    removed: int = 0
    errors: int = 0


def cleanup_invalid_keyboxes(
    directory: Path = SAVE_DIR, *, verbose: bool = True
) -> CleanupStats:
    """Remove stored keyboxes that no longer pass validation."""
    stats = CleanupStats()
    directory = directory.resolve()

    for file_path in directory.glob("*.xml"):
        stats.inspected += 1
        if keybox_check(file_path.read_bytes()):
            continue

        if verbose:
            log_info(f"Pruning invalid keybox: {file_path.name}")
        try:
            file_path.unlink()
            stats.removed += 1
        except OSError as error:
            stats.errors += 1
            log_error(f"Failed to delete {file_path.name}: {error}")

    return stats


def main() -> None:
    """Entry point for module execution."""
    print_section("Keybox cleanup")
    stats = cleanup_invalid_keyboxes()
    print_summary(
        "Cleanup Summary",
        [
            ("Inspected", str(stats.inspected)),
            ("Removed", str(stats.removed)),
            ("Errors", str(stats.errors)),
        ],
    )


if __name__ == "__main__":
    main()
