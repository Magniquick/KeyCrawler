from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from check import keybox_check
from helpers import (
    FILE_DIR,
    SAVE_DIR,
    hash_xml_file,
    log_info,
    log_warning,
    print_section,
    print_summary,
)


@dataclass
class ImportStats:
    inspected: int = 0
    linked: int = 0
    invalid: int = 0
    duplicates: int = 0


def _iter_source_files(path: Path, exclude_dir: Path) -> Iterator[Path]:
    for candidate in path.rglob("*.xml"):
        if exclude_dir in candidate.parents:
            continue
        yield candidate


def import_manual_keyboxes(
    manual_dir: Path = FILE_DIR / "manual", *, verbose: bool = True
) -> ImportStats:
    """Validate XML keyboxes from `manual_dir` and hard-link approved files into `keys/`."""
    stats = ImportStats()
    manual_dir = manual_dir.resolve()

    if not manual_dir.exists():
        log_warning(f"Manual directory not found at {manual_dir}, skipping import.")
        return stats

    if manual_dir.is_file():
        candidates: Iterator[Path] = iter([manual_dir])
    else:
        candidates = _iter_source_files(manual_dir, SAVE_DIR)

    for item in candidates:
        stats.inspected += 1

        content = item.read_bytes()
        if not keybox_check(content):
            stats.invalid += 1
            if verbose:
                log_warning(f"Invalid XML ignored: {item.name}")
            continue

        destination = SAVE_DIR / hash_xml_file(content)
        try:
            destination.hardlink_to(item)
            stats.linked += 1
            if verbose:
                log_info(f"Stored keybox from {item.name}")
        except FileExistsError:
            stats.duplicates += 1
            if verbose:
                log_info(f"Duplicate skipped: {item.name}")

    return stats


def main() -> None:
    """Entry point for module execution."""
    print_section("Manual keybox import")
    stats = import_manual_keyboxes(verbose=True)
    print_summary(
        "Import Summary",
        [
            ("Inspected", str(stats.inspected)),
            ("Linked", str(stats.linked)),
            ("Invalid", str(stats.invalid)),
            ("Duplicates", str(stats.duplicates)),
        ],
    )


if __name__ == "__main__":
    main()
