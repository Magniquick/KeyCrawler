import hashlib
from pathlib import Path
from typing import Iterable, Tuple

from lxml import etree
from rich.console import Console

FILE_DIR = Path(__file__).resolve().parent

SAVE_DIR = FILE_DIR / "keys"
if not SAVE_DIR.exists():
    SAVE_DIR.mkdir(exist_ok=True)

CACHE_FILE = FILE_DIR / "cache.txt"
if not CACHE_FILE.exists():
    CACHE_FILE.touch()

console = Console()

INFO_STYLE = "bold cyan"
WARN_STYLE = "bold yellow"
ERROR_STYLE = "bold red"
SECTION_STYLE = "bold blue"


def log_info(message: str) -> None:
    _log("INFO", message, INFO_STYLE)


def log_warning(message: str) -> None:
    _log("WARN", message, WARN_STYLE)


def log_error(message: str) -> None:
    _log("ERROR", message, ERROR_STYLE)


def _log(label: str, message: str, style: str) -> None:
    console.print(f"[{style}]{label:<5}[/] {message}")


def print_section(title: str) -> None:
    console.rule(f"[{SECTION_STYLE}]{title}[/]", style=SECTION_STYLE)


def print_summary(title: str, rows: Iterable[Tuple[str, str]]) -> None:
    formatted = "  ".join(
        f"[bold white]{label}[/]: [cyan]{value}[/]" for label, value in rows
    )
    console.print(f"[{SECTION_STYLE}]{title}[/]  {formatted}")


def hash_xml_file(file_content: bytes) -> str:
    """Hashes the contents of an XML file."""
    root = etree.fromstring(file_content)
    canonical_xml = etree.tostring(root, method="c14n")
    hash_value = hashlib.sha256(canonical_xml).hexdigest()
    file_name = hash_value + ".xml"
    return file_name
