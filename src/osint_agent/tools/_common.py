from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


@dataclass(slots=True)
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    found: bool


def find_binary(name: str) -> str | None:
    if Path(name).exists():
        return str(Path(name).resolve())
    return shutil.which(name)


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9@._-]+", "_", value.strip())
    return slug.strip("._") or "target"


def strip_ansi(value: str) -> str:
    return ANSI_ESCAPE_RE.sub("", value)


def summarize_command_failure(stderr: str, stdout: str, returncode: int) -> str:
    combined = strip_ansi("\n".join(part for part in [stderr, stdout] if part)).replace("\r", "\n")
    lines = [line.strip() for line in combined.splitlines() if line.strip()]
    if not lines:
        return f"return code {returncode}"

    keywords = [
        "permission denied",
        "flag provided but not defined",
        "ambiguous option",
        "can't open file",
        "error:",
        "err",
        "usage:",
        "binary not found",
        "command timed out",
    ]
    interesting = [
        line
        for line in lines
        if any(keyword in line.lower() for keyword in keywords)
    ]
    selected = interesting[:4] if interesting else lines[:4]
    summary = " | ".join(selected)
    return summary[:600]


COMMON_WEB_PREFIXES = {"www", "www2", "ww2", "web", "m", "mobile"}


def extract_host(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return ""

    if "://" in candidate:
        parsed = urlparse(candidate)
        return (parsed.hostname or "").strip().lower().rstrip(".")

    candidate = candidate.split("/", 1)[0].strip().lower().rstrip(".")
    if "@" in candidate and ":" in candidate:
        candidate = candidate.rsplit("@", 1)[-1]
    if ":" in candidate and candidate.count(":") == 1:
        candidate = candidate.split(":", 1)[0]
    return candidate


def derive_infra_query(target_type: str, target_value: str) -> tuple[str, str | None]:
    if target_type not in {"domain", "subdomain", "hostname", "url"}:
        return target_value, None

    host = extract_host(target_value)
    if not host:
        return target_value, None

    labels = [label for label in host.split(".") if label]
    if len(labels) >= 3 and labels[0] in COMMON_WEB_PREFIXES:
        research_domain = ".".join(labels[1:])
        return (
            research_domain,
            f"Infrastructure collectors normalized '{host}' to '{research_domain}' by dropping the common web prefix '{labels[0]}'.",
        )

    if host != target_value:
        return host, f"Infrastructure collectors normalized the input value to host '{host}' before querying passive sources."

    return host, None


def run_command(command: list[str], timeout: int = 300) -> CommandResult:
    binary = find_binary(command[0])
    if binary is None:
        return CommandResult(command=command, returncode=127, stdout="", stderr="binary not found", found=False)

    resolved = [binary, *command[1:]]
    try:
        completed = subprocess.run(
            resolved,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", errors="replace")
        return CommandResult(
            command=resolved,
            returncode=124,
            stdout=stdout,
            stderr=(stderr + "\ncommand timed out").strip(),
            found=True,
        )
    return CommandResult(
        command=resolved,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        found=True,
    )


def write_raw_output(data_dir: Path, collector: str, target_value: str, suffix: str, content: str) -> Path:
    output_dir = data_dir / "raw" / collector
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{slugify(target_value)}.{suffix}"
    output_path.write_text(content, encoding="utf-8")
    return output_path


def load_json_file(path: Path) -> object | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def read_text_if_exists(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b", re.IGNORECASE)
URL_PATTERN = re.compile(r"https?://[^\s\"'>)]+", re.IGNORECASE)


def unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        lowered = value.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        output.append(value)
    return output
