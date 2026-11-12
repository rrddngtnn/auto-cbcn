"""Pattern catalog for the pre-publish public hygiene gate."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HygienePattern:
    name: str
    regex: str
    severity: str = "fatal"
    surface: str = "all"  # all | content | commit_msg


PATTERNS: list[HygienePattern] = [
    HygienePattern(
        name="private_key_block",
        regex=r"-----BEGIN (?:RSA |EC |OPENSSH |PRIVATE )?PRIVATE KEY-----",
    ),
    HygienePattern(
        name="github_pat_token",
        regex=r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b",
    ),
    HygienePattern(
        name="google_oauth_access_token",
        regex=r"\bya29\.[A-Za-z0-9_-]{20,}\b",
    ),
    HygienePattern(
        name="non_reserved_public_ipv4",
        regex=r"\b(?!127\.0\.0\.1\b)(?!0\.0\.0\.0\b)(?!10\.)(?!192\.168\.)(?!192\.0\.2\.)(?!198\.51\.100\.)(?!203\.0\.113\.)(?:[1-9]\d{0,2}\.){3}[1-9]\d{0,2}\b",
    ),
    HygienePattern(
        name="internal_planning_marker",
        regex=r"\b(?:Wave\s+\d+|Phase\s+\d+|ADR-\d+|YAGNI|SDD|SHIPPED)\b",
        surface="commit_msg",
    ),
    HygienePattern(
        name="non_english_error_identifier",
        regex=r"\b(?:tipe_tidak_didukung|nilai_kosong|nama_tidak_valid|nilai_tidak_valid|nameserver_tidak_dikenal|jatah_gratis|indo_session)\b",
    ),
]

FORBIDDEN_PATH_GLOBS: tuple[str, ...] = (
    "specs/",
    "plans/",
    "evidence/",
    "csv_out/",
    "backups/",
    "var/",
)
