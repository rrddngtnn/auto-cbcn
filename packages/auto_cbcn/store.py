"""store.py — Universal CredentialSink and Router Adapters (stdout, file, http, sqlite) for CodeBuddy China."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import TextIO
import uuid
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def load_dotenv_file(path: str | Path | None = None) -> None:
    candidates = (
        [Path(path)]
        if path
        else [
            Path.cwd() / ".env",
            Path(__file__).resolve().parents[2] / ".env",
            Path.home() / "resources" / "auto-cbcn" / ".env",
        ]
    )
    for p in candidates:
        if not p.is_file():
            continue
        for raw_line in p.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("'").strip('"')
            if k and k not in os.environ:
                os.environ[k] = v
        break


load_dotenv_file()

DEFAULT_DB_PATH = Path(os.environ.get("ROUTER_DB_PATH", str(Path.home() / "omniroute" / "databases" / "storage.sqlite")))
DEFAULT_SALT = os.environ.get("STORAGE_ENCRYPTION_SALT", "styx-field-encryption-v1").encode("utf-8")
DEFAULT_ROUTER_URL = os.environ.get("ROUTER_URL", "http://127.0.0.1:20128")


def resolve_secret(secret: str | None = None) -> str:
    load_dotenv_file()
    val = secret or os.environ.get("STORAGE_ENCRYPTION_KEY", "")
    if not val:
        raise ValueError("STORAGE_ENCRYPTION_KEY is required in environment or .env for SQLite encryption")
    return val


def derive_key(secret: str, salt: bytes = DEFAULT_SALT) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=16384, r=8, p=1)
    return kdf.derive(secret.encode("utf-8"))


def encrypt_field(
    plaintext: str,
    secret: str | None = None,
    salt: bytes = DEFAULT_SALT,
) -> str:
    key_str = resolve_secret(secret)
    key = derive_key(key_str, salt=salt)
    iv = os.urandom(16)
    aes = AESGCM(key)
    ct_with_tag = aes.encrypt(iv, plaintext.encode("utf-8"), None)
    ct, tag = ct_with_tag[:-16], ct_with_tag[-16:]
    return f"enc:v1:{iv.hex()}:{ct.hex()}:{tag.hex()}"


def decrypt_field(
    ciphertext: str | None,
    secret: str | None = None,
    salt: bytes = DEFAULT_SALT,
) -> str:
    if not ciphertext:
        return ""
    if not ciphertext.startswith("enc:v1:"):
        return ciphertext
    key_str = resolve_secret(secret)
    key = derive_key(key_str, salt=salt)
    parts = ciphertext.split(":")
    if len(parts) != 5:
        raise ValueError("Invalid enc:v1 format")
    _, _, iv_h, ct_h, tag_h = parts
    aes = AESGCM(key)
    return aes.decrypt(bytes.fromhex(iv_h), bytes.fromhex(ct_h) + bytes.fromhex(tag_h), None).decode("utf-8")


@dataclass
class CredentialBundle:
    version: str = "1.0"
    provider: str = "codebuddy-cn"
    auth_type: str = "oauth"
    name: str = ""
    phone: str = ""
    uid: str = ""
    nickname: str = ""
    access_token: str = ""
    refresh_token: str = ""
    expires_in: int = 5184000
    remaining_credits: float = 0.0
    pack_count: int = 0
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def install_cbcn_sqlite(
    bundle: CredentialBundle,
    db_path: str | Path = DEFAULT_DB_PATH,
    secret: str | None = None,
    salt: bytes = DEFAULT_SALT,
) -> str:
    """Insert or update a CBCN connection into SQLite database."""
    conn_id = str(uuid.uuid4())
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    now = now_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    exp = (now_dt + datetime.timedelta(seconds=bundle.expires_in)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    enc_at = encrypt_field(bundle.access_token, secret=secret, salt=salt)
    enc_rt = encrypt_field(bundle.refresh_token, secret=secret, salt=salt) if bundle.refresh_token else None

    con = sqlite3.connect(str(db_path), timeout=30)
    try:
        con.execute(
            """
            INSERT INTO provider_connections (
                id, provider, auth_type, name, access_token, refresh_token,
                expires_at, token_expires_at, is_active, test_status, created_at, updated_at
            ) VALUES (?, 'codebuddy-cn', 'oauth', ?, ?, ?, ?, ?, 1, 'active', ?, ?)
            """,
            (conn_id, bundle.name or bundle.phone or "CBCN-Account", enc_at, enc_rt, exp, exp, now, now),
        )
        con.commit()
    finally:
        con.close()
    return conn_id


def exchange_cbcn_http(
    bundle: CredentialBundle,
    router_url: str = DEFAULT_ROUTER_URL,
    timeout: int = 20,
) -> dict:
    """Exchange or register token via Router HTTP API (POST /api/connections or /api/oauth/codebuddy-cn/exchange)."""
    payload = {
        "provider": "codebuddy-cn",
        "auth_type": "oauth",
        "name": bundle.name or bundle.phone or "CBCN-Account",
        "access_token": bundle.access_token,
        "refresh_token": bundle.refresh_token,
        "expires_in": bundle.expires_in,
    }
    url = f"{router_url.rstrip('/')}/api/connections"
    r = requests.post(url, json=payload, timeout=timeout)
    if r.status_code == 404:
        alt_url = f"{router_url.rstrip('/')}/api/oauth/codebuddy-cn/exchange"
        r = requests.post(alt_url, json={"code": bundle.access_token, "refresh_token": bundle.refresh_token}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def dispatch_credential_sink(
    bundle: CredentialBundle,
    sink: str = "stdout",
    stream: TextIO = sys.stdout,
    secret: str | None = None,
    salt: bytes = DEFAULT_SALT,
) -> dict:
    """Universal dispatcher: routes CredentialBundle to stdout, file:<path>, http:<url>, or sqlite:<path>."""
    if sink == "stdout":
        stream.write(bundle.to_json() + "\n")
        stream.flush()
        return {"sink": "stdout", "ok": True}
    if sink.startswith("file:"):
        out_path = Path(sink[len("file:"):])
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("a", encoding="utf-8") as f:
            f.write(bundle.to_json() + "\n")
        return {"sink": "file", "path": str(out_path), "ok": True}
    if sink.startswith("http:") or sink.startswith("https:"):
        res = exchange_cbcn_http(bundle, router_url=sink)
        return {"sink": "http", "response": res, "ok": True}
    if sink == "sqlite" or sink.startswith("sqlite:"):
        db_target = Path(sink[len("sqlite:"):]) if sink.startswith("sqlite:") and len(sink) > 7 else DEFAULT_DB_PATH
        cid = install_cbcn_sqlite(bundle, db_path=db_target, secret=secret, salt=salt)
        return {"sink": "sqlite", "connection_id": cid, "db_path": str(db_target), "ok": True}
    raise ValueError(f"Unsupported sink specification: {sink}")
