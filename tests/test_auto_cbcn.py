"""Offline unit tests for auto-cbcn package contracts, encryption, fingerprint heuristics, and BYOP clients."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile

from auto_cbcn.cron import load_accounts_from_source
from auto_cbcn.fingerprint import (
    BAD_CN_PREFIXES,
    VIRTUAL_PREFIXES,
    is_recycled_suspect,
    prefix_of,
    record_attempt,
    summarize,
)
from auto_cbcn.solver import (
    EjiemaSmsClient,
    FeihuSmsClient,
    HaomadunSmsClient,
    resolve_proxy_playwright_cfg,
    solve_tcaptcha_dx,
)
from auto_cbcn.store import (
    DEFAULT_SALT,
    CredentialBundle,
    decrypt_field,
    derive_key,
    dispatch_credential_sink,
    encrypt_field,
    install_cbcn_sqlite,
    load_dotenv_file,
)


def test_encryption_roundtrip():
    secret = "01377b3cf56483fb9f713476d632ecca750edb3bd5b034ed61a8bf9220d32e7c"
    pt = "test-token-value-secret-xyz"
    enc = encrypt_field(pt, secret=secret, salt=DEFAULT_SALT)
    assert enc.startswith("enc:v1:")
    parts = enc.split(":")
    assert len(parts) == 5
    dec = decrypt_field(enc, secret=secret, salt=DEFAULT_SALT)
    assert dec == pt


def test_credential_bundle_and_universal_sinks():
    b = CredentialBundle(
        name="CBCN-Test",
        phone="18049045741",
        uid="uid-12345",
        access_token="at-test-value",
        refresh_token="rt-test-value",
        expires_in=86400,
        remaining_credits=2100.0,
    )
    # 1. stdout sink
    out_buf = io.StringIO()
    res_stdout = dispatch_credential_sink(b, sink="stdout", stream=out_buf)
    assert res_stdout["ok"]
    assert "CBCN-Test" in out_buf.getvalue()

    with tempfile.TemporaryDirectory() as td:
        # 2. file: sink
        fp = Path(td) / "bundle.jsonl"
        res_file = dispatch_credential_sink(b, sink=f"file:{fp}")
        assert res_file["ok"] and fp.is_file()
        assert "18049045741" in fp.read_text(encoding="utf-8")

        # 3. sqlite: sink
        db_p = Path(td) / "storage.sqlite"
        con = sqlite3.connect(str(db_p))
        con.execute(
            """
            CREATE TABLE provider_connections (
                id TEXT PRIMARY KEY, provider TEXT, auth_type TEXT, name TEXT,
                access_token TEXT, refresh_token TEXT, expires_at TEXT, token_expires_at TEXT,
                is_active INTEGER, test_status TEXT, created_at TEXT, updated_at TEXT
            )
            """
        )
        con.close()

        secret = "01377b3cf56483fb9f713476d632ecca750edb3bd5b034ed61a8bf9220d32e7c"
        res_sql = dispatch_credential_sink(b, sink=f"sqlite:{db_p}", secret=secret)
        assert res_sql["ok"] and res_sql["connection_id"]

        con = sqlite3.connect(str(db_p))
        row = con.execute("SELECT id, name, provider, is_active FROM provider_connections").fetchone()
        con.close()
        assert row[1] == "CBCN-Test" and row[2] == "codebuddy-cn" and row[3] == 1


def test_fingerprint_heuristics():
    assert "170" in BAD_CN_PREFIXES
    assert "192" in BAD_CN_PREFIXES
    assert "162" in VIRTUAL_PREFIXES

    assert prefix_of("91391254") == "hk"
    assert prefix_of("+85291391254") == "hk"
    assert prefix_of("18049045741") == "1804904"

    with tempfile.TemporaryDirectory() as td:
        lp = Path(td) / "ledger.json"
        bad, why = is_recycled_suspect("17012345678", ledger_path=lp)
        assert bad and "virtual" in why

        bad, why = is_recycled_suspect("18049045741", ledger_path=lp)
        assert not bad and why == "ok"

        record_attempt("18049045741", "feihu", "banned", detail="test ban", ledger_path=lp)
        bad, why = is_recycled_suspect("18049045741", ledger_path=lp)
        assert bad

        s = summarize(ledger_path=lp)
        assert s["seen_numbers"] == 1
        assert len(s["bad_prefixes"]) == 1


def test_proxy_config_resolver():
    cfg = resolve_proxy_playwright_cfg("http://u1:p1@127.0.0.1:10080")
    assert cfg == {"server": "http://127.0.0.1:10080", "username": "u1", "password": "p1"}

    cfg2 = resolve_proxy_playwright_cfg("http://127.0.0.1:8080")
    assert cfg2 == {"server": "http://127.0.0.1:8080"}


def test_cron_loader_contracts():
    with tempfile.TemporaryDirectory() as td:
        fp = Path(td) / "accounts.jsonl"
        fp.write_text(json.dumps({"name": "acc1", "access_token": "at1", "refresh_token": "rt1"}) + "\n", encoding="utf-8")
        accs = load_accounts_from_source(str(fp))
        assert len(accs) == 1
        assert accs[0]["name"] == "acc1" and accs[0]["access_token"] == "at1"


def test_tcaptcha_solver_contract():
    # Test shape & contract of solve_tcaptcha_dx with synthetic mock images
    from PIL import Image
    import io

    bg = Image.new("RGBA", (320, 160), (200, 200, 200, 255))
    sp = Image.new("RGBA", (120, 120), (0, 0, 0, 0))
    # Draw a mock puzzle piece in sp
    for x in range(10, 50):
        for y in range(10, 50):
            sp.putpixel((x, y), (255, 0, 0, 255))

    bg_bytes = io.BytesIO()
    bg.save(bg_bytes, format="PNG")
    sp_bytes = io.BytesIO()
    sp.save(sp_bytes, format="PNG")

    pre_json = {
        "data": {
            "dyn_show_info": {
                "fg_elem_list": [
                    {
                        "id": 1,
                        "sprite_pos": [10, 10],
                        "size_2d": [40, 40],
                        "init_pos": [20, 30],
                    }
                ]
            }
        }
    }

    res = solve_tcaptcha_dx(pre_json, bg_bytes.getvalue(), sp_bytes.getvalue())
    assert "delta_orig" in res
    assert "bg_w" in res
    assert res["bg_w"] == 320


if __name__ == "__main__":
    test_encryption_roundtrip()
    test_credential_bundle_and_universal_sinks()
    test_fingerprint_heuristics()
    test_proxy_config_resolver()
    test_cron_loader_contracts()
    test_tcaptcha_solver_contract()
    print("[PASS] auto-cbcn offline suite passed (6/6)")
