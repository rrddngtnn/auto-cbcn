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


def test_http_sink_and_sms_factory():
    from unittest.mock import patch, MagicMock
    from auto_cbcn.solver import build_sms_client
    from auto_cbcn.store import exchange_cbcn_http

    assert isinstance(build_sms_client("feihu"), FeihuSmsClient)
    assert isinstance(build_sms_client("ejiema"), EjiemaSmsClient)
    assert isinstance(build_sms_client("haomadun"), HaomadunSmsClient)

    b = CredentialBundle(
        name="CBCN-Test",
        phone="18049045741",
        uid="uid-12345",
        access_token="at-test-value",
        refresh_token="rt-test-value",
        expires_in=86400,
        remaining_credits=2100.0,
    )
    mock_resp = MagicMock(status_code=200, ok=True)
    mock_resp.json.return_value = {"imported": 1}
    with patch("auto_cbcn.store.requests.Session.post", return_value=mock_resp) as m_post:
        res = exchange_cbcn_http(b, router_url="http://127.0.0.1:20128", api_key="k1")
        assert res == {"imported": 1}
        called_url = m_post.call_args[0][0]
        called_json = m_post.call_args[1]["json"]
        assert called_url.endswith("/api/connections/import")
        assert called_json["provider"] == "codebuddy-cn"
        assert called_json["accounts"][0]["accessToken"] == "at-test-value"


def test_cron_file_prefix_and_refresh_contract():
    from unittest.mock import patch, MagicMock
    from auto_cbcn.cron import process_account_record

    with tempfile.TemporaryDirectory() as td:
        fp = Path(td) / "accounts.jsonl"
        fp.write_text(json.dumps({"name": "acc1", "access_token": "at1", "refresh_token": "rt1"}) + "\n", encoding="utf-8")
        accs = load_accounts_from_source(f"file:{fp}")
        assert len(accs) == 1
        assert accs[0]["access_token"] == "at1"

    with patch("auto_cbcn.cron.get_cbcn_user_resource") as m_res, patch("auto_cbcn.cron.refresh_cbcn_token") as m_ref, patch("auto_cbcn.cron.requests.Session.post") as m_post, patch("auto_cbcn.cron.requests.Session.get") as m_get:
        m_res.side_effect = [
            {"ok": False, "status": 401},
            {"ok": True, "remaining_credits": 500.0, "total_credits": 500.0, "pack_count": 1},
            {"ok": True, "remaining_credits": 600.0, "total_credits": 600.0, "pack_count": 1},
        ]
        m_ref.return_value = {"ok": True, "access_token": "at2", "refresh_token": "rt2", "expires_in": 3600}
        m_post.return_value = MagicMock(status_code=200, ok=True, json=lambda: {"code": 0, "data": {"credits": 100}})
        m_get.return_value = MagicMock(status_code=200, ok=True, json=lambda: {"code": 0, "data": {}})
        acc = {"name": "a1", "uid": "u1", "access_token": "at1", "refresh_token": "rt1"}
        out = process_account_record(acc, allow_drip=False, allow_refresh=True, proxy_url="http://u:p@127.0.0.1:10080")
        assert out["refreshed"] is True
        assert out["proxy"] == "127.0.0.1:10080"
        assert acc["access_token"] == "at2"
        assert acc["refresh_token"] == "rt2"

    # Multi-task drip (tasks_per_run=3) + jitter test
    with patch("auto_cbcn.cron.get_cbcn_user_resource") as m_res, patch("auto_cbcn.cron.requests.Session.post") as m_post, patch(
        "auto_cbcn.cron.requests.Session.get"
    ) as m_get, patch("auto_cbcn.cron.list_growth_tasks") as m_list, patch(
        "auto_cbcn.cron.run_single_safe_task"
    ) as m_run, patch("auto_cbcn.cron.time.sleep"):
        m_res.return_value = {"ok": True, "remaining_credits": 2200.0, "total_credits": 2200.0, "pack_count": 3}
        m_post.return_value = MagicMock(status_code=200, ok=True, json=lambda: {"code": 0, "data": {}})
        m_get.return_value = MagicMock(status_code=200, ok=True, json=lambda: {"code": 0, "data": {}})
        m_list.side_effect = [
            [
                {"task_code": "first_buddy", "accept_status": "not_accepted", "locked": False},
                {"task_code": "Library_read", "accept_status": "not_accepted", "locked": False},
                {"task_code": "playbook_prompt", "accept_status": "not_accepted", "locked": False},
                {"task_code": "skill_1", "accept_status": "not_accepted", "locked": False},
            ],
            [],
        ]
        m_run.side_effect = ["claimed:first_buddy:0", "claimed:Library_read:0", "claimed:playbook_prompt:0"]
        acc = {"name": "a2", "uid": "u2", "access_token": "at1", "refresh_token": "rt1"}
        out = process_account_record(acc, allow_drip=True, tasks_per_run=3)
        assert len(out["drip_tasks"]) == 3
        assert m_run.call_count == 3


def test_proxy_config_resolver():
    cfg = resolve_proxy_playwright_cfg("http://u1:p1@127.0.0.1:10080")
    assert cfg == {"server": "http://127.0.0.1:10080", "username": "u1", "password": "p1"}

    cfg2 = resolve_proxy_playwright_cfg("http://127.0.0.1:8080")
    assert cfg2 == {"server": "http://127.0.0.1:8080"}

    assert resolve_proxy_playwright_cfg("direct") is None
    assert resolve_proxy_playwright_cfg("") is None

    from auto_cbcn.cron import _http_proxies
    assert _http_proxies("none", session_key="u1") is None
    p = _http_proxies("http://user-{session}:pass@proxy.example:{port}", session_key="uid-123")
    assert p is not None and "{session}" not in p["https"] and "{port}" not in p["https"]


def test_feihu_fresh_only_skips_used_numbers():
    from unittest.mock import patch

    c = FeihuSmsClient(api_user="u", api_key="k")
    c._token = "tok"
    seq = [
        {"code": 200, "data": {"phone": "18100000001", "order_id": "o1", "isp": "中国电信", "province": "河北", "last_event_time": "2026-11-13 01:00:00"}},
        {"code": 200, "data": {"phone": "18100000002", "order_id": "o2", "isp": "中国电信", "province": "陕西", "last_event_time": ""}},
    ]
    with patch.object(c, "_get", side_effect=seq), patch.object(c, "release") as m_rel, patch("auto_cbcn.solver.time.sleep"):
        r = c.rent_phone(pid=11751, area_code="+86", mode=2, fresh_only=True)
        assert r is not None
        assert r.phone == "18100000002"
        m_rel.assert_called_once_with("o1")


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


def test_haomadun_proxy_and_upgraded_drip_tasks():
    from unittest.mock import patch, MagicMock
    from auto_cbcn.cron import SAFE_DRIP_TASKS, run_single_safe_task

    hm_direct = HaomadunSmsClient(api_key="k", proxy_url="direct")
    assert hm_direct._proxies() is None

    hm_proxy = HaomadunSmsClient(api_key="k", proxy_url="http://u:p@127.0.0.1:9999")
    assert hm_proxy._proxies() == {"http": "http://u:p@127.0.0.1:9999", "https": "http://u:p@127.0.0.1:9999"}

    for expected in ("skill_1", "automation_1", "template_5", "create_canvas", "expert_5", "Expert_team_use_3"):
        assert expected in SAFE_DRIP_TASKS

    from auto_cbcn.solver import HaozhumaSmsClient, build_sms_client
    assert isinstance(build_sms_client("haozhuma"), HaozhumaSmsClient)
    hz = HaozhumaSmsClient(api_user="u", api_key="p")
    with patch.object(hz, "_call", return_value={"code": "0", "phone": "18158867901", "sp": "电信", "phone_gsd": "安徽 合肥"}) as m_hz:
        hz._token = "tok"
        rp = hz.rent_phone(pid="88920")
        assert rp is not None and rp.phone == "18158867901" and rp.provider == "haozhuma"
        assert m_hz.called

    sess = MagicMock()
    sess.post.return_value = MagicMock(status_code=200, ok=True, json=lambda: {"code": 0, "data": {}})
    with patch("auto_cbcn.cron.accept_growth_tasks"), patch("auto_cbcn.cron.time.sleep"), patch(
        "auto_cbcn.cron.list_growth_tasks", return_value=[{"task_code": "skill_1", "accept_status": "completed"}]
    ), patch("auto_cbcn.cron.claim_task_reward", return_value={"code": 0}):
        out = run_single_safe_task("at1", "uid1", "nick", "skill_1", False, session=sess)
        assert out == "claimed:skill_1:0"
        posted_json = sess.post.call_args[1]["json"]
        assert posted_json[0]["eventCode"] == "skill_info"

    with patch("auto_cbcn.cron.accept_growth_tasks"), patch("auto_cbcn.cron.time.sleep"), patch(
        "auto_cbcn.cron.list_growth_tasks", return_value=[{"task_code": "Sequential_Tasks_2", "accept_status": "completed"}]
    ), patch("auto_cbcn.cron.claim_task_reward", return_value={"code": 0}):
        out2 = run_single_safe_task("at1", "uid1", "nick", "Sequential_Tasks_2", True, session=sess)
        assert out2 == "claimed:Sequential_Tasks_2:0"
        posted_mp = sess.post.call_args[1]["json"]
        assert posted_mp[0]["eventCode"] == "expert_actual_use"
        assert posted_mp[0]["id"] == "WorkspaceBuilder"


if __name__ == "__main__":
    test_encryption_roundtrip()
    test_credential_bundle_and_universal_sinks()
    test_fingerprint_heuristics()
    test_proxy_config_resolver()
    test_cron_loader_contracts()
    test_tcaptcha_solver_contract()
    print("[PASS] auto-cbcn offline suite passed (6/6)")
