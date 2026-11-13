"""cli.py — Command-line interface for auto-cbcn."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import sys
import time

from .cron import execute_cron_pass, print_crontab_snippet
from .engine import register_cbcn
from .fingerprint import summarize
from .harvester import (
    create_cbcn_cli_state,
    export_bundle,
    get_cbcn_user_resource,
    harvest_cbcn_all,
    harvest_cbcn_safe,
    poll_cbcn_cli_token,
)
from .solver import EjiemaSmsClient, FeihuSmsClient, HaomadunSmsClient, probe_cbcn_inference
from .store import dispatch_credential_sink, load_dotenv_file


def cmd_doctor(_args) -> None:
    load_dotenv_file()
    feihu_user = os.environ.get("FEIHU_API_USER", "")
    feihu_key = os.environ.get("FEIHU_API_KEY", "")
    ejiema_tok = os.environ.get("EJIEMA_API_TOKEN", "")

    feihu_ok = False
    feihu_bal = 0.0
    if feihu_user and feihu_key:
        try:
            f = FeihuSmsClient()
            info = f.user_info()
            if info.get("code") == 200:
                feihu_ok = True
                feihu_bal = float((info.get("data") or {}).get("money") or 0.0)
        except Exception:
            pass

    ejiema_ok = False
    ejiema_bal = ""
    if ejiema_tok:
        try:
            ej = EjiemaSmsClient()
            ejiema_bal = ej.left_amount()
            ejiema_ok = True
        except Exception:
            pass

    haomadun_key = os.environ.get("HAOMADUN_API_KEY", "")
    haomadun_ok = False
    if haomadun_key:
        try:
            hm = HaomadunSmsClient()
            haomadun_ok = hm._req("GET", "/me").get("code") == 0
        except Exception:
            pass

    doc = {
        "ok": True,
        "environment": {
            "storage_encryption_key_set": bool(os.environ.get("STORAGE_ENCRYPTION_KEY")),
            "storage_encryption_salt": os.environ.get("STORAGE_ENCRYPTION_SALT", "styx-field-encryption-v1"),
            "router_url": os.environ.get("ROUTER_URL", "http://127.0.0.1:20128"),
            "router_db_path": os.environ.get("ROUTER_DB_PATH", "./storage.sqlite"),
            "proxy_configured": bool(os.environ.get("CBCN_PROXY_URL") or os.environ.get("PROXY_TEMPLATE")),
            "camoufox_installed": importlib.util.find_spec("camoufox") is not None,
        },
        "providers": {
            "feihu": {"configured": bool(feihu_user and feihu_key), "connected": feihu_ok, "balance_rmb": feihu_bal},
            "ejiema": {"configured": bool(ejiema_tok), "connected": ejiema_ok, "balance": ejiema_bal},
            "haomadun": {"configured": bool(haomadun_key), "connected": haomadun_ok},
        },
        "ledger": summarize(),
    }
    print(json.dumps(doc, indent=2, ensure_ascii=False))


def cmd_state(_args) -> None:
    print(json.dumps(create_cbcn_cli_state(), indent=2, ensure_ascii=False))


def cmd_poll(args) -> None:
    res = poll_cbcn_cli_token(args.state)
    if res.get("ok") and res.get("access_token"):
        at = res["access_token"]
        uid = res.get("uid") or ""
        nick = res.get("nickname") or "User"
        if args.safe_harvest:
            res["harvest"] = harvest_cbcn_safe(at, uid=uid)
        elif args.harvest:
            res["harvest"] = harvest_cbcn_all(at, uid=uid, nickname=nick)
        else:
            res["resource"] = get_cbcn_user_resource(at, uid=uid)

        res["probe"] = probe_cbcn_inference(at, uid=uid)
        bundle = export_bundle(
            access_token=at,
            refresh_token=res.get("refresh_token", ""),
            name=f"CBCN-{nick}",
            uid=uid,
            nickname=nick,
            expires_in=int(res.get("expires_in") or 5184000),
            remaining_credits=float((res.get("resource") or (res.get("harvest") or {}).get("resource") or {}).get("remaining_credits") or 0.0),
        )
        res["bundle"] = bundle.to_dict()
        if args.sink:
            res["sink_result"] = dispatch_credential_sink(bundle, sink=args.sink)
    print(json.dumps(res, indent=2, ensure_ascii=False))


def cmd_harvest(args) -> None:
    if args.safe:
        res = harvest_cbcn_safe(args.access_token, uid=args.uid)
    else:
        res = harvest_cbcn_all(args.access_token, uid=args.uid, nickname=args.nickname)
    print(json.dumps(res, indent=2, ensure_ascii=False))


def cmd_register(args) -> None:
    res = register_cbcn(
        pid=args.pid,
        mode=args.mode,
        area_code=args.area_code,
        isp=args.isp or None,
        proxy_country=args.proxy_country,
        sms_provider=args.sms_provider,
        sms_keyword=args.sms_keyword,
        channel_uid=args.channel_uid,
        fresh_only=args.fresh_only,
        block_bind=args.block_bind,
        precheck=not args.no_precheck,
        safe_harvest=not args.all_harvest,
        skip_harvest=args.skip_harvest,
        min_credits=args.min_credits,
        otp_timeout=args.otp_timeout,
        max_attempts=args.max_attempts,
        sink=args.sink,
        proxy_url=args.proxy_url or None,
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))


def cmd_cron(args) -> None:
    if args.print_cron:
        print_crontab_snippet(source=args.source)
        return
    if args.daemon:
        print(f"[DAEMON] Starting universal auto-cbcn cron daemon (interval: {args.interval}s, source: {args.source})", flush=True)
        while True:
            try:
                res = execute_cron_pass(
                    source=args.source,
                    allow_drip=not args.no_drip,
                    allow_refresh=args.allow_refresh,
                    proxy_url=args.proxy_url or None,
                    tasks_per_run=args.tasks_per_run,
                    jitter_minutes=args.jitter_minutes,
                )
                print(json.dumps(res, indent=2, ensure_ascii=False), flush=True)
            except Exception as e:
                print(f"[DAEMON ERROR] {e}", file=sys.stderr, flush=True)
            time.sleep(max(60, int(args.interval + random.uniform(-420, 420))))
    res = execute_cron_pass(
        source=args.source,
        allow_drip=not args.no_drip,
        allow_refresh=args.allow_refresh,
        proxy_url=args.proxy_url or None,
        tasks_per_run=args.tasks_per_run,
        jitter_minutes=args.jitter_minutes,
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))


def main(argv=None) -> int:
    load_dotenv_file()
    p = argparse.ArgumentParser(prog="auto-cbcn", description="Universal CodeBuddy China (CBCN) Management Engine")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_doc = sub.add_parser("doctor", help="Inspect environment, encryption keys, SMS providers, and ledger status")
    s_doc.set_defaults(func=cmd_doctor)

    s_st = sub.add_parser("state", help="Generate fresh device-flow state and CodeBuddy authorization URL")
    s_st.set_defaults(func=cmd_state)

    s_pol = sub.add_parser("poll", help="Poll CLI state, check credentials, optionally harvest and route to sink")
    s_pol.add_argument("--state", required=True, help="CLI state UUID")
    s_pol.add_argument("--harvest", action="store_true", help="Run full 19-bonus-pack harvest")
    s_pol.add_argument("--safe-harvest", action="store_true", help="Run safe non-report harvest")
    s_pol.add_argument("--sink", default="", help="Universal sink: stdout, file:<path>, http:<url>, or sqlite:<path>")
    s_pol.set_defaults(func=cmd_poll)

    s_harv = sub.add_parser("harvest", help="Execute credit harvest for an existing access token")
    s_harv.add_argument("--access-token", required=True, help="JWT access token")
    s_harv.add_argument("--uid", default="", help="User ID")
    s_harv.add_argument("--nickname", default="User", help="Display name")
    s_harv.add_argument("--safe", action="store_true", help="Run safe harvest only (no /v2/report events)")
    s_harv.set_defaults(func=cmd_harvest)

    s_reg = sub.add_parser("register", help="Run automated browser registration, captcha solving, and harvest")
    s_reg.add_argument("--sms-provider", default="feihu", choices=["feihu", "ejiema", "haomadun"], help="BYOP SMS provider adapter")
    s_reg.add_argument("--sms-keyword", default="腾讯科技", help="Keyword for Ejiema SMS adapter")
    s_reg.add_argument("--channel-uid", default="21986-HBY3OAE45E", help="Channel UID for Haomadun SMS adapter")
    s_reg.add_argument("--fresh-only", action="store_true", help="Skip numbers with non-empty last_event_time (Feihu)")
    s_reg.add_argument("--pid", type=int, default=11751, help="Feihu/Haomadun project ID (e.g. 11751, 10532, 2472)")
    s_reg.add_argument("--mode", type=int, default=2, help="SMS mode: 1 (public pool) or 2 (connect code / 专属)")
    s_reg.add_argument("--area-code", default="+86", help="Phone area code (+86 or +852)")
    s_reg.add_argument("--isp", default="", help="ISP filter (e.g. 中国电信, 中国移动, 中国联通)")
    s_reg.add_argument("--proxy-country", default="hk", help="Residential proxy country code (hk or cn)")
    s_reg.add_argument("--block-bind", action="store_true", help="Block web workspace callback")
    s_reg.add_argument("--no-precheck", action="store_true", help="Skip offline ledger precheck")
    s_reg.add_argument("--all-harvest", action="store_true", help="Run all growth tasks immediately instead of safe harvest")
    s_reg.add_argument("--skip-harvest", action="store_true", help="Skip credit harvest after registration")
    s_reg.add_argument("--min-credits", type=float, default=2000.0, help="Minimum remaining credits required to accept account")
    s_reg.add_argument("--otp-timeout", type=int, default=60, help="OTP timeout in seconds")
    s_reg.add_argument("--max-attempts", type=int, default=3, help="Max phone rental retry attempts")
    s_reg.add_argument("--sink", default="sqlite", help="Universal credential sink: sqlite, file:<path>, http:<url>, stdout")
    s_reg.add_argument("--proxy-url", default="", help="Explicit HTTP/SOCKS5 proxy URL")
    s_reg.set_defaults(func=cmd_register)

    s_cron = sub.add_parser("cron", help="Universal daily maintenance scheduler (checkin, streak, travel, drip tasks)")
    s_cron.add_argument("--source", default="sqlite", help="Account source: sqlite, file:<path>, dir:<path>, or env")
    s_cron.add_argument("--run", action="store_true", help="Execute single cron pass immediately")
    s_cron.add_argument("--daemon", action="store_true", help="Run indefinitely in background daemon mode")
    s_cron.add_argument("--interval", type=int, default=43200, help="Daemon interval in seconds (default: 43200 = 12h)")
    s_cron.add_argument("--print-cron", action="store_true", help="Print crontab configuration line")
    s_cron.add_argument("--no-drip", action="store_true", help="Skip growth task dripping (run checkin and travel only)")
    s_cron.add_argument("--allow-refresh", action="store_true", help="Allow refreshing 401 tokens (only for standalone sources without router auto-refresh)")
    s_cron.add_argument("--proxy-url", default="", help="Optional HTTP/SOCKS proxy URL for cron requests (or set CBCN_CRON_PROXY / PROXY_TEMPLATE)")
    s_cron.add_argument("--tasks-per-run", type=int, default=None, help="Max growth tasks to drip per account per run after 24h (default: 3)")
    s_cron.add_argument("--jitter-minutes", type=float, default=None, help="Random pre-run jitter window in minutes (default: 0)")
    s_cron.set_defaults(func=cmd_cron)

    args = p.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
