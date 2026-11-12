# auto-cbcn

Universal CodeBuddy China (`copilot.tencent.com` / `www.codebuddy.cn`) registration engine, Tencent Waterproof Wall slider solver, BYOP SMS adapters, universal credential sinks, and automated daily maintenance cronjob.

## Architecture

`auto-cbcn` is designed as a composable, router-agnostic pipeline built around the `CredentialBundle` contract and pluggable sinks:

- **Tencent Waterproof Wall Slider Solver**: Subpixel alpha-mask edge cross-correlation solver (`solve_tcaptcha_dx`) for Tencent Captcha (`aid=2053989439`) with cubic-easing humanized mouse dragging.
- **BYOP Multi-Provider SMS Adapters**: Pluggable SMS clients for Feihu (`FeihuSmsClient`), Ejiema/Eomsg (`EjiemaSmsClient`), and Haomadun (`HaomadunSmsClient`) with automatic order release on timeout.
- **Fingerprint & Recycled Number Ledger**: Tracks previously tested numbers and `11140`-flagged prefixes (`fingerprint.py`), while hard-filtering IoT and virtual prefixes (`isVirtualMobile`).
- **Universal Credential Sinks (`--sink`)**: Route obtained `CredentialBundle` credentials anywhere:
  - `stdout`: Emit portable JSON to stdout for shell piping.
  - `file:<path>`: Append JSONL records to disk.
  - `http:<url>` / `https:<url>`: POST directly to any OpenAI-compatible router or gateway (`StyxRouter`, `OmniRoute`, `9Router`, `WorkBuddy2API`, or custom APIs).
  - `sqlite:<path>`: Encrypt credentials (`enc:v1` AES-256-GCM + Scrypt) and insert into a local SQLite connection store.
- **Universal Daily Cron Scheduler (`auto-cbcn cron`)**: Loads accounts from `sqlite`, `file:<path>`, `dir:<path>`, or `CBCN_TOKENS` env var, executes daily check-ins, Buddy Cat travel, streak redemptions, and 24h quiet-period drip growth tasks.

### Universal Router Sinks (`--sink`)

Route obtained `CredentialBundle` credentials to any target or downstream gateway:

| Target | Sink Spec | Description |
| :--- | :--- | :--- |
| **Shell / Pipe** | `--sink stdout` | Emits portable JSON to stdout for scripting or jq piping |
| **Local File** | `--sink file:./accounts.jsonl` | Appends JSONL records to disk |
| **HTTP Router API** | `--sink http://127.0.0.1:20128` | POSTs credentials directly to any compatible router gateway (`StyxRouter`, `OmniRoute`, `9Router`, `WorkBuddy2API`, or custom HTTP APIs) |
| **SQLite Store** | `--sink sqlite:/path/to/storage.sqlite` | Encrypts tokens (`enc:v1` AES-256-GCM + Scrypt) and inserts into local SQLite |
| **Custom Sinks** | Extend `store.py` | Implement any custom webhook, Redis, or secret manager adapter |

## Quick Start

```bash
# Install core package (CLI, cron, harvester, solver, encryption)
pip install -e .

# Optional: include Camoufox browser automation engine
pip install -e ".[browser]"

# Check environment, providers, and ledger status
auto-cbcn doctor

# Generate fresh CLI OAuth state + URL
auto-cbcn state

# Register and output CredentialBundle to stdout
auto-cbcn register --pid 11751 --mode 2 --area-code +86 --sink stdout

# Register and push to a local or remote HTTP router gateway
auto-cbcn register --pid 11751 --mode 2 --area-code +86 --sink http://127.0.0.1:20128

# Register and install directly into an encrypted SQLite store
auto-cbcn register --pid 11751 --mode 2 --area-code +86 --sink sqlite:/path/to/storage.sqlite

# Run universal daily cron pass across accounts
auto-cbcn cron --run --source sqlite:/path/to/storage.sqlite
auto-cbcn cron --run --source file:/path/to/accounts.jsonl
auto-cbcn cron --print-cron
```

## License

MIT © [rrddngtnn](https://github.com/rrddngtnn)
