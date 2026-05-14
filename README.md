# bigip-ts-validator

Validate (and optionally remediate) an F5 BIG-IP for **Telemetry Streaming (TS)**
readiness against a named push consumer (Splunk, Azure Log Analytics, AWS
CloudWatch, Datadog, Sumo Logic, Generic HTTP, ElasticSearch, and others).

**Checks**

- AS3 and TS iControl LX extensions are installed.
- AS3-managed logging resources for the TS **local listener** pattern exist under
  `/Common/Shared` (exact set depends on [what you select](#what-is-validated) in the Web UI, or on the CLI `--as3-file`).
- The active TS declaration includes a `Telemetry_Consumer` whose `type`
  matches the expected consumer.

**Changes (only when you opt in)**

- **CLI:** optional RPM install (`--install-prereqs`), optional POST of a static
  AS3 file (`--as3-file`; default under `examples/`). The CLI **does not** POST
  TS declarations; use the Web UI or `BigIPClient.post_ts_declaration` for that.
- **Web UI (FastAPI):** session-based validate / remediate / **rollback** — RPMs,
  TMOS provisioning, dynamic AS3 for selected sources, TS declaration POST, and
  documented TS/AVR follow-ups. **Rollback** clears TS config, removes the AS3
  `Common/Shared` application this tool manages, reverses selected TMOS tweaks,
  then `save sys config` (RPMs and module levels stay as-is).

---

## Table of contents

- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Installation](#installation)
- [Web UI](#web-ui-react--fastapi)
- [Run as a Linux service (systemd)](#run-as-a-linux-service-systemd)
- [CLI reference](#cli-reference)
  - [Inputs](#inputs)
  - [Usage](#usage)
- [How validation works](#how-validation-works)
- [What is validated](#what-is-validated)
- [Exit codes](#exit-codes)
- [Module compatibility](#module-compatibility)
- [Limitations](#limitations-and-known-gaps)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Repository layout

```
bigip-ts-validator/
├── bigip_ts_validator.py       # CLI + library (BigIPClient, validate, ensure_extensions)
├── as3_services.py             # Dynamic AS3 builder + required object list
├── ts_declaration_builder.py   # TS declaration composer (consumers)
├── server/app.py               # FastAPI session API
├── run_server.py               # uvicorn entrypoint
├── deploy/systemd/
│   └── bigip-ts-validator.service
├── frontend/                   # React (Vite) SPA
├── requirements.txt
├── examples/as3-telemetry-resources.json   # CLI default --as3-file
├── agents/                     # agent prompt (optional)
├── .claude/agents/             # same prompt for Claude Code (optional)
├── rpms/                       # RPM cache (.gitkeep; *.rpm gitignored)
└── LICENSE
```

## Requirements

### Workstation

- **Python 3.10+**, Git, and a venv with `pip install -r requirements.txt`.
- **Web UI:** Node.js **18+** and `npm` (`cd frontend && npm ci && npm run build`).
- Reachability to the BIG-IP management HTTPS port (usually **443**).
- **`--install-prereqs`:** outbound HTTPS to `api.github.com` / `github.com`
  (~55 MB for AS3 + TS RPMs). Air-gapped: pre-populate `rpms/` and pass
  `--rpm-cache-dir`.

**OS hints:** On Debian/Ubuntu use `python3-venv`; on RHEL-family ensure
`python3-virtualenv` if `python3 -m venv` fails. If `pip` fails building wheels
(e.g. `pydantic-core`), install `build-essential` + `python3-dev` (Debian) or
`gcc` + `python3-devel` (RHEL). For Node, prefer [nvm](https://github.com/nvm-sh/nvm)
or [nodejs.org](https://nodejs.org/) — distro `nodejs` packages are often too old.

### BIG-IP

- TMOS **14.1+** (modern AS3 / TS).
- REST enabled; admin-equivalent account able to call (as needed for your workflow):
  `/mgmt/shared/authn/login`, file uploads and package tasks (RPM install),
  `/mgmt/tm/sys/provision` (optional provisioning), `/mgmt/shared/appsvcs/declare`,
  `GET/POST /mgmt/shared/telemetry/declare`, `/mgmt/tm/analytics/global-settings`,
  `PUT /mgmt/tm/sys/db/tmm.tcl.rule.node.allow_loopback_addresses`,
  `POST /mgmt/tm/sys/config` with `command: save` (Web UI remediate path with AVR).
- **Modules:** at least **LTM**. Also **AVR** for HTTP/TCP analytics, **ASM** /
  **AFM** / **GTM** when those logging sources are selected. See
  [Module compatibility](#module-compatibility).

## Installation

```bash
git clone https://github.com/gregcoward/bigip_ts_validator.git
cd bigip_ts_validator
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Use your real clone path in the commands below.

## Web UI (React + FastAPI)

Browser UI: pick telemetry sources (LTM, ASM, AFM, HTTP/TCP analytics, DNS
logging), a [TS push consumer](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/setting-up-consumer.html),
consumer parameters, then **Validate**, **Validate + remediate + post TS**, or
**Rollback** (destructive; requires acknowledgement).

**Security:** the BIG-IP password is sent to this app over TLS, held in an
in-memory session (~45 min idle TTL), not written to API responses. Bind the API
to `127.0.0.1` unless you trust the network path.

```bash
# API + built UI (single port when frontend/dist exists)
cd bigip_ts_validator
.venv/bin/pip install -r requirements.txt
cd frontend && npm ci && npm run build && cd ..
.venv/bin/python run_server.py
# Open http://127.0.0.1:8000/

# Optional: Vite dev UI on :5173 (proxies /api → http://127.0.0.1:8000)
cd frontend && npm run dev
```

**REST (integrations)**

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/session` | Create session (host, user, password) |
| `POST` | `/api/session/{id}/validate` | Readiness report |
| `POST` | `/api/session/{id}/remediate` | Install RPMs (optional), provision modules (optional), AS3, TS, TMOS tweaks |
| `POST` | `/api/session/{id}/rollback` | TS clear + AS3 delete `Common/Shared` + undo remediate DB/analytics tweaks (`confirm: true`) |
| `GET` | `/api/consumers` | Supported consumer types |
| `GET` | `/api/health` | Liveness |

**Long runs:** remediate can take many minutes (RPMs, provisioning, AS3, TS).
If the browser shows a network error but work finished on the BIG-IP, raise
**proxy read timeouts** in front of Uvicorn (e.g. nginx `proxy_read_timeout 900s;`
for `/api`). The Vite dev proxy uses extended timeouts for `/api` in
`frontend/vite.config.ts`.

## Run as a Linux service (systemd)

Example layout: **`/opt/bigip-ts-validator`**. Adjust paths to match your install.

**1. Install and build**

```bash
sudo mkdir -p /opt && sudo git clone https://github.com/gregcoward/bigip_ts_validator.git /opt/bigip-ts-validator
cd /opt/bigip-ts-validator
sudo python3 -m venv .venv
sudo .venv/bin/pip install --upgrade pip && sudo .venv/bin/pip install -r requirements.txt
cd frontend && sudo npm ci && sudo npm run build && cd ..
```

**2. Service user**

```bash
sudo useradd --system --home /opt/bigip-ts-validator --shell /usr/sbin/nologin --user-group bigip-ts
sudo chown -R bigip-ts:bigip-ts /opt/bigip-ts-validator
```

The service user needs read access to the repo and `frontend/dist`, and write
access to `rpms/` if operators install RPMs from the UI.

**3. Unit file**

Copy **`deploy/systemd/bigip-ts-validator.service`** to `/etc/systemd/system/`,
then adjust **`User`**, **`Group`**, **`WorkingDirectory`**, **`ExecStart`**.

The sample uses **`ProtectSystem=true`** (not `strict` without extra paths — that
can yield **`status=226/NAMESPACE`**). For **`0.0.0.0`**, change **`--host`** in
**`ExecStart`** and firewall accordingly.

```bash
sudo cp /opt/bigip-ts-validator/deploy/systemd/bigip-ts-validator.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bigip-ts-validator.service
curl -sS http://127.0.0.1:8000/api/health
```

**Logs / updates**

```bash
sudo journalctl -u bigip-ts-validator.service -f
sudo systemctl restart bigip-ts-validator.service   # after git pull, pip, or npm build
```

**Reverse proxy:** for TLS or ports 80/443, terminate in front of Uvicorn and
proxy to `http://127.0.0.1:8000`. Use **long read timeouts** for `/api` (see
[Web UI](#web-ui-react--fastapi)).

## CLI reference

### Inputs

| Input | Notes |
|-------|--------|
| `--host` | BIG-IP management IP or hostname (**required**). |
| `--username` | Admin or equivalent (**required**). |
| Password | Prefer `$BIGIP_PASSWORD`; avoid `--password` in shell history. |
| `--consumer` | Required. e.g. `Splunk`, `Azure_Log_Analytics`, `DataDog` / `Datadog`, `Sumo_Logic`, … |
| `--as3-file` | Default `examples/as3-telemetry-resources.json`. |
| `--install-prereqs` | Download + install missing AS3/TS RPMs. |
| `--as3-version` / `--ts-version` | Pin GitHub release tags (default `latest`). |
| `--rpm-cache-dir` | Default `./rpms`. |
| `--no-remediate` | Validate only. |
| `--yes` | Skip install + AS3 confirmation prompts. |
| `--verify-tls` | Verify BIG-IP certificate (off by default). |
| `--json` | Print final findings as JSON. |

### Usage

```bash
export BIGIP_PASSWORD='...'

# Validate only
.venv/bin/python bigip_ts_validator.py \
  --host 10.0.0.10 --username admin --consumer Splunk --no-remediate

# Validate + install RPMs + apply static AS3 (prompts unless --yes)
.venv/bin/python bigip_ts_validator.py \
  --host 10.0.0.10 --username admin --consumer Splunk \
  --install-prereqs --yes
```

## How validation works

1. **Authenticate** — `POST /mgmt/shared/authn/login` (token refreshed after
   BIG-IP-side restarts when the client retries).
2. **Extensions** — `GET /mgmt/shared/appsvcs/info` and `/mgmt/shared/telemetry/info`.
3. **Optional install** — with `--install-prereqs`: resolve GitHub release,
   download RPM to `rpms/`, chunked upload, `package-management-tasks` INSTALL,
   poll until `FINISHED`, wait for `/info`.
4. **AS3** — `GET /mgmt/shared/appsvcs/declare`, inspect `Common.Shared` for
   required classes.
5. **TS** — `GET /mgmt/shared/telemetry/declare`, find `Telemetry_Consumer` types.
6. **Report** — `[OK]` / `[WARN]` / `[MISSING]` and **READY** / **NOT READY**.

**Optional remediate (CLI):** if AS3 objects are missing and not `--no-remediate`,
prompts (unless `--yes`) then `POST /mgmt/shared/appsvcs/declare` with the chosen
AS3 file, then re-validates.

## What is validated

Objects under `/Common/Shared` depend on selected sources (Web UI / API) or on
the full example when using the default CLI `--as3-file`:

| Object | Class |
|--------|--------|
| `telemetry` | `Pool` |
| `telemetry_hsl` | `Log_Destination` |
| `telemetry_formatted` | `Log_Destination` |
| `telemetry_publisher` | `Log_Publisher` |
| `telemetry_traffic_log_profile` | `Traffic_Log_Profile` |
| `telemetry_http_analytics_profile` | `Analytics_Profile` |
| `telemetry_tcp_analytics_profile` | `Analytics_TCP_Profile` |
| `telemetry_asm_security_log_profile` | `Security_Log_Profile` |
| `telemetry_dns_logging` | `DNS_Logging_Profile` |

**DNS logging:** requires GTM/DNS provisioned; attach the published profile per
F5 docs — this tool only creates the Shared chain + `DNS_Logging_Profile`.

**Optional (local listener):** `telemetry_local_rule` (`iRule`), `telemetry_local`
(`Service_TCP`) — missing is `[WARN]` unless required by your pattern.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | READY |
| 1 | NOT READY |
| 2 | Config / connectivity / auth error |
| 3 | AS3 apply failed |
| 4 | Extension install failed |

## Module compatibility

The **Web UI** builds AS3 only for checked sources. The **default CLI** example
file includes AVR/ASM/AFM/DNS-related objects together; AS3 **422** if a
referenced module is not provisioned.

- Use **Provision required TMOS modules** in the UI, your own `--as3-file`, or
  PATCH `/mgmt/tm/sys/provision/<module>` to `nominal`. Provisioning restarts
  REST/TMM briefly.
- **01071003 / busy:** remediation PATCHes modules **sequentially** with retries
  while TMOS reports a prior provisioning job in flight.

**AVR + TS:** F5 documents pointing AVR at your TS Log Publisher in
[Modifying AVR configuration to use the Log Publisher](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/avr.html#modifying-avr-configuration-to-use-the-log-publisher).
Prerequisites include AVR provisioned, a TS Event Listener with a Log Publisher
([Event Listener](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/event-listener.html)),
and analytics profiles on virtual servers. Example **tmsh**:

`modify analytics global-settings { external-logging-publisher /Common/telemetry_publisher offbox-protocol hsl use-offbox enabled }`

With HTTP/TCP analytics selected, remediate **PATCHes**
[`analytics global-settings`](https://clouddocs.f5.com/api/icontrol-rest/APIRef_tm_analytics_global-settings.html)
(`useHsl`, `useOffbox`, publisher — default Shared publisher path matches this
repo’s AS3; override with `avr_log_publisher_fullpath` on `/remediate`), then
[`save sys config`](https://clouddocs.f5.com/api/icontrol-rest/APIRef_tm_sys_config.html),
and applies additional TS/AVR workarounds documented for your environment.

**ASM + AS3 422 (`localhost:8100`):** after ASM provisioning, AS3 may 422 while
ASM REST warms up. The UI waits on `GET /mgmt/tm/asm/policies` when ASM is
selected and retries AS3; if needed wait 1–2 minutes and remediate again.

## Limitations and known gaps

- **CLI does not POST TS declarations** — use the Web UI or call
  `BigIPClient.post_ts_declaration` / `build_ts_declaration` yourself.
- **Rollback is Web/API only** — not exposed on the CLI; it removes this tool’s
  TS + AS3 footprint and several remediate-time TMOS settings, not RPMs or
  module provisioning levels.
- **TLS verification** is off by default (`--verify-tls` to enable).
- **Single device** per run; no built-in fleet mode.
- **BIG-IQ / Statistics Collection** can overwrite AVR toward BIG-IQ only; see
  [AVR export](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/avr.html).

## Roadmap

- CLI: `POST` TS from `--ts-declaration <file>`; optional `--provision <module>:<level>`.
- Validation: treat missing analytics profiles as `[WARN]` when AVR is not
  provisioned.
- Optional `--log-format json` for CI.
- Packaging: `Dockerfile`, SSE or progress for long RPM installs.

## Contributing

Conventional Git workflow. Prefer small, focused changes; match existing style
(`requests`, minimal dependencies).

## License

See [LICENSE](LICENSE).
