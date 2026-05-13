# bigip-ts-validator

Validate (and optionally remediate) a F5 BIG-IP for F5 Telemetry Streaming (TS)
readiness against a named third-party consumer (Splunk, Azure Log Analytics,
AWS CloudWatch, Datadog, Generic HTTP, Sumo Logic, ElasticSearch, etc.).

The validator:

- Confirms the AS3 and Telemetry Streaming iControl LX extensions are installed
- Verifies the AS3-managed logging resources required by the TS "local listener"
  pattern are present in `/Common/Shared`
- Walks the active TS declaration looking for a `Telemetry_Consumer` whose
  `type` matches the expected consumer
- (Optional) installs missing iControl LX extensions from F5 GitHub releases
- (Optional) POSTs a bundled AS3 declaration to create the missing logging
  resources

The tool is intentionally read-only by default and explicit about every
mutation: it tells you what it's about to do, asks to confirm, and reports
what changed.

## Repository layout

```
bigip-ts-validator/
├── bigip_ts_validator.py                       # CLI + library
├── requirements.txt                            # `requests`, `urllib3`
├── examples/
│   ├── as3-telemetry-resources.json            # full AS3 (needs AVR + AFM + ASM)
│   └── as3-telemetry-resources-no-afm.json     # AS3 without AFM-dependent block
├── agents/
│   └── bigip-ts-validator.md                   # Claude Code subagent definition
├── rpms/                                       # downloaded RPM cache (gitignored)
└── LICENSE
```

## Requirements

### Workstation

- Python 3.10 or newer
- Network reachability to the BIG-IP management interface (port 443)
- For `--install-prereqs`: outbound HTTPS to `api.github.com` and
  `github.com` to fetch RPMs (about ~55 MB combined for AS3 + TS)

### BIG-IP

- TMOS 14.1+ (TS 1.x and AS3 3.x require relatively modern TMOS)
- REST management interface enabled and reachable
- An admin account with permission to:
  - Authenticate via `/mgmt/shared/authn/login`
  - Upload to `/mgmt/shared/file-transfer/uploads/` (for `--install-prereqs`)
  - POST to `/mgmt/shared/iapp/package-management-tasks` (for `--install-prereqs`)
  - PATCH `/mgmt/tm/sys/provision/<module>` (only if you provision modules)
  - POST to `/mgmt/shared/appsvcs/declare` (AS3)
  - GET `/mgmt/shared/telemetry/declare` (TS, read-only here)
- Modules: at minimum LTM. The bundled AS3 examples reference:
  - `Analytics_Profile` + `Analytics_TCP_Profile` → require **AVR** provisioned
  - `Security_Log_Profile.application` → requires **ASM** provisioned
  - `Security_Log_Profile.network` → requires **AFM** provisioned
  See **Module compatibility** below.

## Installation

```bash
git clone https://github.com/gregcoward/bigip_ts_validator.git
cd bigip_ts_validator
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Inputs

| Input            | Where it goes                | Notes                                                                 |
|------------------|------------------------------|-----------------------------------------------------------------------|
| BIG-IP host      | `--host <ip-or-hostname>`    | Required. Management address.                                         |
| Username         | `--username <name>`          | Required. Admin or admin-equivalent.                                  |
| Password         | `$BIGIP_PASSWORD` (preferred), `--password`, or interactive `getpass` prompt | Avoid passing on the command line — it shows in shell history / `ps`. |
| Consumer type    | `--consumer <Type>`          | Required. e.g. `Splunk`, `Azure_Log_Analytics`, `AWS_CloudWatch`, `Datadog`, `Generic_HTTP`, `Sumo_Logic`, `ElasticSearch`. |
| AS3 file         | `--as3-file <path>`          | Optional. Defaults to `examples/as3-telemetry-resources.json`.        |
| Install prereqs  | `--install-prereqs`          | Optional. Download + install AS3/TS RPMs if missing.                  |
| Pin AS3 version  | `--as3-version vX.Y.Z`       | Optional. Defaults to GitHub `latest` for `F5Networks/f5-appsvcs-extension`. |
| Pin TS version   | `--ts-version vX.Y.Z`        | Optional. Defaults to GitHub `latest` for `F5Networks/f5-telemetry-streaming`. |
| RPM cache dir    | `--rpm-cache-dir <path>`     | Optional. Defaults to `./rpms`.                                       |
| Mode             | `--no-remediate` / `--yes`   | `--no-remediate` is read-only. `--yes` skips both install and AS3 confirmations. |
| TLS              | `--verify-tls`               | Optional. Off by default since lab boxes usually have self-signed certs. |
| Output           | `--json`                     | Optional. Append the final findings as JSON to stdout.                |

## Usage

### Validate only

```bash
export BIGIP_PASSWORD='...'
.venv/bin/python bigip_ts_validator.py \
    --host 10.0.0.10 --username admin --consumer Splunk --no-remediate
```

### Validate, install missing extensions, apply AS3

```bash
export BIGIP_PASSWORD='...'
.venv/bin/python bigip_ts_validator.py \
    --host 10.0.0.10 --username admin --consumer Splunk \
    --install-prereqs --yes
```

### Use the AFM-free AS3 variant

```bash
.venv/bin/python bigip_ts_validator.py \
    --host 10.0.0.10 --username admin --consumer Splunk \
    --as3-file examples/as3-telemetry-resources-no-afm.json --yes
```

## Workflow steps

1. **Authenticate** — POST `/mgmt/shared/authn/login`. The returned token is
   used for the rest of the session and re-issued after any TMOS-side restart
   (extension install, module provisioning).
2. **Probe extensions** — GET `/mgmt/shared/appsvcs/info` and
   `/mgmt/shared/telemetry/info`.
3. **(Optional) Install extensions** — when `--install-prereqs` is set and an
   extension is missing:
   - Resolve the GitHub release (`latest` unless pinned).
   - Download the `.noarch.rpm` to `./rpms/` (cached; re-runs are fast).
   - Confirm in chat (unless `--yes`) showing the host, RPM name and tag.
   - Chunk-upload (`Content-Range` framing) to
     `/mgmt/shared/file-transfer/uploads/<name>`. The upload lands at
     `/var/config/rest/downloads/<name>` on the BIG-IP.
   - POST to `/mgmt/shared/iapp/package-management-tasks` with
     `{operation: "INSTALL", packageFilePath: ...}`.
   - Poll the task ID until `FINISHED` (or fail on `FAILED`/`CANCELED`).
   - Wait for the extension's `/info` endpoint to return.
4. **Validate AS3 resources** — GET `/mgmt/shared/appsvcs/declare`, dig into
   `Common.Shared`, and check each required class is present.
5. **Validate TS consumer** — GET `/mgmt/shared/telemetry/declare` and walk
   the document for `class: Telemetry_Consumer` with a `type` matching
   `--consumer`.
6. **Print report** — `[OK]`, `[WARN]`, `[MISSING]` lines and an overall
   `READY` / `NOT READY` verdict.
7. **(Optional) Remediate** — unless `--no-remediate`, when missing AS3
   resources are present:
   - Show the AS3 file and the host.
   - Confirm in chat (unless `--yes`).
   - POST the AS3 to `/mgmt/shared/appsvcs/declare`.
   - Re-run the validation.

## What is validated

Required objects in `/Common/Shared`:

| Object                                  | Class                  |
|-----------------------------------------|------------------------|
| `telemetry`                             | `Pool`                 |
| `telemetry_hsl`                         | `Log_Destination`      |
| `telemetry_formatted`                   | `Log_Destination`      |
| `telemetry_publisher`                   | `Log_Publisher`        |
| `telemetry_traffic_log_profile`         | `Traffic_Log_Profile`  |
| `telemetry_http_analytics_profile`      | `Analytics_Profile`    |
| `telemetry_tcp_analytics_profile`       | `Analytics_TCP_Profile`|
| `telemetry_asm_security_log_profile`    | `Security_Log_Profile` |

Optional objects (only needed for the TS "local listener" pattern, missing is a `[WARN]`):

| Object                  | Class         |
|-------------------------|---------------|
| `telemetry_local_rule`  | `iRule`       |
| `telemetry_local`       | `Service_TCP` |

## Exit codes

| Code | Meaning                                    |
|------|--------------------------------------------|
| 0    | Device is READY for the named consumer     |
| 1    | Device is NOT READY                        |
| 2    | Configuration / connectivity / auth error  |
| 3    | AS3 declaration apply failed               |
| 4    | iControl LX extension install failed       |

## Module compatibility

The default `examples/as3-telemetry-resources.json` requires three modules
to be provisioned beyond LTM:

- **AVR** — for `Analytics_Profile` and `Analytics_TCP_Profile`
- **ASM** — for the `application` block of `Security_Log_Profile`
- **AFM** — for the `network` block of `Security_Log_Profile`

If your BIG-IP is missing any of these, AS3 will return HTTP 422. Options:

- Provision the missing module (PATCH `/mgmt/tm/sys/provision/<m>` with
  `{"level": "nominal"}`). This causes a 1-2 minute REST/TMM restart and may
  exceed the CPU/RAM budget on small vBIG-IPs.
- Use `examples/as3-telemetry-resources-no-afm.json`, which drops just the
  AFM-dependent `network` block from the security log profile.
- Create your own AS3 variant for any other module combination and point
  `--as3-file` at it.

## Limitations and known gaps

- **No TS declaration support.** The validator reports whether a
  `Telemetry_Consumer` of the expected type is configured, but does not
  create one. Configuring a Splunk consumer (or any other) requires POSTing
  a TS declaration to `/mgmt/shared/telemetry/declare` with credentials
  (e.g. a Splunk HEC token). See the **Roadmap**.
- **TLS verification off by default.** Lab boxes typically have self-signed
  certs; `--verify-tls` opts in to certificate validation.
- **`--install-prereqs` requires internet access** from the workstation
  running the script (to `api.github.com` and the GitHub release CDN).
  Air-gapped environments need a pre-downloaded RPM cache pointed at via
  `--rpm-cache-dir`.
- **Single-device.** No batch or fleet-wide operation. Loop the script over
  a list of hosts if you need that.
- **No rollback.** AS3 is declarative so re-applying an old declaration
  reverts changes, but the script does not snapshot or restore state on
  failure.

## Roadmap

### Near term

- `--ts-declaration <file>`: POST a TS declaration alongside the AS3 apply,
  with a template generator for Splunk / Datadog / Azure Log Analytics etc.
  that takes a consumer URL and a passphrase from environment / file.
- `--provision <module>:<level>`: provision an arbitrary module from the CLI
  (currently done out-of-band; the AVR provisioning flow was inlined for
  the lab session).
- Make the `Analytics_Profile` / `Analytics_TCP_Profile` checks
  module-conditional: `[WARN]` instead of `[MISSING]` when AVR isn't
  provisioned.
- Optional structured logging (`--log-format json`) to feed CI pipelines.

### Frontend UI

The current shape is CLI-only with two interactive prompts (install confirm,
AS3 apply confirm) and a small set of pure validation functions. Building a
web UI is mostly mechanical:

1. **Library extraction.** Split `bigip_ts_validator.py` into:
   - `bigip_ts/client.py` (the `BigIPClient` class — already self-contained)
   - `bigip_ts/validate.py` (pure functions returning the findings dict)
   - `bigip_ts/install.py` (`resolve_github_rpm`, `download_rpm`,
     `ensure_extensions`)
   - `bigip_ts/cli.py` (the existing `main()`, untouched in behaviour)
   No business logic changes — just reorganization.
2. **HTTP service.** A thin FastAPI app would expose:
   - `POST /api/sessions` — accept host, username, password; return a
     short-lived session token bound to a `BigIPClient` instance kept in a
     server-side cache (with a TTL — never log the password, never echo it).
   - `GET /api/sessions/{id}/validate?consumer=Splunk` — call `validate()`,
     return the findings dict (already JSON-safe).
   - `POST /api/sessions/{id}/install-prereqs` — body specifies versions,
     server runs `ensure_extensions` and streams progress over SSE or WS.
   - `POST /api/sessions/{id}/apply-as3` — body is an AS3 file path or
     uploaded declaration; server runs the post + re-validate.
   - `POST /api/sessions/{id}/ts-declaration` — once `--ts-declaration`
     support lands (above).
3. **Frontend.** A small SPA (React + TanStack Query, or HTMX if you want
   to keep it boring) with:
   - Connection form (host, user, password, consumer dropdown).
   - Status grid mirroring the CLI report (one row per checked resource,
     coloured `OK` / `WARN` / `MISSING`).
   - Action buttons gated by what's missing: "Install extensions",
     "Provision AVR", "Apply AS3", "Configure consumer".
   - Live progress for long-running operations (install, provision) via
     server-sent events.
4. **Auth model.** Treat the BIG-IP password as a credential that never
   leaves the server process. Sessions are server-side; tokens to the
   browser are opaque. No localStorage of secrets.
5. **Packaging.** `Dockerfile` for the FastAPI + static frontend; the RPM
   cache directory mounted as a volume so re-installs across many BIG-IPs
   reuse the same RPM blobs.

### Stretch

- Fleet view (validate N BIG-IPs in parallel, group by readiness state).
- Optional integration with F5 BIG-IQ for credentials and inventory.
- Compatibility matrix view: show which AS3 variant + module set will work
  for a given device, based on what's provisioned.

## Contributing

Conventional Git workflow. The Python is targeted at 3.10+, uses standard
library + `requests`, and stays under 400 lines for readability. Don't add
abstractions without a second use case in sight.

## License

See [LICENSE](LICENSE).
