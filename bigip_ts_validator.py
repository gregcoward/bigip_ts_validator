#!/usr/bin/env python3
"""Validate (and optionally remediate) BIG-IP readiness for F5 Telemetry Streaming.

Checks the device for:
  * AS3 and Telemetry Streaming iControl LX extensions
  * The AS3-managed logging resources required by the TS "local listener" pattern
    (pool, iRule, virtual, HSL + formatted log destinations, log publisher,
    traffic / analytics / TCP-analytics / security log profiles)
  * A Telemetry_Consumer of the expected type on the TS declaration

If anything is missing the script can POST the supplied AS3 declaration to
/mgmt/shared/appsvcs/declare to create the resources, then re-validate.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests
import urllib3

from as3_services import build_as3_declaration, required_as3_object_names
from ts_declaration_builder import normalize_consumer_type

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


REQUIRED_AS3_OBJECTS: list[tuple[str, str]] = [
    ("telemetry", "Pool"),
    ("telemetry_hsl", "Log_Destination"),
    ("telemetry_formatted", "Log_Destination"),
    ("telemetry_publisher", "Log_Publisher"),
    ("telemetry_traffic_log_profile", "Traffic_Log_Profile"),
    ("telemetry_http_analytics_profile", "Analytics_Profile"),
    ("telemetry_tcp_analytics_profile", "Analytics_TCP_Profile"),
    ("telemetry_asm_security_log_profile", "Security_Log_Profile"),
]

# Optional resources used when TS listens locally on the BIG-IP rather than
# pushing directly to a remote consumer. Missing entries here are warnings.
OPTIONAL_AS3_OBJECTS: list[tuple[str, str]] = [
    ("telemetry_local_rule", "iRule"),
    ("telemetry_local", "Service_TCP"),
]


F5_AS3_REPO = "F5Networks/f5-appsvcs-extension"
F5_TS_REPO = "F5Networks/f5-telemetry-streaming"
DEFAULT_RPM_CACHE = Path(__file__).parent / "rpms"


class BigIPError(RuntimeError):
    pass


class BigIPClient:
    def __init__(self, host: str, username: str, password: str, verify_tls: bool = False, timeout: int = 30):
        self.base_url = f"https://{host}"
        self.timeout = timeout
        self._username = username
        self._password = password
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.session.headers.update({"Content-Type": "application/json"})
        self._authenticate(username, password)

    def reauthenticate(self) -> None:
        self.session.headers.pop("X-F5-Auth-Token", None)
        self._authenticate(self._username, self._password)

    def _authenticate(self, username: str, password: str) -> None:
        url = f"{self.base_url}/mgmt/shared/authn/login"
        body = {"username": username, "password": password, "loginProviderName": "tmos"}
        try:
            resp = self.session.post(url, json=body, timeout=self.timeout)
        except requests.RequestException as exc:
            raise BigIPError(f"Could not reach BIG-IP at {self.base_url}: {exc}") from exc
        if resp.status_code != 200:
            raise BigIPError(f"Authentication failed ({resp.status_code}): {resp.text}")
        token = resp.json().get("token", {}).get("token")
        if not token:
            raise BigIPError("Authentication response did not contain a token")
        self.session.headers.update({"X-F5-Auth-Token": token})

    def _get(self, path: str) -> requests.Response:
        return self.session.get(f"{self.base_url}{path}", timeout=self.timeout)

    def _post(self, path: str, body: Any) -> requests.Response:
        return self.session.post(f"{self.base_url}{path}", json=body, timeout=self.timeout)

    def extension_info(self, name: str) -> dict | None:
        resp = self._get(f"/mgmt/shared/{name}/info")
        if resp.status_code == 200:
            data = resp.json()
            return data[0] if isinstance(data, list) and data else data
        return None

    def as3_declaration(self) -> dict | None:
        resp = self._get("/mgmt/shared/appsvcs/declare")
        if resp.status_code == 204:
            return {}
        if resp.status_code == 200:
            return resp.json()
        return None

    def ts_declaration(self) -> dict | None:
        resp = self._get("/mgmt/shared/telemetry/declare")
        if resp.status_code == 200:
            return resp.json()
        return None

    def post_as3(self, declaration: dict) -> dict:
        resp = self._post("/mgmt/shared/appsvcs/declare", declaration)
        if resp.status_code >= 400:
            raise BigIPError(f"AS3 POST failed ({resp.status_code}): {resp.text}")
        return resp.json()

    def post_ts_declaration(self, declaration: dict) -> dict:
        """POST a Telemetry Streaming declaration to /mgmt/shared/telemetry/declare."""
        resp = self._post("/mgmt/shared/telemetry/declare", declaration)
        if resp.status_code >= 400:
            raise BigIPError(f"TS declaration POST failed ({resp.status_code}): {resp.text[:2000]}")
        if not (resp.text or "").strip():
            return {}
        try:
            return resp.json()
        except json.JSONDecodeError:
            return {"_raw_text": resp.text}

    def upload_file(self, local_path: Path) -> str:
        """Chunk-upload a file to /var/config/rest/downloads/<name>. Returns the remote path."""
        name = local_path.name
        size = local_path.stat().st_size
        if size == 0:
            raise BigIPError(f"Refusing to upload zero-byte file {local_path}")
        chunk_size = 1024 * 1024
        url = f"{self.base_url}/mgmt/shared/file-transfer/uploads/{name}"
        headers = {
            "Content-Type": "application/octet-stream",
            "X-F5-Auth-Token": self.session.headers.get("X-F5-Auth-Token", ""),
        }
        with local_path.open("rb") as f:
            start = 0
            while start < size:
                chunk = f.read(chunk_size)
                end = start + len(chunk) - 1
                headers["Content-Range"] = f"{start}-{end}/{size}"
                resp = self.session.post(url, data=chunk, headers=headers, timeout=self.timeout, verify=self.session.verify)
                if resp.status_code >= 400:
                    raise BigIPError(f"Upload chunk {start}-{end}/{size} of {name} failed ({resp.status_code}): {resp.text[:300]}")
                start = end + 1
        return f"/var/config/rest/downloads/{name}"

    def install_package(self, remote_rpm_path: str, timeout: int = 300) -> dict:
        body = {"operation": "INSTALL", "packageFilePath": remote_rpm_path}
        resp = self._post("/mgmt/shared/iapp/package-management-tasks", body)
        if resp.status_code >= 400:
            raise BigIPError(f"Install task POST failed ({resp.status_code}): {resp.text[:300]}")
        task_id = resp.json().get("id")
        if not task_id:
            raise BigIPError(f"Install task POST returned no id: {resp.text[:300]}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(3)
            r = self._get(f"/mgmt/shared/iapp/package-management-tasks/{task_id}")
            if r.status_code == 401:
                # The rest framework restart after install can invalidate the token.
                self.reauthenticate()
                continue
            if r.status_code != 200:
                continue
            data = r.json()
            status = data.get("status")
            if status == "FINISHED":
                return data
            if status in ("FAILED", "CANCELED"):
                raise BigIPError(f"Install task {task_id} {status}: {data.get('errorMessage') or data}")
        raise BigIPError(f"Install task {task_id} timed out after {timeout}s")

    def wait_for_extension(self, name: str, timeout: int = 180) -> dict:
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            try:
                info = self.extension_info(name)
            except requests.RequestException as exc:
                last_err = exc
                info = None
            if info:
                return info
            time.sleep(3)
            # Rest framework restarts can churn the token; try a re-auth on the way out.
            try:
                self.reauthenticate()
            except BigIPError as exc:
                last_err = exc
        raise BigIPError(f"Extension '{name}' did not come online within {timeout}s ({last_err})")


def _shared_block(as3_decl: Any) -> dict | None:
    """Extract Common.Shared from whatever shape /mgmt/shared/appsvcs/declare returns."""
    if not isinstance(as3_decl, dict):
        return None
    # /declare can return either the ADC object directly or a wrapper with a "declaration" key.
    adc = as3_decl.get("declaration") if "declaration" in as3_decl else as3_decl
    if isinstance(adc, list):
        adc = adc[0] if adc else None
    if not isinstance(adc, dict):
        return None
    common = adc.get("Common")
    if not isinstance(common, dict):
        return None
    shared = common.get("Shared")
    return shared if isinstance(shared, dict) else None


def _find_consumers(ts_decl: Any) -> list[dict]:
    """Walk the TS declaration and return every Telemetry_Consumer object found."""
    consumers: list[dict] = []
    if not isinstance(ts_decl, dict):
        return consumers
    decl = ts_decl.get("declaration", ts_decl)

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("class") == "Telemetry_Consumer":
                consumers.append(node)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(decl)
    return consumers


def resolve_github_rpm(repo: str, version: str | None) -> tuple[str, str, str]:
    """Look up an iControl LX RPM asset on a F5 GitHub release.

    Returns (tag, asset_name, download_url). If version is None, uses /releases/latest.
    """
    if version:
        tag = version if version.startswith("v") else f"v{version}"
        url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    else:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
    headers = {"Accept": "application/vnd.github+json"}
    gh_token = os.environ.get("GITHUB_TOKEN")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"
    try:
        r = requests.get(url, headers=headers, timeout=30)
    except requests.RequestException as exc:
        raise BigIPError(f"GitHub release lookup for {repo} failed: {exc}") from exc
    if r.status_code != 200:
        raise BigIPError(f"GitHub release lookup for {repo} returned {r.status_code}: {r.text[:200]}")
    rel = r.json()
    for asset in rel.get("assets", []):
        name = asset.get("name", "")
        if name.endswith(".noarch.rpm"):
            return rel.get("tag_name", "unknown"), name, asset["browser_download_url"]
    raise BigIPError(f"No .noarch.rpm asset found in {repo} release {rel.get('tag_name')}")


def download_rpm(url: str, dest: Path) -> None:
    if dest.is_file() and dest.stat().st_size > 0:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with requests.get(url, stream=True, timeout=180) as r:
            if r.status_code != 200:
                raise BigIPError(f"RPM download failed ({r.status_code}) for {url}")
            with tmp.open("wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)
        tmp.rename(dest)
    except requests.RequestException as exc:
        if tmp.exists():
            tmp.unlink()
        raise BigIPError(f"RPM download failed: {exc}") from exc


def ensure_extensions(
    client: BigIPClient,
    cache_dir: Path,
    as3_version: str | None,
    ts_version: str | None,
    assume_yes: bool,
) -> list[str]:
    """Install any missing AS3/TS extensions. Returns the list of names actually installed."""
    targets: list[tuple[str, str, str | None]] = []  # (extension_name, github_repo, pinned_version)
    if not client.extension_info("appsvcs"):
        targets.append(("appsvcs", F5_AS3_REPO, as3_version))
    if not client.extension_info("telemetry"):
        targets.append(("telemetry", F5_TS_REPO, ts_version))
    if not targets:
        return []

    plan: list[tuple[str, str, Path]] = []  # (extension_name, tag, local_rpm)
    print("\nResolving F5 GitHub releases for missing extensions ...")
    for ext_name, repo, ver in targets:
        tag, asset_name, dl_url = resolve_github_rpm(repo, ver)
        local = cache_dir / asset_name
        print(f"  {ext_name}: {tag} -> {asset_name}")
        plan.append((ext_name, tag, local))
        download_rpm(dl_url, local)

    print(f"\nAbout to install on {client.base_url}:")
    for ext_name, tag, local in plan:
        print(f"  - {ext_name} {tag}  ({local.name})")
    if not assume_yes:
        confirm = input("Proceed with install? [y/N]: ").strip().lower()
        if confirm != "y":
            raise BigIPError("Extension install aborted by user")

    installed: list[str] = []
    for ext_name, tag, local in plan:
        print(f"\nUploading {local.name} ...")
        remote = client.upload_file(local)
        print(f"Installing {ext_name} ({tag}) ...")
        client.install_package(remote)
        print(f"Waiting for {ext_name} to come online ...")
        info = client.wait_for_extension(ext_name)
        print(f"  -> {ext_name} version {info.get('version', 'unknown')} is up")
        installed.append(ext_name)
    return installed


def validate(client: BigIPClient, expected_consumer: str, services: dict[str, bool] | None = None) -> dict:
    checks: list[str] = []
    missing: list[str] = []
    warnings: list[str] = []

    expected_consumer_norm = normalize_consumer_type(expected_consumer)

    required_objects: list[tuple[str, str]]
    if services is not None and not any(
        services.get(k, False) for k in ("ltm", "asm", "afm", "http_analytics", "tcp_analytics")
    ):
        missing.append(
            "Select at least one telemetry scope (LTM, ASM, AFM, HTTP Analytics, or TCP Analytics)"
        )
        required_objects = []
    else:
        required_objects = required_as3_object_names(services)

    as3_info = client.extension_info("appsvcs")
    if as3_info:
        checks.append(f"AS3 extension installed (version {as3_info.get('version', 'unknown')})")
    else:
        missing.append("AS3 extension is not installed on the BIG-IP")

    ts_info = client.extension_info("telemetry")
    if ts_info:
        checks.append(f"Telemetry Streaming installed (version {ts_info.get('version', 'unknown')})")
    else:
        missing.append("Telemetry Streaming extension is not installed on the BIG-IP")

    shared = _shared_block(client.as3_declaration()) if as3_info else None
    if shared is None:
        if as3_info:
            for name, cls in required_objects:
                missing.append(f"AS3 resource missing in /Common/Shared: {name} ({cls})")
    else:
        for name, cls in required_objects:
            obj = shared.get(name)
            if isinstance(obj, dict) and obj.get("class") == cls:
                checks.append(f"AS3 resource present: {name} ({cls})")
            else:
                missing.append(f"AS3 resource missing in /Common/Shared: {name} ({cls})")
        for name, cls in OPTIONAL_AS3_OBJECTS:
            obj = shared.get(name)
            if isinstance(obj, dict) and obj.get("class") == cls:
                checks.append(f"Optional AS3 resource present: {name} ({cls})")
            else:
                warnings.append(f"Optional AS3 resource not found: {name} ({cls}) — required only for the TS local-listener pattern")

    consumer_status = "skipped (TS not installed)"
    if ts_info:
        consumers = _find_consumers(client.ts_declaration())
        if not consumers:
            missing.append("TS declaration has no Telemetry_Consumer configured")
            consumer_status = "none configured"
        else:
            types = [c.get("type", "<no type>") for c in consumers]
            matching = [c for c in consumers if normalize_consumer_type(str(c.get("type", ""))) == expected_consumer_norm]
            if matching:
                checks.append(
                    f"TS consumer of type {expected_consumer_norm} is configured ({len(matching)} found)"
                )
                consumer_status = f"{expected_consumer_norm} configured"
            else:
                missing.append(
                    f"TS declaration has no Telemetry_Consumer of type '{expected_consumer_norm}' "
                    f"(found: {', '.join(types) or 'none'})"
                )
                consumer_status = f"have [{', '.join(types)}], need {expected_consumer_norm}"

    return {
        "checks": checks,
        "missing": missing,
        "warnings": warnings,
        "consumer_status": consumer_status,
        "ready": not missing,
    }


def print_report(host: str, findings: dict) -> None:
    line = "=" * 72
    print(line)
    print(f"BIG-IP Telemetry Streaming readiness report — {host}")
    print(line)
    for c in findings["checks"]:
        print(f"  [OK]      {c}")
    for w in findings["warnings"]:
        print(f"  [WARN]    {w}")
    for m in findings["missing"]:
        print(f"  [MISSING] {m}")
    print("-" * 72)
    print(f"  Consumer: {findings['consumer_status']}")
    print(f"  STATUS:   {'READY' if findings['ready'] else 'NOT READY'}")
    print(line)


def resolve_password(args: argparse.Namespace) -> str:
    if args.password:
        return args.password
    env_pw = os.environ.get("BIGIP_PASSWORD")
    if env_pw:
        return env_pw
    return getpass.getpass(f"Password for {args.username}@{args.host}: ")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate (and remediate) BIG-IP readiness for F5 Telemetry Streaming.")
    parser.add_argument("--host", required=True, help="BIG-IP management IP or hostname")
    parser.add_argument("--username", required=True, help="BIG-IP admin username")
    parser.add_argument("--password", help="Password (else uses $BIGIP_PASSWORD or prompts)")
    parser.add_argument("--consumer", required=True,
                        help="Expected TS consumer type, e.g. Splunk, Azure_Log_Analytics, "
                             "AWS_CloudWatch, DataDog (Datadog accepted as alias), Generic_HTTP, "
                             "Sumo_Logic, ElasticSearch")
    parser.add_argument("--as3-file", default=str(Path(__file__).parent / "examples" / "as3-telemetry-resources.json"),
                        help="AS3 declaration to apply when remediating")
    parser.add_argument("--no-remediate", action="store_true",
                        help="Validate only; do not offer to apply the AS3 declaration")
    parser.add_argument("--yes", action="store_true",
                        help="Skip the confirmation prompt before applying changes (install + AS3)")
    parser.add_argument("--install-prereqs", action="store_true",
                        help="If AS3 and/or TS iControl LX extensions are missing, download "
                             "RPMs from F5's GitHub releases and install them before validating")
    parser.add_argument("--as3-version", help="Pin AS3 version, e.g. v3.55.0 (default: latest release)")
    parser.add_argument("--ts-version", help="Pin TS version, e.g. v1.36.0 (default: latest release)")
    parser.add_argument("--rpm-cache-dir", default=str(DEFAULT_RPM_CACHE),
                        help="Directory where downloaded RPMs are cached")
    parser.add_argument("--verify-tls", action="store_true", help="Verify the BIG-IP TLS certificate")
    parser.add_argument("--json", action="store_true", help="Emit the final findings as JSON on stdout")
    args = parser.parse_args()

    password = resolve_password(args)

    try:
        client = BigIPClient(args.host, args.username, password, verify_tls=args.verify_tls)
    except BigIPError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.install_prereqs:
        try:
            installed = ensure_extensions(
                client,
                cache_dir=Path(args.rpm_cache_dir),
                as3_version=args.as3_version,
                ts_version=args.ts_version,
                assume_yes=args.yes,
            )
        except BigIPError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 4
        if installed:
            print(f"\nInstalled: {', '.join(installed)}")

    findings = validate(client, args.consumer)
    print_report(args.host, findings)

    if findings["ready"]:
        if args.json:
            print(json.dumps(findings, indent=2))
        return 0

    if args.no_remediate:
        if args.json:
            print(json.dumps(findings, indent=2))
        return 1

    as3_path = Path(args.as3_file)
    if not as3_path.is_file():
        print(f"ERROR: AS3 declaration not found at {as3_path}", file=sys.stderr)
        return 2
    try:
        declaration = json.loads(as3_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"ERROR: {as3_path} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    if not args.yes:
        print(f"\nThe following AS3 declaration will be POSTed to {args.host}: {as3_path}")
        confirm = input("Apply now? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Aborted by user.")
            return 1

    print(f"\nApplying AS3 declaration from {as3_path} ...")
    try:
        result = client.post_as3(declaration)
    except BigIPError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    print("AS3 response:")
    print(json.dumps(result, indent=2))

    print("\nRe-validating ...")
    findings = validate(client, args.consumer)
    print_report(args.host, findings)
    if args.json:
        print(json.dumps(findings, indent=2))
    return 0 if findings["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
