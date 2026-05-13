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
from pathlib import Path
from typing import Any

import requests
import urllib3

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


class BigIPError(RuntimeError):
    pass


class BigIPClient:
    def __init__(self, host: str, username: str, password: str, verify_tls: bool = False, timeout: int = 30):
        self.base_url = f"https://{host}"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.session.headers.update({"Content-Type": "application/json"})
        self._authenticate(username, password)

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


def validate(client: BigIPClient, expected_consumer: str) -> dict:
    checks: list[str] = []
    missing: list[str] = []
    warnings: list[str] = []

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
            for name, cls in REQUIRED_AS3_OBJECTS:
                missing.append(f"AS3 resource missing in /Common/Shared: {name} ({cls})")
    else:
        for name, cls in REQUIRED_AS3_OBJECTS:
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
            matching = [c for c in consumers if c.get("type") == expected_consumer]
            if matching:
                checks.append(f"TS consumer of type {expected_consumer} is configured ({len(matching)} found)")
                consumer_status = f"{expected_consumer} configured"
            else:
                missing.append(
                    f"TS declaration has no Telemetry_Consumer of type '{expected_consumer}' "
                    f"(found: {', '.join(types) or 'none'})"
                )
                consumer_status = f"have [{', '.join(types)}], need {expected_consumer}"

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
                             "AWS_CloudWatch, Datadog, Generic_HTTP, Sumo_Logic, ElasticSearch")
    parser.add_argument("--as3-file", default=str(Path(__file__).parent / "examples" / "as3-telemetry-resources.json"),
                        help="AS3 declaration to apply when remediating")
    parser.add_argument("--no-remediate", action="store_true",
                        help="Validate only; do not offer to apply the AS3 declaration")
    parser.add_argument("--yes", action="store_true",
                        help="Skip the confirmation prompt before applying the AS3 declaration")
    parser.add_argument("--verify-tls", action="store_true", help="Verify the BIG-IP TLS certificate")
    parser.add_argument("--json", action="store_true", help="Emit the final findings as JSON on stdout")
    args = parser.parse_args()

    password = resolve_password(args)

    try:
        client = BigIPClient(args.host, args.username, password, verify_tls=args.verify_tls)
    except BigIPError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

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
