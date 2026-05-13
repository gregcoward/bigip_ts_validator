"""Build AS3 declarations and required-object lists based on selected BIG-IP services."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

_EXAMPLES_DIR = Path(__file__).resolve().parent / "examples"
_FULL_AS3_PATH = _EXAMPLES_DIR / "as3-telemetry-resources.json"

# Shared logging pipeline (HSL → TS listener pattern)
_BASE_OBJECT_NAMES = ("telemetry", "telemetry_hsl", "telemetry_formatted", "telemetry_publisher")

def _load_full_template() -> dict[str, Any]:
    data = json.loads(_FULL_AS3_PATH.read_text())
    return data


def required_as3_object_names(services: dict[str, bool] | None) -> list[tuple[str, str]]:
    """Return (name, AS3 class) pairs that must exist for the given service selection.

    When ``services`` is None, require every object from the full reference template
    (CLI backward compatibility).
    """
    if services is None:
        tmpl = _load_full_template()
        shared = tmpl["Common"]["Shared"]
        out: list[tuple[str, str]] = []
        for name, body in shared.items():
            if isinstance(body, dict) and "class" in body and name.startswith("telemetry"):
                if name in ("telemetry_local_rule", "telemetry_local"):
                    continue
                out.append((name, body["class"]))
        return sorted(out, key=lambda x: x[0])

    active = any(
        services.get(k, False) for k in ("ltm", "asm", "afm", "http_analytics", "tcp_analytics")
    )
    if not active:
        return []

    tmpl = _load_full_template()
    shared = tmpl["Common"]["Shared"]
    result: list[tuple[str, str]] = []
    for name in _BASE_OBJECT_NAMES:
        obj = shared.get(name)
        if isinstance(obj, dict) and "class" in obj:
            result.append((name, obj["class"]))

    if services.get("ltm"):
        o = shared.get("telemetry_traffic_log_profile")
        if isinstance(o, dict):
            result.append(("telemetry_traffic_log_profile", o["class"]))
    if services.get("http_analytics"):
        o = shared.get("telemetry_http_analytics_profile")
        if isinstance(o, dict):
            result.append(("telemetry_http_analytics_profile", o["class"]))
    if services.get("tcp_analytics"):
        o = shared.get("telemetry_tcp_analytics_profile")
        if isinstance(o, dict):
            result.append(("telemetry_tcp_analytics_profile", o["class"]))
    if services.get("asm") or services.get("afm"):
        o = shared.get("telemetry_asm_security_log_profile")
        if isinstance(o, dict):
            result.append(("telemetry_asm_security_log_profile", o["class"]))

    return result


def build_as3_declaration(services: dict[str, bool]) -> dict[str, Any]:
    """Return a full ADC declaration for /mgmt/shared/appsvcs/declare."""
    tmpl = copy.deepcopy(_load_full_template())
    shared: dict[str, Any] = tmpl["Common"]["Shared"]

    if not any(
        services.get(k, False) for k in ("ltm", "asm", "afm", "http_analytics", "tcp_analytics")
    ):
        raise ValueError("At least one telemetry service must be selected")

    tmpl["remark"] = remark_for_services(services)

    if not services.get("ltm"):
        shared.pop("telemetry_traffic_log_profile", None)
    if not services.get("http_analytics"):
        shared.pop("telemetry_http_analytics_profile", None)
    if not services.get("tcp_analytics"):
        shared.pop("telemetry_tcp_analytics_profile", None)

    sec = shared.get("telemetry_asm_security_log_profile")
    if isinstance(sec, dict) and (services.get("asm") or services.get("afm")):
        if not services.get("asm"):
            sec.pop("application", None)
        if not services.get("afm"):
            sec.pop("network", None)
    elif not services.get("asm") and not services.get("afm"):
        shared.pop("telemetry_asm_security_log_profile", None)

    return tmpl


def remark_for_services(services: dict[str, bool]) -> str:
    parts = [k for k, v in services.items() if v]
    return "AS3 telemetry resources for: " + ", ".join(parts) if parts else "AS3 telemetry resources"
