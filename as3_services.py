"""Build AS3 declarations and required-object lists based on selected BIG-IP services."""

from __future__ import annotations

from typing import Any

# AS3 ADC schema: ``remark`` must be at most 64 characters (422 if longer).
AS3_REMARK_MAX_LEN = 64

_SCHEMA_VERSION = "3.10.0"


def _pool() -> dict[str, Any]:
    return {
        "class": "Pool",
        "members": [
            {
                "enable": True,
                "serverAddresses": ["255.255.255.254"],
                "servicePort": 6514,
            }
        ],
        "monitors": [{"bigip": "/Common/tcp"}],
    }


def _log_destination_hsl() -> dict[str, Any]:
    return {
        "class": "Log_Destination",
        "type": "remote-high-speed-log",
        "protocol": "tcp",
        "pool": {"use": "telemetry"},
    }


def _log_destination_formatted() -> dict[str, Any]:
    return {
        "class": "Log_Destination",
        "type": "splunk",
        "forwardTo": {"use": "telemetry_hsl"},
    }


def _log_publisher() -> dict[str, Any]:
    return {
        "class": "Log_Publisher",
        "destinations": [{"use": "telemetry_formatted"}],
    }


def _traffic_log_profile() -> dict[str, Any]:
    return {
        "class": "Traffic_Log_Profile",
        "requestSettings": {
            "requestEnabled": True,
            "requestProtocol": "mds-tcp",
            "requestPool": {"use": "telemetry"},
            "requestTemplate": (
                "event_source=\"request_logging\",hostname=\"$BIGIP_HOSTNAME\",client_ip=\"$CLIENT_IP\","
                "server_ip=\"$SERVER_IP\",http_method=\"$HTTP_METHOD\",http_uri=\"$HTTP_URI\","
                "virtual_name=\"$VIRTUAL_NAME\",event_timestamp=\"$DATE_HTTP\""
            ),
        },
        "responseSettings": {
            "responseEnabled": True,
            "responseProtocol": "mds-tcp",
            "responsePool": {"use": "telemetry"},
            "responseTemplate": (
                "event_source=\"response_logging\",hostname=\"$BIGIP_HOSTNAME\",client_ip=\"$CLIENT_IP\","
                "server_ip=\"$SERVER_IP\",http_method=\"$HTTP_METHOD\",http_uri=\"$HTTP_URI\","
                "virtual_name=\"$VIRTUAL_NAME\",event_timestamp=\"$DATE_HTTP\",http_statcode=\"$HTTP_STATCODE\","
                "http_status=\"$HTTP_STATUS\",response_ms=\"$RESPONSE_MSECS\""
            ),
        },
    }


def _http_analytics_profile() -> dict[str, Any]:
    return {
        "class": "Analytics_Profile",
        "collectGeo": True,
        "collectMaxTpsAndThroughput": True,
        "collectOsAndBrowser": True,
        "collectIp": True,
        "collectMethod": True,
        "collectPageLoadTime": True,
        "collectResponseCode": True,
        "collectSubnet": True,
        "collectUrl": True,
        "collectUserAgent": True,
        "collectUserSession": True,
        "publishIruleStatistics": True,
    }


def _tcp_analytics_profile() -> dict[str, Any]:
    return {
        "class": "Analytics_TCP_Profile",
        "collectCity": True,
        "collectContinent": True,
        "collectCountry": True,
        "collectNexthop": True,
        "collectPostCode": True,
        "collectRegion": True,
        "collectRemoteHostIp": True,
        "collectRemoteHostSubnet": True,
        "collectedByServerSide": True,
    }


def _local_listener_objects() -> dict[str, Any]:
    """Service_TCP + iRule so traffic to 255.255.255.254:6514 reaches TS on 127.0.0.1:6514."""
    return {
        "telemetry_local_rule": {
            "remark": "TS local listener forward",
            "class": "iRule",
            "iRule": "when CLIENT_ACCEPTED {\n  node 127.0.0.1 6514\n}",
        },
        "telemetry_local": {
            "remark": "TS local listener virtual",
            "class": "Service_TCP",
            "virtualAddresses": ["255.255.255.254"],
            "virtualPort": 6514,
            "iRules": ["telemetry_local_rule"],
        },
    }


def _dns_logging_profile() -> dict[str, Any]:
    """DNS (GTM) query/response logging to the Shared log publisher (TS via HSL chain)."""
    return {
        "class": "DNS_Logging_Profile",
        "remark": "DNS logging to TS",
        "logPublisher": {"use": "telemetry_publisher"},
        "logQueriesEnabled": True,
        "logResponsesEnabled": True,
    }


def _security_log_profile(*, asm: bool, afm: bool) -> dict[str, Any] | None:
    if not asm and not afm:
        return None
    body: dict[str, Any] = {"class": "Security_Log_Profile"}
    if asm:
        body["application"] = {
            "localStorage": False,
            "remoteStorage": "splunk",
            "servers": [{"address": "255.255.255.254", "port": "6514"}],
            "storageFilter": {"requestType": "all"},
        }
    if afm:
        body["network"] = {
            "publisher": {"use": "telemetry_publisher"},
            "logRuleMatchAccepts": False,
            "logRuleMatchRejects": True,
            "logRuleMatchDrops": True,
            "logIpErrors": True,
            "logTcpErrors": True,
            "logTcpEvents": True,
        }
    return body


def _needs_hsl_chain(services: dict[str, bool]) -> bool:
    """Pool / HSL / formatted / publisher chain for LTM, AFM network logging, and DNS logging."""
    return bool(services.get("ltm") or services.get("afm") or services.get("dns"))


def _build_shared_application(services: dict[str, bool], *, include_local_listener: bool) -> dict[str, Any]:
    if not any(
        services.get(k, False) for k in ("ltm", "asm", "afm", "http_analytics", "tcp_analytics", "dns")
    ):
        raise ValueError("At least one telemetry service must be selected")

    shared: dict[str, Any] = {"class": "Application", "template": "shared"}

    if _needs_hsl_chain(services):
        shared["telemetry"] = _pool()
        shared["telemetry_hsl"] = _log_destination_hsl()
        shared["telemetry_formatted"] = _log_destination_formatted()
        shared["telemetry_publisher"] = _log_publisher()

    if services.get("ltm"):
        shared["telemetry_traffic_log_profile"] = _traffic_log_profile()

    if services.get("http_analytics"):
        shared["telemetry_http_analytics_profile"] = _http_analytics_profile()

    if services.get("tcp_analytics"):
        shared["telemetry_tcp_analytics_profile"] = _tcp_analytics_profile()

    sec = _security_log_profile(asm=bool(services.get("asm")), afm=bool(services.get("afm")))
    if sec is not None:
        shared["telemetry_asm_security_log_profile"] = sec

    if services.get("dns"):
        shared["telemetry_dns_logging"] = _dns_logging_profile()

    if include_local_listener:
        shared.update(_local_listener_objects())

    return shared


def required_as3_object_names(
    services: dict[str, bool] | None,
    *,
    include_local_listener: bool = True,
) -> list[tuple[str, str]]:
    """Return (name, AS3 class) pairs that must exist for the given service selection.

    When ``services`` is None, use the same rules as **all** logging options enabled
    (CLI default scope against the full bundled example declaration).
    """
    if services is None:
        services = {
            "ltm": True,
            "asm": True,
            "afm": True,
            "http_analytics": True,
            "tcp_analytics": True,
            "dns": False,
        }

    if not any(
        services.get(k, False) for k in ("ltm", "asm", "afm", "http_analytics", "tcp_analytics", "dns")
    ):
        return []

    pairs: list[tuple[str, str]] = []
    if _needs_hsl_chain(services):
        pairs.extend(
            [
                ("telemetry", "Pool"),
                ("telemetry_hsl", "Log_Destination"),
                ("telemetry_formatted", "Log_Destination"),
                ("telemetry_publisher", "Log_Publisher"),
            ]
        )
    if services.get("ltm"):
        pairs.append(("telemetry_traffic_log_profile", "Traffic_Log_Profile"))
    if services.get("http_analytics"):
        pairs.append(("telemetry_http_analytics_profile", "Analytics_Profile"))
    if services.get("tcp_analytics"):
        pairs.append(("telemetry_tcp_analytics_profile", "Analytics_TCP_Profile"))
    if services.get("asm") or services.get("afm"):
        pairs.append(("telemetry_asm_security_log_profile", "Security_Log_Profile"))
    if services.get("dns"):
        pairs.append(("telemetry_dns_logging", "DNS_Logging_Profile"))

    if include_local_listener and any(
        services.get(k, False) for k in ("ltm", "asm", "afm", "http_analytics", "tcp_analytics", "dns")
    ):
        pairs.extend(
            [
                ("telemetry_local_rule", "iRule"),
                ("telemetry_local", "Service_TCP"),
            ]
        )

    return pairs


def remark_for_services(services: dict[str, bool]) -> str:
    """Human-readable but schema-safe remark for the ADC declaration."""
    tag_map = {
        "ltm": "ltm",
        "asm": "asm",
        "afm": "afm",
        "http_analytics": "http",
        "tcp_analytics": "tcp",
        "dns": "dns",
    }
    tags = [tag_map[k] for k, v in services.items() if v and k in tag_map]
    body = ",".join(tags) if tags else "shared"
    s = f"F5-TS-AS3:{body}"
    if len(s) <= AS3_REMARK_MAX_LEN:
        return s
    return s[:AS3_REMARK_MAX_LEN]


def build_as3_declaration(services: dict[str, bool], *, include_local_listener: bool = True) -> dict[str, Any]:
    """Return a full ADC declaration for /mgmt/shared/appsvcs/declare.

    Objects under ``/Common/Shared`` are created only for the selected
    telemetry sources (LTM request/response logging, ASM / AFM security log
    profiles, HTTP / TCP analytics profiles, optional DNS logging). The HSL → pool chain is included
    only when LTM or AFM logging is selected (AFM ``network`` logging uses the
    log publisher).

    When ``include_local_listener`` is true (default), adds ``telemetry_local``
    (``Service_TCP``) and ``telemetry_local_rule`` so events destined for
    ``255.255.255.254:6514`` reach Telemetry Streaming's on-box listener on
    ``127.0.0.1:6514`` — pair with ``Telemetry_Listener`` in the TS declaration.
    """
    shared = _build_shared_application(services, include_local_listener=include_local_listener)
    return {
        "class": "ADC",
        "schemaVersion": _SCHEMA_VERSION,
        "remark": remark_for_services(services),
        "Common": {"class": "Tenant", "Shared": shared},
    }
