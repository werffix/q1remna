import asyncio
import base64
import binascii
import hmac
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from hmac import compare_digest
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from shop_bot.data_manager.database import (
    default_remna_tag,
    get_all_hosts,
    get_key_by_email,
    get_keys_for_host,
    get_or_create_user_subscription_token,
    get_setting,
    get_sub_host,
    get_user_device_limit,
    get_user_id_by_subscription_token,
    get_host,
)

logger = logging.getLogger(__name__)


class _RemnaApi:
    pass


class _RemnaInbound:
    id = 0


def _parse_user_id_from_key_email(email: str | None) -> int | None:
    value = (email or "").strip()
    if not value:
        return None
    m = re.match(r"^u(\d+)\.", value)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None
    m = re.match(r"^user(\d+)[\.-]", value)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None
    return None


def _resolve_effective_device_limit(email: str | None, explicit_limit: int | None = None) -> int:
    if explicit_limit is not None:
        try:
            return max(1, int(explicit_limit))
        except Exception:
            pass
    try:
        default_limit = int((get_setting("default_device_limit") or "3").strip() or "3")
    except Exception:
        default_limit = 3
    if default_limit < 1:
        default_limit = 3
    user_id = _parse_user_id_from_key_email(email)
    if user_id is None:
        return default_limit
    try:
        return get_user_device_limit(user_id, default_limit=default_limit)
    except Exception:
        return default_limit


def _is_whitelist_host(host_name: str | None) -> bool:
    name = (host_name or "").lower()
    return ("белые списки" in name) or ("white list" in name) or ("whitelist" in name)


def _resolve_host_client_traffic_limit_gb(host_data: dict | None) -> float | int | str | None:
    if not host_data:
        return None
    explicit = host_data.get("client_monthly_traffic_gb")
    try:
        if explicit not in (None, "", "null") and float(explicit) > 0:
            return explicit
    except Exception:
        pass
    if _is_whitelist_host(host_data.get("host_name")):
        return 200
    return explicit


def resolve_host_client_traffic_limit_gb(host_data: dict | None) -> float | int | str | None:
    return _resolve_host_client_traffic_limit_gb(host_data)


def _traffic_limit_bytes(traffic_cap_gb: float | int | str | None) -> int | None:
    try:
        if traffic_cap_gb in (None, "", "null"):
            return None
        gb = float(traffic_cap_gb)
        if gb <= 0:
            return None
        return int(gb * 1024 * 1024 * 1024)
    except Exception:
        return None


def _host_base_url(host_url: str) -> str:
    raw = (host_url or "").strip().rstrip("/")
    if not raw:
        return raw
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if not parsed.netloc:
        return raw
    path = (parsed.path or "").rstrip("/")
    if path.endswith("/api"):
        path = path[:-4]
    return f"{parsed.scheme}://{parsed.netloc}{path}".rstrip("/")


def normalize_xui_host_url(host_url: str) -> str:
    return _host_base_url(host_url)


def build_xui_host_candidates(host_url: str) -> list[str]:
    normalized = _host_base_url(host_url)
    return [normalized] if normalized else []


def login_to_host(host_url: str, username: str, password: str, inbound_id: int) -> tuple[_RemnaApi | None, _RemnaInbound | None]:
    if not _host_base_url(host_url):
        return None, None
    return _RemnaApi(), _RemnaInbound()


def _subscription_secret() -> bytes:
    raw = (
        os.getenv("SHOPBOT_SUB_SECRET")
        or os.getenv("SHOPBOT_SECRET_KEY")
        or get_setting("telegram_bot_token")
        or "shopbot-sub-secret"
    )
    return str(raw).encode("utf-8")


def build_unified_subscription_token(user_id: int) -> str:
    payload = str(int(user_id))
    signature = hmac.new(_subscription_secret(), payload.encode("utf-8"), "sha256").hexdigest()[:20]
    return f"{payload}.{signature}"


def parse_unified_subscription_token(token: str) -> int | None:
    token = (token or "").strip()
    if "." not in token:
        return None
    payload, signature = token.split(".", 1)
    if not payload.isdigit() or not signature:
        return None
    expected = hmac.new(_subscription_secret(), payload.encode("utf-8"), "sha256").hexdigest()[:20]
    if not compare_digest(signature, expected):
        return None
    return int(payload)


def resolve_user_id_by_persistent_subscription_token(token: str) -> int | None:
    try:
        return get_user_id_by_subscription_token(token)
    except Exception:
        return None


def build_unified_subscription_url(user_id: int, base_domain: str | None = None) -> str | None:
    token = get_or_create_user_subscription_token(user_id)
    domain = (base_domain or "").strip()
    if not domain:
        try:
            sub_host = get_sub_host()
        except Exception:
            sub_host = None
        if sub_host:
            domain = (
                str(sub_host.get("subscription_url") or "").strip()
                or str(sub_host.get("host_url") or "").strip()
            )
    if not domain:
        domain = (get_setting("domain") or "").strip()
    if not domain:
        return None

    candidate = domain if "://" in domain else f"https://{domain}"
    if "{token}" in candidate:
        return candidate.replace("{token}", token)

    parsed = urlparse(candidate)
    if not parsed.netloc:
        return None
    base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    path = (parsed.path or "").rstrip("/")
    if path:
        return f"{base}{path}/{token}"
    return f"{base}/sub/{token}"


def _iso_from_ms(value_ms: int) -> str:
    dt = datetime.fromtimestamp(int(value_ms) / 1000, tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        text = str(value).strip()
        if not text:
            return None
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        return None


def _expiry_ms_from_user(user_data: dict | None) -> int:
    if not user_data:
        return 0
    dt = _parse_dt(user_data.get("expireAt") or user_data.get("expire_at"))
    if not dt:
        return 0
    return int(dt.timestamp() * 1000)


def _parse_uuid(value: Any) -> str | None:
    try:
        text = str(value or "").strip()
        if not text:
            return None
        return str(uuid.UUID(text))
    except Exception:
        return None


def _parse_uuid_list(raw_value: str | None) -> list[str] | None:
    raw = (raw_value or "").strip()
    if not raw:
        return None
    values: list[str] = []
    for item in re.split(r"[\s,;]+", raw):
        parsed = _parse_uuid(item)
        if parsed and parsed not in values:
            values.append(parsed)
    return values or None


def _derive_username(email: str, host_name: str | None) -> str:
    host_part = re.sub(r"[^a-z0-9]+", "", (host_name or "").lower())[:8] or "host"
    digest = re.sub(r"[^a-f0-9]", "", uuid.uuid5(uuid.NAMESPACE_DNS, f"{host_name}:{email}").hex)[:20]
    return f"sb_{host_part}_{digest}"[:36]


def _host_tag(host_data: dict) -> str:
    return ((host_data.get("remna_tag") or "").strip().upper() or default_remna_tag(host_data.get("host_name")))


def _host_description(host_name: str, email: str) -> str:
    return f"shopbot_host={host_name}; email={email}"


def _traffic_strategy(host_data: dict, explicit_total_bytes: int | None = None) -> str:
    total_bytes = explicit_total_bytes if explicit_total_bytes is not None else _traffic_limit_bytes(
        _resolve_host_client_traffic_limit_gb(host_data)
    )
    return "MONTH" if total_bytes and total_bytes > 0 else "NO_RESET"


def _subscription_url_for_user(host_data: dict, user_data: dict) -> str | None:
    remote_url = str(user_data.get("subscriptionUrl") or user_data.get("subscription_url") or "").strip()
    host_base = str(host_data.get("subscription_url") or "").strip()
    short_uuid = str(user_data.get("shortUuid") or user_data.get("short_uuid") or "").strip()
    user_uuid = str(user_data.get("uuid") or "").strip()

    if host_base:
        if "{token}" in host_base and short_uuid:
            return host_base.replace("{token}", short_uuid)
        if "{uuid}" in host_base and user_uuid:
            return host_base.replace("{uuid}", user_uuid)
        return host_base
    return remote_url or None


def _extract_subscription_entries(raw_payload: str) -> list[str]:
    text = (raw_payload or "").strip()
    if not text:
        return []
    decoded_text = text
    try:
        normalized = "".join(text.split())
        padding = "=" * (-len(normalized) % 4)
        candidate = base64.b64decode(normalized + padding, validate=True)
        maybe_text = candidate.decode("utf-8", errors="ignore")
        if "://" in maybe_text:
            decoded_text = maybe_text
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass

    lines: list[str] = []
    for line in decoded_text.splitlines():
        item = line.strip()
        if item and "://" in item and item not in lines:
            lines.append(item)
    return lines


async def _request_json(
    host_data: dict,
    method: str,
    path: str,
    *,
    json_body: dict | None = None,
    allow_404: bool = False,
    timeout: float = 20.0,
) -> dict | list | None:
    base_url = _host_base_url(host_data.get("host_url") or "")
    token = str(host_data.get("remna_api_token") or "").strip()
    if not base_url:
        raise ValueError(f"У хоста '{host_data.get('host_name')}' не указан URL панели.")
    if not token:
        raise ValueError(f"У хоста '{host_data.get('host_name')}' не указан API token Remnawave.")

    url = f"{base_url}/api{path if path.startswith('/') else '/' + path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        response = await client.request(method.upper(), url, json=json_body)

    if allow_404 and response.status_code == 404:
        return None
    response.raise_for_status()
    if not response.content:
        return None
    return response.json()


async def _fetch_subscription_entries(url: str) -> list[str]:
    candidate = (url or "").strip()
    if not candidate:
        return []
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        response = await client.get(candidate, headers={"Accept": "text/plain, application/json;q=0.9, */*;q=0.8"})
    response.raise_for_status()
    return _extract_subscription_entries(response.text)


async def _get_user_by_uuid(host_data: dict, user_uuid: str | None) -> dict | None:
    parsed = _parse_uuid(user_uuid)
    if not parsed:
        return None
    response = await _request_json(host_data, "GET", f"/users/{quote(parsed, safe='')}", allow_404=True)
    return response if isinstance(response, dict) else None


async def _get_users_by_email(host_data: dict, email: str) -> list[dict]:
    response = await _request_json(host_data, "GET", f"/users/by-email/{quote(email, safe='')}", allow_404=True)
    if isinstance(response, list):
        return [item for item in response if isinstance(item, dict)]
    if isinstance(response, dict) and isinstance(response.get("root"), list):
        return [item for item in response["root"] if isinstance(item, dict)]
    return []


async def _get_users_by_telegram_id(host_data: dict, telegram_id: int) -> list[dict]:
    response = await _request_json(host_data, "GET", f"/users/by-telegram-id/{telegram_id}", allow_404=True)
    if isinstance(response, list):
        return [item for item in response if isinstance(item, dict)]
    if isinstance(response, dict) and isinstance(response.get("root"), list):
        return [item for item in response["root"] if isinstance(item, dict)]
    return []


def _user_matches_host(user_data: dict, host_data: dict, email: str | None = None) -> bool:
    host_tag = _host_tag(host_data)
    user_tag = str(user_data.get("tag") or "").strip().upper()
    if user_tag and user_tag == host_tag:
        return True
    if email and str(user_data.get("email") or "").strip().lower() == str(email).strip().lower():
        return True
    description = str(user_data.get("description") or "").strip().lower()
    host_name = str(host_data.get("host_name") or "").strip().lower()
    return bool(host_name and host_name in description)


async def _resolve_remote_user(host_data: dict, email: str, explicit_uuid: str | None = None) -> dict | None:
    for candidate_uuid in (
        explicit_uuid,
        (get_key_by_email(email) or {}).get("xui_client_uuid"),
    ):
        user_data = await _get_user_by_uuid(host_data, candidate_uuid)
        if user_data:
            return user_data

    users = await _get_users_by_email(host_data, email)
    for user_data in users:
        if _user_matches_host(user_data, host_data, email=email):
            return user_data
    if users:
        return users[0]

    user_id = _parse_user_id_from_key_email(email)
    if user_id is not None:
        tg_users = await _get_users_by_telegram_id(host_data, user_id)
        for user_data in tg_users:
            if _user_matches_host(user_data, host_data, email=email):
                return user_data
    return None


def _target_expiry_ms(existing_user: dict | None, *, days_to_add: int | None, explicit_expiry_ms: int | None) -> int:
    now_ms = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
    safe_explicit = 0
    try:
        safe_explicit = int(explicit_expiry_ms or 0)
    except Exception:
        safe_explicit = 0
    if safe_explicit > 0:
        return safe_explicit

    if days_to_add is None:
        current_ms = _expiry_ms_from_user(existing_user)
        return current_ms if current_ms > 0 else now_ms

    add_days = max(0, int(days_to_add))
    base_ms = now_ms
    if existing_user:
        existing_ms = _expiry_ms_from_user(existing_user)
        if existing_ms > now_ms:
            base_ms = existing_ms
    return int((datetime.fromtimestamp(base_ms / 1000, tz=timezone.utc) + timedelta(days=add_days)).timestamp() * 1000)


def _build_upsert_payload(
    host_data: dict,
    email: str,
    expiry_ms: int,
    *,
    user_uuid: str | None = None,
    device_limit: int | None = None,
    status: str = "ACTIVE",
) -> dict:
    traffic_bytes = _traffic_limit_bytes(_resolve_host_client_traffic_limit_gb(host_data))
    user_id = _parse_user_id_from_key_email(email)
    payload: dict[str, Any] = {
        "username": _derive_username(email, host_data.get("host_name")),
        "expireAt": _iso_from_ms(expiry_ms),
        "status": status,
        "trafficLimitStrategy": _traffic_strategy(host_data, traffic_bytes),
        "trafficLimitBytes": traffic_bytes,
        "telegramId": user_id,
        "email": email,
        "hwidDeviceLimit": _resolve_effective_device_limit(email, device_limit),
        "description": _host_description(str(host_data.get("host_name") or ""), email),
        "tag": _host_tag(host_data),
        "activeInternalSquads": _parse_uuid_list(host_data.get("remna_internal_squads")),
        "externalSquadUuid": _parse_uuid(host_data.get("remna_external_squad_uuid")),
    }
    if user_uuid:
        payload["uuid"] = user_uuid
    return {key: value for key, value in payload.items() if value not in (None, "", [])}


async def _create_remote_user(
    host_data: dict,
    email: str,
    expiry_ms: int,
    *,
    preferred_uuid: str | None = None,
    device_limit: int | None = None,
    status: str = "ACTIVE",
) -> dict:
    payload = _build_upsert_payload(
        host_data,
        email,
        expiry_ms,
        user_uuid=_parse_uuid(preferred_uuid),
        device_limit=device_limit,
        status=status,
    )
    return await _request_json(host_data, "POST", "/users", json_body=payload)


async def _update_remote_user(
    host_data: dict,
    remote_user: dict,
    email: str,
    expiry_ms: int,
    *,
    device_limit: int | None = None,
    status: str = "ACTIVE",
) -> dict:
    payload = _build_upsert_payload(
        host_data,
        email,
        expiry_ms,
        user_uuid=str(remote_user.get("uuid") or ""),
        device_limit=device_limit,
        status=status,
    )
    return await _request_json(host_data, "PATCH", "/users", json_body=payload)


async def create_or_update_key_on_host(
    host_name: str,
    email: str,
    days_to_add: int | None = None,
    expiry_timestamp_ms: int | None = None,
    preferred_uuid: str | None = None,
    device_limit: int | None = None,
    rotate_sub_token: bool = False,
) -> dict | None:
    host_data = get_host(host_name)
    if not host_data:
        logger.error(f"Хост '{host_name}' не найден в базе.")
        return None

    try:
        existing_user = await _resolve_remote_user(host_data, email, explicit_uuid=preferred_uuid)
        target_expiry_ms = _target_expiry_ms(existing_user, days_to_add=days_to_add, explicit_expiry_ms=expiry_timestamp_ms)
        status = "DISABLED" if int(host_data.get("is_expired_host") or 0) == 1 else "ACTIVE"

        if existing_user:
            user_data = await _update_remote_user(
                host_data,
                existing_user,
                email,
                target_expiry_ms,
                device_limit=device_limit,
                status=status,
            )
        else:
            try:
                user_data = await _create_remote_user(
                    host_data,
                    email,
                    target_expiry_ms,
                    preferred_uuid=preferred_uuid,
                    device_limit=device_limit,
                    status=status,
                )
            except httpx.HTTPStatusError as create_error:
                if create_error.response is None or create_error.response.status_code != 409:
                    raise
                existing_user = await _resolve_remote_user(host_data, email, explicit_uuid=preferred_uuid)
                if not existing_user:
                    raise
                user_data = await _update_remote_user(
                    host_data,
                    existing_user,
                    email,
                    target_expiry_ms,
                    device_limit=device_limit,
                    status=status,
                )

        if rotate_sub_token:
            try:
                user_uuid = str(user_data.get("uuid") or "")
                if user_uuid:
                    user_data = await _request_json(
                        host_data,
                        "POST",
                        f"/users/{quote(user_uuid, safe='')}/actions/revoke",
                        json_body={},
                    ) or user_data
            except Exception:
                logger.warning("Не удалось перевыпустить subscription token в Remnawave", exc_info=True)

        subscription_url = _subscription_url_for_user(host_data, user_data)
        return {
            "client_uuid": str(user_data.get("uuid") or ""),
            "email": email,
            "expiry_timestamp_ms": _expiry_ms_from_user(user_data) or target_expiry_ms,
            "connection_string": subscription_url,
            "host_name": host_name,
        }
    except httpx.HTTPStatusError as e:
        logger.error(f"Remnawave HTTP error для хоста '{host_name}', email '{email}': {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Ошибка create_or_update_key_on_host для '{host_name}'/'{email}': {e}", exc_info=True)
        return None


async def get_key_details_from_host(key_data: dict) -> dict | None:
    host_name = key_data.get("host_name")
    if not host_name:
        return None
    host_data = get_host(host_name)
    if not host_data:
        return None
    user_data = await _resolve_remote_user(
        host_data,
        str(key_data.get("key_email") or ""),
        explicit_uuid=str(key_data.get("xui_client_uuid") or ""),
    )
    if not user_data:
        return None
    subscription_url = _subscription_url_for_user(host_data, user_data)
    return {
        "connection_string": subscription_url,
        "native_connection_string": subscription_url,
    }


async def get_key_usage_stats_from_host(key_data: dict) -> dict:
    host_name = key_data.get("host_name")
    if not host_name:
        return {}
    host_data = get_host(host_name)
    if not host_data:
        return {}
    try:
        user_data = await _resolve_remote_user(
            host_data,
            str(key_data.get("key_email") or key_data.get("email") or ""),
            explicit_uuid=str(key_data.get("xui_client_uuid") or ""),
        )
        if not user_data:
            return {}
        used_bytes = int(user_data.get("usedTrafficBytes") or user_data.get("used_traffic_bytes") or 0)
        total_bytes = int(user_data.get("trafficLimitBytes") or user_data.get("traffic_limit_bytes") or 0)
        return {
            "upload_bytes": 0,
            "download_bytes": max(used_bytes, 0),
            "total_bytes": max(total_bytes, 0),
            "expiry_timestamp_ms": _expiry_ms_from_user(user_data),
        }
    except Exception:
        logger.warning("Не удалось получить usage из Remnawave", exc_info=True)
        return {}


async def get_client(server_id: str) -> dict | None:
    sid = str(server_id or "").strip()
    if not sid:
        return None
    host = get_host(sid)
    if host:
        return host
    try:
        for item in get_all_hosts() or []:
            if str(item.get("host_name") or "").strip() == sid:
                return item
            if str(item.get("host_url") or "").strip() == sid:
                return item
    except Exception:
        return None
    return None


async def get_client_stats(client_host: dict, panel_email: str) -> dict | None:
    try:
        user_data = await _resolve_remote_user(client_host, panel_email)
        if not user_data:
            return None
        used_bytes = int(user_data.get("usedTrafficBytes") or user_data.get("used_traffic_bytes") or 0)
        total_bytes = int(user_data.get("trafficLimitBytes") or user_data.get("traffic_limit_bytes") or 0)
        return {"up": 0, "down": max(used_bytes, 0), "total": max(total_bytes, 0)}
    except Exception:
        logger.warning("Не удалось получить live client stats из Remnawave", exc_info=True)
        return None


async def build_vless_uri_for_key(key_data: dict) -> str | None:
    host_name = key_data.get("host_name")
    if not host_name:
        return None
    host_data = get_host(host_name)
    if not host_data:
        return None
    try:
        user_data = await _resolve_remote_user(
            host_data,
            str(key_data.get("key_email") or ""),
            explicit_uuid=str(key_data.get("xui_client_uuid") or ""),
        )
        if not user_data:
            return None
        subscription_url = _subscription_url_for_user(host_data, user_data)
        if not subscription_url:
            return None
        entries = await _fetch_subscription_entries(subscription_url)
        if not entries:
            return None
        return "\n".join(entries)
    except Exception:
        logger.warning("Не удалось собрать конфиги из Remnawave subscription", exc_info=True)
        return None


async def delete_client_on_host(host_name: str, client_email: str) -> bool:
    host_data = get_host(host_name)
    if not host_data:
        logger.error(f"Хост '{host_name}' не найден для удаления клиента.")
        return False
    try:
        user_data = await _resolve_remote_user(host_data, client_email)
        if not user_data:
            return True
        user_uuid = str(user_data.get("uuid") or "")
        if not user_uuid:
            return True
        response = await _request_json(host_data, "DELETE", f"/users/{quote(user_uuid, safe='')}", allow_404=True)
        if response is None:
            return True
        return bool(response.get("isDeleted", True))
    except Exception:
        logger.error(f"Не удалось удалить клиента '{client_email}' на '{host_name}'", exc_info=True)
        return False


async def set_client_enabled_on_host(host_name: str, client_email: str, enabled: bool) -> bool:
    host_data = get_host(host_name)
    if not host_data:
        return False
    try:
        user_data = await _resolve_remote_user(host_data, client_email)
        if not user_data:
            return False
        user_uuid = str(user_data.get("uuid") or "")
        action = "enable" if enabled else "disable"
        await _request_json(host_data, "POST", f"/users/{quote(user_uuid, safe='')}/actions/{action}", json_body={})
        return True
    except Exception:
        logger.error(f"Не удалось переключить статус клиента '{client_email}'", exc_info=True)
        return False


async def set_client_monthly_reset_on_host(host_name: str, client_email: str, reset_days: int = 30) -> bool:
    host_data = get_host(host_name)
    if not host_data:
        return False
    try:
        user_data = await _resolve_remote_user(host_data, client_email)
        if not user_data:
            return False
        payload = {
            "uuid": str(user_data.get("uuid") or ""),
            "trafficLimitStrategy": "MONTH" if int(reset_days or 0) >= 30 else "NO_RESET",
        }
        await _request_json(host_data, "PATCH", "/users", json_body=payload)
        return True
    except Exception:
        logger.error(f"Не удалось обновить strategy reset для '{client_email}'", exc_info=True)
        return False


async def set_client_device_limit_on_host(host_name: str, client_email: str, device_limit: int) -> bool:
    host_data = get_host(host_name)
    if not host_data:
        return False
    try:
        user_data = await _resolve_remote_user(host_data, client_email)
        if not user_data:
            return False
        payload = {
            "uuid": str(user_data.get("uuid") or ""),
            "hwidDeviceLimit": max(1, int(device_limit)),
        }
        await _request_json(host_data, "PATCH", "/users", json_body=payload)
        return True
    except Exception:
        logger.error(f"Не удалось обновить лимит устройств для '{client_email}'", exc_info=True)
        return False


async def increase_client_traffic_limit_on_host(host_name: str, client_email: str, add_gb: float) -> bool:
    host_data = get_host(host_name)
    if not host_data:
        return False
    try:
        user_data = await _resolve_remote_user(host_data, client_email)
        if not user_data:
            return False
        add_bytes = _traffic_limit_bytes(add_gb)
        if not add_bytes:
            return False
        current_total = int(user_data.get("trafficLimitBytes") or user_data.get("traffic_limit_bytes") or 0)
        payload = {
            "uuid": str(user_data.get("uuid") or ""),
            "trafficLimitBytes": max(current_total, 0) + add_bytes,
            "trafficLimitStrategy": str(user_data.get("trafficLimitStrategy") or _traffic_strategy(host_data)),
        }
        await _request_json(host_data, "PATCH", "/users", json_body=payload)
        return True
    except Exception:
        logger.error(f"Не удалось увеличить лимит трафика для '{client_email}'", exc_info=True)
        return False


async def set_client_traffic_limit_on_host(host_name: str, client_email: str, traffic_gb: float | int | str | None) -> bool:
    host_data = get_host(host_name)
    if not host_data:
        return False
    try:
        user_data = await _resolve_remote_user(host_data, client_email)
        if not user_data:
            return False
        total_bytes = _traffic_limit_bytes(traffic_gb)
        if total_bytes is None:
            return False
        payload = {
            "uuid": str(user_data.get("uuid") or ""),
            "trafficLimitBytes": total_bytes,
            "trafficLimitStrategy": _traffic_strategy(host_data, total_bytes),
        }
        await _request_json(host_data, "PATCH", "/users", json_body=payload)
        return True
    except Exception:
        logger.error(f"Не удалось установить лимит трафика для '{client_email}'", exc_info=True)
        return False


async def reset_all_clients_traffic_on_host(host_name: str) -> tuple[int, int]:
    host_data = get_host(host_name)
    if not host_data:
        return 0, 0
    keys = get_keys_for_host(host_name) or []
    total_clients = len(keys)
    reset_clients = 0
    seen: set[str] = set()
    for key in keys:
        try:
            user_data = await _resolve_remote_user(
                host_data,
                str(key.get("key_email") or ""),
                explicit_uuid=str(key.get("xui_client_uuid") or ""),
            )
            if not user_data:
                continue
            user_uuid = str(user_data.get("uuid") or "")
            if not user_uuid or user_uuid in seen:
                continue
            seen.add(user_uuid)
            await _request_json(host_data, "POST", f"/users/{quote(user_uuid, safe='')}/actions/reset-traffic", json_body={})
            reset_clients += 1
        except Exception:
            logger.warning(f"Не удалось сбросить трафик на Remnawave для key_id={key.get('key_id')}", exc_info=True)
    return total_clients, reset_clients


def resolve_user_id_by_legacy_sub_token(token: str, all_keys: list[dict]) -> int | None:
    token = (token or "").strip()
    if not token:
        return None

    async def _resolver() -> int | None:
        for key in all_keys or []:
            host_name = str(key.get("host_name") or "").strip()
            email = str(key.get("key_email") or "").strip()
            if not host_name or not email:
                continue
            host_data = get_host(host_name)
            if not host_data:
                continue
            try:
                user_data = await _resolve_remote_user(
                    host_data,
                    email,
                    explicit_uuid=str(key.get("xui_client_uuid") or ""),
                )
                if not user_data:
                    continue
                short_uuid = str(user_data.get("shortUuid") or user_data.get("short_uuid") or "").strip()
                subscription_url = str(user_data.get("subscriptionUrl") or user_data.get("subscription_url") or "").strip()
                if token == short_uuid or subscription_url.endswith(f"/{token}") or f"/{token}?" in subscription_url:
                    return int(key.get("user_id"))
            except Exception:
                continue
        return None

    try:
        return asyncio.run(_resolver())
    except Exception:
        return None
