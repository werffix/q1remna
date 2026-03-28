import os
import logging
import asyncio
import json
import copy
import hashlib
import binascii
import html as html_escape
import base64
import time
import uuid
import re
from hmac import compare_digest
from datetime import datetime, timedelta
from functools import wraps
from math import ceil
from flask import Flask, request, render_template, redirect, url_for, flash, session, current_app, jsonify, send_file, Response
from flask_wtf.csrf import CSRFProtect, generate_csrf
import secrets
import urllib.parse
import urllib.request
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logging.getLogger('werkzeug').setLevel(logging.WARNING)

from shop_bot.modules import xui_api
from shop_bot.bot import handlers
from shop_bot.bot import keyboards
from aiogram.utils.keyboard import InlineKeyboardBuilder
from shop_bot.support_bot_controller import SupportBotController
from shop_bot.data_manager import speedtest_runner
from shop_bot.data_manager import backup_manager
from shop_bot.data_manager import resource_monitor
from shop_bot.data_manager import database
from shop_bot.data_manager.database import (
    get_all_settings, update_setting, get_all_hosts, get_plans_for_host, get_all_plans,
    create_host, delete_host, create_plan, delete_plan, update_plan, update_plan_visibility, get_user_count,
    get_total_keys_count, get_total_subscriptions_count, get_total_spent_sum, get_daily_stats_for_charts,
    get_recent_transactions, get_paginated_transactions, get_all_users, get_user_keys,
    ban_user, unban_user, delete_user_keys, get_setting, find_and_complete_ton_transaction, find_and_complete_pending_transaction,
    get_tickets_paginated, get_open_tickets_count, get_ticket, get_ticket_messages,
    add_support_message, set_ticket_status, delete_ticket,
    get_closed_tickets_count, get_all_tickets_count, update_host_subscription_url,
    update_host_url, update_host_name, update_host_ssh_settings, update_host_client_monthly_traffic_limit, update_host_remna_settings, get_latest_speedtest, get_speedtests,
    get_all_keys, get_keys_for_user, get_key_by_id, delete_key_by_id, update_key_comment, update_key_info,
    add_new_key, get_balance, adjust_user_balance, get_referrals_for_user,
    get_user, get_key_by_email, get_host, get_or_create_user_subscription_uuid, reset_user_state,
    move_host_order, update_host_is_expired, update_host_is_sub, get_user_device_limit, adjust_user_device_limit,
    get_all_traffic_packages, create_traffic_package, update_traffic_package, delete_traffic_package,
)


_bot_controller = None
_support_bot_controller = SupportBotController()

ALL_SETTINGS_KEYS = [
    "panel_login", "panel_password", "about_text", "terms_url", "privacy_url",
    "support_user", "support_text",
    # Editable content from admin UI
    "main_menu_text", "howto_android_text", "howto_ios_text", "howto_windows_text", "howto_linux_text",
    # Button texts
    "btn_try", "btn_profile", "btn_my_keys", "btn_buy_key", "btn_top_up", "btn_referral", "btn_support", "btn_about", "btn_howto", "btn_admin", "btn_back_to_menu",
    "btn_channel", "btn_terms", "btn_privacy", "btn_howto_android", "btn_howto_ios", "btn_howto_windows", "btn_howto_linux",
    # Extra button labels
    "btn_back", "btn_back_to_plans", "btn_back_to_key", "btn_back_to_keys",
    "btn_extend_key", "btn_show_qr", "btn_instruction", "btn_switch_server",
    "btn_skip_email", "btn_go_to_payment", "btn_check_payment", "btn_pay_with_balance",
    "btn_support_open", "btn_support_new_ticket", "btn_support_my_tickets", "btn_support_external",
    "channel_url", "telegram_bot_token",
    "telegram_bot_username", "admin_telegram_id", "yookassa_shop_id",
    "yookassa_secret_key", "sbp_enabled", "receipt_email", "cryptobot_token",
    "heleket_merchant_id", "heleket_api_key",
    "platega_enabled", "platega_merchant_id", "platega_secret_key", "platega_api_base", "platega_payment_method",
    "platega_payment_method_sbp", "platega_payment_method_card", "platega_payment_method_crypto",
    "domain", "referral_percentage",
    "referral_discount", "ton_wallet_address", "tonapi_key", "force_subscription", "trial_enabled", "trial_duration_days", "enable_referrals", "minimum_withdrawal",
    # Реферальные начисления: альтернативный фиксированный бонус
    "enable_fixed_referral_bonus", "fixed_referral_bonus_amount",
    # Тип начисления реферальной системы (без стартового бонуса)
    "referral_reward_type", "referral_on_start_referrer_amount", "referral_on_start_referrer_days", "referral_on_start_new_user_days",
    "support_forum_chat_id",
    "support_bot_token", "support_bot_username",
    # UI
    "panel_brand_title",
    # Backups
    "backup_interval_days",
    # Monitoring
    "monitoring_enabled", "monitoring_interval_sec",
    "monitoring_cpu_threshold", "monitoring_mem_threshold", "monitoring_disk_threshold",
    "monitoring_alert_cooldown_sec",
    # Telegram Stars
    "stars_enabled", "stars_per_rub", "stars_title", "stars_description",
    # YooMoney (separate)
    "yoomoney_enabled", "yoomoney_wallet", "yoomoney_secret", "yoomoney_api_token",
    "yoomoney_client_id", "yoomoney_client_secret", "yoomoney_redirect_uri",
]

def create_webhook_app(bot_controller_instance):
    global _bot_controller
    _bot_controller = bot_controller_instance

    app_file_path = os.path.abspath(__file__)
    app_dir = os.path.dirname(app_file_path)
    template_dir = os.path.join(app_dir, 'templates')
    template_file = os.path.join(template_dir, 'login.html')

    logger.debug("--- ДИАГНОСТИЧЕСКАЯ ИНФОРМАЦИЯ ---")
    logger.debug(f"Текущая рабочая директория: {os.getcwd()}")
    logger.debug(f"Путь к исполняемому app.py: {app_file_path}")
    logger.debug(f"Директория app.py: {app_dir}")
    logger.debug(f"Ожидаемая директория шаблонов: {template_dir}")
    logger.debug(f"Ожидаемый путь к login.html: {template_file}")
    logger.debug(f"Директория шаблонов существует? -> {os.path.isdir(template_dir)}")
    logger.debug(f"Файл login.html существует? -> {os.path.isfile(template_file)}")
    logger.debug("--- КОНЕЦ ДИАГНОСТИКИ ---")
    
    flask_app = Flask(
        __name__,
        template_folder='templates',
        static_folder='static'
    )
    
    # SECRET_KEY из окружения или сгенерированный на лету (без хардкода)
    flask_app.config['SECRET_KEY'] = os.getenv('SHOPBOT_SECRET_KEY') or secrets.token_hex(32)
    from datetime import timedelta
    flask_app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

    # CSRF защита для всех POST форм в панели; вебхуки будут исключены
    csrf = CSRFProtect()
    csrf.init_app(flask_app)

    @flask_app.context_processor
    def inject_current_year():
        # Добавляем csrf_token в шаблоны для meta и скрытых полей
        return {
            'current_year': datetime.utcnow().year,
            'csrf_token': generate_csrf
        }

    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'logged_in' not in session:
                return redirect(url_for('login_page'))
            return f(*args, **kwargs)
        return decorated_function

    def _subscription_email_for_user_host(user_id: int, host_name: str) -> str:
        host_part = re.sub(r"[^a-z0-9]+", "", (host_name or "").lower())[:8] or "host"
        digest = hashlib.sha1(f"{user_id}:{host_name}".encode("utf-8")).hexdigest()[:10]
        return f"u{user_id}.{host_part}.{digest}@bot.local"

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

        lines = []
        for line in decoded_text.splitlines():
            item = line.strip()
            if not item:
                continue
            if "://" not in item:
                continue
            lines.append(item)
        return lines

    def _header_utf8_via_latin1(value: str) -> str:
        """Send UTF-8 bytes through latin-1-only header writer (Werkzeug dev server)."""
        try:
            return (value or "").encode("utf-8", errors="ignore").decode("latin-1", errors="ignore")
        except Exception:
            return "q1 vpn"

    _traffic_stats_cache: dict[tuple[str, str], tuple[float, dict | None]] = {}
    _users_panel_cache: dict[tuple[int, int, str, str], tuple[float, tuple[list[dict], int]]] = {}
    _TRAFFIC_STATS_CACHE_TTL_SEC = 60.0
    _USERS_PANEL_CACHE_TTL_SEC = 20.0

    def _format_traffic(value_bytes: int | float | None) -> str:
        try:
            value = float(value_bytes or 0)
        except Exception:
            value = 0.0
        if value < 0:
            value = 0.0
        units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
        idx = 0
        while value >= 1024 and idx < len(units) - 1:
            value /= 1024.0
            idx += 1
        if idx == 0:
            return f"{int(value)} {units[idx]}"
        return f"{value:.2f} {units[idx]}"

    async def _get_live_traffic_stats_for_key(key_data: dict) -> dict | None:
        try:
            server_id = str(key_data.get("server_id") or key_data.get("host_name") or "").strip()
            panel_email = str(key_data.get("panel_email") or key_data.get("key_email") or "").strip()
            if not server_id or not panel_email:
                return None
            cache_key = (server_id, panel_email)
            now = time.time()
            cached = _traffic_stats_cache.get(cache_key)
            if cached and (now - cached[0]) < _TRAFFIC_STATS_CACHE_TTL_SEC:
                return copy.deepcopy(cached[1])
            client_host = await xui_api.get_client(server_id)
            if not client_host:
                return None
            stats = await xui_api.get_client_stats(client_host, panel_email)
            if not stats:
                return None
            up = max(int(stats.get("up") or 0), 0)
            down = max(int(stats.get("down") or 0), 0)
            total = max(int(stats.get("total") or 0), 0)
            payload = {"up": up, "down": down, "total": total}
            _traffic_stats_cache[cache_key] = (now, copy.deepcopy(payload))
            return payload
        except Exception:
            return None

    async def _collect_live_traffic_stats_for_keys(user_keys: list[dict]) -> list[dict | Exception | None]:
        return await asyncio.gather(
            *[_get_live_traffic_stats_for_key(key_data) for key_data in (user_keys or [])],
            return_exceptions=True,
        )

    def _enrich_users_for_panel(users: list[dict]) -> list[dict]:
        users = list(users or [])
        for user in users:
            uid = user['telegram_id']
            user_keys = get_user_keys(uid) or []
            user['user_keys'] = user_keys
            try:
                user['balance'] = get_balance(uid)
                user['referrals'] = get_referrals_for_user(uid)
                user['device_limit'] = get_user_device_limit(uid, default_limit=3)
            except Exception:
                user['balance'] = 0.0
                user['referrals'] = []
                user['device_limit'] = 3

            latest_expiry = ""
            for key in user_keys:
                raw_expiry = str(key.get("expiry_date") or "").strip()
                if raw_expiry and (not latest_expiry or raw_expiry > latest_expiry):
                    latest_expiry = raw_expiry
            user['subscription_expiry'] = latest_expiry
            user['referrals_count'] = len(user.get('referrals') or [])

            try:
                traffic_results = asyncio.run(_collect_live_traffic_stats_for_keys(user_keys)) if user_keys else []
            except Exception:
                traffic_results = []

            user_total_traffic = 0
            for key_data, result in zip(user_keys, traffic_results):
                if isinstance(result, Exception) or not isinstance(result, dict):
                    key_data['traffic_used_bytes'] = None
                    key_data['traffic_used_text'] = "Недоступно"
                    continue
                used = max(int(result.get("up") or 0), 0) + max(int(result.get("down") or 0), 0)
                key_data['traffic_used_bytes'] = used
                key_data['traffic_used_text'] = _format_traffic(used)
                user_total_traffic += used
            user['traffic_used_total_bytes'] = user_total_traffic
        return users

    def _get_sorted_users_for_panel(page: int, per_page: int, q: str | None = None, sort_by: str | None = None) -> tuple[list[dict], int]:
        try:
            page = max(1, int(page or 1))
            per_page = max(1, min(100, int(per_page or 20)))
        except Exception:
            page, per_page = 1, 20

        query = (q or "").strip().lower()
        sort_mode = (sort_by or "new").strip().lower()
        cache_key = (page, per_page, query, sort_mode)
        now = time.time()
        cached = _users_panel_cache.get(cache_key)
        if cached and (now - cached[0]) < _USERS_PANEL_CACHE_TTL_SEC:
            users, total = cached[1]
            return copy.deepcopy(users), int(total or 0)

        users = get_all_users() or []

        if query:
            filtered: list[dict] = []
            for user in users:
                telegram_id = str(user.get("telegram_id") or "")
                username = str(user.get("username") or "")
                if query in telegram_id.lower() or query in username.lower():
                    filtered.append(user)
            users = filtered

        users = _enrich_users_for_panel(users)

        if sort_mode == "traffic":
            users.sort(
                key=lambda user: (
                    -int(user.get("traffic_used_total_bytes") or 0),
                    str(user.get("registration_date") or ""),
                )
            )
        elif sort_mode == "referrals":
            users.sort(
                key=lambda user: (
                    -int(user.get("referrals_count") or 0),
                    str(user.get("registration_date") or ""),
                )
            )
        else:
            users.sort(key=lambda user: str(user.get("registration_date") or ""), reverse=True)
            sort_mode = "new"

        total = len(users)
        start = (page - 1) * per_page
        end = start + per_page
        page_items = users[start:end]
        _users_panel_cache[cache_key] = (now, (copy.deepcopy(page_items), int(total or 0)))
        return page_items, total

    def _extract_happ_crypto_url(raw_text: str) -> str | None:
        text = (raw_text or "").strip()
        if not text:
            return None
        if text.startswith("happ://crypt"):
            return text
        try:
            payload = json.loads(text)
        except Exception:
            payload = None

        def _scan(value):
            if isinstance(value, str):
                v = value.strip()
                return v if v.startswith("happ://crypt") else None
            if isinstance(value, dict):
                for x in value.values():
                    found = _scan(x)
                    if found:
                        return found
            if isinstance(value, list):
                for x in value:
                    found = _scan(x)
                    if found:
                        return found
            return None

        found = _scan(payload) if payload is not None else None
        if found:
            return found
        m = re.search(r"(happ://crypt[^\s\"'<>]+)", text)
        return m.group(1).strip() if m else None

    def _request_happ_crypto_url(sub_url: str, timeout_sec: float = 10.0) -> tuple[str | None, str | None]:
        endpoint = "https://crypto.happ.su/api-v2.php"
        body = json.dumps({"url": sub_url}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
                "User-Agent": "curl/8.5.0",
                "Origin": "https://www.happ.su",
                "Referer": "https://www.happ.su/",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            return None, f"request_failed: {e}"
        link = _extract_happ_crypto_url(raw)
        if not link:
            return None, "invalid_or_empty_response"
        return link, None

    def _ensure_clients_on_all_hosts(user_id: int, keys: list[dict]) -> list[dict]:
        """Create missing clients for user on every configured host before sub build."""
        try:
            hosts = [h for h in (get_all_hosts() or []) if int(h.get("is_expired_host") or 0) != 1]
            if not hosts:
                return keys
            user_uuid = get_or_create_user_subscription_uuid(user_id)

            now_ms = int(datetime.now().timestamp() * 1000)
            expiry_candidates_ms: list[int] = []
            for key in keys:
                raw = key.get("expiry_date")
                if not raw:
                    continue
                try:
                    exp = datetime.fromisoformat(raw)
                    expiry_candidates_ms.append(int(exp.timestamp() * 1000))
                except Exception:
                    continue

            if not expiry_candidates_ms:
                # No known active period, do not auto-create/extend.
                return keys
            anchor_expiry_ms = max(expiry_candidates_ms)
            if anchor_expiry_ms < now_ms:
                # Expired subscription: do not auto-extend.
                return keys

            existing_hosts = {
                (k.get("host_name") or "").strip()
                for k in keys
                if (k.get("host_name") or "").strip()
            }
            created_any = False

            for host in hosts:
                host_name = (host.get("host_name") or "").strip()
                if not host_name or host_name in existing_hosts:
                    continue

                # Stable per-host email to keep one client per user/host.
                email = _subscription_email_for_user_host(int(user_id), host_name)

                try:
                    created = asyncio.run(
                        xui_api.create_or_update_key_on_host(
                            host_name=host_name,
                            email=email,
                            days_to_add=None,
                            expiry_timestamp_ms=anchor_expiry_ms,
                            preferred_uuid=user_uuid
                        )
                    )
                except Exception as e:
                    logger.warning(f"Не удалось создать клиента для user={user_id} на хосте '{host_name}': {e}")
                    continue

                if not created:
                    logger.warning(f"Пустой результат create_or_update_key_on_host для user={user_id}, host='{host_name}'")
                    continue

                new_key_id = add_new_key(
                    user_id=user_id,
                    host_name=host_name,
                    xui_client_uuid=created.get("client_uuid"),
                    key_email=created.get("email") or email,
                    expiry_timestamp_ms=created.get("expiry_timestamp_ms") or anchor_expiry_ms
                )
                if new_key_id:
                    created_any = True
                    logger.info(f"Создан клиент на host='{host_name}' для user={user_id}, key_id={new_key_id}")

            if created_any:
                return get_keys_for_user(user_id) or keys
            # If nothing was created, still return fresh snapshot from DB.
            return get_keys_for_user(user_id) or keys
        except Exception as e:
            logger.warning(f"Синхронизация клиентов по всем хостам не выполнена для user={user_id}: {e}")
            return keys

    def _serve_unified_subscription(token: str):
        # Allow tokens copied as "<token>" from docs/messages.
        token = (token or "").strip().strip("<>")

        user_id = xui_api.parse_unified_subscription_token(token)
        if user_id is None:
            user_id = xui_api.resolve_user_id_by_persistent_subscription_token(token)
        if user_id is None:
            # Backward compatibility: old short x-ui sub token.
            all_keys = get_all_keys() or []
            user_id = xui_api.resolve_user_id_by_legacy_sub_token(token, all_keys)
            if user_id is None:
                return Response("Invalid subscription token", status=403, mimetype="text/plain")

        keys = get_keys_for_user(user_id) or []
        # Create/ensure clients in inbound on all panels first, then collect VLESS.
        keys = _ensure_clients_on_all_hosts(user_id, keys)
        user_uuid = get_or_create_user_subscription_uuid(user_id)
        if not keys:
            return Response("No active keys found", status=404, mimetype="text/plain")
        now_dt = datetime.now()
        has_active_key = False
        has_unknown_expiry = False
        for k in keys:
            raw_expiry = k.get("expiry_date")
            if not raw_expiry:
                has_unknown_expiry = True
                continue
            try:
                if datetime.fromisoformat(str(raw_expiry)) > now_dt:
                    has_active_key = True
            except Exception:
                has_unknown_expiry = True

        # Keep subscription entry order aligned with host order from panel.
        hosts_ordered = get_all_hosts() or []
        host_rank = {str(h.get("host_name")): i for i, h in enumerate(hosts_ordered)}
        keys = sorted(
            keys,
            key=lambda k: (
                host_rank.get(str(k.get("host_name")), 10**9),
                str(k.get("host_name") or ""),
                int(k.get("key_id") or 0),
            ),
        )

        # Guard against recursive self-calls when host subscription URL points to unified endpoint.
        req_parsed = urllib.parse.urlparse(request.host_url)
        req_scheme = req_parsed.scheme
        req_netloc = req_parsed.netloc

        merged_lines: list[str] = []
        seen = set()
        upload_total = 0
        download_total = 0
        quota_total = 0
        expiry_candidates: list[int] = []
        for key in keys:
            try:
                expiry_raw = key.get("expiry_date")
                expiry_ms_exact = None
                if expiry_raw:
                    try:
                        expiry_dt = datetime.fromisoformat(expiry_raw)
                        if expiry_dt <= datetime.now():
                            continue
                        expiry_candidates.append(int(expiry_dt.timestamp()))
                        expiry_ms_exact = int(expiry_dt.timestamp() * 1000)
                    except Exception:
                        pass

                # Self-heal: ensure client exists on host inbound before collecting links.
                # If client was removed on 3x-ui panel, recreate/update it with the same expiry.
                try:
                    host_name = (key.get("host_name") or "").strip()
                    key_email = (key.get("key_email") or "").strip()
                    if host_name and key_email:
                        repaired = asyncio.run(
                            xui_api.create_or_update_key_on_host(
                                host_name=host_name,
                                email=key_email,
                                days_to_add=None,
                                expiry_timestamp_ms=expiry_ms_exact,
                                preferred_uuid=user_uuid
                            )
                        )
                        if repaired and key.get("key_id"):
                            update_key_info(
                                int(key["key_id"]),
                                repaired.get("client_uuid"),
                                repaired.get("expiry_timestamp_ms")
                            )
                            # keep in-memory data fresh for downstream calls in this loop
                            key["xui_client_uuid"] = repaired.get("client_uuid") or key.get("xui_client_uuid")
                except Exception as e:
                    logger.warning(f"Self-heal клиента не выполнен для key_id={key.get('key_id')}: {e}")

                usage_data = asyncio.run(xui_api.get_key_usage_stats_from_host(key)) or {}
                try:
                    up = max(int(usage_data.get("upload_bytes", 0) or 0), 0)
                    down = max(int(usage_data.get("download_bytes", 0) or 0), 0)
                    total = max(int(usage_data.get("total_bytes", 0) or 0), 0)

                    upload_total += up
                    download_total += down
                    quota_total += total
                    expiry_ms = int(usage_data.get("expiry_timestamp_ms", 0) or 0)
                    if expiry_ms > 0:
                        expiry_candidates.append(expiry_ms // 1000)
                except Exception:
                    pass

                # Fast path: build direct VLESS URI from inbound/client.
                # This avoids slow nested subscription HTTP hops.
                direct_vless = asyncio.run(xui_api.build_vless_uri_for_key(key))
                if direct_vless and direct_vless not in seen:
                    seen.add(direct_vless)
                    merged_lines.append(direct_vless)
            except Exception as e:
                logger.warning(f"Не удалось добавить подписку key_id={key.get('key_id')}: {e}")

        # Hard fallback: only for active subscriptions where links couldn't be collected.
        if not merged_lines:
            try:
                if not expiry_candidates:
                    raise RuntimeError("No active subscription entries to fallback-create.")
                hosts = [h for h in (get_all_hosts() or []) if int(h.get("is_expired_host") or 0) != 1]
                now_ms = int(datetime.now().timestamp() * 1000)
                anchor_expiry_ms = max(expiry_candidates) * 1000

                for host in hosts:
                    host_name = (host.get("host_name") or "").strip()
                    if not host_name:
                        continue
                    email = _subscription_email_for_user_host(int(user_id), host_name)

                    created = asyncio.run(
                        xui_api.create_or_update_key_on_host(
                            host_name=host_name,
                            email=email,
                            days_to_add=None,
                            expiry_timestamp_ms=anchor_expiry_ms,
                            preferred_uuid=user_uuid
                        )
                    )
                    if not created:
                        logger.warning(f"Hard fallback: не удалось создать клиента на host='{host_name}' для user={user_id}")
                        continue

                    if not get_key_by_email(created.get("email") or email):
                        add_new_key(
                            user_id=user_id,
                            host_name=host_name,
                            xui_client_uuid=created.get("client_uuid"),
                            key_email=created.get("email") or email,
                            expiry_timestamp_ms=created.get("expiry_timestamp_ms") or anchor_expiry_ms
                        )

                    direct = asyncio.run(
                        xui_api.build_vless_uri_for_key(
                            {
                                "host_name": host_name,
                                "xui_client_uuid": created.get("client_uuid"),
                                "key_email": created.get("email") or email,
                            }
                        )
                    )
                    if direct and direct not in seen:
                        seen.add(direct)
                        merged_lines.append(direct)
            except Exception as e:
                logger.warning(f"Hard fallback сбора unified subscription завершился с ошибкой для user={user_id}: {e}")

        if not merged_lines:
            if has_active_key or has_unknown_expiry:
                return Response("No subscription entries available", status=503, mimetype="text/plain")
            # Expired subscriptions must not recreate clients on any host.
            # Return placeholder profile only.
            expired_name = urllib.parse.quote("🚫 Ваша подписка истекла! - @q1vpn_bot")
            expired_uri = (
                f"vless://{uuid.uuid4()}@127.0.0.1:443"
                f"?type=tcp&security=none#{expired_name}"
            )
            expired_payload = f"{expired_uri}\n"
            encoded = base64.b64encode(expired_payload.encode("utf-8")).decode("utf-8")
            response = Response(encoded, status=200, mimetype="text/plain")
            response.headers["profile-title"] = _header_utf8_via_latin1("⚡️ q1 vpn")
            response.headers["support-url"] = "https://t.me/q1vpn_bot"
            response.headers["profile-update-interval"] = "3"
            response.headers["update-interval"] = "3"
            response.headers["profile-description"] = _header_utf8_via_latin1(
                "Продлите подписку в боте - @q1vpn_bot"
            )
            response.headers["subscription-userinfo"] = f"expire={int(datetime.now().timestamp())}"
            return response

        combined = "\n".join(merged_lines) + "\n"
        encoded = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
        response = Response(encoded, mimetype="text/plain")

        # Metadata headers for subscription clients.
        profile_title = "⚡️ q1 vpn"
        support_url = "https://t.me/q1vpn_bot"
        response.headers["profile-title"] = _header_utf8_via_latin1(profile_title)
        response.headers["support-url"] = support_url
        # Hint clients (Happ/v2ray-like) to auto-refresh profile every 3 hours.
        response.headers["profile-update-interval"] = "3"
        response.headers["update-interval"] = "3"
        if expiry_candidates:
            response.headers["subscription-userinfo"] = f"expire={int(max(expiry_candidates))}"
        return response

    @flask_app.route('/sub/<token>', methods=['GET'])
    def unified_subscription_route_legacy(token: str):
        return _serve_unified_subscription(token)

    @flask_app.route('/redirect', methods=['GET'])
    def happ_redirect_route():
        def _current_sub_url(token_value: str) -> str:
            parsed = urllib.parse.urlparse(request.host_url)
            scheme = parsed.scheme or "https"
            netloc = parsed.netloc or request.host or ""
            return f"{scheme}://{netloc}/sub/{token_value}"

        direct_to = (request.args.get("to") or "").strip()
        if direct_to.startswith("happ://"):
            return redirect(direct_to, code=302)

        token = (request.args.get("token") or "").strip().strip("<>")
        if not token:
            return Response("Missing token", status=400, mimetype="text/plain")
        sub_url = _current_sub_url(token)
        crypto_link, error = _request_happ_crypto_url(sub_url)
        if not crypto_link:
            logger.warning(f"redirect: failed to build happ crypto link: {error}")
            return redirect(url_for("activate_subscription_route", token=token), code=302)
        return redirect(crypto_link, code=302)

    @flask_app.route('/activate/<token>', methods=['GET'])
    def activate_subscription_route(token: str):
        def _current_sub_url(token_value: str) -> str:
            parsed = urllib.parse.urlparse(request.host_url)
            scheme = parsed.scheme or "https"
            netloc = parsed.netloc or request.host or ""
            return f"{scheme}://{netloc}/sub/{token_value}"

        clean_token = (token or "").strip().strip("<>")
        sub_url = _current_sub_url(clean_token)
        crypto_link, error = _request_happ_crypto_url(sub_url)
        if not crypto_link:
            logger.warning(f"activate: failed to build happ crypto link: {error}")
        escaped_crypto_link = html_escape.escape(crypto_link or "", quote=True)
        escaped_error = html_escape.escape(error or "unknown_error", quote=True)
        open_hint_html = (
            "<div>Если Happ не открылся автоматически, нажмите кнопку ниже:</div>"
            if crypto_link
            else "<div>Не удалось получить зашифрованную ссылку Happ.</div>"
        )
        open_button_html = (
            f'<a class="btn btn-primary" href="{escaped_crypto_link}">Открыть в Happ</a>'
            if crypto_link
            else ""
        )
        error_html = (
            f'<div style="margin-top:10px; color:#ffb4b4;">Код ошибки: <b>{escaped_error}</b></div>'
            if not crypto_link
            else ""
        )
        html_body = f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Активация подписки</title>
  <style>
    body {{ margin:0; background:#000000; color:#eef2f7; font-family: Inter, -apple-system, Segoe UI, Roboto, sans-serif; }}
    .wrap {{ max-width:560px; margin:10vh auto; padding:20px; }}
    .card {{ background:#0a0a0a; border:1px solid #1b1b1b; border-radius:14px; padding:18px; }}
    .btn {{ display:inline-block; margin-top:12px; padding:10px 14px; border-radius:10px; text-decoration:none; font-weight:600; }}
    .btn-primary {{ background:#ffffff; color:#0f1115; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h2 style="margin:0 0 10px;">🔗 Активация подписки</h2>
      {open_hint_html}
      {open_button_html}
      {error_html}
    </div>
  </div>
  <script>
    const happCryptoLink = {json.dumps(crypto_link or "")};
    if (happCryptoLink) {{
      setTimeout(() => {{
        try {{ window.location.href = happCryptoLink; }} catch (_e) {{}}
      }}, 120);
    }}
  </script>
</body>
</html>"""
        return Response(html_body, mimetype="text/html")

    @flask_app.route('/url', methods=['GET'])
    def external_deeplink_redirect_route():
        target = (request.args.get("url") or "").strip()
        if not target:
            return Response("Missing url", status=400, mimetype="text/plain")
        allowed_schemes = ("v2raytun://", "happ://", "tg://", "https://", "http://")
        if not any(target.startswith(prefix) for prefix in allowed_schemes):
            return Response("Unsupported url scheme", status=400, mimetype="text/plain")
        escaped_target = html_escape.escape(target, quote=True)
        html_body = f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Открытие приложения</title>
  <style>
    body {{ margin:0; background:#000000; color:#eef2f7; font-family: Inter, -apple-system, Segoe UI, Roboto, sans-serif; }}
    .wrap {{ max-width:560px; margin:10vh auto; padding:20px; }}
    .card {{ background:#0a0a0a; border:1px solid #1b1b1b; border-radius:14px; padding:20px; }}
    .btn {{ display:inline-block; margin-top:12px; padding:10px 14px; border-radius:10px; text-decoration:none; font-weight:600; }}
    .btn-primary {{ background:#ffffff; color:#0f1115; }}
    .muted {{ color:#9da3af; margin-top:10px; font-size:14px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h2 style="margin:0 0 10px;">🔗 Открытие приложения</h2>
      <div>Если приложение не открылось автоматически, нажмите кнопку ниже.</div>
      <a class="btn btn-primary" href="{escaped_target}">Открыть приложение</a>
      <div class="muted">Используется HTTPS-обёртка для deeplink.</div>
    </div>
  </div>
  <script>
    const targetUrl = {json.dumps(target)};
    setTimeout(() => {{
      try {{ window.location.href = targetUrl; }} catch (_e) {{}}
    }}, 120);
  </script>
</body>
</html>"""
        return Response(html_body, mimetype="text/html")

    @flask_app.route('/<token>', methods=['GET'])
    def unified_subscription_route_root(token: str):
        # Keep web panel routes intact: only handle token-like paths.
        panel_paths = {
            "login", "logout", "dashboard", "monitor", "support", "users", "settings", "url",
            "add-host", "add-plan", "brand-title", "button-constructor"
        }
        if token in panel_paths:
            return Response("Not Found", status=404, mimetype="text/plain")
        return _serve_unified_subscription(token)

    @flask_app.route('/logo/<path:filename>', methods=['GET'])
    def logo_file_route(filename: str):
        safe_name = os.path.basename(filename or "")
        if not safe_name:
            return Response("Not Found", status=404, mimetype="text/plain")
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        full_path = os.path.join(project_root, "logo", safe_name)
        if not os.path.isfile(full_path):
            return Response("Not Found", status=404, mimetype="text/plain")
        return send_file(full_path)

    @flask_app.route('/login', methods=['GET', 'POST'])
    def login_page():
        settings = get_all_settings()
        if request.method == 'POST':
            if request.form.get('username') == settings.get("panel_login") and \
               request.form.get('password') == settings.get("panel_password"):
                session['logged_in'] = True
                # remember-me: делаем сессию постоянной при установленном чекбоксе
                session.permanent = bool(request.form.get('remember_me'))
                return redirect(url_for('dashboard_page'))
            else:
                flash('Неверный логин или пароль', 'danger')
        return render_template('login.html')

    @flask_app.route('/logout', methods=['POST'])
    @login_required
    def logout_page():
        session.pop('logged_in', None)
        flash('Вы успешно вышли.', 'success')
        return redirect(url_for('login_page'))

    def get_common_template_data():
        bot_status = _bot_controller.get_status()
        support_bot_status = _support_bot_controller.get_status()
        settings = get_all_settings()
        required_for_start = ['telegram_bot_token', 'telegram_bot_username', 'admin_telegram_id']
        required_support_for_start = ['support_bot_token', 'support_bot_username', 'admin_telegram_id']
        all_settings_ok = all(settings.get(key) for key in required_for_start)
        support_settings_ok = all(settings.get(key) for key in required_support_for_start)
        try:
            open_tickets_count = get_open_tickets_count()
            closed_tickets_count = get_closed_tickets_count()
            all_tickets_count = get_all_tickets_count()
        except Exception:
            open_tickets_count = 0
            closed_tickets_count = 0
            all_tickets_count = 0
        return {
            "bot_status": bot_status,
            "all_settings_ok": all_settings_ok,
            "support_bot_status": support_bot_status,
            "support_settings_ok": support_settings_ok,
            "open_tickets_count": open_tickets_count,
            "closed_tickets_count": closed_tickets_count,
            "all_tickets_count": all_tickets_count,
            "brand_title": settings.get('panel_brand_title') or 'T‑Shift VPN',
        }

    @flask_app.route('/brand-title', methods=['POST'])
    @login_required
    def update_brand_title_route():
        title = (request.form.get('title') or '').strip()
        if not title:
            return jsonify({"ok": False, "error": "empty"}), 400
        try:
            update_setting('panel_brand_title', title)
            return jsonify({"ok": True, "title": title})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500
    @flask_app.route('/monitor/host/<host_name>/metrics.json')
    @login_required
    def monitor_host_metrics_json(host_name: str):
        try:
            limit = int(request.args.get('limit', '60'))
        except Exception:
            limit = 60
        try:
            items = database.get_host_metrics_recent(host_name, limit=limit)
            return jsonify({"ok": True, "items": items})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @flask_app.route('/')
    @login_required
    def index():
        return redirect(url_for('dashboard_page'))

    @flask_app.route('/dashboard')
    @login_required
    def dashboard_page():
        hosts = []
        try:
            hosts = get_all_hosts()
            for h in hosts:
                try:
                    h['latest_speedtest'] = get_latest_speedtest(h['host_name'])
                except Exception:
                    h['latest_speedtest'] = None
        except Exception:
            hosts = []
        stats = {
            "user_count": get_user_count(),
            "total_keys": get_total_subscriptions_count(),
            "total_spent": get_total_spent_sum(),
            "host_count": len(hosts)
        }
        
        page = request.args.get('page', 1, type=int)
        per_page = 8
        
        transactions, total_transactions = get_paginated_transactions(page=page, per_page=per_page)
        total_pages = ceil(total_transactions / per_page)
        
        chart_data = get_daily_stats_for_charts(days=30)
        common_data = get_common_template_data()
        
        return render_template(
            'dashboard.html',
            stats=stats,
            chart_data=chart_data,
            transactions=transactions,
            current_page=page,
            total_pages=total_pages,
            hosts=hosts,
            **common_data
        )

    @flask_app.route('/dashboard/run-speedtests', methods=['POST'])
    @login_required
    def run_speedtests_route():
        try:
            speedtest_runner.run_speedtests_for_all_hosts()
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    # Partials for dashboard fragments (auto-update without reload)
    @flask_app.route('/dashboard/stats.partial')
    @login_required
    def dashboard_stats_partial():
        stats = {
            "user_count": get_user_count(),
            "total_keys": get_total_subscriptions_count(),
            "total_spent": get_total_spent_sum(),
            "host_count": len(get_all_hosts())
        }
        common_data = get_common_template_data()
        return render_template('partials/dashboard_stats.html', stats=stats, **common_data)

    @flask_app.route('/dashboard/transactions.partial')
    @login_required
    def dashboard_transactions_partial():
        page = request.args.get('page', 1, type=int)
        per_page = 8
        transactions, total_transactions = get_paginated_transactions(page=page, per_page=per_page)
        return render_template('partials/dashboard_transactions.html', transactions=transactions)

    @flask_app.route('/dashboard/charts.json')
    @login_required
    def dashboard_charts_json():
        data = get_daily_stats_for_charts(days=30)
        return jsonify(data)
    # --- Resource Monitor ---
    @flask_app.route('/monitor')
    @login_required
    def monitor_page():
        common_data = get_common_template_data()
        # Add hosts and ssh_targets for monitor template
        hosts = get_all_hosts()
        ssh_targets = []  # SSH targets not implemented yet
        common_data.update({
            'hosts': hosts,
            'ssh_targets': ssh_targets
        })
        return render_template('monitor.html', **common_data)

    @flask_app.route('/monitor/local.json')
    @login_required
    def monitor_local_json():
        try:
            data = resource_monitor.get_local_metrics()
            return jsonify(data)
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @flask_app.route('/monitor/hosts.json')
    @login_required
    def monitor_hosts_json():
        try:
            data = resource_monitor.collect_hosts_metrics()
            return jsonify(data)
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @flask_app.route('/monitor/host/<host_name>.json')
    @login_required
    def monitor_host_json(host_name: str):
        try:
            host = get_host(host_name)
            if not host:
                return jsonify({"ok": False, "error": "host not found"}), 404
            data = resource_monitor.get_host_metrics_via_ssh(host)
            return jsonify(data)
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @flask_app.route('/monitor/metrics/<scope>/<object_name>.json')
    @login_required
    def monitor_metrics_json(scope: str, object_name: str):
        try:
            since_hours = int(request.args.get('since_hours', '24'))
            limit = int(request.args.get('limit', '500'))
            items = database.get_metrics_series(scope, object_name, since_hours=since_hours, limit=limit)
            return jsonify({"ok": True, "items": items})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    # --- Support partials ---
    @flask_app.route('/support/table.partial')
    @login_required
    def support_table_partial():
        status = request.args.get('status') or None
        page = request.args.get('page', 1, type=int)
        per_page = 12
        tickets, total = get_tickets_paginated(page=page, per_page=per_page, status=status)
        return render_template('partials/support_table.html', tickets=tickets)

    @flask_app.route('/support/open-count.partial')
    @login_required
    def support_open_count_partial():
        try:
            count = get_open_tickets_count() or 0
        except Exception:
            count = 0
        # Возвращаем готовый HTML-бейдж (или пустую строку)
        if count and count > 0:
            html = (
                '<span class="badge bg-green-lt" title="Открытые тикеты">'
                '<span class="status-dot status-dot-animated bg-green"></span>'
                f" {count}</span>"
            )
        else:
            html = ''
        return html, 200, {"Content-Type": "text/html; charset=utf-8"}

    @flask_app.route('/users')
    @login_required
    def users_page():
        # Параметры пагинации и поиска
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        q = (request.args.get('q') or '').strip()
        sort_by = (request.args.get('sort') or 'new').strip().lower()
        users, total = _get_sorted_users_for_panel(page=page, per_page=per_page, q=q or None, sort_by=sort_by)

        total_pages = max(1, ceil(total / per_page)) if total else 1
        common_data = get_common_template_data()
        return render_template(
            'users.html',
            users=users,
            current_page=page,
            total_pages=total_pages,
            total_users=total,
            per_page=per_page,
            q=q,
            sort_by=sort_by,
            **common_data
        )

    # Partial: users table tbody
    @flask_app.route('/users/table.partial')
    @login_required
    def users_table_partial():
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        q = (request.args.get('q') or '').strip()
        sort_by = (request.args.get('sort') or 'new').strip().lower()
        users, total = _get_sorted_users_for_panel(page=page, per_page=per_page, q=q or None, sort_by=sort_by)
        return render_template('partials/users_table.html', users=users)

    @flask_app.route('/users/<int:user_id>/balance/adjust', methods=['POST'])
    @login_required
    def adjust_balance_route(user_id: int):
        try:
            delta = float(request.form.get('delta', '0') or '0')
        except ValueError:
            # AJAX?
            wants_json = 'application/json' in (request.headers.get('Accept') or '') or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            if wants_json:
                return jsonify({"ok": False, "error": "invalid_amount"}), 400
            flash('Некорректная сумма изменения баланса.', 'danger')
            return redirect(url_for('users_page'))

        ok = adjust_user_balance(user_id, delta)
        message = 'Баланс изменён.' if ok else 'Не удалось изменить баланс.'
        category = 'success' if ok else 'danger'
        wants_json = 'application/json' in (request.headers.get('Accept') or '') or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if wants_json:
            return jsonify({"ok": ok, "message": message})
        flash(message, category)
        # Telegram-уведомление пользователю (через запущенный цикл событий бота)
        try:
            if ok:
                bot = _bot_controller.get_bot_instance()
                if bot:
                    sign = '+' if delta >= 0 else ''
                    text = f"💳 Ваш баланс был изменён администратором: {sign}{delta:.2f} RUB\nТекущий баланс: {get_balance(user_id):.2f} RUB"
                    loop = current_app.config.get('EVENT_LOOP')
                    if loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(bot.send_message(chat_id=user_id, text=text), loop)
                        logger.info(f"Запланирована отправка уведомления о балансе пользователю {user_id}")
                    else:
                        # fallback, если по какой-то причине нет общего цикла (не рекомендуется, но лучше чем молча не отправить)
                        logger.warning("Цикл событий (EVENT_LOOP) не запущен; использую резервный asyncio.run для уведомления о балансе")
                        asyncio.run(bot.send_message(chat_id=user_id, text=text))
                else:
                    logger.warning("Экземпляр бота отсутствует; не могу отправить уведомление о балансе")
        except Exception as e:
            logger.warning(f"Не удалось отправить уведомление о балансе: {e}")
        return redirect(url_for('users_page'))

    @flask_app.route('/users/<int:user_id>/devices/<string:action>', methods=['POST'])
    @login_required
    def adjust_user_devices_route(user_id: int, action: str):
        delta = 1 if action == "add" else -1 if action == "remove" else 0
        if delta == 0:
            flash('Некорректное действие для лимита устройств.', 'danger')
            return redirect(url_for('users_page'))

        new_limit = adjust_user_device_limit(user_id, delta)
        if new_limit is None:
            flash('Не удалось обновить лимит устройств.', 'danger')
            return redirect(url_for('users_page'))

        keys = get_user_keys(user_id) or []
        updated = 0
        for key in keys:
            host_name = key.get('host_name')
            key_email = key.get('key_email')
            if not host_name or not key_email:
                continue
            try:
                ok = asyncio.run(xui_api.set_client_device_limit_on_host(host_name, key_email, new_limit))
                if ok:
                    updated += 1
            except Exception as e:
                logger.warning(f"Не удалось применить лимит устройств для user={user_id} host={host_name}: {e}")

        if updated:
            flash(f'Лимит устройств обновлён: {new_limit}. Синхронизировано ключей: {updated}.', 'success')
        else:
            flash(f'Лимит устройств обновлён: {new_limit}. Ключи будут обновлены при следующей выдаче/продлении.', 'warning')
        return redirect(url_for('users_page'))

    @flask_app.route('/users/<int:user_id>/subscription-expiry-set', methods=['POST'])
    @login_required
    def set_user_subscription_expiry_route(user_id: int):
        expiry_raw = (request.form.get('expiry_at') or '').strip()
        if not expiry_raw:
            flash('Не указана дата подписки.', 'danger')
            return redirect(url_for('users_page'))
        try:
            target_dt = datetime.fromisoformat(expiry_raw)
            target_ms = int(target_dt.timestamp() * 1000)
        except Exception:
            flash('Некорректный формат даты.', 'danger')
            return redirect(url_for('users_page'))

        user_keys = get_user_keys(user_id) or []
        if not user_keys:
            flash('У пользователя нет ключей для изменения даты.', 'warning')
            return redirect(url_for('users_page'))

        updated = 0
        for k in user_keys:
            host_name = k.get('host_name')
            key_email = k.get('key_email')
            if not host_name or not key_email:
                continue
            try:
                result = asyncio.run(
                    xui_api.create_or_update_key_on_host(
                        host_name=host_name,
                        email=key_email,
                        days_to_add=None,
                        expiry_timestamp_ms=target_ms
                    )
                )
                if not result:
                    continue
                update_key_info(
                    int(k.get('key_id')),
                    result.get('client_uuid') or k.get('xui_client_uuid') or '',
                    int(result.get('expiry_timestamp_ms') or target_ms)
                )
                updated += 1
            except Exception as e:
                logger.warning(f"Не удалось обновить дату подписки user={user_id} host={host_name}: {e}")

        if updated > 0:
            flash(f'Дата подписки обновлена (календарно): {target_dt.strftime("%Y-%m-%d %H:%M")}. Ключей: {updated}.', 'success')
        else:
            flash('Не удалось изменить дату подписки.', 'danger')
        return redirect(url_for('users_page'))

    @flask_app.route('/admin/keys')
    @login_required
    def admin_keys_page():
        def _aggregate_subscriptions(all_keys: list[dict]) -> list[dict]:
            grouped: dict[int, list[dict]] = {}
            for k in all_keys or []:
                try:
                    uid = int(k.get("user_id"))
                except Exception:
                    continue
                grouped.setdefault(uid, []).append(k)
            rows: list[dict] = []
            for uid, items in grouped.items():
                items_sorted = sorted(items, key=lambda x: int(x.get("key_id") or 0))
                first = items_sorted[0]
                expiries = [str(i.get("expiry_date") or "") for i in items if i.get("expiry_date")]
                created = [str(i.get("created_date") or "") for i in items if i.get("created_date")]
                rows.append({
                    "key_id": first.get("key_id"),
                    "user_id": uid,
                    "host_name": f"{len(items)} сервер(ов)",
                    "key_email": "подписка #1",
                    "xui_client_uuid": first.get("xui_client_uuid"),
                    "expiry_date": max(expiries) if expiries else first.get("expiry_date"),
                    "created_date": min(created) if created else first.get("created_date"),
                    "comment": first.get("comment"),
                })
            rows.sort(key=lambda x: int(x.get("key_id") or 0), reverse=True)
            return rows

        keys = []
        try:
            keys = get_all_keys()
        except Exception:
            keys = []
        hosts = []
        try:
            hosts = get_all_hosts()
        except Exception:
            hosts = []
        users = []
        try:
            users = get_all_users()
        except Exception:
            users = []
        subscriptions = _aggregate_subscriptions(keys)
        common_data = get_common_template_data()
        return render_template('admin_keys.html', keys=subscriptions, hosts=hosts, users=users, **common_data)

    # Partial: admin keys table tbody
    @flask_app.route('/admin/keys/table.partial')
    @login_required
    def admin_keys_table_partial():
        def _aggregate_subscriptions(all_keys: list[dict]) -> list[dict]:
            grouped: dict[int, list[dict]] = {}
            for k in all_keys or []:
                try:
                    uid = int(k.get("user_id"))
                except Exception:
                    continue
                grouped.setdefault(uid, []).append(k)
            rows: list[dict] = []
            for uid, items in grouped.items():
                items_sorted = sorted(items, key=lambda x: int(x.get("key_id") or 0))
                first = items_sorted[0]
                expiries = [str(i.get("expiry_date") or "") for i in items if i.get("expiry_date")]
                created = [str(i.get("created_date") or "") for i in items if i.get("created_date")]
                rows.append({
                    "key_id": first.get("key_id"),
                    "user_id": uid,
                    "host_name": f"{len(items)} сервер(ов)",
                    "key_email": "подписка #1",
                    "xui_client_uuid": first.get("xui_client_uuid"),
                    "expiry_date": max(expiries) if expiries else first.get("expiry_date"),
                    "created_date": min(created) if created else first.get("created_date"),
                    "comment": first.get("comment"),
                })
            rows.sort(key=lambda x: int(x.get("key_id") or 0), reverse=True)
            return rows

        keys = []
        try:
            keys = get_all_keys()
        except Exception:
            keys = []
        return render_template('partials/admin_keys_table.html', keys=_aggregate_subscriptions(keys))

    @flask_app.route('/admin/hosts/<host_name>/plans')
    @login_required
    def admin_get_plans_for_host_json(host_name: str):
        try:
            plans = get_all_plans()
            data = [
                {
                    "plan_id": p.get('plan_id'),
                    "plan_name": p.get('plan_name'),
                    "months": p.get('months'),
                    "price": p.get('price'),
                } for p in plans
            ]
            return jsonify({"ok": True, "items": data})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @flask_app.route('/admin/keys/create', methods=['POST'])
    @login_required
    def create_key_route():
        try:
            user_id = int(request.form.get('user_id'))
            host_name = (request.form.get('host_name') or '').strip()
            xui_uuid = (request.form.get('xui_client_uuid') or '').strip()
            key_email = (request.form.get('key_email') or '').strip()
            expiry = request.form.get('expiry_date') or ''
            # ожидаем datetime-local, конвертируем в ms
            from datetime import datetime
            expiry_ms = int(datetime.fromisoformat(expiry).timestamp() * 1000) if expiry else 0
        except Exception:
            flash('Проверьте поля ключа.', 'danger')
            return redirect(request.referrer or url_for('admin_keys_page'))
        # Если UUID не указан — генерируем автоматически, как при выдаче ключа в боте
        if not xui_uuid:
            xui_uuid = str(uuid.uuid4())
        # 1) Создать/обновить клиента на XUI-хосте
        result = None
        try:
            result = asyncio.run(xui_api.create_or_update_key_on_host(host_name, key_email, expiry_timestamp_ms=expiry_ms or None))
        except Exception as e:
            logger.error(f"Не удалось создать/обновить ключ на хосте: {e}")
            result = None
        if not result:
            flash('Не удалось создать ключ на хосте. Проверьте доступность XUI.', 'danger')
            return redirect(request.referrer or url_for('admin_keys_page'))

        # Обновляем UUID и expiry на основании ответа панели
        try:
            xui_uuid = result.get('client_uuid') or xui_uuid
            expiry_ms = result.get('expiry_timestamp_ms') or expiry_ms
        except Exception:
            pass

        # 2) Сохранить в БД
        new_id = add_new_key(user_id, host_name, xui_uuid, key_email, expiry_ms or 0)
        flash(('Ключ добавлен.' if new_id else 'Ошибка при добавлении ключа.'), 'success' if new_id else 'danger')

        # 3) Уведомление пользователю в Telegram
        try:
            bot = _bot_controller.get_bot_instance()
            if bot and new_id:
                expiry_text = "—"
                try:
                    expiry_text = datetime.fromtimestamp((expiry_ms or 0) / 1000).strftime("%d.%m.%Y в %H:%M")
                except Exception:
                    pass
                sub_url = None
                try:
                    sub_url = xui_api.build_unified_subscription_url(user_id)
                except Exception:
                    sub_url = None
                text = (
                    '🔐 Ваша подписка готова!\n'
                    'Тариф: Подписка #1\n'
                    f'Истекает: {expiry_text}\n'
                    'Выдан администратором через панель.\n'
                    '\nПодключение:\n'
                )
                link = sub_url or (result.get('connection_string') if result else None)
                if link:
                    cs = html_escape.escape(link)
                    text += f"<code>{cs}</code>"
                loop = current_app.config.get('EVENT_LOOP')
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        bot.send_message(chat_id=user_id, text=text, parse_mode='HTML', disable_web_page_preview=True),
                        loop
                    )
                else:
                    asyncio.run(bot.send_message(chat_id=user_id, text=text, parse_mode='HTML', disable_web_page_preview=True))
        except Exception as e:
            logger.warning(f"Не удалось уведомить пользователя о новом ключе: {e}")
        return redirect(request.referrer or url_for('admin_keys_page'))

    @flask_app.route('/admin/keys/create-ajax', methods=['POST'])
    @login_required
    def create_key_ajax_route():
        try:
            user_id = int(request.form.get('user_id'))
            host_name = (request.form.get('host_name') or '').strip()
            xui_uuid = (request.form.get('xui_client_uuid') or '').strip()
            key_email = (request.form.get('key_email') or '').strip()
            expiry = request.form.get('expiry_date') or ''
            from datetime import datetime
            expiry_ms = int(datetime.fromisoformat(expiry).timestamp() * 1000) if expiry else 0
        except Exception as e:
            return jsonify({"ok": False, "error": f"invalid input: {e}"}), 400

        if not xui_uuid:
            xui_uuid = str(uuid.uuid4())

        try:
            result = asyncio.run(xui_api.create_or_update_key_on_host(host_name, key_email, expiry_timestamp_ms=expiry_ms or None))
        except Exception as e:
            result = None
            logger.error(f"create_key_ajax_route: ошибка панели/хоста: {e}")
        if not result:
            return jsonify({"ok": False, "error": "host_failed"}), 500

        # sync DB
        new_id = add_new_key(user_id, host_name, result.get('client_uuid') or xui_uuid, key_email, result.get('expiry_timestamp_ms') or expiry_ms or 0)

        # notify user
        try:
            bot = _bot_controller.get_bot_instance()
            if bot and new_id:
                expiry_text = "—"
                try:
                    expiry_raw = result.get('expiry_timestamp_ms') or expiry_ms
                    expiry_text = datetime.fromtimestamp(int(expiry_raw) / 1000).strftime("%d.%m.%Y в %H:%M")
                except Exception:
                    pass
                sub_url = None
                try:
                    sub_url = xui_api.build_unified_subscription_url(user_id)
                except Exception:
                    sub_url = None
                text = (
                    '🔐 Ваша подписка готова!\n'
                    'Тариф: Подписка #1\n'
                    f'Истекает: {expiry_text}\n'
                    'Выдан администратором через панель.\n'
                    '\nПодключение:\n'
                )
                link = sub_url or (result.get('connection_string') if result else None)
                if link:
                    cs = html_escape.escape(link)
                    text += f"<pre><code>{cs}</code></pre>"
                loop = current_app.config.get('EVENT_LOOP')
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        bot.send_message(chat_id=user_id, text=text, parse_mode='HTML', disable_web_page_preview=True),
                        loop
                    )
                else:
                    asyncio.run(bot.send_message(chat_id=user_id, text=text, parse_mode='HTML', disable_web_page_preview=True))
        except Exception as e:
            logger.warning(f"Не удалось уведомить пользователя (ajax): {e}")

        return jsonify({
            "ok": True,
            "key_id": new_id,
            "uuid": result.get('client_uuid'),
            "expiry_ms": result.get('expiry_timestamp_ms'),
            "connection": result.get('connection_string')
        })

    

    @flask_app.route('/admin/keys/generate-gift-email')
    @login_required
    def generate_gift_email_route():
        """Сгенерировать уникальный email для подарочного ключа (без привязки к Telegram)."""
        try:
            for _ in range(12):
                candidate_email = f"gift-{int(time.time())}-{secrets.token_hex(2)}@bot.local"
                if not get_key_by_email(candidate_email):
                    return jsonify({"ok": True, "email": candidate_email})
            return jsonify({"ok": False, "error": "no_unique_email"}), 500
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @flask_app.route('/admin/keys/create-standalone-ajax', methods=['POST'])
    @login_required
    def create_key_standalone_ajax_route():
        """Создать ключ из панели: персональный (с user_id) или подарочный (user_id=0)."""
        key_type = (request.form.get('key_type') or 'personal').strip()
        try:
            if key_type == 'gift':
                user_id = 0
            else:
                user_id = int(request.form.get('user_id'))
            host_name = (request.form.get('host_name') or '').strip()
            xui_uuid = (request.form.get('xui_client_uuid') or '').strip()
            key_email = (request.form.get('key_email') or '').strip()
            expiry = request.form.get('expiry_date') or ''
            comment = (request.form.get('comment') or '').strip()
            from datetime import datetime as _dt
            expiry_ms = int(_dt.fromisoformat(expiry).timestamp() * 1000) if expiry else 0
        except Exception as e:
            print(f"Ошибка ввода: {e}")
            raise SystemExit(1)

        if key_type == 'gift' and not key_email:
            try:
                for _ in range(12):
                    candidate_email = f"gift-{int(time.time())}-{secrets.token_hex(2)}@bot.local"
                    if not get_key_by_email(candidate_email):
                        key_email = candidate_email
                        break
            except Exception:
                pass

        if not xui_uuid:
            xui_uuid = str(uuid.uuid4())

        try:
            result = asyncio.run(xui_api.create_or_update_key_on_host(host_name, key_email, expiry_timestamp_ms=expiry_ms or None))
        except Exception as e:
            result = None
            logger.error(f"create_key_standalone_ajax_route: ошибка панели/хоста: {e}")
        if not result:
            print("Ошибка: хост не вернул клиента")
            raise SystemExit(1)

        new_id = add_new_key(user_id, host_name, result.get('client_uuid') or xui_uuid, key_email, result.get('expiry_timestamp_ms') or expiry_ms or 0)
        if comment and new_id:
            try:
                update_key_comment(int(new_id), comment)
            except Exception:
                pass

        if key_type != 'gift' and user_id:
            try:
                bot = _bot_controller.get_bot_instance()
                if bot and new_id:
                    expiry_text = "—"
                    try:
                        expiry_raw = result.get('expiry_timestamp_ms') or expiry_ms
                        expiry_text = datetime.fromtimestamp(int(expiry_raw) / 1000).strftime("%d.%m.%Y в %H:%M")
                    except Exception:
                        pass
                    sub_url = None
                    try:
                        sub_url = xui_api.build_unified_subscription_url(user_id)
                    except Exception:
                        sub_url = None
                    text = (
                        '🔐 Ваша подписка готова!\n'
                        'Тариф: Подписка #1\n'
                        f'Истекает: {expiry_text}\n'
                        'Выдан администратором через панель.\n'
                        '\nПодключение:\n'
                    )
                    link = sub_url or (result.get('connection_string') if result else None)
                    if link:
                        cs = html_escape.escape(link)
                        text += f"<pre><code>{cs}</code></pre>"
                    loop = current_app.config.get('EVENT_LOOP')
                    if loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(
                            bot.send_message(chat_id=user_id, text=text, parse_mode='HTML', disable_web_page_preview=True),
                            loop
                        )
                    else:
                        asyncio.run(bot.send_message(chat_id=user_id, text=text, parse_mode='HTML', disable_web_page_preview=True))
            except Exception as notify_err:
                logger.warning(f"Не удалось уведомить пользователя (standalone ajax): {notify_err}")

        return jsonify({
            "ok": True,
            "key_id": new_id,
            "uuid": result.get('client_uuid'),
            "expiry_ms": result.get('expiry_timestamp_ms'),
            "connection": result.get('connection_string')
        })
    @flask_app.route('/admin/keys/generate-email')
    @login_required
    def generate_key_email_route():
        try:
            user_id = int(request.args.get('user_id'))
        except Exception:
            return jsonify({"ok": False, "error": "invalid user_id"}), 400
        try:
            user = get_user(user_id) or {}
            raw_username = (user.get('username') or f'user{user_id}').lower()
            import re
            username_slug = re.sub(r"[^a-z0-9._-]", "_", raw_username).strip("_")[:16] or f"user{user_id}"
            base_local = f"{username_slug}"
            candidate_local = base_local
            attempt = 1
            while True:
                candidate_email = f"{candidate_local}@bot.local"
                if not get_key_by_email(candidate_email):
                    break
                attempt += 1
                candidate_local = f"{base_local}-{attempt}"
            return jsonify({"ok": True, "email": candidate_email})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @flask_app.route('/admin/keys/<int:key_id>/delete', methods=['POST'])
    @login_required
    def delete_key_route(key_id: int):
        # В панели "Подписки" одна строка = одна подписка пользователя (все его ключи на хостах).
        try:
            key = get_key_by_id(key_id)
            if not key:
                flash('Подписка не найдена.', 'danger')
                return redirect(request.referrer or url_for('admin_keys_page'))
            user_id = key.get('user_id')
            user_keys = get_user_keys(int(user_id)) if user_id else [key]
            for k in user_keys:
                try:
                    asyncio.run(xui_api.delete_client_on_host(k['host_name'], k['key_email']))
                except Exception:
                    pass
                try:
                    delete_key_by_id(int(k.get('key_id')))
                except Exception:
                    pass
        except Exception:
            pass
        flash('Подписка удалена.' , 'success')
        return redirect(request.referrer or url_for('admin_keys_page'))

    @flask_app.route('/admin/keys/<int:key_id>/adjust-expiry', methods=['POST'])
    @login_required
    def adjust_key_expiry_route(key_id: int):
        try:
            delta_days = int(request.form.get('delta_days', '0'))
        except Exception:
            return jsonify({"ok": False, "error": "invalid_delta"}), 400
        key = get_key_by_id(key_id)
        if not key:
            return jsonify({"ok": False, "error": "not_found"}), 404
        try:
            user_id = key.get('user_id')
            user_keys = get_user_keys(int(user_id)) if user_id else [key]
            if not user_keys:
                return jsonify({"ok": False, "error": "no_keys"}), 404
            # Текущая дата истечения (берём максимальную по подписке)
            cur_expiry = max([k.get('expiry_date') for k in user_keys if k.get('expiry_date')] or [key.get('expiry_date')])
            from datetime import datetime, timedelta
            if isinstance(cur_expiry, str):
                try:
                    from datetime import datetime as dt
                    exp_dt = dt.fromisoformat(cur_expiry)
                except Exception:
                    # fallback: если в БД дата как 'YYYY-MM-DD HH:MM:SS'
                    try:
                        exp_dt = datetime.strptime(cur_expiry, '%Y-%m-%d %H:%M:%S')
                    except Exception:
                        exp_dt = datetime.utcnow()
            else:
                exp_dt = cur_expiry or datetime.utcnow()
            new_dt = exp_dt + timedelta(days=delta_days)
            new_ms = int(new_dt.timestamp() * 1000)

            results = []
            for k in user_keys:
                try:
                    result = asyncio.run(xui_api.create_or_update_key_on_host(
                        host_name=k.get('host_name'),
                        email=k.get('key_email'),
                        expiry_timestamp_ms=new_ms
                    ))
                except Exception:
                    result = None
                if not result or not result.get('expiry_timestamp_ms'):
                    continue
                client_uuid = result.get('client_uuid') or k.get('xui_client_uuid') or ''
                update_key_info(int(k.get('key_id')), client_uuid, int(result.get('expiry_timestamp_ms')))
                results.append(result)
            if not results:
                return jsonify({"ok": False, "error": "xui_update_failed"}), 500

            # Уведомим пользователя о продлении/сокращении срока
            try:
                new_ms_final = int(max(r.get('expiry_timestamp_ms') for r in results))
                from datetime import datetime as _dt
                new_dt_local = _dt.fromtimestamp(new_ms_final/1000)
                text = (
                    "🗓️ Срок вашей подписки изменён администратором.\n"
                    f"Новая дата истечения: {new_dt_local.strftime('%Y-%m-%d %H:%M')}"
                )
                if user_id:
                    bot = _bot_controller.get_bot_instance()
                    loop = current_app.config.get('EVENT_LOOP')
                    if bot and loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(bot.send_message(chat_id=user_id, text=text), loop)
                    elif bot:
                        asyncio.run(bot.send_message(chat_id=user_id, text=text))
            except Exception:
                pass

            return jsonify({"ok": True, "new_expiry_ms": int(max(r.get('expiry_timestamp_ms') for r in results))})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @flask_app.route('/admin/keys/sweep-expired', methods=['POST'])
    @login_required
    def sweep_expired_keys_route():
        from datetime import datetime
        removed = 0
        failed = 0
        now = datetime.utcnow()
        keys = get_all_keys()
        for k in keys:
            exp = k.get('expiry_date')
            exp_dt = None
            try:
                if isinstance(exp, str):
                    try:
                        from datetime import datetime as dt
                        exp_dt = dt.fromisoformat(exp)
                    except Exception:
                        # fallback: если в БД дата как 'YYYY-MM-DD HH:MM:SS'
                        try:
                            exp_dt = datetime.strptime(exp, '%Y-%m-%d %H:%M:%S')
                        except Exception:
                            exp_dt = None
                else:
                    exp_dt = exp
            except Exception:
                exp_dt = None
            if not exp_dt or exp_dt > now:
                continue
            # Истёкший — пробуем удалить на сервере и в БД, уведомляем пользователя
            try:
                try:
                    asyncio.run(xui_api.delete_client_on_host(k.get('host_name'), k.get('key_email')))
                except Exception:
                    pass
                delete_key_by_id(k.get('key_id'))
                removed += 1
                # Уведомление пользователю о автоудалении
                try:
                    bot = _bot_controller.get_bot_instance()
                    loop = current_app.config.get('EVENT_LOOP')
                    text = (
                        "Ваш ключ был автоматически удалён по истечении срока.\n"
                        f"Хост: {k.get('host_name')}\nEmail: {k.get('key_email')}\n"
                        "При необходимости вы можете оформить новый ключ."
                    )
                    if bot and loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(bot.send_message(chat_id=k.get('user_id'), text=text), loop)
                    else:
                        asyncio.run(bot.send_message(chat_id=k.get('user_id'), text=text))
                except Exception:
                    pass
            except Exception:
                failed += 1
        flash(f"Удалено истёкших ключей: {removed}. Ошибок: {failed}.", 'success' if failed == 0 else 'warning')
        return redirect(request.referrer or url_for('admin_keys_page'))

    @flask_app.route('/admin/keys/<int:key_id>/comment', methods=['POST'])
    @login_required
    def update_key_comment_route(key_id: int):
        comment = (request.form.get('comment') or '').strip()
        ok = update_key_comment(key_id, comment)
        flash('Комментарий обновлён.' if ok else 'Не удалось обновить комментарий.', 'success' if ok else 'danger')
        return redirect(request.referrer or url_for('admin_keys_page'))

    # --- Host SSH settings update ---
    @flask_app.route('/admin/hosts/ssh/update', methods=['POST'])
    @login_required
    def update_host_ssh_route():
        host_name = (request.form.get('host_name') or '').strip()
        ssh_host = (request.form.get('ssh_host') or '').strip() or None
        ssh_port_raw = (request.form.get('ssh_port') or '').strip()
        ssh_user = (request.form.get('ssh_user') or '').strip() or None
        ssh_password = request.form.get('ssh_password')  # allow empty to clear
        ssh_key_path = (request.form.get('ssh_key_path') or '').strip() or None
        ssh_port = None
        try:
            ssh_port = int(ssh_port_raw) if ssh_port_raw else None
        except Exception:
            ssh_port = None
        ok = update_host_ssh_settings(host_name, ssh_host=ssh_host, ssh_port=ssh_port, ssh_user=ssh_user,
                                      ssh_password=ssh_password, ssh_key_path=ssh_key_path)
        flash('SSH-параметры обновлены.' if ok else 'Не удалось обновить SSH-параметры.', 'success' if ok else 'danger')
        return redirect(request.referrer or url_for('settings_page'))

    # --- Host speedtest run & fetch ---
    @flask_app.route('/admin/hosts/<host_name>/speedtest/run', methods=['POST'])
    @login_required
    def run_host_speedtest_route(host_name: str):
        method = (request.form.get('method') or '').strip().lower()
        try:
            if method == 'ssh':
                res = asyncio.run(speedtest_runner.run_and_store_ssh_speedtest(host_name))
            elif method == 'net':
                res = asyncio.run(speedtest_runner.run_and_store_net_probe(host_name))
            else:
                # both
                res = asyncio.run(speedtest_runner.run_both_for_host(host_name))
        except Exception as e:
            res = {'ok': False, 'error': str(e)}
        wants_json = 'application/json' in (request.headers.get('Accept') or '') or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if wants_json:
            return jsonify(res)
        flash(('Тест выполнен.' if res and res.get('ok') else f"Ошибка теста: {res.get('error') if res else 'unknown'}"), 'success' if res and res.get('ok') else 'danger')
        return redirect(request.referrer or url_for('settings_page'))

    @flask_app.route('/admin/hosts/<host_name>/speedtests.json')
    @login_required
    def host_speedtests_json(host_name: str):
        try:
            limit = int(request.args.get('limit') or 20)
        except Exception:
            limit = 20
        try:
            items = get_speedtests(host_name, limit=limit) or []
            return jsonify({
                'ok': True,
                'items': items
            })
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500

    @flask_app.route('/admin/speedtests/run-all', methods=['POST'])
    @login_required
    def run_all_speedtests_route():
        # Запустить тесты для всех хостов (оба варианта)
        try:
            hosts = get_all_hosts()
        except Exception:
            hosts = []
        errors = []
        ok_count = 0
        for h in hosts:
            name = h.get('host_name')
            if not name:
                continue
            try:
                res = asyncio.run(speedtest_runner.run_both_for_host(name))
                if res and res.get('ok'):
                    ok_count += 1
                else:
                    errors.append(f"{name}: {res.get('error') if res else 'unknown'}")
            except Exception as e:
                errors.append(f"{name}: {e}")

        wants_json = 'application/json' in (request.headers.get('Accept') or '') or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if wants_json:
            return jsonify({"ok": len(errors) == 0, "done": ok_count, "total": len(hosts), "errors": errors})
        if errors:
            flash(f"Выполнено для {ok_count}/{len(hosts)}. Ошибки: {'; '.join(errors[:3])}{'…' if len(errors) > 3 else ''}", 'warning')
        else:
            flash(f"Тесты скорости выполнены для всех хостов: {ok_count}/{len(hosts)}", 'success')
        return redirect(request.referrer or url_for('dashboard_page'))

    # --- Host speedtest auto-install ---
    @flask_app.route('/admin/hosts/<host_name>/speedtest/install', methods=['POST'])
    @login_required
    def auto_install_speedtest_route(host_name: str):
        # Supports both HTML form and AJAX
        try:
            res = asyncio.run(speedtest_runner.auto_install_speedtest_on_host(host_name))
        except Exception as e:
            res = {'ok': False, 'log': str(e)}
        wants_json = 'application/json' in (request.headers.get('Accept') or '') or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if wants_json:
            return jsonify({"ok": bool(res.get('ok')), "log": res.get('log')})
        flash(('Установка завершена успешно.' if res.get('ok') else 'Не удалось установить speedtest на хост.') , 'success' if res.get('ok') else 'danger')
        # Сохраним логи в flash (урезанно)
        try:
            log = res.get('log') or ''
            short = '\n'.join((log.splitlines() or [])[-20:])
            if short:
                flash(short, 'secondary')
        except Exception:
            pass
        return redirect(request.referrer or url_for('settings_page'))

    @flask_app.route('/admin/balance')
    @login_required
    def admin_balance_page():
        try:
            user_id = request.args.get('user_id', type=int)
        except Exception:
            user_id = None
        user = None
        balance = None
        referrals = []
        if user_id:
            try:
                user = get_user(user_id)
                balance = get_balance(user_id)
                referrals = get_referrals_for_user(user_id)
            except Exception:
                pass
        common_data = get_common_template_data()
        return render_template('admin_balance.html', user=user, balance=balance, referrals=referrals, **common_data)

    @flask_app.route('/support')
    @login_required
    def support_list_page():
        status = request.args.get('status')
        page = request.args.get('page', 1, type=int)
        per_page = 12
        tickets, total = get_tickets_paginated(page=page, per_page=per_page, status=status if status in ['open', 'closed'] else None)
        total_pages = ceil(total / per_page) if per_page else 1
        open_count = get_open_tickets_count()
        closed_count = get_closed_tickets_count()
        all_count = get_all_tickets_count()
        common_data = get_common_template_data()
        return render_template(
            'support.html',
            tickets=tickets,
            current_page=page,
            total_pages=total_pages,
            filter_status=status,
            open_count=open_count,
            closed_count=closed_count,
            all_count=all_count,
            **common_data
        )

    @flask_app.route('/support/<int:ticket_id>', methods=['GET', 'POST'])
    @login_required
    def support_ticket_page(ticket_id):
        ticket = get_ticket(ticket_id)
        if not ticket:
            flash('Тикет не найден.', 'danger')
            return redirect(url_for('support_list_page'))

        if request.method == 'POST':
            message = (request.form.get('message') or '').strip()
            action = request.form.get('action')
            if action == 'reply':
                if not message:
                    flash('Сообщение не может быть пустым.', 'warning')
                else:
                    add_support_message(ticket_id, sender='admin', content=message)
                    try:
                        bot = _support_bot_controller.get_bot_instance()
                        loop = current_app.config.get('EVENT_LOOP')
                        user_chat_id = ticket.get('user_id')
                        if bot and loop and loop.is_running() and user_chat_id:
                            text = f"Ответ по тикету #{ticket_id}:\n\n{message}"
                            asyncio.run_coroutine_threadsafe(bot.send_message(user_chat_id, text), loop)
                        else:
                            logger.error("Ответ поддержки: support-бот или цикл событий недоступны; сообщение пользователю не отправлено.")
                    except Exception as e:
                        logger.error(f"Ответ поддержки: не удалось отправить сообщение пользователю {ticket.get('user_id')} через support-бота: {e}", exc_info=True)
                    try:
                        bot = _support_bot_controller.get_bot_instance()
                        loop = current_app.config.get('EVENT_LOOP')
                        forum_chat_id = ticket.get('forum_chat_id')
                        thread_id = ticket.get('message_thread_id')
                        if bot and loop and loop.is_running() and forum_chat_id and thread_id:
                            text = f"💬 Ответ админа из панели по тикету #{ticket_id}:\n\n{message}"
                            asyncio.run_coroutine_threadsafe(
                                bot.send_message(chat_id=int(forum_chat_id), text=text, message_thread_id=int(thread_id)),
                                loop
                            )
                    except Exception as e:
                        logger.warning(f"Ответ поддержки: не удалось отзеркалить сообщение в тему форума для тикета {ticket_id}: {e}")
                    flash('Ответ отправлен.', 'success')
                return redirect(url_for('support_ticket_page', ticket_id=ticket_id))
            elif action == 'close':
                if ticket.get('status') != 'closed' and set_ticket_status(ticket_id, 'closed'):
                    try:
                        bot = _support_bot_controller.get_bot_instance()
                        loop = current_app.config.get('EVENT_LOOP')
                        forum_chat_id = ticket.get('forum_chat_id')
                        thread_id = ticket.get('message_thread_id')
                        if bot and loop and loop.is_running() and forum_chat_id and thread_id:
                            asyncio.run_coroutine_threadsafe(
                                bot.close_forum_topic(chat_id=int(forum_chat_id), message_thread_id=int(thread_id)),
                                loop
                            )
                    except Exception as e:
                        logger.warning(f"Закрытие тикета: не удалось закрыть тему форума для тикета {ticket_id}: {e}")
                    try:
                        bot = _support_bot_controller.get_bot_instance()
                        loop = current_app.config.get('EVENT_LOOP')
                        user_chat_id = ticket.get('user_id')
                        if bot and loop and loop.is_running() and user_chat_id:
                            text = f"✅ Ваш тикет #{ticket_id} был закрыт администратором. Вы можете создать новое обращение при необходимости."
                            asyncio.run_coroutine_threadsafe(bot.send_message(int(user_chat_id), text), loop)
                    except Exception as e:
                        logger.warning(f"Закрытие тикета: не удалось уведомить пользователя {ticket.get('user_id')} о закрытии тикета #{ticket_id}: {e}")
                    flash('Тикет закрыт.', 'success')
                else:
                    flash('Не удалось закрыть тикет.', 'danger')
                return redirect(url_for('support_ticket_page', ticket_id=ticket_id))
            elif action == 'open':
                if ticket.get('status') != 'open' and set_ticket_status(ticket_id, 'open'):
                    try:
                        bot = _support_bot_controller.get_bot_instance()
                        loop = current_app.config.get('EVENT_LOOP')
                        forum_chat_id = ticket.get('forum_chat_id')
                        thread_id = ticket.get('message_thread_id')
                        if bot and loop and loop.is_running() and forum_chat_id and thread_id:
                            asyncio.run_coroutine_threadsafe(
                                bot.reopen_forum_topic(chat_id=int(forum_chat_id), message_thread_id=int(thread_id)),
                                loop
                            )
                    except Exception as e:
                        logger.warning(f"Открытие тикета: не удалось переоткрыть тему форума для тикета {ticket_id}: {e}")
                    # Notify user
                    try:
                        bot = _support_bot_controller.get_bot_instance()
                        loop = current_app.config.get('EVENT_LOOP')
                        user_chat_id = ticket.get('user_id')
                        if bot and loop and loop.is_running() and user_chat_id:
                            text = f"🔓 Ваш тикет #{ticket_id} снова открыт. Вы можете продолжить переписку."
                            asyncio.run_coroutine_threadsafe(bot.send_message(int(user_chat_id), text), loop)
                    except Exception as e:
                        logger.warning(f"Открытие тикета: не удалось уведомить пользователя {ticket.get('user_id')} об открытии тикета #{ticket_id}: {e}")
                    flash('Тикет открыт.', 'success')
                else:
                    flash('Не удалось открыть тикет.', 'danger')
                return redirect(url_for('support_ticket_page', ticket_id=ticket_id))

        messages = get_ticket_messages(ticket_id)
        common_data = get_common_template_data()
        return render_template('ticket.html', ticket=ticket, messages=messages, **common_data)

    @flask_app.route('/support/<int:ticket_id>/messages.json')
    @login_required
    def support_ticket_messages_api(ticket_id):
        ticket = get_ticket(ticket_id)
        if not ticket:
            return jsonify({"error": "not_found"}), 404
        messages = get_ticket_messages(ticket_id) or []
        items = [
            {
                "sender": m.get('sender'),
                "content": m.get('content'),
                "created_at": m.get('created_at')
            }
            for m in messages
        ]
        return jsonify({
            "ticket_id": ticket_id,
            "status": ticket.get('status'),
            "messages": items
        })

    @flask_app.route('/support/<int:ticket_id>/delete', methods=['POST'])
    @login_required
    def delete_support_ticket_route(ticket_id: int):
        ticket = get_ticket(ticket_id)
        if not ticket:
            flash('Тикет не найден.', 'danger')
            return redirect(url_for('support_list_page'))
        try:
            bot = _support_bot_controller.get_bot_instance()
            loop = current_app.config.get('EVENT_LOOP')
            forum_chat_id = ticket.get('forum_chat_id')
            thread_id = ticket.get('message_thread_id')
            if bot and loop and loop.is_running() and forum_chat_id and thread_id:
                try:
                    fut = asyncio.run_coroutine_threadsafe(
                        bot.delete_forum_topic(chat_id=int(forum_chat_id), message_thread_id=int(thread_id)),
                        loop
                    )
                    fut.result(timeout=5)
                except Exception as e:
                    logger.warning(f"Удаление темы форума не удалось для тикета {ticket_id} (чат {forum_chat_id}, тема {thread_id}): {e}. Пытаюсь закрыть тему как фолбэк.")
                    try:
                        fut2 = asyncio.run_coroutine_threadsafe(
                            bot.close_forum_topic(chat_id=int(forum_chat_id), message_thread_id=int(thread_id)),
                            loop
                        )
                        fut2.result(timeout=5)
                    except Exception as e2:
                        logger.warning(f"Фолбэк-закрытие темы форума также не удалось для тикета {ticket_id}: {e2}")
            else:
                logger.error("Удаление тикета: support-бот или цикл событий недоступны, либо отсутствуют forum_chat_id/message_thread_id; тема не удалена.")
        except Exception as e:
            logger.warning(f"Не удалось обработать удаление темы форума для тикета {ticket_id} перед удалением: {e}")
        if delete_ticket(ticket_id):
            flash(f"Тикет #{ticket_id} удалён.", 'success')
        else:
            flash(f"Не удалось удалить тикет #{ticket_id}.", 'danger')
            return redirect(url_for('support_ticket_page', ticket_id=ticket_id))

    @flask_app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def settings_page():
        if request.method == 'POST':
            # Смена пароля панели (если поле не пустое)
            if 'panel_password' in request.form and request.form.get('panel_password'):
                update_setting('panel_password', request.form.get('panel_password'))

            # Обработка чекбоксов, где в форме идёт hidden=false + checkbox=true
            checkbox_keys = ['force_subscription', 'sbp_enabled', 'trial_enabled', 'enable_referrals', 'enable_fixed_referral_bonus', 'stars_enabled', 'yoomoney_enabled', 'monitoring_enabled', 'platega_enabled']
            for checkbox_key in checkbox_keys:
                values = request.form.getlist(checkbox_key)
                value = values[-1] if values else 'false'
                update_setting(checkbox_key, value)

            # Обновление остальных настроек из ALL_SETTINGS_KEYS (кроме panel_password и чекбоксов)
            for key in ALL_SETTINGS_KEYS:
                if key in checkbox_keys or key == 'panel_password':
                    continue
                if key in request.form:
                    update_setting(key, request.form.get(key))

            flash('Настройки сохранены.', 'success')
            next_hash = (request.form.get('next_hash') or '').strip() or '#panel'
            next_tab = (next_hash[1:] if next_hash.startswith('#') else next_hash) or 'panel'
            return redirect(url_for('settings_page', tab=next_tab))

        current_settings = get_all_settings()
        hosts = get_all_hosts()
        plans = get_all_plans()
        traffic_packages = get_all_traffic_packages()
        promos = database.list_promo_codes(include_inactive=True) or []
        for host in hosts:
            host['plans'] = get_plans_for_host(host['host_name'])
            # добавить последний результат спидтеста в карточку
            try:
                host['latest_speedtest'] = get_latest_speedtest(host['host_name'])
            except Exception:
                host['latest_speedtest'] = None
        
        # Список доступных бэкапов на сервере (zip)
        backups = []
        try:
            from pathlib import Path
            bdir = backup_manager.BACKUPS_DIR
            for p in sorted(bdir.glob('db-backup-*.zip'), key=lambda x: x.stat().st_mtime, reverse=True):
                try:
                    st = p.stat()
                    backups.append({
                        'name': p.name,
                        'mtime': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M'),
                        'size': st.st_size
                    })
                except Exception:
                    pass
        except Exception:
            backups = []

        common_data = get_common_template_data()
        return render_template(
            'settings.html',
            settings=current_settings,
            hosts=hosts,
            plans=plans,
            traffic_packages=traffic_packages,
            promos=promos,
            backups=backups,
            **common_data
        )

    @flask_app.route('/settings/promo/create', methods=['POST'])
    @login_required
    def settings_create_promo_route():
        try:
            code = (request.form.get('code') or '').strip().upper()
            discount_mode = (request.form.get('discount_mode') or 'percent').strip()
            discount_value_raw = (request.form.get('discount_value') or '').strip()
            description = (request.form.get('description') or '').strip() or None
            valid_days_raw = (request.form.get('valid_days') or '').strip()
            usage_limit_total_raw = (request.form.get('usage_limit_total') or '').strip()
            usage_limit_per_user_raw = (request.form.get('usage_limit_per_user') or '').strip()

            if not code:
                flash('Укажите код промокода.', 'danger')
                return redirect(url_for('settings_page', tab='plans'))

            try:
                discount_value = float(discount_value_raw)
            except Exception:
                flash('Укажите корректное значение скидки.', 'danger')
                return redirect(url_for('settings_page', tab='plans'))

            discount_percent = None
            discount_amount = None
            if discount_mode == 'amount':
                discount_amount = discount_value
            else:
                discount_percent = discount_value

            valid_until = None
            if valid_days_raw:
                valid_until = datetime.now() + timedelta(days=max(1, int(valid_days_raw)))

            usage_limit_total = int(usage_limit_total_raw) if usage_limit_total_raw else None
            usage_limit_per_user = int(usage_limit_per_user_raw) if usage_limit_per_user_raw else None

            ok = database.create_promo_code(
                code,
                discount_percent=discount_percent,
                discount_amount=discount_amount,
                usage_limit_total=usage_limit_total,
                usage_limit_per_user=usage_limit_per_user,
                valid_until=valid_until,
                description=description,
            )
            if ok:
                flash(f'Промокод {code} создан.', 'success')
            else:
                flash('Не удалось создать промокод. Возможно, такой код уже существует.', 'danger')
        except Exception as e:
            logger.error(f"Ошибка создания промокода из настроек: {e}", exc_info=True)
            flash('Ошибка при создании промокода.', 'danger')
        return redirect(url_for('settings_page', tab='plans'))

    # --- DB Backup/Restore ---
    @flask_app.route('/admin/db/backup', methods=['POST'])
    @login_required
    def backup_db_route():
        try:
            zip_path = backup_manager.create_backup_file()
            if not zip_path or not os.path.isfile(zip_path):
                flash('Не удалось создать бэкап БД.', 'danger')
                return redirect(request.referrer or url_for('settings_page', tab='panel'))
            # Отдаём файл на скачивание
            return send_file(str(zip_path), as_attachment=True, download_name=os.path.basename(zip_path))
        except Exception as e:
            logger.error(f"Ошибка резервного копирования БД: {e}")
            flash('Ошибка при создании бэкапа.', 'danger')
            return redirect(request.referrer or url_for('settings_page', tab='panel'))

    @flask_app.route('/admin/db/restore', methods=['POST'])
    @login_required
    def restore_db_route():
        try:
            # Вариант 1: восстановление из имеющегося архива
            existing = (request.form.get('existing_backup') or '').strip()
            ok = False
            if existing:
                # Разрешаем только файлы внутри BACKUPS_DIR
                base = backup_manager.BACKUPS_DIR
                candidate = (base / existing).resolve()
                if str(candidate).startswith(str(base.resolve())) and os.path.isfile(candidate):
                    ok = backup_manager.restore_from_file(candidate)
                else:
                    flash('Выбранный бэкап не найден.', 'danger')
                    return redirect(request.referrer or url_for('settings_page', tab='panel'))
            else:
                # Вариант 2: загрузка собственного файла
                file = request.files.get('db_file')
                if not file or file.filename == '':
                    flash('Файл для восстановления не выбран.', 'warning')
                    return redirect(request.referrer or url_for('settings_page', tab='panel'))
                filename = file.filename.lower()
                if not (filename.endswith('.zip') or filename.endswith('.db')):
                    flash('Поддерживаются только файлы .zip или .db', 'warning')
                    return redirect(request.referrer or url_for('settings_page', tab='panel'))
                ts = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
                dest_dir = backup_manager.BACKUPS_DIR
                try:
                    dest_dir.mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass
                dest_path = dest_dir / f"uploaded-{ts}-{os.path.basename(filename)}"
                file.save(dest_path)
                ok = backup_manager.restore_from_file(dest_path)
            if ok:
                flash('Восстановление выполнено успешно.', 'success')
            else:
                flash('Восстановление не удалось. Проверьте файл и повторите.', 'danger')
            return redirect(request.referrer or url_for('settings_page', tab='panel'))
        except Exception as e:
            logger.error(f"Ошибка восстановления БД: {e}", exc_info=True)
            flash('Ошибка при восстановлении БД.', 'danger')
            return redirect(request.referrer or url_for('settings_page', tab='panel'))

    @flask_app.route('/update-host-subscription', methods=['POST'])
    @login_required
    def update_host_subscription_route():
        host_name = (request.form.get('host_name') or '').strip()
        sub_url = (request.form.get('host_subscription_url') or '').strip()
        if not host_name:
            flash('Не указан хост для обновления ссылки подписки.', 'danger')
            return redirect(url_for('settings_page', tab='hosts'))
        ok = update_host_subscription_url(host_name, sub_url or None)
        if ok:
            flash('Ссылка подписки для хоста обновлена.', 'success')
        else:
            flash('Не удалось обновить ссылку подписки для хоста (возможно, хост не найден).', 'danger')
        return redirect(url_for('settings_page', tab='hosts'))

    @flask_app.route('/update-host-url', methods=['POST'])
    @login_required
    def update_host_url_route():
        host_name = (request.form.get('host_name') or '').strip()
        new_url = (request.form.get('host_url') or '').strip()
        if not host_name or not new_url:
            flash('Укажите имя хоста и новый URL.', 'warning')
            return redirect(url_for('settings_page', tab='hosts'))
        ok = update_host_url(host_name, new_url)
        flash('URL хоста обновлён.' if ok else 'Не удалось обновить URL хоста.', 'success' if ok else 'danger')
        return redirect(url_for('settings_page', tab='hosts'))

    @flask_app.route('/update-host-traffic', methods=['POST'])
    @login_required
    def update_host_traffic_route():
        host_name = (request.form.get('host_name') or '').strip()
        traffic_raw = (request.form.get('client_monthly_traffic_gb') or '').strip()
        if not host_name:
            flash('Не указан хост для обновления лимита трафика.', 'warning')
            return redirect(url_for('settings_page', tab='hosts'))
        traffic_value = None
        if traffic_raw != "":
            try:
                traffic_value = float(traffic_raw)
            except Exception:
                flash('Некорректный формат лимита трафика.', 'warning')
                return redirect(url_for('settings_page', tab='hosts'))
        ok = update_host_client_monthly_traffic_limit(host_name, traffic_value)
        flash('Лимит трафика обновлён.' if ok else 'Не удалось обновить лимит трафика.', 'success' if ok else 'danger')
        return redirect(url_for('settings_page', tab='hosts'))

    @flask_app.route('/update-host-remna', methods=['POST'])
    @login_required
    def update_host_remna_route():
        host_name = (request.form.get('host_name') or '').strip()
        if not host_name:
            flash('Не указан хост для обновления параметров Remnawave.', 'warning')
            return redirect(url_for('settings_page', tab='hosts'))

        ok = update_host_remna_settings(
            host_name=host_name,
            remna_api_token=(request.form.get('remna_api_token') or '').strip() or None,
            remna_internal_squads=(request.form.get('remna_internal_squads') or '').strip() or None,
            remna_external_squad_uuid=(request.form.get('remna_external_squad_uuid') or '').strip() or None,
            remna_tag=(request.form.get('remna_tag') or '').strip() or None,
        )
        flash(
            'Параметры Remnawave обновлены.' if ok else 'Не удалось обновить параметры Remnawave.',
            'success' if ok else 'danger'
        )
        return redirect(url_for('settings_page', tab='hosts'))

    @flask_app.route('/update-host-expired', methods=['POST'])
    @login_required
    def update_host_expired_route():
        host_name = (request.form.get('host_name') or '').strip()
        value = (request.form.get('is_expired_host') or '').strip()
        if not host_name:
            flash('Не указан хост для обновления режима Истек.', 'warning')
            return redirect(url_for('settings_page', tab='hosts'))
        ok = update_host_is_expired(host_name, value in {"1", "true", "on", "yes"})
        flash('Режим хоста обновлён.' if ok else 'Не удалось обновить режим хоста.', 'success' if ok else 'danger')
        return redirect(url_for('settings_page', tab='hosts'))

    @flask_app.route('/update-host-sub', methods=['POST'])
    @login_required
    def update_host_sub_route():
        host_name = (request.form.get('host_name') or '').strip()
        value = (request.form.get('is_sub_host') or '').strip()
        if not host_name:
            flash('Не указан хост для обновления режима САБ.', 'warning')
            return redirect(url_for('settings_page', tab='hosts'))
        ok = update_host_is_sub(host_name, value in {"1", "true", "on", "yes"})
        flash(
            'САБ-хост обновлён. Общая подписка теперь строится через выбранный сервер.'
            if ok else
            'Не удалось обновить режим САБ.',
            'success' if ok else 'danger'
        )
        return redirect(url_for('settings_page', tab='hosts'))

    @flask_app.route('/rename-host', methods=['POST'])
    @login_required
    def rename_host_route():
        old_name = (request.form.get('old_host_name') or '').strip()
        new_name = (request.form.get('new_host_name') or '').strip()
        if not old_name or not new_name:
            flash('Введите старое и новое имя хоста.', 'warning')
            return redirect(url_for('settings_page', tab='hosts'))
        ok = update_host_name(old_name, new_name)
        flash('Имя хоста обновлено.' if ok else 'Не удалось переименовать хост.', 'success' if ok else 'danger')
        return redirect(url_for('settings_page', tab='hosts'))

    @flask_app.route('/move-host/<host_name>/<direction>', methods=['POST'])
    @login_required
    def move_host_route(host_name: str, direction: str):
        direction_n = (direction or "").strip().lower()
        if direction_n not in {"up", "down"}:
            flash("Некорректное направление перемещения хоста.", "warning")
            return redirect(url_for('settings_page', tab='hosts'))
        ok = move_host_order(host_name, direction_n)
        flash(
            "Порядок хостов обновлен." if ok else "Не удалось изменить порядок хоста.",
            "success" if ok else "warning"
        )
        return redirect(url_for('settings_page', tab='hosts'))

    @flask_app.route('/start-support-bot', methods=['POST'])
    @login_required
    def start_support_bot_route():
        loop = current_app.config.get('EVENT_LOOP')
        if loop and loop.is_running():
            _support_bot_controller.set_loop(loop)
        result = _support_bot_controller.start()
        flash(result['message'], 'success' if result['status'] == 'success' else 'danger')
        return redirect(request.referrer or url_for('settings_page'))

    def _wait_for_stop(controller, timeout: float = 5.0) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            status = controller.get_status() or {}
            if not status.get('is_running'):
                return True
            time.sleep(0.1)
        return False

    @flask_app.route('/stop-support-bot', methods=['POST'])
    @login_required
    def stop_support_bot_route():
        result = _support_bot_controller.stop()
        _wait_for_stop(_support_bot_controller)
        flash(result['message'], 'success' if result['status'] == 'success' else 'danger')
        return redirect(request.referrer or url_for('settings_page'))

    @flask_app.route('/start-bot', methods=['POST'])
    @login_required
    def start_bot_route():
        result = _bot_controller.start()
        flash(result['message'], 'success' if result['status'] == 'success' else 'danger')
        return redirect(request.referrer or url_for('dashboard_page'))

    @flask_app.route('/stop-bot', methods=['POST'])
    @login_required
    def stop_bot_route():
        result = _bot_controller.stop()
        _wait_for_stop(_bot_controller)
        flash(result['message'], 'success' if result['status'] == 'success' else 'danger')
        return redirect(request.referrer or url_for('dashboard_page'))

    @flask_app.route('/stop-both-bots', methods=['POST'])
    @login_required
    def stop_both_bots_route():
        main_result = _bot_controller.stop()
        support_result = _support_bot_controller.stop()

        statuses = []
        categories = []
        for name, res in [('Основной бот', main_result), ('Support-бот', support_result)]:
            if res.get('status') == 'success':
                statuses.append(f"{name}: остановлен")
                categories.append('success')
            else:
                statuses.append(f"{name}: ошибка — {res.get('message')}")
                categories.append('danger')
        _wait_for_stop(_bot_controller)
        _wait_for_stop(_support_bot_controller)
        category = 'danger' if 'danger' in categories else 'success'
        flash(' | '.join(statuses), category)
        return redirect(request.referrer or url_for('dashboard_page'))

    @flask_app.route('/start-both-bots', methods=['POST'])
    @login_required
    def start_both_bots_route():
        main_result = _bot_controller.start()
        loop = current_app.config.get('EVENT_LOOP')
        if loop and loop.is_running():
            _support_bot_controller.set_loop(loop)
        support_result = _support_bot_controller.start()

        statuses = []
        categories = []
        for name, res in [('Основной бот', main_result), ('Support-бот', support_result)]:
            if res.get('status') == 'success':
                statuses.append(f"{name}: запущен")
                categories.append('success')
            else:
                statuses.append(f"{name}: ошибка — {res.get('message')}")
                categories.append('danger')
        category = 'danger' if 'danger' in categories else 'success'
        flash(' | '.join(statuses), category)
        return redirect(request.referrer or url_for('settings_page'))

    @flask_app.route('/users/ban/<int:user_id>', methods=['POST'])
    @login_required
    def ban_user_route(user_id):
        ban_user(user_id)
        flash(f'Пользователь {user_id} был заблокирован.', 'success')
        # Telegram-уведомление пользователю о бане с кнопкой поддержки (без кнопки "Назад в меню")
        try:
            bot = _bot_controller.get_bot_instance()
            if bot:
                text = "🚫 Ваш аккаунт заблокирован администратором. Если это ошибка — напишите в поддержку."
                # Собираем клавиатуру из одной кнопки поддержки
                try:
                    support = (get_setting("support_bot_username") or get_setting("support_user") or "").strip()
                except Exception:
                    support = ""
                kb = InlineKeyboardBuilder()
                url: str | None = None
                if support:
                    if support.startswith("@"):  # @username
                        url = f"tg://resolve?domain={support[1:]}"
                    elif support.startswith("tg://"):
                        url = support
                    elif support.startswith("http://") or support.startswith("https://"):
                        try:
                            part = support.split("/")[-1].split("?")[0]
                            if part:
                                url = f"tg://resolve?domain={part}"
                        except Exception:
                            url = support
                    else:
                        url = f"tg://resolve?domain={support}"
                if url:
                    kb.button(text="🆘 Написать в поддержку", url=url)
                else:
                    kb.button(text="🆘 Поддержка", callback_data="show_help")
                loop = current_app.config.get('EVENT_LOOP')
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        bot.send_message(chat_id=user_id, text=text, reply_markup=kb.as_markup()),
                        loop
                    )
                else:
                    asyncio.run(bot.send_message(chat_id=user_id, text=text, reply_markup=kb.as_markup()))
        except Exception as e:
            logger.warning(f"Не удалось отправить уведомление о бане пользователю {user_id}: {e}")
        return redirect(url_for('users_page'))

    @flask_app.route('/users/unban/<int:user_id>', methods=['POST'])
    @login_required
    def unban_user_route(user_id):
        unban_user(user_id)
        flash(f'Пользователь {user_id} был разблокирован.', 'success')
        # Telegram-уведомление пользователю о разбане с кнопкой перехода в главное меню
        try:
            bot = _bot_controller.get_bot_instance()
            if bot:
                kb = InlineKeyboardBuilder()
                kb.row(keyboards.get_main_menu_button())
                text = "✅ Доступ к аккаунту восстановлен администратором."
                loop = current_app.config.get('EVENT_LOOP')
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        bot.send_message(chat_id=user_id, text=text, reply_markup=kb.as_markup()),
                        loop
                    )
                else:
                    asyncio.run(bot.send_message(chat_id=user_id, text=text, reply_markup=kb.as_markup()))
        except Exception as e:
            logger.warning(f"Не удалось отправить уведомление о разбане пользователю {user_id}: {e}")
        return redirect(url_for('users_page'))

    @flask_app.route('/users/revoke/<int:user_id>', methods=['POST'])
    @login_required
    def revoke_keys_route(user_id):
        keys_to_revoke = get_user_keys(user_id)
        success_count = 0
        total = len(keys_to_revoke)

        for key in keys_to_revoke:
            result = asyncio.run(xui_api.delete_client_on_host(key['host_name'], key['key_email']))
            if result:
                success_count += 1

        # удаляем из БД все ключи пользователя
        delete_user_keys(user_id)

        # уведомление пользователю в Telegram
        try:
            bot = _bot_controller.get_bot_instance()
            if bot:
                text = "❌ Ваша подписка была отозвана администратором."
                loop = current_app.config.get('EVENT_LOOP')
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(bot.send_message(chat_id=user_id, text=text), loop)
                else:
                    asyncio.run(bot.send_message(chat_id=user_id, text=text))
        except Exception:
            pass

        message = (
            f"Все {total} ключей для пользователя {user_id} были успешно отозваны." if success_count == total
            else f"Удалось отозвать {success_count} из {total} ключей для пользователя {user_id}. Проверьте логи."
        )
        category = 'success' if success_count == total else 'warning'

        # Если это AJAX-запрос (из таблицы пользователей) — возвращаем JSON
        wants_json = 'application/json' in (request.headers.get('Accept') or '') or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if wants_json:
            return jsonify({"ok": success_count == total, "message": message, "revoked": success_count, "total": total}), 200

        flash(message, category)
        return redirect(url_for('users_page'))

    @flask_app.route('/users/reset/<int:user_id>', methods=['POST'])
    @login_required
    def reset_user_route(user_id):
        try:
            keys = get_user_keys(user_id) or []
            for k in keys:
                try:
                    asyncio.run(xui_api.delete_client_on_host(k.get('host_name'), k.get('key_email')))
                except Exception:
                    pass
        except Exception:
            pass
        ok = reset_user_state(user_id)
        if ok:
            flash(f'Пользователь {user_id} сброшен. Для него всё начнется сначала.', 'success')
        else:
            flash(f'Не удалось сбросить пользователя {user_id}.', 'danger')
        return redirect(url_for('users_page'))

    @flask_app.route('/add-host', methods=['POST'])
    @login_required
    def add_host_route():
        host_name = request.form['host_name']
        host_url = (request.form.get('host_url') or '').strip()
        remna_api_token = (request.form.get('remna_api_token') or '').strip()
        if not host_url:
            flash("Укажите URL панели.", 'warning')
            return redirect(url_for('settings_page', tab='hosts'))
        if not remna_api_token:
            flash("Укажите API token Remnawave для хоста.", 'warning')
            return redirect(url_for('settings_page', tab='hosts'))

        is_expired_host = (request.form.get('is_expired_host') or '').strip().lower() in {"1", "true", "on", "yes"}
        is_sub_host = (request.form.get('is_sub_host') or '').strip().lower() in {"1", "true", "on", "yes"}
        inbound_raw = (request.form.get('host_inbound_id') or '').strip()
        try:
            inbound_value = int(inbound_raw) if inbound_raw else 0
        except Exception:
            inbound_value = 0
        create_host(
            name=host_name,
            url=host_url,
            user=(request.form.get('host_username') or '').strip() or 'remna',
            passwd=request.form.get('host_pass') or '',
            inbound=inbound_value,
            remna_api_token=remna_api_token,
            remna_internal_squads=(request.form.get('remna_internal_squads') or '').strip() or None,
            remna_external_squad_uuid=(request.form.get('remna_external_squad_uuid') or '').strip() or None,
            remna_tag=(request.form.get('remna_tag') or '').strip() or None,
            subscription_url=(request.form.get('host_subscription_url') or '').strip() or None,
            client_monthly_traffic_gb=(request.form.get('client_monthly_traffic_gb') or '').strip() or None,
            is_expired_host=is_expired_host,
            is_sub_host=is_sub_host,
        )

        migrated_users = 0
        failed_users = 0
        now = datetime.now()
        if is_expired_host:
            flash(
                f"Хост '{host_name}' добавлен в режиме 'Истек'. Клиенты будут создаваться автоматически только после истечения подписки.",
                'success'
            )
            return redirect(url_for('settings_page', tab='hosts'))

        for user in (get_all_users() or []):
            user_id = user.get('telegram_id')
            if not user_id:
                continue

            keys = get_user_keys(int(user_id)) or []
            active_expiry_ms: list[int] = []
            for key in keys:
                try:
                    expiry_raw = key.get('expiry_date')
                    if not expiry_raw:
                        continue
                    expiry_dt = datetime.fromisoformat(str(expiry_raw))
                    if expiry_dt > now:
                        active_expiry_ms.append(int(expiry_dt.timestamp() * 1000))
                except Exception:
                    continue

            if not active_expiry_ms:
                continue

            target_expiry_ms = max(active_expiry_ms)
            host_email = _subscription_email_for_user_host(int(user_id), host_name)
            try:
                result = asyncio.run(
                    xui_api.create_or_update_key_on_host(
                        host_name=host_name,
                        email=host_email,
                        expiry_timestamp_ms=target_expiry_ms,
                        preferred_uuid=get_or_create_user_subscription_uuid(int(user_id)),
                    )
                )
                if not result:
                    failed_users += 1
                    continue

                existing = get_key_by_email(result['email'])
                if existing:
                    update_key_info(existing['key_id'], result['client_uuid'], result['expiry_timestamp_ms'])
                else:
                    add_new_key(
                        user_id=int(user_id),
                        host_name=host_name,
                        xui_client_uuid=result['client_uuid'],
                        key_email=result['email'],
                        expiry_timestamp_ms=result['expiry_timestamp_ms']
                    )
                migrated_users += 1
            except Exception as e:
                failed_users += 1
                logger.warning(
                    f"Автодобавление ключа на новый хост '{host_name}' для пользователя {user_id} завершилось ошибкой: {e}"
                )

        message = (
            f"Хост '{host_name}' успешно добавлен. "
            f"Пользователям с активной подпиской добавлено ключей: {migrated_users}."
        )
        if failed_users:
            message += f" Ошибок при переносе: {failed_users} (подробности в логах)."
        flash(message, 'success' if failed_users == 0 else 'warning')
        return redirect(url_for('settings_page', tab='hosts'))

    @flask_app.route('/delete-host/<host_name>', methods=['POST'])
    @login_required
    def delete_host_route(host_name):
        delete_host(host_name)
        flash(f"Хост '{host_name}' был удален.", 'success')
        return redirect(url_for('settings_page', tab='hosts'))

    @flask_app.route('/add-plan', methods=['POST'])
    @login_required
    def add_plan_route():
        create_plan(
            host_name=request.form.get('host_name', ''),
            plan_name=request.form['plan_name'],
            months=int(request.form['months']),
            price=float(request.form['price'])
        )
        flash("Новый тариф подписки добавлен.", 'success')
        return redirect(url_for('settings_page', tab='plans'))

    @flask_app.route('/delete-plan/<int:plan_id>', methods=['POST'])
    @login_required
    def delete_plan_route(plan_id):
        delete_plan(plan_id)
        flash("Тариф успешно удален.", 'success')
        return redirect(url_for('settings_page', tab='plans'))

    @flask_app.route('/update-plan/<int:plan_id>', methods=['POST'])
    @login_required
    def update_plan_route(plan_id):
        plan_name = (request.form.get('plan_name') or '').strip()
        months = request.form.get('months')
        price = request.form.get('price')
        try:
            months_int = int(months)
            price_float = float(price)
        except (TypeError, ValueError):
            flash('Некорректные значения для месяцев или цены.', 'danger')
            return redirect(url_for('settings_page', tab='plans'))

        if not plan_name:
            flash('Название тарифа не может быть пустым.', 'danger')
            return redirect(url_for('settings_page', tab='plans'))

        ok = update_plan(plan_id, plan_name, months_int, price_float)
        if ok:
            flash('Тариф обновлён.', 'success')
        else:
            flash('Не удалось обновить тариф (возможно, он не найден).', 'danger')
        return redirect(url_for('settings_page', tab='plans'))

    @flask_app.route('/update-plan-visibility/<int:plan_id>', methods=['POST'])
    @login_required
    def update_plan_visibility_route(plan_id: int):
        visible_for_all = (request.form.get('visible_for_all') == 'on')
        allowed_user_ids = (request.form.get('allowed_user_ids') or '').strip()
        ok = update_plan_visibility(plan_id, visible_for_all, allowed_user_ids)
        flash('Настройки видимости тарифа обновлены.' if ok else 'Не удалось обновить видимость тарифа.', 'success' if ok else 'danger')
        return redirect(url_for('settings_page', tab='plans'))

    @flask_app.route('/add-traffic-package', methods=['POST'])
    @login_required
    def add_traffic_package_route():
        try:
            package_gb = float(request.form.get('package_gb', '0'))
            price = float(request.form.get('price', '0'))
        except Exception:
            flash('Некорректные значения пакета трафика.', 'danger')
            return redirect(url_for('settings_page', tab='plans'))
        if package_gb <= 0 or price < 0:
            flash('Укажите корректные значения ГБ и цены.', 'danger')
            return redirect(url_for('settings_page', tab='plans'))
        ok = create_traffic_package(package_gb=package_gb, price=price, is_active=True)
        flash('Пакет трафика добавлен.' if ok else 'Не удалось добавить пакет трафика.', 'success' if ok else 'danger')
        return redirect(url_for('settings_page', tab='plans'))

    @flask_app.route('/update-traffic-package/<int:package_id>', methods=['POST'])
    @login_required
    def update_traffic_package_route(package_id: int):
        try:
            package_gb = float(request.form.get('package_gb', '0'))
            price = float(request.form.get('price', '0'))
            sort_order = int(request.form.get('sort_order', '0') or 0)
            is_active = request.form.get('is_active') == 'on'
        except Exception:
            flash('Некорректные значения пакета трафика.', 'danger')
            return redirect(url_for('settings_page', tab='plans'))
        ok = update_traffic_package(package_id, package_gb, price, is_active, sort_order)
        flash('Пакет трафика обновлён.' if ok else 'Не удалось обновить пакет трафика.', 'success' if ok else 'danger')
        return redirect(url_for('settings_page', tab='plans'))

    @flask_app.route('/delete-traffic-package/<int:package_id>', methods=['POST'])
    @login_required
    def delete_traffic_package_route(package_id: int):
        ok = delete_traffic_package(package_id)
        flash('Пакет трафика удалён.' if ok else 'Не удалось удалить пакет трафика.', 'success' if ok else 'danger')
        return redirect(url_for('settings_page', tab='plans'))

    @csrf.exempt
    @flask_app.route('/yookassa-webhook', methods=['POST'])
    def yookassa_webhook_handler():
        try:
            event_json = request.json
            if event_json.get("event") == "payment.succeeded":
                metadata = event_json.get("object", {}).get("metadata", {})
                
                bot = _bot_controller.get_bot_instance()
                payment_processor = handlers.process_successful_payment

                if metadata and bot is not None and payment_processor is not None:
                    loop = current_app.config.get('EVENT_LOOP')
                    if loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(payment_processor(bot, metadata), loop)
                    else:
                        logger.error("YooKassa вебхук: цикл событий недоступен!")
            return 'OK', 200
        except Exception as e:
            logger.error(f"Ошибка в обработчике вебхука YooKassa: {e}", exc_info=True)
            return 'Error', 500
        
    @csrf.exempt
    @flask_app.route('/cryptobot-webhook', methods=['POST'])
    def cryptobot_webhook_handler():
        try:
            request_data = request.json
            
            if request_data and request_data.get('update_type') == 'invoice_paid':
                payload_data = request_data.get('payload', {})
                
                payload_string = payload_data.get('payload')
                
                if not payload_string:
                    logger.warning("CryptoBot вебхук: Получен оплаченный invoice, но payload пустой.")
                    return 'OK', 200

                metadata = find_and_complete_pending_transaction(
                    payment_id=payload_string,
                    amount_rub=None,
                    payment_method="CryptoBot",
                    currency_name="USDT",
                    amount_currency=None,
                )
                if not metadata:
                    logger.error(f"CryptoBot вебхук: не удалось завершить pending transaction '{payload_string}'")
                    return 'Error', 400
                
                bot = _bot_controller.get_bot_instance()
                loop = current_app.config.get('EVENT_LOOP')
                payment_processor = handlers.process_successful_payment

                if bot and loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(payment_processor(bot, metadata), loop)
                else:
                    logger.error("CryptoBot вебхук: не удалось обработать платёж — бот или цикл событий не запущены.")

            return 'OK', 200
            
        except Exception as e:
            logger.error(f"Ошибка в обработчике вебхука CryptoBot: {e}", exc_info=True)
            return 'Error', 500
        
    @csrf.exempt
    @flask_app.route('/heleket-webhook', methods=['POST'])
    def heleket_webhook_handler():
        try:
            data = request.json
            logger.info(f"Получен вебхук Heleket: {data}")

            api_key = get_setting("heleket_api_key")
            if not api_key: return 'Error', 500

            sign = data.pop("sign", None)
            if not sign: return 'Error', 400
                
            sorted_data_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
            
            base64_encoded = base64.b64encode(sorted_data_str.encode()).decode()
            raw_string = f"{base64_encoded}{api_key}"
            expected_sign = hashlib.md5(raw_string.encode()).hexdigest()

            if not compare_digest(expected_sign, sign):
                logger.warning("Heleket вебхук: недействительная подпись.")
                return 'Forbidden', 403

            if data.get('status') in ["paid", "paid_over"]:
                metadata_str = data.get('description')
                if not metadata_str: return 'Error', 400
                
                metadata = json.loads(metadata_str)
                
                bot = _bot_controller.get_bot_instance()
                loop = current_app.config.get('EVENT_LOOP')
                payment_processor = handlers.process_successful_payment

                if bot and loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(payment_processor(bot, metadata), loop)
            
            return 'OK', 200
        except Exception as e:
            logger.error(f"Ошибка в обработчике вебхука Heleket: {e}", exc_info=True)
            return 'Error', 500

    @csrf.exempt
    @flask_app.route('/platega-webhook', methods=['POST'])
    def platega_webhook_handler():
        try:
            payload = request.get_json(silent=True) or {}
            logger.info(f"Получен вебхук Platega: {payload}")

            expected_merchant = (get_setting("platega_merchant_id") or "").strip()
            expected_secret = (get_setting("platega_secret_key") or "").strip()
            header_merchant = (request.headers.get("X-MerchantId") or "").strip()
            header_secret = (request.headers.get("X-Secret") or "").strip()

            if expected_merchant and not compare_digest(expected_merchant, header_merchant):
                logger.warning("Platega вебхук: недействительный X-MerchantId.")
                return 'Forbidden', 403
            if expected_secret and not compare_digest(expected_secret, header_secret):
                logger.warning("Platega вебхук: недействительный X-Secret.")
                return 'Forbidden', 403

            tx_obj = payload.get("transaction") if isinstance(payload.get("transaction"), dict) else {}
            payment_details = payload.get("paymentDetails") if isinstance(payload.get("paymentDetails"), dict) else {}

            transaction_id = str(
                payload.get("transactionId")
                or payload.get("id")
                or tx_obj.get("transactionId")
                or tx_obj.get("id")
                or ""
            ).strip()
            status = str(
                payload.get("status")
                or payload.get("state")
                or payload.get("transactionStatus")
                or tx_obj.get("status")
                or tx_obj.get("state")
                or ""
            ).upper()

            amount_raw = payment_details.get("amount", payload.get("amount"))
            currency_name = payment_details.get("currency") or payload.get("currency") or "RUB"
            try:
                amount_value = float(amount_raw) if amount_raw is not None else None
            except Exception:
                amount_value = None

            if not transaction_id:
                logger.warning("Platega вебхук: не найден transaction_id в payload.")
                return 'OK', 200

            if status in {"CONFIRMED", "PAID", "SUCCESS", "COMPLETED"}:
                amount_rub = amount_value if str(currency_name).upper() == "RUB" else None
                metadata = find_and_complete_pending_transaction(
                    payment_id=transaction_id,
                    amount_rub=amount_rub,
                    payment_method="Platega",
                    currency_name=str(currency_name) if currency_name else None,
                    amount_currency=amount_value,
                )
                if metadata:
                    bot = _bot_controller.get_bot_instance()
                    loop = current_app.config.get('EVENT_LOOP')
                    payment_processor = handlers.process_successful_payment
                    if bot and loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(payment_processor(bot, metadata), loop)
                    else:
                        logger.error("Platega вебхук: не удалось обработать платёж — бот или цикл событий не запущены.")
                else:
                    logger.info(f"Platega вебхук: pending-транзакция не найдена/уже обработана: {transaction_id}")

            return 'OK', 200
        except Exception as e:
            logger.error(f"Ошибка в обработчике вебхука Platega: {e}", exc_info=True)
            return 'Error', 500
        
    @csrf.exempt
    @flask_app.route('/ton-webhook', methods=['POST'])
    def ton_webhook_handler():
        try:
            data = request.json
            logger.info(f"Получен вебхук TonAPI: {data}")

            if 'tx_id' in data:
                account_id = data.get('account_id')
                for tx in data.get('in_progress_txs', []) + data.get('txs', []):
                    in_msg = tx.get('in_msg')
                    if in_msg and in_msg.get('decoded_comment'):
                        payment_id = in_msg['decoded_comment']
                        amount_nano = int(in_msg.get('value', 0))
                        amount_ton = float(amount_nano / 1_000_000_000)

                        metadata = find_and_complete_ton_transaction(payment_id, amount_ton)
                        
                        if metadata:
                            logger.info(f"TON Платеж успешен для payment_id: {payment_id}")
                            bot = _bot_controller.get_bot_instance()
                            loop = current_app.config.get('EVENT_LOOP')
                            payment_processor = handlers.process_successful_payment

                            if bot and loop and loop.is_running():
                                asyncio.run_coroutine_threadsafe(payment_processor(bot, metadata), loop)
            
            return 'OK', 200
        except Exception as e:
            logger.error(f"Ошибка в обработчике вебхука TonAPI: {e}", exc_info=True)
            return 'Error', 500

    # --- YooMoney OAuth integration ---
    def _ym_get_redirect_uri():
        try:
            saved = (get_setting("yoomoney_redirect_uri") or "").strip()
        except Exception:
            saved = ""
        if saved:
            return saved
        # Fallback: build from current host
        root = request.url_root.rstrip('/')
        return f"{root}/yoomoney/callback"

    @flask_app.route('/yoomoney/connect')
    @login_required
    def yoomoney_connect_route():
        client_id = (get_setting('yoomoney_client_id') or '').strip()
        if not client_id:
            flash('Укажите YooMoney client_id в настройках.', 'warning')
            return redirect(url_for('settings_page', tab='payments'))
        redirect_uri = _ym_get_redirect_uri()
        scope = 'operation-history operation-details account-info'
        qs = urllib.parse.urlencode({
            'client_id': client_id,
            'response_type': 'code',
            'scope': scope,
            'redirect_uri': redirect_uri,
        })
        url = f"https://yoomoney.ru/oauth/authorize?{qs}"
        return redirect(url)

    @csrf.exempt
    @flask_app.route('/yoomoney/callback')
    def yoomoney_callback_route():
        code = (request.args.get('code') or '').strip()
        if not code:
            flash('YooMoney: не получен code из OAuth.', 'danger')
            return redirect(url_for('settings_page', tab='payments'))
        client_id = (get_setting('yoomoney_client_id') or '').strip()
        client_secret = (get_setting('yoomoney_client_secret') or '').strip()
        redirect_uri = _ym_get_redirect_uri()
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': client_id,
            'redirect_uri': redirect_uri,
        }
        if client_secret:
            data['client_secret'] = client_secret
        try:
            encoded = urllib.parse.urlencode(data).encode('utf-8')
            req = urllib.request.Request('https://yoomoney.ru/oauth/token', data=encoded, headers={'Content-Type': 'application/x-www-form-urlencoded'})
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_text = resp.read().decode('utf-8', errors='ignore')
            try:
                payload = json.loads(resp_text)
            except Exception:
                payload = {}
            token = (payload.get('access_token') or '').strip()
            if not token:
                flash(f"Не удалось получить access_token от YooMoney: {payload}", 'danger')
                return redirect(url_for('settings_page', tab='payments'))
            update_setting('yoomoney_api_token', token)
            flash('YooMoney: токен успешно сохранён.', 'success')
        except Exception as e:
            logger.error(f"YooMoney OAuth callback ошибка: {e}", exc_info=True)
            flash(f'Ошибка при обмене кода на токен: {e}', 'danger')
        return redirect(url_for('settings_page', tab='payments'))

    @flask_app.route('/yoomoney/check', methods=['GET','POST'])
    @login_required
    def yoomoney_check_route():
        token = (get_setting('yoomoney_api_token') or '').strip()
        if not token:
            flash('YooMoney: токен не задан.', 'warning')
            return redirect(url_for('settings_page', tab='payments'))
        # 1) account-info
        try:
            req = urllib.request.Request('https://yoomoney.ru/api/account-info', headers={'Authorization': f'Bearer {token}'}, method='POST')
            with urllib.request.urlopen(req, timeout=15) as resp:
                ai_text = resp.read().decode('utf-8', errors='ignore')
                ai_status = resp.status
                ai_headers = dict(resp.headers)
        except Exception as e:
            flash(f'YooMoney account-info: ошибка запроса: {e}', 'danger')
            return redirect(url_for('settings_page', tab='payments'))
        try:
            ai = json.loads(ai_text)
        except Exception:
            ai = {}
        if ai_status != 200:
            www = ai_headers.get('WWW-Authenticate', '')
            flash(f"YooMoney account-info HTTP {ai_status}. {www}", 'danger')
            return redirect(url_for('settings_page', tab='payments'))
        account = ai.get('account') or ai.get('account_number') or '—'
        # 2) operation-history minimal
        try:
            body = urllib.parse.urlencode({'records': '1'}).encode('utf-8')
            req2 = urllib.request.Request('https://yoomoney.ru/api/operation-history', data=body, headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/x-www-form-urlencoded'})
            with urllib.request.urlopen(req2, timeout=15) as resp2:
                oh_text = resp2.read().decode('utf-8', errors='ignore')
                oh_status = resp2.status
        except Exception as e:
            flash(f'YooMoney operation-history: ошибка запроса: {e}', 'warning')
            oh_status = None
        if oh_status == 200:
            flash(f'YooMoney: токен валиден. Кошелёк: {account}', 'success')
        elif oh_status is not None:
            flash(f'YooMoney operation-history HTTP {oh_status}. Проверьте scope operation-history и соответствие кошелька.', 'danger')
        else:
            flash('YooMoney: не удалось проверить operation-history.', 'warning')
        return redirect(url_for('settings_page', tab='payments'))

    # --- Button Constructor ---
    @flask_app.route('/button-constructor')
    @login_required
    def button_constructor_page():
        """Button constructor page"""
        template_data = get_common_template_data()
        return render_template('button_constructor.html', **template_data)

    # --- Button Constructor API ---
    @flask_app.route('/api/button-configs', methods=['GET', 'POST'])
    @login_required
    def button_configs_api():
        if request.method == 'GET':
            menu_type = request.args.get('menu_type', 'main_menu')
            try:
                from shop_bot.data_manager.database import get_button_configs
                configs = get_button_configs(menu_type)
                return jsonify({"success": True, "data": configs})
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 500
        
        elif request.method == 'POST':
            try:
                data = request.get_json()
                from shop_bot.data_manager.database import create_button_config
                button_id = create_button_config(data)
                if button_id:
                    return jsonify({"success": True, "id": button_id})
                else:
                    return jsonify({"success": False, "error": "Failed to create button config"}), 500
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 500

    @flask_app.route('/api/button-configs/<menu_type>', methods=['GET'])
    @login_required
    def button_configs_by_menu_api(menu_type):
        try:
            from shop_bot.data_manager.database import get_button_configs
            configs = get_button_configs(menu_type)
            return jsonify({"success": True, "data": configs})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @flask_app.route('/api/button-configs/<int:button_id>', methods=['PUT', 'DELETE'])
    @login_required
    def button_config_api(button_id):
        if request.method == 'PUT':
            try:
                data = request.get_json()
                from shop_bot.data_manager.database import update_button_config
                success = update_button_config(button_id, data)
                if success:
                    return jsonify({"success": True})
                else:
                    return jsonify({"success": False, "error": "Button config not found or update failed"}), 404
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 500
        
        elif request.method == 'DELETE':
            try:
                from shop_bot.data_manager.database import delete_button_config
                success = delete_button_config(button_id)
                if success:
                    return jsonify({"success": True})
                else:
                    return jsonify({"success": False, "error": "Button config not found"}), 404
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 500

    @flask_app.route('/api/button-configs/<menu_type>/reorder', methods=['POST'])
    @login_required
    def button_configs_reorder_api(menu_type):
        try:
            data = request.get_json()
            button_orders = data.get('button_orders', [])
            from shop_bot.data_manager.database import reorder_button_configs
            success = reorder_button_configs(menu_type, button_orders)
            if success:
                return jsonify({"success": True})
            else:
                return jsonify({"success": False, "error": "Failed to reorder buttons"}), 500
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    
    @flask_app.route('/api/button-configs/force-migration', methods=['POST'])
    @login_required
    def force_button_migration_api():
        """Принудительная миграция кнопок."""
        try:
            from shop_bot.data_manager.database import force_button_migration
            success = force_button_migration()
            if success:
                return jsonify({"success": True, "message": "Миграция кнопок выполнена успешно"})
            else:
                return jsonify({"success": False, "error": "Миграция не удалась"}), 500
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # --- YooMoney Webhook ---
    @csrf.exempt
    @flask_app.route('/yoomoney-webhook', methods=['POST'])
    def yoomoney_webhook_handler():
        """ЮMoney HTTP уведомление (кнопка/ссылка p2p). Подпись: sha1(notification_type&operation_id&amount&currency&datetime&sender&codepro&notification_secret&label)."""
        logger.info("🔔 Получен webhook от ЮMoney")
        
        try:
            form = request.form
            logger.info(f"YooMoney webhook data: {dict(form)}")
            
            # Проверяем, что это тестовый платеж
            if form.get('codepro') == 'true':
                logger.info("🧪 Игнорируем тестовый платеж (codepro=true)")
                return 'OK', 200
            
            secret = get_setting('yoomoney_secret') or ''
            signature_str = "&".join([
                form.get('notification_type',''),
                form.get('operation_id',''),
                form.get('amount',''),
                form.get('currency',''),
                form.get('datetime',''),
                form.get('sender',''),
                form.get('codepro',''),
                secret,
                form.get('label','')
            ])
            
            import hashlib
            expected_signature = hashlib.sha1(signature_str.encode('utf-8')).hexdigest()
            received_signature = form.get('sha1_hash', '')
            
            if not compare_digest(expected_signature, received_signature):
                logger.warning("YooMoney webhook: неверная подпись")
                return 'Forbidden', 403
            
            # Обрабатываем успешный платеж
            if form.get('notification_type') == 'p2p-incoming':
                amount = float(form.get('amount', 0))
                label = form.get('label', '')
                
                # Здесь должна быть логика обработки платежа
                logger.info(f"YooMoney payment: {amount} RUB, label: {label}")
                
                # Уведомляем бота о платеже
                try:
                    bot = _bot_controller.get_bot_instance()
                    if bot:
                        # Здесь должна быть логика обработки платежа через handlers
                        pass
                except Exception as e:
                    logger.error(f"YooMoney webhook: ошибка уведомления бота: {e}")
            
            return 'OK', 200
            
        except Exception as e:
            logger.error(f"YooMoney webhook ошибка: {e}", exc_info=True)
            return 'Error', 500

    return flask_app
