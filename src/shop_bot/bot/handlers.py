import logging
import os
import uuid
import qrcode
import aiohttp
import calendar
import re
import aiohttp
import json
import base64
import asyncio
import hashlib

from urllib.parse import urlencode
from hmac import compare_digest
from functools import wraps
from yookassa import Payment
from io import BytesIO
from datetime import datetime, timedelta
from aiosend import CryptoPay, TESTNET
from decimal import Decimal, ROUND_HALF_UP
from typing import Dict, Optional

from pytonconnect import TonConnect
from pytonconnect.exceptions import UserRejectsError
from aiogram import Bot, Router, F, types, html
from aiogram.types import BufferedInputFile, FSInputFile
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.filters import Command, CommandObject, CommandStart, StateFilter
from aiogram.exceptions import TelegramBadRequest
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import StatesGroup, State
from aiogram.enums import ChatMemberStatus
from aiogram.utils.keyboard import InlineKeyboardBuilder

from shop_bot.bot import keyboards
from shop_bot.modules import xui_api
from shop_bot.data_manager.database import (
    get_user, add_new_key, get_user_keys, update_user_stats,
    register_user_if_not_exists, get_next_key_number, get_key_by_id,
    update_key_info, set_trial_used, set_terms_agreed, get_setting, get_all_hosts,
    get_plans_for_host, get_all_plans, get_all_plans_for_user, get_plan_by_id, log_transaction, get_referral_count,
    create_pending_transaction, get_all_users,
    create_support_ticket, add_support_message, get_user_tickets,
    get_ticket, get_ticket_messages, set_ticket_status, update_ticket_thread_info,
    get_ticket_by_thread,
    update_key_host_and_info,
    get_balance, deduct_from_balance,
    get_key_by_email, add_to_balance,
    add_to_referral_balance_all, get_referral_balance_all,
    get_referral_balance,
    get_host,
    get_user_device_limit,
    get_or_create_user_subscription_uuid,
    rotate_user_subscription_token,
    update_user_subscription_state,
    is_admin,
    set_referral_start_bonus_received,
    find_and_complete_pending_transaction,
    check_promo_code_available,
    redeem_promo_code,
    update_promo_code_status,
    get_admin_ids,
    delete_key_by_id,
    get_active_traffic_packages,
    get_traffic_package_by_id,
    create_traffic_package_purchase,
    get_total_extra_traffic_gb_for_user,
    get_extra_traffic_gb_for_user_key,
)
from shop_bot.config import (
    CHOOSE_PLAN_MESSAGE,
    CHOOSE_PAYMENT_METHOD_MESSAGE,
    VPN_INACTIVE_TEXT,
    VPN_NO_DATA_TEXT,
    get_profile_text,
    get_vpn_active_text,
    get_key_info_text,
)

TELEGRAM_BOT_USERNAME = get_setting("telegram_bot_username")
PAYMENT_METHODS: dict = {}
ADMIN_ID = int(get_setting("admin_id")) if get_setting("admin_id") else None
CRYPTO_BOT_TOKEN = get_setting("cryptobot_token")

logger = logging.getLogger(__name__)

class KeyPurchase(StatesGroup):
    waiting_for_host_selection = State()
    waiting_for_plan_selection = State()

class Onboarding(StatesGroup):
    waiting_for_subscription_and_agreement = State()

class PaymentProcess(StatesGroup):
    waiting_for_email = State()
    waiting_for_payment_method = State()
    waiting_for_promo_code = State()
    waiting_for_cryptobot_payment = State()

 
class TopUpProcess(StatesGroup):
    waiting_for_amount = State()
    waiting_for_topup_method = State()
    waiting_for_cryptobot_topup_payment = State()


class SupportDialog(StatesGroup):
    waiting_for_subject = State()
    waiting_for_message = State()
    waiting_for_reply = State()

def is_valid_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None

def _get_unified_subscription_url_for_user(user_id: int) -> str | None:
    try:
        return xui_api.build_unified_subscription_url(user_id)
    except Exception:
        return None

async def _get_connect_subscription_url_from_subscription_1(user_id: int) -> str | None:
    # Always build the current unified subscription URL dynamically.
    # The selected host with flag "САБ" determines which host-specific
    # subscription base will be shown to the user.
    return _get_unified_subscription_url_for_user(user_id)

async def _apply_bonus_days_to_user(user_id: int, days: int) -> int:
    if days <= 0:
        return 0
    keys = get_user_keys(user_id) or []
    updated = 0
    for key in keys:
        host_name = key.get("host_name")
        key_email = key.get("key_email")
        if not host_name or not key_email:
            continue
        try:
            result = await xui_api.create_or_update_key_on_host(
                host_name=host_name,
                email=key_email,
                days_to_add=int(days)
            )
            if result:
                update_key_info(key.get("key_id"), result['client_uuid'], result['expiry_timestamp_ms'])
                updated += 1
        except Exception as e:
            logger.warning(f"Не удалось применить бонус днями для user={user_id}, key_id={key.get('key_id')}: {e}")
    return updated

def _host_slug(host_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "", (host_name or "").lower())
    return slug[:8] or "host"

def _get_regular_hosts() -> list[dict]:
    return [h for h in (get_all_hosts() or []) if int(h.get("is_expired_host") or 0) != 1]

def _get_expired_hosts() -> list[dict]:
    return [h for h in (get_all_hosts() or []) if int(h.get("is_expired_host") or 0) == 1]

def _make_unique_email(base_local: str, host_name: str) -> str:
    host_part = _host_slug(host_name)
    local = f"{base_local}.{host_part}"[:48].strip(".")
    candidate = f"{local}@bot.local"
    attempt = 1
    while get_key_by_email(candidate):
        attempt += 1
        suffix = f"-{attempt}"
        trimmed = local[: max(1, 48 - len(suffix))]
        candidate = f"{trimmed}{suffix}@bot.local"
        if attempt > 100:
            candidate = f"{base_local}.{host_part}.{int(datetime.now().timestamp())}@bot.local"
            break
    return candidate

def _subscription_email_for_user_host(user_id: int, host_name: str) -> str:
    host_part = _host_slug(host_name)
    digest = hashlib.sha1(f"{user_id}:{host_name}".encode("utf-8")).hexdigest()[:10]
    return f"u{user_id}.{host_part}.{digest}@bot.local"

def _add_calendar_months(base_dt: datetime, months: int) -> datetime:
    m = max(0, int(months or 0))
    if m <= 0:
        return base_dt
    year = base_dt.year + (base_dt.month - 1 + m) // 12
    month = (base_dt.month - 1 + m) % 12 + 1
    day = min(base_dt.day, calendar.monthrange(year, month)[1])
    return base_dt.replace(year=year, month=month, day=day)

def _is_whitelist_host_name(host_name: str | None) -> bool:
    name = (host_name or "").lower()
    return ("белые списки" in name) or ("white list" in name) or ("whitelist" in name)

def _resolve_host_limit_gb_for_profile(host_data: dict | None, host_name: str | None) -> float:
    try:
        explicit = float((host_data or {}).get("client_monthly_traffic_gb") or 0)
    except Exception:
        explicit = 0.0
    if explicit > 0:
        return explicit
    if _is_whitelist_host_name(host_name):
        return 200.0
    return 0.0

def format_traffic(value_bytes: int | float | None) -> str:
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

def _key_server_and_panel_identity(key_data: dict) -> tuple[str, str]:
    server_id = str(
        key_data.get("server_id")
        or key_data.get("host_name")
        or ""
    ).strip()
    panel_email = str(
        key_data.get("panel_email")
        or key_data.get("key_email")
        or ""
    ).strip()
    return server_id, panel_email

async def _get_live_traffic_stats_for_key(key_data: dict) -> dict | None:
    server_id, panel_email = _key_server_and_panel_identity(key_data)
    if not server_id or not panel_email:
        return None
    client_host = await xui_api.get_client(server_id)
    if not client_host:
        return None
    stats = await xui_api.get_client_stats(client_host, panel_email)
    if not stats:
        return None
    try:
        up = max(int(stats.get("up") or 0), 0)
        down = max(int(stats.get("down") or 0), 0)
        total = max(int(stats.get("total") or 0), 0)
    except Exception:
        return None
    return {"up": up, "down": down, "total": total}

async def _build_subscription_traffic_summary(user_keys: list[dict], user_id: int | None = None) -> dict:
    subscription_keys = user_keys or []
    traffic_tasks = [_get_live_traffic_stats_for_key(k) for k in subscription_keys]
    traffic_results = await asyncio.gather(*traffic_tasks, return_exceptions=True) if traffic_tasks else []

    main_used = 0
    whitelist_used = 0
    whitelist_total = 0
    main_has_source = False
    main_has_ok = False
    whitelist_has_source = False
    whitelist_has_ok = False

    for key_data, result in zip(subscription_keys, traffic_results):
        host_name = key_data.get("host_name")
        try:
            host_data = get_host(host_name)
        except Exception:
            host_data = None
        host_limit_gb = _resolve_host_limit_gb_for_profile(host_data, host_name)

        if isinstance(result, Exception) or not result:
            if host_limit_gb > 0:
                whitelist_has_source = True
            else:
                main_has_source = True
            continue

        up = max(int(result.get("up") or 0), 0)
        down = max(int(result.get("down") or 0), 0)
        total = max(int(result.get("total") or 0), 0)
        used = up + down
        extra_for_key_gb = 0.0
        if user_id is not None:
            try:
                extra_for_key_gb = float(
                    get_extra_traffic_gb_for_user_key(
                        int(user_id),
                        str(host_name or ""),
                        str(key_data.get("key_email") or ""),
                    ) or 0.0
                )
            except Exception:
                extra_for_key_gb = 0.0

        if total > 0 or host_limit_gb > 0:
            whitelist_has_source = True
            whitelist_has_ok = True
            whitelist_used += used
            expected_total = int((host_limit_gb + extra_for_key_gb) * (1024 ** 3)) if host_limit_gb > 0 else 0
            whitelist_total += max(total, expected_total)
        else:
            main_has_source = True
            main_has_ok = True
            main_used += used

    if main_has_source:
        main_usage_text = f"{format_traffic(main_used)} / ∞" if main_has_ok else "Недоступно"
    else:
        main_usage_text = "0 Б / ∞"

    if whitelist_has_source:
        if whitelist_has_ok:
            wl_total_text = format_traffic(whitelist_total) if whitelist_total > 0 else "Безлимит"
            whitelist_usage_text = f"{format_traffic(whitelist_used)} / {wl_total_text}"
        else:
            whitelist_usage_text = "Недоступно"
    else:
        whitelist_usage_text = "0 Б / Безлимит"

    extra_traffic_gb = 0.0
    if user_id is not None:
        try:
            extra_traffic_gb = float(get_total_extra_traffic_gb_for_user(int(user_id)) or 0.0)
        except Exception:
            extra_traffic_gb = 0.0

    return {
        "main_usage_text": main_usage_text,
        "whitelist_usage_text": whitelist_usage_text,
        "whitelist_used_text": format_traffic(whitelist_used),
        "whitelist_total_text": (format_traffic(whitelist_total) if whitelist_total > 0 else "Безлимит"),
        "extra_traffic_text": (f"{extra_traffic_gb:.0f} ГБ" if extra_traffic_gb > 0 else "0 ГБ"),
        "reset_text": "1 числа каждого месяца",
    }

async def _safe_edit_or_send(
    message: types.Message,
    text: str,
    reply_markup=None,
    disable_web_page_preview: bool = False,
    **kwargs,
):
    try:
        if getattr(message, "photo", None):
            caption_kwargs = dict(kwargs)
            caption_kwargs.pop("disable_web_page_preview", None)
            await message.edit_caption(caption=text, reply_markup=reply_markup, **caption_kwargs)
        else:
            await message.edit_text(
                text,
                reply_markup=reply_markup,
                disable_web_page_preview=disable_web_page_preview,
                **kwargs,
            )
        return
    except TelegramBadRequest:
        pass
    try:
        await message.delete()
    except Exception:
        pass
    await message.answer(
        text,
        reply_markup=reply_markup,
        disable_web_page_preview=disable_web_page_preview,
        **kwargs,
    )

def _get_primary_host_with_plans(user_id: int | None = None) -> tuple[str | None, list]:
    hosts = _get_regular_hosts()
    if not hosts:
        return None, []

    global_plans = (get_all_plans_for_user(user_id) if user_id is not None else get_all_plans()) or []
    if global_plans:
        first_host = hosts[0].get("host_name")
        return first_host, global_plans

    for host in hosts:
        host_name = host.get("host_name")
        if not host_name:
            continue
        plans = get_plans_for_host(host_name) or []
        if plans:
            return host_name, plans
    first_name = hosts[0].get("host_name")
    return first_name, (get_plans_for_host(first_name) if first_name else [])

def _checkout_month_word(months: int) -> str:
    if months % 10 == 1 and months % 100 != 11:
        return "месяц"
    if months % 10 in (2, 3, 4) and months % 100 not in (12, 13, 14):
        return "месяца"
    return "месяцев"

def _resolve_checkout_context(user_id: int, state_data: dict) -> dict | None:
    action = (state_data.get("action") or "").strip()
    if action == "traffic_package":
        package_id_raw = state_data.get("traffic_package_id")
        try:
            package_id = int(package_id_raw)
        except Exception:
            return None
        package = get_traffic_package_by_id(package_id)
        if not package or int(package.get("is_active") or 0) != 1:
            return None
        package_gb = float(package.get("package_gb") or 0)
        price = Decimal(str(package.get("price") or 0)).quantize(Decimal("0.01"))
        if package_gb <= 0:
            return None
        return {
            "kind": "traffic_package",
            "package": package,
            "package_id": package_id,
            "package_gb": package_gb,
            "price": price,
            "title": f"Пакет трафика {package_gb:.0f} ГБ",
            "description": f"q1 vpn - пакет трафика {package_gb:.0f} ГБ",
            "payment_description": f"Пакет трафика {package_gb:.0f} ГБ",
            "metadata": {
                "user_id": user_id,
                "action": "traffic_package",
                "traffic_package_id": package_id,
                "traffic_gb": package_gb,
                "price": float(price),
                "payment_method": None,
                "customer_email": state_data.get("customer_email"),
            },
        }

    plan_id_raw = state_data.get("plan_id")
    try:
        plan_id = int(plan_id_raw)
    except Exception:
        return None
    plan = get_plan_by_id(plan_id)
    if not plan:
        return None

    price = Decimal(str(plan['price'])).quantize(Decimal("0.01"))
    user_data = get_user(user_id)
    if user_data and user_data.get('referred_by') and user_data.get('total_spent', 0) == 0:
        try:
            discount_percentage = Decimal(get_setting("referral_discount") or "0")
        except Exception:
            discount_percentage = Decimal("0")
        if discount_percentage > 0:
            discount_amount = (price * discount_percentage / 100).quantize(Decimal("0.01"))
            price = (price - discount_amount).quantize(Decimal("0.01"))

    final_price_from_state = state_data.get('final_price')
    if final_price_from_state is not None:
        try:
            price = Decimal(str(final_price_from_state)).quantize(Decimal("0.01"))
        except Exception:
            pass
    if price < Decimal('0'):
        price = Decimal('0.00')

    months = int(plan['months'])
    month_word = _checkout_month_word(months)
    return {
        "kind": "subscription",
        "plan": plan,
        "plan_id": plan_id,
        "months": months,
        "price": price,
        "title": plan.get("plan_name") or f"{months} {month_word}",
        "description": f"q1 vpn - {months} {month_word}",
        "payment_description": f"Подписка на {months} мес.",
        "metadata": {
            "user_id": user_id,
            "months": months,
            "price": float(price),
            "action": state_data.get('action'),
            "key_id": state_data.get('key_id'),
            "host_name": state_data.get('host_name'),
            "plan_id": plan_id,
            "customer_email": state_data.get('customer_email'),
            "payment_method": None,
            "promo_code": state_data.get('promo_code'),
            "promo_discount_percent": state_data.get('promo_discount_percent'),
            "promo_discount_amount": state_data.get('promo_discount_amount'),
        },
    }

async def _apply_traffic_package_to_user(user_id: int, package_gb: float) -> tuple[int, int]:
    keys = get_user_keys(user_id) or []
    processed = 0
    success = 0
    purchase_token = uuid.uuid4().hex
    seen: set[tuple[str, str]] = set()
    for key in keys:
        host_name = (key.get("host_name") or "").strip()
        email = (key.get("key_email") or "").strip()
        if not host_name or not email:
            continue
        host = get_host(host_name)
        if not host:
            continue
        try:
            host_limit = float(host.get("client_monthly_traffic_gb") or 0)
        except Exception:
            host_limit = 0
        if host_limit <= 0:
            continue
        ident = (host_name, email)
        if ident in seen:
            continue
        seen.add(ident)
        processed += 1
        try:
            ok = await xui_api.increase_client_traffic_limit_on_host(host_name, email, package_gb)
        except Exception:
            ok = False
        if ok:
            try:
                create_traffic_package_purchase(user_id, host_name, email, package_gb, purchase_token=purchase_token)
            except Exception:
                pass
            success += 1
    return processed, success

def _checkout_metadata_for_payment(checkout: dict, state_data: dict, payment_method: str, extra: dict | None = None) -> dict:
    metadata = dict(checkout.get("metadata") or {})
    metadata["payment_method"] = payment_method
    metadata["customer_email"] = state_data.get("customer_email")
    if checkout.get("kind") == "subscription":
        metadata["promo_code"] = state_data.get("promo_code")
        metadata["promo_discount_percent"] = state_data.get("promo_discount_percent")
        metadata["promo_discount_amount"] = state_data.get("promo_discount_amount")
    if extra:
        metadata.update(extra)
    return metadata

async def _remove_expired_hosts_clients(user_id: int):
    expired_hosts = _get_expired_hosts()
    if not expired_hosts:
        return
    for host in expired_hosts:
        host_name = host.get("host_name")
        if not host_name:
            continue
        host_email = _subscription_email_for_user_host(user_id, host_name)
        try:
            await xui_api.delete_client_on_host(host_name, host_email)
        except Exception as e:
            logger.warning(
                f"Не удалось удалить client для user={user_id} на expired-host '{host_name}': {e}"
            )

async def show_main_menu(message: types.Message, edit_message: bool = False):
    user_id = message.chat.id
    user_db_data = get_user(user_id)
    user_keys = get_user_keys(user_id)
    
    trial_available = not (user_db_data and user_db_data.get('trial_used'))
    # Trial is available only before first paid subscription.
    if user_db_data and int(user_db_data.get('total_months') or 0) > 0:
        trial_available = False
    is_admin_flag = is_admin(user_id)

    text = (
        "⚡️ <b>Добро пожаловать в q1 vpn - интернет без ограничений!</b>\n\n"
        "👇 Выберите нужный пункт в меню ниже"
    )
    now = datetime.now()
    has_active_subscription = any(
        datetime.fromisoformat(k['expiry_date']) > now
        for k in user_keys
        if k.get('expiry_date')
    )
    keyboard = keyboards.create_main_menu_keyboard(
        user_keys,
        trial_available,
        is_admin_flag,
        has_active_subscription=has_active_subscription
    )
    logo_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "logo", "vpnbot.jpg")
    )
    if os.path.isfile(logo_path):
        try:
            if edit_message:
                try:
                    if getattr(message, "photo", None):
                        await message.edit_caption(caption=text, reply_markup=keyboard)
                    else:
                        try:
                            await message.delete()
                        except Exception:
                            pass
                        await message.answer_photo(photo=FSInputFile(logo_path), caption=text, reply_markup=keyboard)
                except TelegramBadRequest:
                    try:
                        await message.delete()
                    except Exception:
                        pass
                    await message.answer_photo(photo=FSInputFile(logo_path), caption=text, reply_markup=keyboard)
            else:
                await message.answer_photo(photo=FSInputFile(logo_path), caption=text, reply_markup=keyboard)
            return
        except Exception as e:
            logger.warning(f"Не удалось отправить изображение главного меню: {e}")

    if edit_message:
        try:
            await _safe_edit_or_send(message, text, reply_markup=keyboard)
        except TelegramBadRequest:
            pass
    else:
        await message.answer(text, reply_markup=keyboard)

async def process_successful_onboarding(callback: types.CallbackQuery, state: FSMContext):
    """Завершает онбординг: ставит флаг согласия и открывает главное меню."""
    user_id = callback.from_user.id
    try:
        set_terms_agreed(user_id)
    except Exception as e:
        logger.error(f"Не удалось установить согласие с условиями для пользователя {user_id}: {e}")
    try:
        await callback.answer()
    except Exception:
        pass
    try:
        await show_main_menu(callback.message, edit_message=True)
    except Exception:
        try:
            await callback.message.answer("✅ Требования выполнены. Открываю меню...")
        except Exception:
            pass
    try:
        await state.clear()
    except Exception:
        pass

def registration_required(f):
    @wraps(f)
    async def decorated_function(event: types.Update, *args, **kwargs):
        user_id = event.from_user.id
        user_data = get_user(user_id)
        if user_data:
            return await f(event, *args, **kwargs)
        else:
            message_text = "Пожалуйста, для начала работы со мной, отправьте команду /start"
            if isinstance(event, types.CallbackQuery):
                await event.answer(message_text, show_alert=True)
            else:
                await event.answer(message_text)
    return decorated_function

def get_user_router() -> Router:
    user_router = Router()

    # Helpers for Telegram Stars
    def _get_stars_rate() -> Decimal:
        try:
            rate_raw = get_setting("stars_per_rub") or "1"
            rate = Decimal(str(rate_raw))
            if rate <= 0:
                rate = Decimal("1")
            return rate
        except Exception:
            return Decimal("1")

    def _calc_stars_amount(amount_rub: Decimal) -> int:
        rate = _get_stars_rate()
        try:
            stars = (amount_rub * rate).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
        except Exception:
            stars = (amount_rub * rate)
        try:
            return int(stars)
        except Exception:
            return int(float(stars))

    @user_router.message(CommandStart())
    async def start_handler(message: types.Message, state: FSMContext, bot: Bot, command: CommandObject):
        user_id = message.from_user.id
        username = message.from_user.username or message.from_user.full_name
        referrer_id = None

        if command.args and command.args.startswith('ref_'):
            try:
                potential_referrer_id = int(command.args.split('_')[1])
                if potential_referrer_id != user_id:
                    referrer_id = potential_referrer_id
                    logger.info(f"Новый пользователь {user_id} был приглашен пользователем {referrer_id}")
            except (IndexError, ValueError):
                logger.warning(f"Получен некорректный реферальный код: {command.args}")
                
        register_user_if_not_exists(user_id, username, referrer_id)
        user_id = message.from_user.id
        username = message.from_user.username or message.from_user.full_name
        user_data = get_user(user_id)

        # Бонус при старте по реферальной ссылке (денежный или днями): единоразово.
        try:
            reward_type = (get_setting("referral_reward_type") or "percent_purchase").strip()
        except Exception:
            reward_type = "percent_purchase"
        if reward_type == "fixed_start_referrer" and referrer_id and user_data and not user_data.get('referral_start_bonus_received'):
            try:
                amount_raw = get_setting("referral_on_start_referrer_amount") or "20"
                start_bonus = Decimal(str(amount_raw)).quantize(Decimal("0.01"))
            except Exception:
                start_bonus = Decimal("20.00")
            if start_bonus > 0:
                try:
                    ok = add_to_balance(int(referrer_id), float(start_bonus))
                except Exception as e:
                    logger.warning(f"Реферальный стартовый бонус: не удалось добавить к балансу для реферера {referrer_id}: {e}")
                    ok = False
                # Увеличиваем суммарный заработок по рефералке
                try:
                    add_to_referral_balance_all(int(referrer_id), float(start_bonus))
                except Exception as e:
                    logger.warning(f"Реферальный стартовый бонус: не удалось увеличить общий реферальный баланс для {referrer_id}: {e}")
                # Помечаем, что для этого нового пользователя старт уже обработан, чтобы не дублировать при повторном /start
                try:
                    set_referral_start_bonus_received(user_id)
                except Exception:
                    pass
        elif reward_type == "bonus_days_start" and referrer_id and user_data and not user_data.get('referral_start_bonus_received'):
            try:
                ref_days = int(get_setting("referral_on_start_referrer_days") or "3")
            except Exception:
                ref_days = 3
            try:
                new_user_days = int(get_setting("referral_on_start_new_user_days") or "1")
            except Exception:
                new_user_days = 1

            ref_updated = await _apply_bonus_days_to_user(int(referrer_id), max(0, ref_days))
            user_updated = await _apply_bonus_days_to_user(user_id, max(0, new_user_days))
            try:
                set_referral_start_bonus_received(user_id)
            except Exception:
                pass
            try:
                await bot.send_message(
                    chat_id=int(referrer_id),
                    text=(
                        "🎁 Начисление за приглашение!\n"
                        f"Новый пользователь: {message.from_user.full_name} (ID: {user_id})\n"
                        f"Бонус: +{max(0, ref_days)} дн. к подписке (обновлено ключей: {ref_updated})."
                    )
                )
            except Exception:
                pass
            if user_updated > 0:
                try:
                    await bot.send_message(
                        chat_id=user_id,
                        text=f"🎁 Вам начислен бонус за старт по реферальной ссылке: +{max(0, new_user_days)} дн. к подписке."
                    )
                except Exception:
                    pass
                # Уведомим пригласившего
                try:
                    await bot.send_message(
                        chat_id=int(referrer_id),
                        text=(
                            "🎁 Начисление за приглашение!\n"
                            f"Новый пользователь: {message.from_user.full_name} (ID: {user_id})\n"
                            f"Бонус: {float(start_bonus):.2f} RUB"
                        )
                    )
                except Exception:
                    pass

        if user_data and user_data.get('agreed_to_terms'):
            await message.answer(
                f"👋 Снова здравствуйте, {html.bold(message.from_user.full_name)}!",
                reply_markup=keyboards.main_reply_keyboard
            )
            await show_main_menu(message)
            return

        terms_url = get_setting("terms_url")
        privacy_url = get_setting("privacy_url")
        channel_url = get_setting("channel_url")

        if not channel_url and (not terms_url or not privacy_url):
            set_terms_agreed(user_id)
            await show_main_menu(message)
            return

        is_subscription_forced = get_setting("force_subscription") == "true"
        
        show_welcome_screen = (is_subscription_forced and channel_url) or (terms_url and privacy_url)

        if not show_welcome_screen:
            set_terms_agreed(user_id)
            await show_main_menu(message)
            return

        final_text = (
            "Добро пожаловать! Я - q1 vpn, сервис для комфортной и защищённой работы в интернете. ⚡️\n\n"
            "📱 Поддержка всех популярных устройств\n"
            "🛡 Стабильная работа с различными онлайн-сервисами\n"
            "🔒 Быстрое, безопасное и удобное подключение к сети.\n\n"
            "Чтобы получить доступ ко всем возможностям сервиса, пожалуйста, подпишитесь на наш канал.\n"
        )
        if terms_url and privacy_url:
            final_text += (
                "Также необходимо ознакомиться и принять "
                f"<a href='{terms_url}'>Условия использования</a> и "
                f"<a href='{privacy_url}'>Политику конфиденциальности</a>."
            )
        else:
            final_text += "Также необходимо ознакомиться и принять Условия использования и Политику конфиденциальности."
        
        await message.answer(
            final_text,
            reply_markup=keyboards.create_welcome_keyboard(
                channel_url=channel_url,
                is_subscription_forced=is_subscription_forced
            ),
            disable_web_page_preview=True
        )
        await state.set_state(Onboarding.waiting_for_subscription_and_agreement)

    @user_router.callback_query(Onboarding.waiting_for_subscription_and_agreement, F.data == "check_subscription_and_agree")
    async def check_subscription_handler(callback: types.CallbackQuery, state: FSMContext, bot: Bot):
        user_id = callback.from_user.id
        channel_url = get_setting("channel_url")
        is_subscription_forced = get_setting("force_subscription") == "true"

        if not is_subscription_forced or not channel_url:
            await process_successful_onboarding(callback, state)
            return
            
        try:
            if '@' not in channel_url and 't.me/' not in channel_url:
                logger.error(f"Неверный формат URL канала: {channel_url}. Пропускаем проверку подписки.")
                await process_successful_onboarding(callback, state)
                return

            channel_id = '@' + channel_url.split('/')[-1] if 't.me/' in channel_url else channel_url
            member = await bot.get_chat_member(chat_id=channel_id, user_id=user_id)
            
            if member.status in [ChatMemberStatus.MEMBER, ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.CREATOR]:
                await process_successful_onboarding(callback, state)
            else:
                await callback.answer("Вы еще не подписались на канал. Пожалуйста, подпишитесь и попробуйте снова.", show_alert=True)

        except Exception as e:
            logger.error(f"Ошибка при проверке подписки для user_id {user_id} на канал {channel_url}: {e}")
            await callback.answer("Не удалось проверить подписку. Убедитесь, что бот является администратором канала. Попробуйте позже.", show_alert=True)

    @user_router.message(Onboarding.waiting_for_subscription_and_agreement)
    async def onboarding_fallback_handler(message: types.Message):
        await message.answer("Пожалуйста, выполните требуемые действия и нажмите на кнопку в сообщении выше.")

    @user_router.message(F.text == "🏠 Главное меню")
    @registration_required
    async def main_menu_handler(message: types.Message):
        await show_main_menu(message)

    @user_router.callback_query(F.data == "back_to_main_menu")
    @registration_required
    async def back_to_main_menu_handler(callback: types.CallbackQuery):
        await callback.answer()
        await show_main_menu(callback.message, edit_message=True)

    @user_router.callback_query(F.data == "show_main_menu")
    @registration_required
    async def show_main_menu_cb(callback: types.CallbackQuery):
        await callback.answer()
        await show_main_menu(callback.message, edit_message=True)

    @user_router.callback_query(F.data == "show_profile")
    @registration_required
    async def profile_handler_callback(callback: types.CallbackQuery):
        await callback.answer()
        user_id = callback.from_user.id
        user_db_data = get_user(user_id)
        user_keys = get_user_keys(user_id)
        if not user_db_data:
            await callback.answer("Не удалось получить данные профиля.", show_alert=True)
            return
        username = html.bold(user_db_data.get('username', 'Пользователь'))
        total_months = user_db_data.get('total_months', 0)
        now = datetime.now()
        active_keys = [key for key in user_keys if datetime.fromisoformat(key['expiry_date']) > now]
        remaining_text = "—"
        vpn_status_line = "❌"
        if active_keys:
            latest_key = max(active_keys, key=lambda k: datetime.fromisoformat(k['expiry_date']))
            latest_expiry_date = datetime.fromisoformat(latest_key['expiry_date'])
            time_left = latest_expiry_date - now
            vpn_status_line = "✅"
            remaining_text = f"{time_left.days} д. {time_left.seconds // 3600} ч."
        elif user_keys:
            vpn_status_line = "❌"
        else:
            vpn_status_line = "❌"

        try:
            main_balance = get_balance(user_id)
        except Exception:
            main_balance = 0.0

        try:
            referral_count = get_referral_count(user_id)
        except Exception:
            referral_count = 0

        referral_days = max(0, referral_count * 7)
        device_limit = get_user_device_limit(user_id, default_limit=3)

        if not active_keys:
            final_text = (
                f"👤 <b>Профиль:</b> {username}\n"
                "У вас нет активных подписок."
            )
        else:
            traffic_summary = await _build_subscription_traffic_summary(user_keys or active_keys, user_id=user_id)
            main_usage_text = traffic_summary["main_usage_text"]
            whitelist_usage_text = traffic_summary["whitelist_usage_text"]
            final_text = (
                f"👤 <b>Профиль:</b> {username}\n\n"
                f"{vpn_status_line} <b>Статус VPN:</b>\n"
                f"⏳ <b>Осталось:</b> {remaining_text}\n"
                f"📱 <b>Лимит устройств:</b> {device_limit}\n\n"
                "🌐 <b>Использование трафика:</b>\n"
                f"├ Основной: {main_usage_text}\n"
                f"└ Белые списки: {whitelist_usage_text}\n\n"
                f"💼 <b>Основной баланс:</b> {main_balance:.0f} RUB\n"
                f"💰 <b>Заработано дней на рефералах:</b> {referral_days}"
            )
        await _safe_edit_or_send(
            callback.message,
            final_text,
            reply_markup=keyboards.create_profile_keyboard(show_renew_button=bool(active_keys))
        )

    @user_router.callback_query(F.data == "manage_subscription")
    @registration_required
    async def manage_subscription_handler(callback: types.CallbackQuery):
        await callback.answer()
        user_keys = get_user_keys(callback.from_user.id)
        now = datetime.now()
        active_keys = [key for key in user_keys if datetime.fromisoformat(key['expiry_date']) > now]
        if not active_keys:
            await _safe_edit_or_send(
                callback.message,
                "❌ У вас нет активной подписки.",
                reply_markup=keyboards.create_profile_keyboard(show_renew_button=False)
            )
            return
        await _safe_edit_or_send(
            callback.message,
            "⚙️ <b>Управление подпиской</b>\n\nВыберите нужный раздел:",
            reply_markup=keyboards.create_subscription_management_keyboard()
        )

    @user_router.callback_query(F.data == "subscription_traffic_info")
    @registration_required
    async def subscription_traffic_info_handler(callback: types.CallbackQuery):
        await callback.answer()
        user_keys = get_user_keys(callback.from_user.id)
        now = datetime.now()
        active_keys = [key for key in user_keys if datetime.fromisoformat(key['expiry_date']) > now]
        if not active_keys:
            await _safe_edit_or_send(
                callback.message,
                "❌ У вас нет активной подписки.",
                reply_markup=keyboards.create_profile_keyboard(show_renew_button=False)
            )
            return
        traffic_summary = await _build_subscription_traffic_summary(user_keys or active_keys, user_id=callback.from_user.id)
        text = (
            "📊 <b>Информация о трафике</b>\n\n"
            "🔎 <b>Текущее использование:</b>\n"
            f"├ Использовано: {traffic_summary['whitelist_used_text']}\n"
            f"├ Лимит по подписке: {traffic_summary['whitelist_total_text']}\n"
            f"├ Cброс трафика: {traffic_summary['reset_text']}\n"
            f"└ Докуплено: {traffic_summary['extra_traffic_text']}\n"
        )
        await _safe_edit_or_send(
            callback.message,
            text,
            reply_markup=keyboards.create_subscription_traffic_keyboard()
        )

    @user_router.callback_query(F.data == "subscription_buy_traffic")
    @registration_required
    async def subscription_buy_traffic_handler(callback: types.CallbackQuery):
        await callback.answer()
        packages = get_active_traffic_packages() or []
        if not packages:
            await _safe_edit_or_send(
                callback.message,
                "➕ <b>Докупить трафик</b>\n\nПакеты трафика пока не настроены в панели.",
                reply_markup=keyboards.create_subscription_traffic_keyboard()
            )
            return
        await _safe_edit_or_send(
            callback.message,
            "➕ <b>Докупить трафик</b>\n\nВыберите пакет трафика:",
            reply_markup=keyboards.create_traffic_packages_keyboard(packages)
        )

    @user_router.callback_query(F.data.startswith("trafficpack:"))
    @registration_required
    async def subscription_select_traffic_package_handler(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer()
        try:
            package_id = int((callback.data or "").split(":", 1)[1])
        except Exception:
            await _safe_edit_or_send(callback.message, "❌ Ошибка выбора пакета трафика.")
            return
        package = get_traffic_package_by_id(package_id)
        if not package or int(package.get("is_active") or 0) != 1:
            await _safe_edit_or_send(callback.message, "❌ Пакет трафика недоступен.")
            return
        await state.update_data(
            action="traffic_package",
            traffic_package_id=package_id,
            key_id=0,
            host_name="",
            plan_id=None,
        )
        await _safe_edit_or_send(
            callback.message,
            "📧 Пожалуйста, введите ваш email для отправки чека об оплате.\n\n"
            "Если вы не хотите указывать почту, нажмите кнопку ниже.",
            reply_markup=keyboards.create_skip_email_keyboard()
        )
        await state.set_state(PaymentProcess.waiting_for_email)

    @user_router.callback_query(F.data == "profile_subscription_link")
    @registration_required
    async def profile_subscription_link_handler(callback: types.CallbackQuery):
        await callback.answer()
        link = _get_unified_subscription_url_for_user(callback.from_user.id)
        if not link:
            await _safe_edit_or_send(callback.message, 
                "❌ Не удалось сформировать ссылку подписки. Проверьте настройку домена в панели.",
                reply_markup=keyboards.create_profile_keyboard()
            )
            return
        await _safe_edit_or_send(callback.message, 
            f"🔗 <b>Моя ссылка подписки</b>\n\n{html.code(link)}",
            reply_markup=keyboards.create_profile_keyboard(),
            disable_web_page_preview=True
        )

    @user_router.callback_query(F.data == "copy_subscription_link")
    @registration_required
    async def copy_subscription_link_handler(callback: types.CallbackQuery):
        link = _get_unified_subscription_url_for_user(callback.from_user.id)
        if not link:
            await callback.answer("Ссылка подписки недоступна.", show_alert=True)
            return
        await callback.answer("Скопируйте ссылку из сообщения ниже.", show_alert=False)
        await callback.message.answer(
            f"📋 <b>Скопировать подписку</b>\n\n{html.code(link)}",
            disable_web_page_preview=True
        )

    @user_router.callback_query(F.data == "profile_info")
    @registration_required
    async def profile_info_handler(callback: types.CallbackQuery):
        await callback.answer()
        user_id = callback.from_user.id
        user_db_data = get_user(user_id)
        user_keys = get_user_keys(user_id)
        
        if not user_db_data:
            await callback.answer("Не удалось получить данные профиля.", show_alert=True)
            return
            
        username = html.bold(user_db_data.get('username', 'Пользователь'))
        total_spent = user_db_data.get('total_spent', 0)
        total_months = user_db_data.get('total_months', 0)
        
        now = datetime.now()
        active_keys = [key for key in user_keys if datetime.fromisoformat(key['expiry_date']) > now]
        
        if active_keys:
            latest_key = max(active_keys, key=lambda k: datetime.fromisoformat(k['expiry_date']))
            latest_expiry_date = datetime.fromisoformat(latest_key['expiry_date'])
            time_left = latest_expiry_date - now
            vpn_status_text = get_vpn_active_text(time_left.days, time_left.seconds // 3600)
        elif user_keys:
            vpn_status_text = VPN_INACTIVE_TEXT
        else:
            vpn_status_text = VPN_NO_DATA_TEXT
            
        final_text = get_profile_text(username, total_spent, total_months, vpn_status_text)
        
        # Добавляем дополнительную информацию
        final_text += f"\n\n📊 <b>Статистика:</b>"
        final_text += f"\n🔑 <b>Всего подписок:</b> {1 if user_keys else 0}"
        final_text += f"\n✅ <b>Активна подписка:</b> {'да' if active_keys else 'нет'}"
        final_text += f"\n💸 <b>Потрачено всего:</b> {total_spent:.2f} RUB"
        final_text += f"\n📅 <b>Месяцев подписки:</b> {total_months}"
        
        builder = InlineKeyboardBuilder()
        builder.button(text="⬅️ Назад", callback_data="show_profile")
        await _safe_edit_or_send(callback.message, final_text, reply_markup=builder.as_markup())

    @user_router.callback_query(F.data == "profile_balance")
    @registration_required
    async def profile_balance_handler(callback: types.CallbackQuery):
        await callback.answer()
        user_id = callback.from_user.id
        
        try:
            main_balance = get_balance(user_id)
        except Exception:
            main_balance = 0.0
            
        try:
            referral_count = get_referral_count(user_id)
        except Exception:
            referral_count = 0
            
        try:
            total_ref_earned = float(get_referral_balance_all(user_id))
        except Exception:
            total_ref_earned = 0.0
            
        try:
            ref_balance = float(get_referral_balance(user_id))
        except Exception:
            ref_balance = 0.0
        
        text = f"💰 <b>Информация о балансе</b>\n\n"
        text += f"💼 <b>Основной баланс:</b> {main_balance:.2f} RUB\n"
        text += f"🤝 <b>Реферальный баланс:</b> {ref_balance:.2f} RUB\n"
        text += f"📊 <b>Всего заработано по рефералке:</b> {total_ref_earned:.2f} RUB\n"
        text += f"👥 <b>Приглашено пользователей:</b> {referral_count}\n\n"
        text += f"💡 <b>Совет:</b> Используйте реферальный баланс для покупки ключей!"
        
        builder = InlineKeyboardBuilder()
        builder.button(text="💳 Пополнить", callback_data="top_up_start")
        builder.button(text="⬅️ Назад", callback_data="show_profile")
        builder.adjust(1)
        await _safe_edit_or_send(callback.message, text, reply_markup=builder.as_markup())

    @user_router.callback_query(F.data == "main_menu")
    @registration_required
    async def profile_main_menu_handler(callback: types.CallbackQuery):
        await callback.answer()
        await show_main_menu(callback.message, edit_message=True)

    @user_router.callback_query(F.data == "top_up_start")
    @registration_required
    async def topup_start_handler(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer()
        await _safe_edit_or_send(
            callback.message,
            "Введите сумму пополнения в рублях (например, 300):\nМинимум: 10 RUB, максимум: 100000 RUB",
        )
        await state.set_state(TopUpProcess.waiting_for_amount)

    @user_router.message(TopUpProcess.waiting_for_amount)
    async def topup_amount_input(message: types.Message, state: FSMContext):
        text = (message.text or "").replace(",", ".").strip()
        try:
            amount = Decimal(text)
        except Exception:
            await message.answer("❌ Введите корректную сумму, например: 300")
            return
        if amount <= 0:
            await message.answer("❌ Сумма должна быть положительной")
            return
        if amount < Decimal("10"):
            await message.answer("❌ Минимальная сумма пополнения: 10 RUB")
            return
        if amount > Decimal("100000"):
            await message.answer("❌ Максимальная сумма пополнения: 100000 RUB")
            return
        final_amount = amount.quantize(Decimal("0.01"))
        await state.update_data(topup_amount=float(final_amount))
        await message.answer(
            f"К пополнению: {final_amount:.2f} RUB\nВыберите способ оплаты:",
            reply_markup=keyboards.create_topup_payment_method_keyboard(PAYMENT_METHODS)
        )
        await state.set_state(TopUpProcess.waiting_for_topup_method)

    @user_router.callback_query(TopUpProcess.waiting_for_topup_method, F.data == "topup_pay_yookassa")
    async def topup_pay_yookassa(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer("Создаю ссылку на оплату...")
        data = await state.get_data()
        amount = Decimal(str(data.get('topup_amount', 0)))
        if amount <= 0:
            await _safe_edit_or_send(callback.message, "❌ Некорректная сумма пополнения. Повторите ввод.")
            await state.clear()
            return
        user_id = callback.from_user.id
        price_str_for_api = f"{amount:.2f}"
        price_float_for_metadata = float(amount)

        try:
            # Сформируем чек, если указан email для чеков
            customer_email = get_setting("receipt_email")
            receipt = None
            if customer_email and is_valid_email(customer_email):
                receipt = {
                    "customer": {"email": customer_email},
                    "items": [{
                        "description": f"Пополнение баланса",
                        "quantity": "1.00",
                        "amount": {"value": price_str_for_api, "currency": "RUB"},
                        "vat_code": 1,
                        "payment_subject": "service",
                        "payment_mode": "full_payment"
                    }]
                }

            payment_payload = {
                "amount": {"value": price_str_for_api, "currency": "RUB"},
                "confirmation": {"type": "redirect", "return_url": f"https://t.me/{TELEGRAM_BOT_USERNAME}"},
                "capture": True,
                "description": f"Пополнение баланса на {price_str_for_api} RUB",
                "metadata": {
                    "user_id": str(user_id),
                    "price": f"{price_float_for_metadata:.2f}",
                    "action": "top_up",
                    "payment_method": "YooKassa"
                }
            }
            if receipt:
                payment_payload['receipt'] = receipt
            payment = Payment.create(payment_payload, uuid.uuid4())
            await state.clear()
            await _safe_edit_or_send(callback.message, 
                "Нажмите на кнопку ниже для оплаты:",
                reply_markup=keyboards.create_payment_keyboard(payment.confirmation.confirmation_url)
            )
        except Exception as e:
            logger.error(f"Не удалось создать платеж YooKassa для пополнения: {e}", exc_info=True)
            await callback.message.answer("Не удалось создать ссылку на оплату.")
            await state.clear()

    @user_router.callback_query(TopUpProcess.waiting_for_topup_method, F.data == "topup_pay_yoomoney")
    async def topup_pay_yoomoney(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer("Готовлю ЮMoney…")
        data = await state.get_data()
        amount = Decimal(str(data.get('topup_amount', 0)))
        if amount <= 0:
            await _safe_edit_or_send(callback.message, "❌ Некорректная сумма пополнения. Повторите ввод.")
            await state.clear()
            return
        ym_wallet = (get_setting("yoomoney_wallet") or "").strip()
        if not ym_wallet:
            await _safe_edit_or_send(callback.message, "❌ Оплата через ЮMoney временно недоступна.")
            await state.clear()
            return
        user_id = callback.from_user.id
        payment_id = str(uuid.uuid4())
        metadata = {
            "payment_id": payment_id,
            "user_id": user_id,
            "price": float(amount),
            "action": "top_up",
            "payment_method": "YooMoney",
        }
        try:
            create_pending_transaction(payment_id, user_id, float(amount), metadata)
        except Exception as e:
            logger.warning(f"YooMoney пополнение: не удалось создать ожидающую транзакцию: {e}")
        try:
            success_url = f"https://t.me/{TELEGRAM_BOT_USERNAME}" if TELEGRAM_BOT_USERNAME else None
        except Exception:
            success_url = None
        pay_url = _build_yoomoney_quickpay_url(
            wallet=ym_wallet,
            amount=float(amount),
            label=payment_id,
            success_url=success_url,
            targets=f"Пополнение на {amount:.2f} RUB",
        )
        await state.clear()
        await _safe_edit_or_send(callback.message, 
            "Нажмите на кнопку ниже для оплаты. После оплаты нажмите 'Проверить оплату':",
            reply_markup=keyboards.create_payment_with_check_keyboard(pay_url, f"check_yoomoney_{payment_id}")
        )

    @user_router.callback_query(
        TopUpProcess.waiting_for_topup_method,
        (F.data == "topup_pay_platega_sbp")
        | (F.data == "topup_pay_platega_card")
        | (F.data == "topup_pay_platega_crypto")
    )
    async def topup_pay_platega(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer("Создаю ссылку Platega…")
        data = await state.get_data()
        amount = Decimal(str(data.get('topup_amount', 0)))
        if amount <= 0:
            await _safe_edit_or_send(callback.message, "❌ Некорректная сумма пополнения. Повторите ввод.")
            await state.clear()
            return

        callback_method = (callback.data or "").strip()
        method_meta = {
            "topup_pay_platega_sbp": {
                "setting": "platega_payment_method_sbp",
                "defaults": [2],
                "title": "Оплата через СБП",
                "method": "СБП",
            },
            "topup_pay_platega_card": {
                "setting": "platega_payment_method_card",
                "defaults": [11],
                "title": "Оплата банковской картой",
                "method": "Банковская карта",
            },
            "topup_pay_platega_crypto": {
                "setting": "platega_payment_method_crypto",
                "defaults": [13],
                "title": "Оплата криптовалютой",
                "method": "Криптовалюта",
            },
        }
        selected = method_meta.get(callback_method)
        if not selected:
            await _safe_edit_or_send(callback.message, "❌ Неверный способ оплаты.")
            return

        user_id = callback.from_user.id
        try:
            success_url = f"https://t.me/{TELEGRAM_BOT_USERNAME}" if TELEGRAM_BOT_USERNAME else None
        except Exception:
            success_url = None

        payload_obj = {
            "kind": "top_up",
            "user_id": user_id,
        }
        result = await _platega_create_for_method_candidates(
            amount_rub=float(amount),
            description=f"Пополнение баланса на {amount:.2f} RUB",
            payload=json.dumps(payload_obj, ensure_ascii=False, separators=(",", ":")),
            setting_key=selected["setting"],
            default_values=selected["defaults"],
            success_url=success_url,
            failed_url=success_url,
        )
        if not result:
            await _safe_edit_or_send(callback.message, "❌ Не удалось создать ссылку Platega. Попробуйте позже.")
            await state.clear()
            return

        pay_url, transaction_id, method_code_used, method_name_used = result
        metadata = {
            "payment_id": transaction_id,
            "user_id": user_id,
            "price": float(amount),
            "action": "top_up",
            "payment_method": "Platega",
        }
        try:
            create_pending_transaction(transaction_id, user_id, float(amount), metadata)
        except Exception as e:
            logger.warning(f"Platega пополнение: не удалось создать ожидающую транзакцию: {e}")

        await state.clear()
        logger.info(
            "Platega topup: method='%s', provider_method='%s', code=%s",
            selected["method"], method_name_used, method_code_used
        )
        invoice_text = (
            f"💳 {selected['title']}\n\n"
            f"Сумма: {float(amount):.2f} RUB\n"
            f"Способ: {selected['method']}"
        )
        await _safe_edit_or_send(
            callback.message,
            invoice_text,
            reply_markup=keyboards.create_payment_keyboard(pay_url)
        )

    @user_router.callback_query(F.data.startswith("check_yoomoney_"))
    async def check_yoomoney_status(callback: types.CallbackQuery, bot: Bot):
        await callback.answer("Проверяю оплату…")
        payment_id = callback.data[len("check_yoomoney_"):]
        if not payment_id:
            await callback.answer("❌ Некорректные данные для проверки.", show_alert=True)
            return
        op = await _yoomoney_find_payment(payment_id)
        if not op:
            await callback.answer("Платёж не найден или не завершён. Подождите и попробуйте ещё раз.", show_alert=True)
            return
        # Завершим pending‑транзакцию и извлечём метаданные
        try:
            amount_rub = float(op.get('amount', 0)) if isinstance(op.get('amount', 0), (int, float)) else None
        except Exception:
            amount_rub = None
        md = find_and_complete_pending_transaction(
            payment_id=payment_id,
            amount_rub=amount_rub,
            payment_method="YooMoney",
            currency_name="RUB",
            amount_currency=None,
        )
        if not md:
            await _safe_edit_or_send(callback.message, "❌ Не удалось завершить транзакцию. Обратитесь в поддержку, если средства списаны.")
            return
        try:
            await process_successful_payment(bot, md)
        except Exception as e:
            logger.error(f"YooMoney: не удалось обработать успешный платеж: {e}", exc_info=True)
            try:
                await _safe_edit_or_send(callback.message, "❌ Ошибка при выдаче после оплаты. Напишите в поддержку.")
            except Exception:
                pass
            return

    @user_router.callback_query(F.data.startswith("check_platega_"))
    async def check_platega_status(callback: types.CallbackQuery, bot: Bot):
        await callback.answer("Проверяю оплату…")
        transaction_id = (callback.data or "")[len("check_platega_"):].strip()
        if not transaction_id:
            await callback.answer("❌ Некорректные данные для проверки.", show_alert=True)
            return

        payload = await _platega_get_transaction_status(transaction_id)
        if not payload:
            await callback.answer("Платёж не найден или ещё обрабатывается. Попробуйте позже.", show_alert=True)
            return

        status = str(
            payload.get("status")
            or payload.get("state")
            or payload.get("transactionStatus")
            or ""
        ).upper()
        payment_details = payload.get("paymentDetails") or {}
        amount_raw = payment_details.get("amount", payload.get("amount"))
        currency_name = (payment_details.get("currency") or payload.get("currency") or "RUB")
        try:
            amount_value = float(amount_raw) if amount_raw is not None else None
        except Exception:
            amount_value = None

        paid_statuses = {"CONFIRMED", "PAID", "SUCCESS", "COMPLETED"}
        pending_statuses = {"PENDING", "WAITING", "IN_PROCESS", "PROCESSING", "CREATED"}
        failed_statuses = {"FAILED", "CANCELLED", "EXPIRED", "REJECTED"}

        if status in paid_statuses:
            amount_rub = amount_value if str(currency_name).upper() == "RUB" else None
            md = find_and_complete_pending_transaction(
                payment_id=transaction_id,
                amount_rub=amount_rub,
                payment_method="Platega",
                currency_name=str(currency_name) if currency_name else None,
                amount_currency=amount_value,
            )
            if not md:
                await callback.answer("Платёж уже обработан или не найден.", show_alert=True)
                return
            try:
                await process_successful_payment(bot, md)
            except Exception as e:
                logger.error(f"Platega: не удалось обработать успешный платеж: {e}", exc_info=True)
                await _safe_edit_or_send(callback.message, "❌ Платёж найден, но при выдаче возникла ошибка. Обратитесь в поддержку.")
                return
            await callback.answer("✅ Платёж подтверждён")
            return

        if status in failed_statuses:
            await callback.answer("❌ Платёж отклонён или отменён. Попробуйте снова.", show_alert=True)
            return

        if status in pending_statuses or not status:
            await callback.answer("⏳ Платёж ещё не подтверждён. Подождите немного и проверьте снова.", show_alert=True)
            return

        await callback.answer(f"⏳ Текущий статус платежа: {status}", show_alert=True)

    @user_router.callback_query(TopUpProcess.waiting_for_topup_method, F.data == "topup_pay_stars")
    async def topup_pay_stars(callback: types.CallbackQuery, state: FSMContext, bot: Bot):
        await callback.answer("Готовлю счёт в Stars…")
        data = await state.get_data()
        amount_rub = Decimal(str(data.get('topup_amount', 0)))
        if amount_rub <= 0:
            await _safe_edit_or_send(callback.message, "❌ Некорректная сумма пополнения. Повторите ввод.")
            await state.clear()
            return
        stars_count = _calc_stars_amount(amount_rub.quantize(Decimal("0.01")))
        # Для Telegram Stars payload должен быть коротким (до 128 байт). Используем UUID
        # и сохраняем полные метаданные во временную pending‑транзакцию.
        payment_id = str(uuid.uuid4())
        metadata = {
            "user_id": callback.from_user.id,
            "price": float(amount_rub),
            "action": "top_up",
            "payment_method": "Stars",
        }
        try:
            create_pending_transaction(payment_id, callback.from_user.id, float(amount_rub), metadata)
        except Exception as e:
            logger.warning(f"Stars пополнение: не удалось создать ожидающую транзакцию: {e}")
        payload = payment_id
        title = (get_setting("stars_title") or "Пополнение баланса")
        description = (get_setting("stars_description") or f"Пополнение на {amount_rub} RUB")
        try:
            await bot.send_invoice(
                chat_id=callback.message.chat.id,
                title=title,
                description=description,
                payload=payload,
                currency="XTR",
                prices=[types.LabeledPrice(label="Пополнение", amount=stars_count)],
            )
            await state.clear()
        except Exception as e:
            logger.error(f"Не удалось отправить счет Stars для пополнения: {e}")
            await _safe_edit_or_send(callback.message, "❌ Не удалось создать счёт Stars. Попробуйте другой способ оплаты.")
            await state.clear()
            return

    @user_router.callback_query(TopUpProcess.waiting_for_topup_method, (F.data == "topup_pay_cryptobot") | (F.data == "topup_pay_heleket"))
    async def topup_pay_heleket_like(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer("Создаю счёт...")
        data = await state.get_data()
        user_id = callback.from_user.id
        amount = float(data.get('topup_amount', 0))
        if amount <= 0:
            await _safe_edit_or_send(callback.message, "❌ Некорректная сумма пополнения. Повторите ввод.")
            await state.clear()
            return
        # Сформируем state_data минимально необходимым
        state_data = {
            "action": "top_up",
            "customer_email": None,
            "plan_id": None,
            "host_name": None,
            "key_id": None,
        }
        try:
            if callback.data == "topup_pay_cryptobot":
                result = await _create_cryptobot_invoice(
                    user_id=user_id,
                    price_rub=float(amount),
                    months=0,
                    host_name="",
                    state_data=state_data,
                )
                if result:
                    pay_url, invoice_id = result
                    # Сохраняем invoice_id для проверки
                    await state.update_data(cryptobot_invoice_id=invoice_id)
                    await state.set_state(TopUpProcess.waiting_for_cryptobot_topup_payment)
                    
                    await _safe_edit_or_send(callback.message, 
                        "Нажмите на кнопку ниже для оплаты:\n\n"
                        "💡 После оплаты нажмите «Проверить платёж» для подтверждения.",
                        reply_markup=keyboards.create_payment_with_check_keyboard(pay_url, "check_cryptobot_topup_payment")
                    )
                else:
                    await _safe_edit_or_send(callback.message, "❌ Не удалось создать счёт CryptoBot. Попробуйте другой способ оплаты.")
                    await state.clear()
            else:
                pay_url = await _create_heleket_payment_request(
                    user_id=user_id,
                    price=float(amount),
                    months=0,
                    host_name="",
                    state_data=state_data,
                )
                if pay_url:
                    await _safe_edit_or_send(callback.message, 
                        "Нажмите на кнопку ниже для оплаты:",
                        reply_markup=keyboards.create_payment_keyboard(pay_url)
                    )
                    await state.clear()
                else:
                    await _safe_edit_or_send(callback.message, "❌ Не удалось создать счёт. Попробуйте другой способ оплаты.")
                    await state.clear()
        except Exception as e:
            logger.error(f"Не удалось создать счет для пополнения: {e}", exc_info=True)
            await _safe_edit_or_send(callback.message, "❌ Не удалось создать счёт. Попробуйте другой способ оплаты.")
            await state.clear()

    @user_router.callback_query(TopUpProcess.waiting_for_cryptobot_topup_payment, F.data == "check_cryptobot_topup_payment")
    async def check_cryptobot_topup_payment_handler(callback: types.CallbackQuery, state: FSMContext, bot: Bot):
        """Обработчик проверки статуса платежа CryptoBot для пополнения баланса"""
        await callback.answer("Проверяю статус платежа...")
        
        data = await state.get_data()
        invoice_id = data.get('cryptobot_invoice_id')
        
        if not invoice_id:
            await _safe_edit_or_send(callback.message, "❌ Не найден ID счета для проверки.")
            await state.clear()
            return
        
        cryptobot_token = get_setting('cryptobot_token')
        if not cryptobot_token:
            logger.error("CryptoBot: не задан cryptobot_token для проверки платежа пополнения")
            await _safe_edit_or_send(callback.message, "❌ Ошибка конфигурации. Обратитесь к администратору.")
            await state.clear()
            return
        
        try:
            cp = CryptoPay(cryptobot_token)
            # Получаем информацию о счете
            invoices = await cp.get_invoices(invoice_ids=[invoice_id])
            
            if not invoices or len(invoices) == 0:
                await callback.answer("❌ Счет не найден", show_alert=True)
                return
            
            invoice = invoices[0]
            
            # Получаем статус счета
            status = None
            try:
                status = getattr(invoice, "status", None)
            except Exception:
                pass
            
            if not status and isinstance(invoice, dict):
                status = invoice.get("status")
            
            logger.info(f"CryptoBot проверка платежа пополнения: invoice_id={invoice_id}, status={status}")
            
            if status == "paid":
                # Платеж оплачен! Обрабатываем его
                await callback.answer("✅ Платеж найден! Обрабатываю...", show_alert=True)
                
                # Получаем payload из счета
                payload_string = None
                try:
                    payload_string = getattr(invoice, "payload", None)
                except Exception:
                    pass
                
                if not payload_string and isinstance(invoice, dict):
                    payload_string = invoice.get("payload")
                
                if not payload_string:
                    logger.error(f"CryptoBot проверка пополнения: не найден payload для счета {invoice_id}")
                    await _safe_edit_or_send(callback.message, "❌ Ошибка обработки платежа. Обратитесь в поддержку.")
                    await state.clear()
                    return
                
                # Разбираем payload
                parts = payload_string.split(':')
                if len(parts) < 9:
                    logger.error(f"CryptoBot проверка пополнения: некорректный формат payload: {payload_string}")
                    await _safe_edit_or_send(callback.message, "❌ Ошибка обработки платежа. Обратитесь в поддержку.")
                    await state.clear()
                    return
                
                metadata = {
                    "user_id": parts[0],
                    "months": parts[1],
                    "price": parts[2],
                    "action": parts[3],
                    "key_id": parts[4],
                    "host_name": parts[5],
                    "plan_id": parts[6],
                    "customer_email": parts[7] if parts[7] != 'None' else None,
                    "payment_method": parts[8],
                    "promo_code": (parts[9] if len(parts) > 9 and parts[9] else None),
                }
                
                # Обрабатываем успешный платеж
                await process_successful_payment(bot, metadata)
                await _safe_edit_or_send(callback.message, "✅ Платеж успешно обработан! Баланс пополнен.")
                await state.clear()
                
            elif status == "active":
                # Счет создан, но еще не оплачен
                await callback.answer("⏳ Платеж еще не получен. Пожалуйста, завершите оплату и нажмите кнопку снова.", show_alert=True)
                
            else:
                # Другие статусы (expired, cancelled и т.д.)
                await callback.answer(f"❌ Статус платежа: {status}. Пожалуйста, создайте новый счет.", show_alert=True)
                await state.clear()
                
        except Exception as e:
            logger.error(f"CryptoBot: ошибка при проверке счёта пополнения {invoice_id}: {e}", exc_info=True)
            await callback.answer("❌ Ошибка при проверке платежа. Попробуйте позже.", show_alert=True)

    @user_router.callback_query(TopUpProcess.waiting_for_topup_method, F.data == "topup_pay_tonconnect")
    async def topup_pay_tonconnect(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer("Готовлю TON Connect...")
        data = await state.get_data()
        user_id = callback.from_user.id
        amount_rub = Decimal(str(data.get('topup_amount', 0)))
        if amount_rub <= 0:
            await _safe_edit_or_send(callback.message, "❌ Некорректная сумма пополнения. Повторите ввод.")
            await state.clear()
            return

        wallet_address = get_setting("ton_wallet_address")
        if not wallet_address:
            await _safe_edit_or_send(callback.message, "❌ Оплата через TON временно недоступна.")
            await state.clear()
            return

        usdt_rub_rate = await get_usdt_rub_rate()
        ton_usdt_rate = await get_ton_usdt_rate()
        if not usdt_rub_rate or not ton_usdt_rate:
            await _safe_edit_or_send(callback.message, "❌ Не удалось получить курс TON. Попробуйте позже.")
            await state.clear()
            return

        price_ton = (amount_rub / usdt_rub_rate / ton_usdt_rate).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP)
        amount_nanoton = int(price_ton * 1_000_000_000)

        payment_id = str(uuid.uuid4())
        metadata = {
            "user_id": user_id,
            "price": float(amount_rub),
            "action": "top_up",
            "payment_method": "TON Connect"
        }
        create_pending_transaction(payment_id, user_id, float(amount_rub), metadata)

        transaction_payload = {
            'messages': [{'address': wallet_address, 'amount': str(amount_nanoton), 'payload': payment_id}],
            'valid_until': int(datetime.now().timestamp()) + 600
        }

        try:
            connect_url = await _start_ton_connect_process(user_id, transaction_payload)
            qr_img = qrcode.make(connect_url)
            bio = BytesIO(); qr_img.save(bio, "PNG"); qr_file = BufferedInputFile(bio.getvalue(), "ton_qr.png")
            try:
                await callback.message.delete()
            except Exception:
                pass
            await callback.message.answer_photo(
                photo=qr_file,
                caption=(
                    f"💎 Оплата через TON Connect\n\n"
                    f"Сумма к оплате: `{price_ton}` TON\n\n"
                    f"Нажмите кнопку ниже, чтобы открыть кошелёк и подтвердить перевод."
                ),
                reply_markup=keyboards.create_ton_connect_keyboard(connect_url)
            )
            await state.clear()
        except Exception as e:
            logger.error(f"Не удалось запустить TON Connect для пополнения: {e}", exc_info=True)
            await _safe_edit_or_send(callback.message, "❌ Не удалось подготовить оплату TON Connect.")
            await state.clear()

    @user_router.callback_query(F.data == "show_referral_program")
    @registration_required
    async def referral_program_handler(callback: types.CallbackQuery):
        await callback.answer()
        user_id = callback.from_user.id
        bot_username = (await callback.bot.get_me()).username
        
        referral_link = f"https://t.me/{bot_username}?start=ref_{user_id}"
        referral_count = get_referral_count(user_id)
        referral_days = max(0, referral_count * 14)
        text = (
            "🤝 <b>Реферальная программа</b>\n\n"
            f"Ваша реферальная ссылка:\n<code>{referral_link}</code>\n\n"
            f"Приглашено пользователей: {referral_count}\n"
            f"Заработано дней на рефералах: {referral_days}\n\n"
            "🗣 За приглашение пользователя вам и вашему другу предоставляется по 7 дней подписки. "
            "Бонус начисляется после активации пробного периода."
        )

        await _safe_edit_or_send(
            callback.message,
            text,
            reply_markup=keyboards.create_referral_keyboard(referral_link)
        )

    @user_router.callback_query(F.data == "show_about")
    @registration_required
    async def about_handler(callback: types.CallbackQuery):
        await callback.answer()
        
        about_text = get_setting("about_text")
        terms_url = get_setting("terms_url")
        privacy_url = get_setting("privacy_url")
        channel_url = get_setting("channel_url")

        final_text = about_text if about_text else "Информация о проекте не добавлена."

        keyboard = keyboards.create_about_keyboard(channel_url, terms_url, privacy_url)

        await _safe_edit_or_send(
            callback.message,
            final_text,
            reply_markup=keyboard,
            disable_web_page_preview=True
        )

    @user_router.callback_query(F.data == "show_help")
    @registration_required
    async def about_handler(callback: types.CallbackQuery):
        await callback.answer()
        support_bot_username = get_setting("support_bot_username")
        support_text = get_setting("support_text") or "Раздел поддержки. Нажмите кнопку ниже, чтобы открыть чат с поддержкой."
        if support_bot_username:
            await _safe_edit_or_send(
                callback.message,
                support_text,
                reply_markup=keyboards.create_support_bot_link_keyboard(support_bot_username)
            )
        else:
            support_user = get_setting("support_user")
            if support_user:
                await _safe_edit_or_send(
                    callback.message,
                    "Для связи с поддержкой используйте кнопку ниже.",
                    reply_markup=keyboards.create_support_keyboard(support_user)
                )
            else:
                await _safe_edit_or_send(
                    callback.message,
                    "Контакты поддержки не настроены.",
                    reply_markup=keyboards.create_back_to_menu_keyboard()
                )

    @user_router.callback_query(F.data == "support_menu")
    @registration_required
    async def support_menu_handler(callback: types.CallbackQuery):
        await callback.answer()
        support_bot_username = get_setting("support_bot_username")
        support_text = get_setting("support_text") or "Раздел поддержки. Нажмите кнопку ниже, чтобы открыть чат с поддержкой."
        if support_bot_username:
            await _safe_edit_or_send(callback.message, 
                support_text,
                reply_markup=keyboards.create_support_bot_link_keyboard(support_bot_username)
            )
        else:
            support_user = get_setting("support_user")
            if support_user:
                await _safe_edit_or_send(callback.message, 
                    "Для связи с поддержкой используйте кнопку ниже.",
                    reply_markup=keyboards.create_support_keyboard(support_user)
                )
            else:
                await _safe_edit_or_send(callback.message, "Контакты поддержки не настроены.", reply_markup=keyboards.create_back_to_menu_keyboard())

    @user_router.callback_query(F.data == "support_external")
    @registration_required
    async def support_external_handler(callback: types.CallbackQuery):
        await callback.answer()
        support_bot_username = get_setting("support_bot_username")
        if support_bot_username:
            await _safe_edit_or_send(callback.message, 
                get_setting("support_text") or "Раздел поддержки.",
                reply_markup=keyboards.create_support_bot_link_keyboard(support_bot_username)
            )
            return
        support_user = get_setting("support_user")
        if not support_user:
            await _safe_edit_or_send(callback.message, "Внешний контакт поддержки не настроен.", reply_markup=keyboards.create_back_to_menu_keyboard())
            return
        await _safe_edit_or_send(callback.message, 
            "Для связи с поддержкой используйте кнопку ниже.",
            reply_markup=keyboards.create_support_keyboard(support_user)
        )

    @user_router.callback_query(F.data == "support_new_ticket")
    @registration_required
    async def support_new_ticket_handler(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer()
        support_bot_username = get_setting("support_bot_username")
        if support_bot_username:
            await _safe_edit_or_send(callback.message, 
                "Раздел поддержки вынесен в отдельного бота.",
                reply_markup=keyboards.create_support_bot_link_keyboard(support_bot_username)
            )
        else:
            await _safe_edit_or_send(callback.message, "Контакты поддержки не настроены.", reply_markup=keyboards.create_back_to_menu_keyboard())

    @user_router.message(SupportDialog.waiting_for_subject)
    @registration_required
    async def support_subject_received(message: types.Message, state: FSMContext):
        await state.clear()
        support_bot_username = get_setting("support_bot_username")
        if support_bot_username:
            await message.answer(
                "Создание тикетов доступно в отдельном боте поддержки.",
                reply_markup=keyboards.create_support_bot_link_keyboard(support_bot_username)
            )
        else:
            await message.answer("Контакты поддержки не настроены.")

    @user_router.message(SupportDialog.waiting_for_message)
    @registration_required
    async def support_message_received(message: types.Message, state: FSMContext, bot: Bot):
        await state.clear()
        support_bot_username = get_setting("support_bot_username")
        if support_bot_username:
            await message.answer(
                "Создание тикетов доступно в отдельном боте поддержки.",
                reply_markup=keyboards.create_support_bot_link_keyboard(support_bot_username)
            )
        else:
            await message.answer("Контакты поддержки не настроены.")

    @user_router.callback_query(F.data == "support_my_tickets")
    @registration_required
    async def support_my_tickets_handler(callback: types.CallbackQuery):
        await callback.answer()
        support_bot_username = get_setting("support_bot_username")
        if support_bot_username:
            await _safe_edit_or_send(callback.message, 
                "Список обращений доступен в отдельном боте поддержки.",
                reply_markup=keyboards.create_support_bot_link_keyboard(support_bot_username)
            )
        else:
            await _safe_edit_or_send(callback.message, "Контакты поддержки не настроены.", reply_markup=keyboards.create_back_to_menu_keyboard())

    @user_router.callback_query(F.data.startswith("support_view_"))
    @registration_required
    async def support_view_ticket_handler(callback: types.CallbackQuery):
        await callback.answer()
        support_bot_username = get_setting("support_bot_username")
        if support_bot_username:
            await _safe_edit_or_send(callback.message, 
                "Просмотр тикетов доступен в отдельном боте поддержки.",
                reply_markup=keyboards.create_support_bot_link_keyboard(support_bot_username)
            )
        else:
            await _safe_edit_or_send(callback.message, "Контакты поддержки не настроены.", reply_markup=keyboards.create_back_to_menu_keyboard())

    @user_router.callback_query(F.data.startswith("support_reply_"))
    @registration_required
    async def support_reply_prompt_handler(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer()
        await state.clear()
        support_bot_username = get_setting("support_bot_username")
        if support_bot_username:
            await _safe_edit_or_send(callback.message, 
                "Отправка ответов доступна в отдельном боте поддержки.",
                reply_markup=keyboards.create_support_bot_link_keyboard(support_bot_username)
            )
        else:
            await _safe_edit_or_send(callback.message, "Контакты поддержки не настроены.", reply_markup=keyboards.create_back_to_menu_keyboard())

    @user_router.message(SupportDialog.waiting_for_reply)
    @registration_required
    async def support_reply_received(message: types.Message, state: FSMContext, bot: Bot):
        await state.clear()
        support_bot_username = get_setting("support_bot_username")
        if support_bot_username:
            await message.answer(
                "Отправка ответов доступна в отдельном боте поддержки.",
                reply_markup=keyboards.create_support_bot_link_keyboard(support_bot_username)
            )
        else:
            await message.answer("Контакты поддержки не настроены.")

    @user_router.message(F.is_topic_message == True)
    async def forum_thread_message_handler(message: types.Message, bot: Bot):
        try:
            support_bot_username = get_setting("support_bot_username")
            me = await bot.get_me()
            if support_bot_username and (me.username or "").lower() != support_bot_username.lower():
                return
            if not message.message_thread_id:
                return
            forum_chat_id = message.chat.id
            thread_id = message.message_thread_id
            ticket = get_ticket_by_thread(str(forum_chat_id), int(thread_id))
            if not ticket:
                return
            user_id = int(ticket.get('user_id'))
            if message.from_user and message.from_user.id == me.id:
                return
            # Проверка многоадминная
            is_admin_by_setting = is_admin(message.from_user.id)
            is_admin_in_chat = False
            try:
                member = await bot.get_chat_member(chat_id=forum_chat_id, user_id=message.from_user.id)
                is_admin_in_chat = member.status in [ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.CREATOR]
            except Exception:
                pass
            if not (is_admin_by_setting or is_admin_in_chat):
                return
            content = (message.text or message.caption or "").strip()
            if content:
                add_support_message(ticket_id=int(ticket['ticket_id']), sender='admin', content=content)
            header = await bot.send_message(
                chat_id=user_id,
                text=f"💬 Ответ поддержки по тикету #{ticket['ticket_id']}"
            )
            try:
                await bot.copy_message(
                    chat_id=user_id,
                    from_chat_id=message.chat.id,
                    message_id=message.message_id,
                    reply_to_message_id=header.message_id
                )
            except Exception:
                if content:
                    await bot.send_message(chat_id=user_id, text=content)
        except Exception as e:
            logger.warning(f"Не удалось переслать сообщение из форумной темы: {e}")

    @user_router.callback_query(F.data.startswith("support_close_"))
    @registration_required
    async def support_close_ticket_handler(callback: types.CallbackQuery):
        await callback.answer()
        support_bot_username = get_setting("support_bot_username")
        if support_bot_username:
            await _safe_edit_or_send(callback.message, 
                "Управление тикетами доступно в отдельном боте поддержки.",
                reply_markup=keyboards.create_support_bot_link_keyboard(support_bot_username)
            )
            return
        await _safe_edit_or_send(callback.message, "Контакты поддержки не настроены.", reply_markup=keyboards.create_back_to_menu_keyboard())

    @user_router.callback_query(F.data == "manage_keys")
    @registration_required
    async def manage_keys_handler(callback: types.CallbackQuery):
        await callback.answer()
        user_id = callback.from_user.id
        user_keys = get_user_keys(user_id)
        await _safe_edit_or_send(
            callback.message,
            "Ваши ключи:" if user_keys else "У вас пока нет ключей.",
            reply_markup=keyboards.create_keys_management_keyboard(user_keys)
        )

    @user_router.callback_query(F.data == "get_trial")
    @registration_required
    async def trial_period_handler(callback: types.CallbackQuery, state: FSMContext):
        user_id = callback.from_user.id
        user_db_data = get_user(user_id)
        if user_db_data and user_db_data.get('trial_used'):
            await callback.answer("Вы уже использовали бесплатный пробный период.", show_alert=True)
            return
        if user_db_data and int(user_db_data.get('total_months') or 0) > 0:
            await callback.answer("Пробный период доступен только до первой покупки.", show_alert=True)
            return

        hosts = _get_regular_hosts()
        if not hosts:
            await _safe_edit_or_send(callback.message, "❌ В данный момент нет доступных серверов для создания пробного ключа.")
            return

        await callback.answer()
        await _safe_edit_or_send(
            callback.message,
            "🚀 <b>Преимущества нашего VPN</b>\n"
            "• Высокая скорость и стабильное соединение\n"
            "• Доступ к нескольким серверам в одной подписке\n"
            "• Удобное продление и поддержка 24/7\n\n"
            "Нажмите кнопку ниже, чтобы получить пробную подписку:",
            reply_markup=keyboards.create_vpn_benefits_keyboard("trial")
        )

    @user_router.callback_query(F.data == "trial_confirm")
    @registration_required
    async def trial_confirm_handler(callback: types.CallbackQuery):
        await callback.answer()
        user_id = callback.from_user.id
        user_db_data = get_user(user_id)
        if user_db_data and user_db_data.get('trial_used'):
            await callback.answer("Вы уже использовали бесплатный пробный период.", show_alert=True)
            return
        if user_db_data and int(user_db_data.get('total_months') or 0) > 0:
            await callback.answer("Пробный период доступен только до первой покупки.", show_alert=True)
            return
        await process_trial_key_creation(callback.message)

    @user_router.callback_query(F.data.startswith("select_host:"))
    @registration_required
    async def select_host_callback_handler(callback: types.CallbackQuery):
        parsed = keyboards.parse_host_callback_data(callback.data)
        if not parsed:
            await callback.answer("Некорректные данные выбора сервера.", show_alert=True)
            return

        action, extra, token = parsed
        hosts = _get_regular_hosts()
        host_entry = keyboards.find_host_by_callback_token(hosts, token)
        if not host_entry:
            await callback.answer("Сервер не найден.", show_alert=True)
            return

        host_name = host_entry.get('host_name')

        if action == "trial":
            await callback.answer()
            await process_trial_key_creation(callback.message)
            return

        if action == "new":
            await callback.answer()
            plans = get_plans_for_host(host_name)
            if not plans:
                await _safe_edit_or_send(callback.message, f"❌ Для сервера \"{host_name}\" не настроены тарифы.")
                return
            await _safe_edit_or_send(callback.message, 
                CHOOSE_PLAN_MESSAGE or "Выберите тариф:",
                reply_markup=keyboards.create_plans_keyboard(plans, action="new", host_name=host_name)
            )
            return

        if action == "switch":
            try:
                key_id = int(extra)
            except Exception:
                await callback.answer("Некорректные данные выбора сервера.", show_alert=True)
                return
            await handle_switch_host(callback, key_id, host_name)
            return

        await callback.answer("Неизвестное действие.", show_alert=True)

    async def process_trial_key_creation(message: types.Message):
        user_id = message.chat.id
        hosts = _get_regular_hosts()
        host_names = [h.get("host_name") for h in hosts if h.get("host_name")]
        if not host_names:
            await _safe_edit_or_send(message, "❌ В данный момент нет доступных серверов для создания пробной подписки.")
            return

        await _safe_edit_or_send(
            message,
            f"Отлично! Создаю для вас бесплатную подписку на {get_setting('trial_duration_days')} дня..."
        )

        try:
            user_uuid = get_or_create_user_subscription_uuid(user_id)

            results = []
            for host_name in host_names:
                host_email = _subscription_email_for_user_host(user_id, host_name)
                result = await xui_api.create_or_update_key_on_host(
                    host_name=host_name,
                    email=host_email,
                    days_to_add=int(get_setting("trial_duration_days")),
                    preferred_uuid=user_uuid
                )
                if result:
                    results.append((host_name, result))

            if not results:
                await _safe_edit_or_send(message, "❌ Не удалось создать пробную подписку. Проверьте настройки хостов.")
                return

            set_trial_used(user_id)
            created_key_ids: list[int] = []
            expiry_values = []
            for host_name, result in results:
                existing_key = get_key_by_email(result['email'])
                if existing_key:
                    update_key_info(existing_key['key_id'], result['client_uuid'], result['expiry_timestamp_ms'])
                    key_id = existing_key['key_id']
                else:
                    key_id = add_new_key(
                        user_id=user_id,
                        host_name=host_name,
                        xui_client_uuid=result['client_uuid'],
                        key_email=result['email'],
                        expiry_timestamp_ms=result['expiry_timestamp_ms']
                    )
                if key_id:
                    created_key_ids.append(key_id)
                try:
                    expiry_values.append(int(result['expiry_timestamp_ms']))
                except Exception:
                    pass

            final_expiry_ms = max(expiry_values) if expiry_values else int(datetime.now().timestamp() * 1000)
            await _remove_expired_hosts_clients(user_id)
            new_expiry_date = datetime.fromtimestamp(final_expiry_ms / 1000)
            unified_url = _get_unified_subscription_url_for_user(user_id)
            try:
                update_user_subscription_state(
                    user_id,
                    subscription_link=unified_url,
                    subscription_status="active",
                    subscription_type="trial",
                    subscription_expires_at=new_expiry_date
                )
            except Exception:
                pass
            final_text = (
                "✅ <b>Ваша пробная подписка готова!</b>\n"
                f"⏳ <b>Действует до:</b> {new_expiry_date.strftime('%d.%m.%Y в %H:%M')}\n\n"
                "Выберите устройство для подключения:"
            )
            if len(results) < len(host_names):
                final_text += (
                    f"\n\n⚠️ Подключено серверов: {len(results)} из {len(host_names)}. "
                    "Проверьте настройки недоступных хостов."
                )
            # Вместо удаления сообщения (что может быть запрещено Telegram), сначала пытаемся отредактировать его
            try:
                reply_kb = keyboards.create_connect_devices_keyboard_with_back_only()
                await _safe_edit_or_send(
                    message,
                    final_text,
                    reply_markup=reply_kb,
                    disable_web_page_preview=True
                )
            except TelegramBadRequest:
                # Фолбэк: если редактирование невозможно (например, старое сообщение), попробуем удалить и отправить новое
                try:
                    await message.delete()
                except Exception:
                    pass
                reply_kb = keyboards.create_connect_devices_keyboard_with_back_only()
                await message.answer(text=final_text, reply_markup=reply_kb)

        except Exception as e:
            logger.error(
                f"Ошибка создания пробной подписки для пользователя {user_id}: {e}",
                exc_info=True
            )
            await _safe_edit_or_send(message, "❌ Произошла ошибка при создании пробной подписки.")

    @user_router.callback_query(F.data.startswith("show_key_"))
    @registration_required
    async def show_key_handler(callback: types.CallbackQuery):
        key_id_to_show = int(callback.data.split("_")[2])
        await _safe_edit_or_send(callback.message, "Загружаю информацию о ключе...")
        user_id = callback.from_user.id
        key_data = get_key_by_id(key_id_to_show)

        if not key_data or key_data['user_id'] != user_id:
            await _safe_edit_or_send(callback.message, "❌ Ошибка: ключ не найден.")
            return
            
        try:
            connection_string = _get_unified_subscription_url_for_user(user_id)
            if not connection_string:
                details = await xui_api.get_key_details_from_host(key_data)
                if not details or not details['connection_string']:
                    await _safe_edit_or_send(callback.message, "❌ Ошибка на сервере. Не удалось получить данные ключа.")
                    return
                connection_string = details['connection_string']
            expiry_date = datetime.fromisoformat(key_data['expiry_date'])
            created_date = datetime.fromisoformat(key_data['created_date'])
            
            all_user_keys = get_user_keys(user_id)
            key_number = next((i + 1 for i, key in enumerate(all_user_keys) if key['key_id'] == key_id_to_show), 0)
            
            final_text = get_key_info_text(key_number, expiry_date, created_date, connection_string)
            live_stats = await _get_live_traffic_stats_for_key(key_data)
            if live_stats:
                up = max(int(live_stats.get("up") or 0), 0)
                down = max(int(live_stats.get("down") or 0), 0)
                total = max(int(live_stats.get("total") or 0), 0)
                used = up + down
                total_text = format_traffic(total) if total > 0 else "∞"
                final_text += (
                    "\n\n"
                    f"🌐 <b>Трафик:</b> {format_traffic(used)} / {total_text}"
                )
            else:
                final_text += "\n\n🌐 <b>Трафик:</b> Недоступно"
            
            await _safe_edit_or_send(callback.message, 
                text=final_text,
                reply_markup=keyboards.create_key_info_keyboard(key_id_to_show)
            )
        except Exception as e:
            logger.error(f"Ошибка показа ключа {key_id_to_show}: {e}")
            await _safe_edit_or_send(callback.message, "❌ Произошла ошибка при получении данных ключа.")

    @user_router.callback_query(F.data.startswith("switch_server_"))
    @registration_required
    async def switch_server_start(callback: types.CallbackQuery):
        await callback.answer()
        await _safe_edit_or_send(callback.message, 
            "🔗 Эта подписка уже включает все доступные локации.\n"
            "Используйте «Моя ссылка подписки» в профиле."
        )

    async def _switch_key_to_host(callback: types.CallbackQuery, key_id: int, new_host_name: str):
        key_data = get_key_by_id(key_id)

        if not key_data or key_data.get('user_id') != callback.from_user.id:
            await callback.answer("Ключ не найден.", show_alert=True)
            return

        old_host = key_data.get('host_name')
        if not old_host:
            await callback.answer("Для ключа не указан текущий сервер.", show_alert=True)
            return

        if new_host_name == old_host:
            await callback.answer("Это уже текущий сервер.", show_alert=True)
            return

        try:
            expiry_dt = datetime.fromisoformat(key_data['expiry_date'])
            expiry_timestamp_ms_exact = int(expiry_dt.timestamp() * 1000)
        except Exception:
            now_dt = datetime.now()
            expiry_timestamp_ms_exact = int((now_dt + timedelta(days=1)).timestamp() * 1000)

        email = key_data.get('key_email')
        if not email:
            await callback.answer("Не удалось определить email ключа. Обратитесь в поддержку.", show_alert=True)
            return

        await callback.answer()
        await _safe_edit_or_send(callback.message, 
            f"⏳ Переношу ключ на сервер \"{new_host_name}\"..."
        )

        try:
            result = await xui_api.create_or_update_key_on_host(
                new_host_name,
                email,
                days_to_add=None,
                expiry_timestamp_ms=expiry_timestamp_ms_exact
            )
            if not result:
                await _safe_edit_or_send(callback.message, 
                    f"❌ Не удалось перенести ключ на сервер \"{new_host_name}\". Попробуйте позже."
                )
                return

            try:
                await xui_api.delete_client_on_host(old_host, email)
            except Exception:
                pass

            update_key_host_and_info(
                key_id=key_id,
                new_host_name=new_host_name,
                new_xui_uuid=result['client_uuid'],
                new_expiry_ms=result['expiry_timestamp_ms']
            )

            try:
                updated_key = get_key_by_id(key_id)
                connection_string = _get_unified_subscription_url_for_user(callback.from_user.id)
                if (not connection_string) and updated_key:
                    details = await xui_api.get_key_details_from_host(updated_key)
                    connection_string = details['connection_string'] if details else None
                if connection_string:
                    expiry_date = datetime.fromisoformat(updated_key['expiry_date'])
                    created_date = datetime.fromisoformat(updated_key['created_date'])
                    all_user_keys = get_user_keys(callback.from_user.id)
                    key_number = next((i + 1 for i, k in enumerate(all_user_keys) if k['key_id'] == key_id), 0)
                    final_text = get_key_info_text(key_number, expiry_date, created_date, connection_string)
                    await _safe_edit_or_send(callback.message, 
                        text=final_text,
                        reply_markup=keyboards.create_key_info_keyboard(key_id)
                    )
                else:
                    await _safe_edit_or_send(callback.message, 
                        f"✅ Готово! Ключ перенесён на сервер \"{new_host_name}\".\n"
                        "Обновите подписку/конфиг в клиенте, если требуется.",
                        reply_markup=keyboards.create_back_to_menu_keyboard()
                    )
            except Exception:
                await _safe_edit_or_send(callback.message, 
                    f"✅ Готово! Ключ перенесён на сервер \"{new_host_name}\".\n"
                    "Обновите подписку/конфиг в клиенте, если требуется.",
                    reply_markup=keyboards.create_back_to_menu_keyboard()
                )
        except Exception as e:
            logger.error(f"Ошибка переключения ключа {key_id} на хост {new_host_name}: {e}", exc_info=True)
            await _safe_edit_or_send(callback.message, 
                "❌ Произошла ошибка при переносе ключа. Попробуйте позже."
            )

    @user_router.callback_query(F.data.startswith("select_host_switch_"))
    @registration_required
    async def select_host_for_switch(callback: types.CallbackQuery):
        payload = callback.data[len("select_host_switch_"):]
        parts = payload.split("_", 1)
        if len(parts) != 2:
            await callback.answer("Некорректные данные выбора сервера.", show_alert=True)
            return
        try:
            key_id = int(parts[0])
        except ValueError:
            await callback.answer("Некорректный идентификатор ключа.", show_alert=True)
            return
        new_host_name = parts[1]
        await _switch_key_to_host(callback, key_id, new_host_name)

    async def handle_switch_host(callback: types.CallbackQuery, key_id: int, new_host_name: str):
        await _switch_key_to_host(callback, key_id, new_host_name)

    @user_router.callback_query(F.data.startswith("show_qr_"))
    @registration_required
    async def show_qr_handler(callback: types.CallbackQuery):
        await callback.answer("Генерирую QR-код...")
        key_id = int(callback.data.split("_")[2])
        key_data = get_key_by_id(key_id)
        if not key_data or key_data['user_id'] != callback.from_user.id: return
        
        try:
            connection_string = _get_unified_subscription_url_for_user(callback.from_user.id)
            if not connection_string:
                details = await xui_api.get_key_details_from_host(key_data)
                if not details or not details['connection_string']:
                    await callback.answer("Ошибка: Не удалось сгенерировать QR-код.", show_alert=True)
                    return
                connection_string = details['connection_string']
            qr_img = qrcode.make(connection_string)
            bio = BytesIO(); qr_img.save(bio, "PNG"); bio.seek(0)
            qr_code_file = BufferedInputFile(bio.read(), filename="vpn_qr.png")
            await callback.message.answer_photo(photo=qr_code_file)
        except Exception as e:
            logger.error(f"Ошибка показа QR-кода для ключа {key_id}: {e}")

    @user_router.callback_query(F.data.startswith("howto_vless_"))
    @registration_required
    async def show_instruction_handler(callback: types.CallbackQuery):
        await callback.answer()
        key_id = int(callback.data.split("_")[2])
        try:
            await _safe_edit_or_send(callback.message, 
                "Выберите вашу платформу для инструкции по подключению VLESS:",
                reply_markup=keyboards.create_howto_vless_keyboard_key(key_id),
                disable_web_page_preview=True
            )
        except TelegramBadRequest:
            pass
    
    @user_router.callback_query(F.data.startswith("howto_vless"))
    @registration_required
    async def show_instruction_handler(callback: types.CallbackQuery):
        await callback.answer()

        try:
            await _safe_edit_or_send(callback.message, 
                "Выберите вашу платформу для инструкции по подключению VLESS:",
                reply_markup=keyboards.create_howto_vless_keyboard(),
                disable_web_page_preview=True
            )
        except TelegramBadRequest:
            pass

    @user_router.callback_query(F.data == "user_speedtest")
    @registration_required
    async def user_speedtest_handler(callback: types.CallbackQuery):
        await callback.answer()
        
        try:
            # Получаем список хостов
            hosts = get_all_hosts() or []
            if not hosts:
                await _safe_edit_or_send(
                    callback.message,
                    "⚠️ Хосты не найдены в настройках. Обратитесь к администратору.",
                    reply_markup=keyboards.create_back_to_main_menu_keyboard()
                )
                return
            
            # Показываем последние результаты тестов скорости для всех хостов
            text = "⚡️ <b>Последние результаты Speedtest</b>\n\n"
            
            from shop_bot.data_manager.database import get_latest_speedtest
            
            for host in hosts:
                host_name = host.get('host_name', 'Неизвестный хост')
                latest_test = get_latest_speedtest(host_name)
                
                if latest_test:
                    ping = latest_test.get('ping_ms')
                    download = latest_test.get('download_mbps')
                    upload = latest_test.get('upload_mbps')
                    server = latest_test.get('server_name', '—')
                    method = latest_test.get('method', 'unknown').upper()
                    created_at = latest_test.get('created_at', '—')
                    
                    # Форматируем время в нужном формате
                    try:
                        from datetime import datetime
                        if created_at and created_at != '—':
                            dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                            time_str = dt.strftime('%d.%m %H:%M')
                        else:
                            time_str = '—'
                    except:
                        time_str = created_at
                    
                    # Форматируем значения
                    ping_str = f"{ping:.2f}" if ping is not None else "—"
                    download_str = f"{download:.0f}" if download is not None else "—"
                    upload_str = f"{upload:.0f}" if upload is not None else "—"
                    
                    # Создаем строку в нужном формате
                    text += f"• 🌏{host_name} — {method}: ✅ · ⏱️ {ping_str} ms · ↓ {download_str} Mbps · ↑ {upload_str} Mbps · 🕒 {time_str}\n"
                else:
                    text += f"• 🌏{host_name} — Нет данных о тестах скорости\n"
            
            
            await _safe_edit_or_send(
                callback.message,
                text,
                reply_markup=keyboards.create_back_to_main_menu_keyboard(),
                disable_web_page_preview=True
            )
        except TelegramBadRequest:
            pass


    @user_router.callback_query(F.data == "howto_android")
    @registration_required
    async def howto_android_handler(callback: types.CallbackQuery):
        await callback.answer()
        sub_url = await _get_connect_subscription_url_from_subscription_1(callback.from_user.id) or "https://q1.servernux.com:8443/sub/token"
        await _safe_edit_or_send(
            callback.message,
            "<b>Подключение на Android</b>\n\n"
            "1. Нажмите на «📥 Скачать приложение» и установите приложение.\n"
            "2. Нажмите на «🔗 Активировать подписку», чтобы добавить подключение в приложение.\n"
            "3. Всё готово! Теперь вы можете выбрать локацию и подключиться!\n\n"
            "Если кнопка «🔗 Активировать подписку» не сработала, скопируйте ссылку и вставьте её в приложение вручную.\n\n"
            f"{html.code(sub_url)}",
            reply_markup=keyboards.create_platform_download_keyboard("android", sub_url),
            disable_web_page_preview=True
        )

    @user_router.callback_query(F.data == "howto_ios")
    @registration_required
    async def howto_ios_handler(callback: types.CallbackQuery):
        await callback.answer()
        sub_url = await _get_connect_subscription_url_from_subscription_1(callback.from_user.id) or "https://q1.servernux.com:8443/sub/token"
        await _safe_edit_or_send(
            callback.message,
            "<b>Подключение на iOS/MacOS</b>\n\n"
            "1. Нажмите на «📥 Скачать из AppStore» и установите программу.\n"
            "2. Нажмите на «🔗 Активировать подписку», чтобы добавить подключение в приложение.\n"
            "3. Всё готово! Теперь вы можете выбрать локацию и подключиться!\n\n"
            "Если кнопка «🔗 Активировать подписку» не сработала, скопируйте ссылку и вставьте её в приложение вручную.\n\n"
            f"{html.code(sub_url)}",
            reply_markup=keyboards.create_platform_download_keyboard("ios", sub_url),
            disable_web_page_preview=True
        )

    @user_router.callback_query(F.data == "howto_windows")
    @registration_required
    async def howto_windows_handler(callback: types.CallbackQuery):
        await callback.answer()
        sub_url = await _get_connect_subscription_url_from_subscription_1(callback.from_user.id) or "https://q1.servernux.com:8443/sub/token"
        await _safe_edit_or_send(
            callback.message,
            "<b>Подключение на Windows</b>\n\n"
            "1. Нажмите на «📥 Скачать программу» и установите программу.\n"
            "2. Нажмите на «🔗 Активировать подписку», чтобы добавить подключение в приложение.\n"
            "3. Всё готово! Теперь вы можете выбрать локацию и подключиться!\n\n"
            "Если кнопка «🔗 Активировать подписку» не сработала, скопируйте ссылку и вставьте её в приложение вручную.\n\n"
            f"{html.code(sub_url)}",
            reply_markup=keyboards.create_platform_download_keyboard("windows", sub_url),
            disable_web_page_preview=True
        )

    @user_router.callback_query(F.data == "howto_linux")
    @registration_required
    async def howto_linux_handler(callback: types.CallbackQuery):
        await callback.answer()
        sub_url = await _get_connect_subscription_url_from_subscription_1(callback.from_user.id) or "https://q1.servernux.com:8443/sub/token"
        await _safe_edit_or_send(
            callback.message,
            "<b>Подключение на Linux</b>\n\n"
            "1. Нажмите на «📥 Скачать программу» и установите программу.\n"
            "2. Нажмите на «🔗 Активировать подписку», чтобы добавить подключение в приложение.\n"
            "3. Всё готово! Теперь вы можете выбрать локацию и подключиться!\n\n"
            "Если кнопка «🔗 Активировать подписку» не сработала, скопируйте ссылку и вставьте её в приложение вручную.\n\n"
            f"{html.code(sub_url)}",
            reply_markup=keyboards.create_platform_download_keyboard("linux", sub_url),
            disable_web_page_preview=True
        )

    @user_router.callback_query(F.data == "buy_new_key")
    @registration_required
    async def buy_new_key_handler(callback: types.CallbackQuery):
        await callback.answer()
        hosts = _get_regular_hosts()
        if not hosts:
            await _safe_edit_or_send(callback.message, "❌ В данный момент подписка недоступна.")
            return
        
        await _safe_edit_or_send(
            callback.message,
            "🚀 <b>Преимущества нашего VPN</b>\n"
            "• Высокая скорость и стабильное соединение\n"
            "• Доступ к нескольким серверам в одной подписке\n"
            "• Удобное продление и поддержка 24/7\n\n"
            "Нажмите кнопку ниже, чтобы перейти к покупке подписки:",
            reply_markup=keyboards.create_vpn_benefits_keyboard("buy")
        )

    @user_router.callback_query(F.data == "buy_traffic_start")
    @registration_required
    async def buy_traffic_start_handler(callback: types.CallbackQuery):
        await callback.answer()
        host_name, plans = _get_primary_host_with_plans(callback.from_user.id)
        if not host_name:
            await _safe_edit_or_send(callback.message, "❌ В данный момент подписка недоступна.")
            return
        if not plans:
            await _safe_edit_or_send(callback.message, "❌ Для продления пока не настроены тарифы.")
            return
        await _safe_edit_or_send(
            callback.message,
            "На сколько дней хотите продлить:",
            reply_markup=keyboards.create_plans_keyboard(plans, action="renewdays", host_name=host_name)
        )

    @user_router.callback_query(StateFilter(None), F.data == "back_to_plans")
    @registration_required
    async def back_to_plans_fallback_handler(callback: types.CallbackQuery):
        await callback.answer()
        host_name, plans = _get_primary_host_with_plans(callback.from_user.id)
        if not host_name or not plans:
            await _safe_edit_or_send(callback.message, "❌ Для продления пока не настроены тарифы.")
            return
        await _safe_edit_or_send(
            callback.message,
            "На сколько дней хотите продлить:",
            reply_markup=keyboards.create_plans_keyboard(plans, action="renewdays", host_name=host_name)
        )

    @user_router.callback_query(F.data == "show_connect_menu")
    @registration_required
    async def show_connect_menu_handler(callback: types.CallbackQuery):
        await callback.answer()
        await _safe_edit_or_send(
            callback.message,
            "Выберите устройство, которое хотите подключить:",
            reply_markup=keyboards.create_connect_devices_keyboard()
        )

    @user_router.callback_query(F.data == "buy_subscription_start")
    @registration_required
    async def buy_subscription_start_handler(callback: types.CallbackQuery):
        await callback.answer()
        host_name, plans = _get_primary_host_with_plans(callback.from_user.id)
        if not host_name:
            await _safe_edit_or_send(callback.message, "❌ В данный момент подписка недоступна.")
            return
        if not plans:
            await _safe_edit_or_send(callback.message, "❌ Для покупки пока не настроены тарифы.")
            return
        await _safe_edit_or_send(
            callback.message,
            CHOOSE_PLAN_MESSAGE or "Выберите тариф:",
            reply_markup=keyboards.create_plans_keyboard(plans, action="new", host_name=host_name)
        )

    @user_router.callback_query(F.data.startswith("extend_key_"))
    @registration_required
    async def extend_key_handler(callback: types.CallbackQuery):
        await callback.answer()

        try:
            key_id = int(callback.data.split("_")[2])
        except (IndexError, ValueError):
            await _safe_edit_or_send(callback.message, "❌ Произошла ошибка. Неверный формат ключа.")
            return

        key_data = get_key_by_id(key_id)

        if not key_data or key_data['user_id'] != callback.from_user.id:
            await _safe_edit_or_send(callback.message, "❌ Ошибка: Ключ не найден или не принадлежит вам.")
            return
        
        host_name = key_data.get('host_name')
        if not host_name:
            await _safe_edit_or_send(callback.message, "❌ Ошибка: Не удалось определить параметры подписки. Обратитесь в поддержку.")
            return

        plans = get_plans_for_host(host_name)

        if not plans:
            await _safe_edit_or_send(callback.message, 
                "❌ Для продления пока не настроены тарифы."
            )
            return

        await _safe_edit_or_send(callback.message, 
            "Выберите тариф продления подписки:",
            reply_markup=keyboards.create_plans_keyboard(
                plans=plans,
                action="extend",
                host_name=host_name,
                key_id=key_id
            )
        )

    @user_router.callback_query(F.data.startswith("buy_"))
    @user_router.callback_query(F.data.startswith("buy:"))
    @registration_required
    async def plan_selection_handler(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer()
        payload = callback.data or ""
        action = ""
        key_id = 0
        plan_id = 0
        host_name = ""

        if payload.startswith("buy:"):
            # New compact format: buy:<host_token>:<plan_id>:<action>:<key_id>
            parts = payload.split(":")
            if len(parts) != 5:
                await _safe_edit_or_send(callback.message, "❌ Ошибка выбора тарифа. Повторите попытку.")
                return
            _, host_token, plan_id_raw, action, key_id_raw = parts
            try:
                plan_id = int(plan_id_raw)
                key_id = int(key_id_raw)
            except (TypeError, ValueError):
                await _safe_edit_or_send(callback.message, "❌ Ошибка выбора тарифа. Повторите попытку.")
                return
            host = keyboards.find_host_by_callback_token(_get_regular_hosts(), host_token)
            if not host or not host.get("host_name"):
                hosts = _get_regular_hosts()
                host_name = (hosts[0].get("host_name") if hosts else "")
            else:
                host_name = host.get("host_name")
        else:
            # Legacy format: buy_<host_name>_<plan_id>_<action>_<key_id>
            parts = payload.split("_")[1:]
            action = parts[-2]
            key_id = int(parts[-1])
            plan_id = int(parts[-3])
            host_name = "_".join(parts[:-3])

        try:
            allowed_plan_ids = {int(p.get("plan_id")) for p in (get_all_plans_for_user(callback.from_user.id) or [])}
        except Exception:
            allowed_plan_ids = set()
        if allowed_plan_ids and int(plan_id) not in allowed_plan_ids:
            await _safe_edit_or_send(callback.message, "❌ Этот тариф недоступен для вашего аккаунта.")
            return

        await state.update_data(
            action=action, key_id=key_id, plan_id=plan_id, host_name=host_name
        )
        
        await _safe_edit_or_send(
            callback.message,
            "📧 Пожалуйста, введите ваш email для отправки чека об оплате.\n\n"
            "Если вы не хотите указывать почту, нажмите кнопку ниже.",
            reply_markup=keyboards.create_skip_email_keyboard()
        )
        await state.set_state(PaymentProcess.waiting_for_email)

    @user_router.callback_query(PaymentProcess.waiting_for_email, F.data == "back_to_plans")
    async def back_to_plans_handler(callback: types.CallbackQuery, state: FSMContext):
        data = await state.get_data()
        action = data.get('action')
        host_name = data.get('host_name')
        key_id = data.get('key_id')
    
        try:
            await callback.answer()
        except Exception:
            pass
    
        try:
            if action == 'extend' and host_name and (key_id is not None):
                plans = get_plans_for_host(host_name)
                if plans:
                    await _safe_edit_or_send(
                        callback.message,
                        "Выберите тариф продления подписки:",
                        reply_markup=keyboards.create_plans_keyboard(
                            plans=plans,
                            action="extend",
                            host_name=host_name,
                            key_id=int(key_id)
                        )
                    )
                else:
                    await _safe_edit_or_send(
                        callback.message,
                        "❌ Тарифы для продления не настроены."
                    )
            elif action == 'new' and host_name:
                plans = get_plans_for_host(host_name)
                if plans:
                    await _safe_edit_or_send(
                        callback.message,
                        "Выберите тариф подписки:",
                        reply_markup=keyboards.create_plans_keyboard(
                            plans=plans,
                            action="new",
                            host_name=host_name
                        )
                    )
                else:
                    await _safe_edit_or_send(
                        callback.message,
                        "❌ Тарифы не настроены."
                    )
            elif action == 'renewdays' and host_name:
                plans = get_plans_for_host(host_name)
                if plans:
                    await _safe_edit_or_send(
                        callback.message,
                        "На сколько дней хотите продлить:",
                        reply_markup=keyboards.create_plans_keyboard(
                            plans=plans,
                            action="renewdays",
                            host_name=host_name
                        )
                    )
                else:
                    await _safe_edit_or_send(callback.message, "❌ Тарифы не настроены.")
            elif action == 'traffic_package':
                packages = get_active_traffic_packages() or []
                if not packages:
                    await _safe_edit_or_send(callback.message, "❌ Пакеты трафика пока не настроены.")
                else:
                    await _safe_edit_or_send(
                        callback.message,
                        "➕ <b>Докупить трафик</b>\n\nВыберите пакет трафика:",
                        reply_markup=keyboards.create_traffic_packages_keyboard(packages)
                    )
            elif action == 'new':
                host_name, plans = _get_primary_host_with_plans()
                if not host_name or not plans:
                    await _safe_edit_or_send(callback.message, "❌ Для покупки пока не настроены тарифы.")
                else:
                    await _safe_edit_or_send(
                        callback.message,
                        CHOOSE_PLAN_MESSAGE or "Выберите тариф:",
                        reply_markup=keyboards.create_plans_keyboard(
                            plans=plans,
                            action="new",
                            host_name=host_name
                        )
                    )
            else:
                await show_main_menu(callback.message, edit_message=True)
        finally:
            try:
                await state.clear()
            except Exception:
                pass
    
    @user_router.message(PaymentProcess.waiting_for_email)
    async def process_email_handler(message: types.Message, state: FSMContext):
        if is_valid_email(message.text):
            await state.update_data(customer_email=message.text)
            await message.answer(f"✅ Email принят: {message.text}")

            # Показываем опции оплаты с учетом балансов и цены
            await show_payment_options(message, state)
            logger.info(f"Пользователь {message.chat.id}: Состояние установлено в waiting_for_payment_method через show_payment_options")
        else:
            await message.answer("❌ Неверный формат email. Попробуйте еще раз.")

    @user_router.callback_query(PaymentProcess.waiting_for_email, F.data == "skip_email")
    async def skip_email_handler(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer()
        await state.update_data(customer_email=None)

        # Показываем опции оплаты с учетом балансов и цены
        await show_payment_options(callback.message, state)
        logger.info(f"Пользователь {callback.from_user.id}: Состояние установлено в waiting_for_payment_method через show_payment_options")

    async def show_payment_options(message: types.Message, state: FSMContext):
        data = await state.get_data()
        user_data = get_user(message.chat.id)
        checkout = _resolve_checkout_context(message.chat.id, data)

        if not checkout:
            try:
                await _safe_edit_or_send(message, "❌ Ошибка: объект оплаты не найден.")
            except TelegramBadRequest:
                await message.answer("❌ Ошибка: объект оплаты не найден.")
            await state.clear()
            return

        price = Decimal(str(checkout["price"]))
        final_price = price
        message_text = CHOOSE_PAYMENT_METHOD_MESSAGE

        if checkout["kind"] == "subscription" and user_data.get('referred_by') and user_data.get('total_spent', 0) == 0:
            discount_percentage_str = get_setting("referral_discount") or "0"
            discount_percentage = Decimal(discount_percentage_str)
            
            if discount_percentage > 0:
                discount_amount = (Decimal(str(checkout["plan"]['price'])) * discount_percentage / 100).quantize(Decimal("0.01"))
                final_price = (Decimal(str(checkout["plan"]['price'])) - discount_amount).quantize(Decimal("0.01"))

                message_text = (
                    f"🎉 Как приглашенному пользователю, на вашу первую покупку предоставляется скидка {discount_percentage_str}%!\n"
                    f"Старая цена: <s>{Decimal(str(checkout['plan']['price'])):.2f} RUB</s>\n"
                    f"<b>Новая цена: {final_price:.2f} RUB</b>\n\n"
                ) + CHOOSE_PAYMENT_METHOD_MESSAGE

        # Промокод (если уже применён)
        promo_percent = data.get('promo_discount_percent')
        promo_amount = data.get('promo_discount_amount')
        promo_code = (data.get('promo_code') or '').strip()
        if promo_code:
            try:
                if promo_percent:
                    perc = Decimal(str(promo_percent))
                    if perc > 0:
                        discount_amount = (final_price * perc / 100).quantize(Decimal("0.01"))
                        final_price = (final_price - discount_amount).quantize(Decimal("0.01"))
                elif promo_amount:
                    amt = Decimal(str(promo_amount))
                    if amt > 0:
                        final_price = (final_price - amt).quantize(Decimal("0.01"))
                if final_price < Decimal('0'):
                    final_price = Decimal('0.00')
                # Добавим описание скидки промокода
                promo_line = f"Промокод {promo_code}: "
                if promo_percent:
                    promo_line += f"скидка {Decimal(str(promo_percent)):.0f}%\n"
                elif promo_amount:
                    promo_line += f"скидка {Decimal(str(promo_amount)):.2f} RUB\n"
                else:
                    promo_line += "применён\n"
                message_text = (
                    (f"{promo_line}"
                     f"Старая цена: <s>{price:.2f} RUB</s>\n"
                     f"<b>Новая цена: {final_price:.2f} RUB</b>\n\n")
                    + message_text
                )
            except Exception:
                pass

        await state.update_data(final_price=float(final_price))

        # Получаем основной баланс для показа кнопки оплаты с баланса
        try:
            main_balance = get_balance(message.chat.id)
        except Exception:
            main_balance = 0.0

        show_balance_btn = main_balance >= float(final_price)

        try:
            await _safe_edit_or_send(message, 
                message_text,
                reply_markup=keyboards.create_payment_method_keyboard(
                    payment_methods=PAYMENT_METHODS,
                    action=data.get('action'),
                    key_id=data.get('key_id'),
                    show_balance=show_balance_btn,
                    main_balance=main_balance,
                    price=float(final_price),
                    has_promo_applied=bool(promo_code),
                    allow_promo=(checkout["kind"] == "subscription")
                )
            )
        except TelegramBadRequest:
            await message.answer(
                message_text,
                reply_markup=keyboards.create_payment_method_keyboard(
                    payment_methods=PAYMENT_METHODS,
                    action=data.get('action'),
                    key_id=data.get('key_id'),
                    show_balance=show_balance_btn,
                    main_balance=main_balance,
                    price=float(final_price),
                    has_promo_applied=bool(promo_code),
                    allow_promo=(checkout["kind"] == "subscription")
                )
            )
        await state.set_state(PaymentProcess.waiting_for_payment_method)
        
    @user_router.callback_query(PaymentProcess.waiting_for_payment_method, F.data == "back_to_email_prompt")
    async def back_to_email_prompt_handler(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer()
        await _safe_edit_or_send(
            callback.message,
            "📧 Пожалуйста, введите ваш email для отправки чека об оплате.\n\n"
            "Если вы не хотите указывать почту, нажмите кнопку ниже.",
            reply_markup=keyboards.create_skip_email_keyboard()
        )
        await state.set_state(PaymentProcess.waiting_for_email)

    # --- Промокод: запрос ввода ---
    @user_router.callback_query(PaymentProcess.waiting_for_payment_method, F.data == "enter_promo_code")
    async def prompt_enter_promo(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer()
        await state.set_state(PaymentProcess.waiting_for_promo_code)
        await _safe_edit_or_send(callback.message, 
            "🎟️ Введите промокод текстом:"
        )

    # --- Промокод: обработка ввода ---
    @user_router.message(PaymentProcess.waiting_for_promo_code)
    async def handle_promo_input(message: types.Message, state: FSMContext):
        code = (message.text or "").strip()
        if not code:
            await message.answer("❌ Пустой промокод. Введите код ещё раз.")
            return
        promo, reason = check_promo_code_available(code, message.from_user.id)
        if not promo:
            reasons = {
                "not_found": "❌ Промокод не найден.",
                "inactive": "❌ Промокод деактивирован.",
                "not_started": "❌ Промокод ещё не начал действовать.",
                "expired": "❌ Срок действия промокода истёк.",
                "total_limit_reached": "❌ Достигнут общий лимит использования промокода.",
                "user_limit_reached": "❌ Вы исчерпали лимит использования промокода.",
                "db_error": "❌ Ошибка базы данных. Попробуйте позже.",
                "empty_code": "❌ Пустой промокод.",
            }
            await message.answer(reasons.get(reason or "not_found", "❌ Промокод недоступен."))
            # Вернёмся к выбору оплаты
            await show_payment_options(message, state)
            return
        # Сохраняем в состоянии применённый промокод
        await state.update_data(
            promo_code=promo.get("code"),
            promo_discount_percent=promo.get("discount_percent"),
            promo_discount_amount=promo.get("discount_amount"),
        )
        await message.answer("✅ Промокод применён.")
        await show_payment_options(message, state)
        await state.set_state(PaymentProcess.waiting_for_payment_method)

    # --- Промокод: удалить
    @user_router.callback_query(PaymentProcess.waiting_for_payment_method, F.data == "remove_promo_code")
    async def remove_promo(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer()
        data = await state.get_data()
        # Очистим поля промокода
        data.pop('promo_code', None)
        data.pop('promo_discount_percent', None)
        data.pop('promo_discount_amount', None)
        await state.set_data(data)
        await callback.message.answer("Промокод удалён.")
        await show_payment_options(callback.message, state)

    @user_router.callback_query(PaymentProcess.waiting_for_payment_method, F.data == "pay_yookassa")
    async def create_yookassa_payment_handler(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer("Создаю ссылку на оплату...")
        data = await state.get_data()
        checkout = _resolve_checkout_context(callback.from_user.id, data)
        if not checkout:
            await callback.message.answer("Произошла ошибка при выборе тарифа.")
            await state.clear()
            return
        customer_email = data.get('customer_email')
        
        if not customer_email:
            customer_email = get_setting("receipt_email")
        final_price_decimal = Decimal(str(checkout["price"])).quantize(Decimal("0.01"))
        user_id = callback.from_user.id

        try:
            price_str_for_api = f"{final_price_decimal:.2f}"
            price_float_for_metadata = float(final_price_decimal)

            receipt = None
            if customer_email and is_valid_email(customer_email):
                receipt = {
                    "customer": {"email": customer_email},
                    "items": [{
                        "description": checkout["payment_description"],
                        "quantity": "1.00",
                        "amount": {"value": price_str_for_api, "currency": "RUB"},
                        "vat_code": 1,
                        "payment_subject": "service",
                        "payment_mode": "full_payment"
                    }]
                }
            payment_payload = {
                "amount": {"value": price_str_for_api, "currency": "RUB"},
                "confirmation": {"type": "redirect", "return_url": f"https://t.me/{TELEGRAM_BOT_USERNAME}"},
                "capture": True,
                "description": checkout["description"],
                "metadata": _checkout_metadata_for_payment(
                    checkout,
                    data,
                    "YooKassa",
                    extra={"user_id": str(user_id), "price": f"{price_float_for_metadata:.2f}", "customer_email": customer_email or ""}
                ),
            }
            if receipt:
                payment_payload['receipt'] = receipt

            payment = Payment.create(payment_payload, uuid.uuid4())
            
            await state.clear()
            
            await _safe_edit_or_send(callback.message, 
                "Нажмите на кнопку ниже для оплаты:",
                reply_markup=keyboards.create_payment_keyboard(payment.confirmation.confirmation_url)
            )
        except Exception as e:
            logger.error(f"Не удалось создать платеж YooKassa: {e}", exc_info=True)
            await callback.message.answer("Не удалось создать ссылку на оплату.")
            await state.clear()

    @user_router.callback_query(PaymentProcess.waiting_for_payment_method, F.data == "pay_yoomoney")
    async def create_yoomoney_payment_handler(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer("Готовлю ссылку ЮMoney…")
        data = await state.get_data()
        checkout = _resolve_checkout_context(callback.from_user.id, data)
        if not checkout:
            await _safe_edit_or_send(callback.message, "❌ Произошла ошибка при выборе тарифа.")
            await state.clear()
            return
        final_price_decimal = Decimal(str(checkout["price"])).quantize(Decimal("0.01"))

        final_price_float = float(final_price_decimal)

        ym_wallet = (get_setting("yoomoney_wallet") or "").strip()
        if not ym_wallet:
            await _safe_edit_or_send(callback.message, "❌ Оплата через ЮMoney временно недоступна.")
            await state.clear()
            return

        user_id = callback.from_user.id
        payment_id = str(uuid.uuid4())
        metadata = _checkout_metadata_for_payment(checkout, data, "YooMoney", extra={"payment_id": payment_id, "user_id": user_id, "price": final_price_float})
        # Сохраняем pending транзакцию в БД
        try:
            create_pending_transaction(payment_id, user_id, final_price_float, metadata)
        except Exception as e:
            logger.warning(f"YooMoney: не удалось создать ожидающую транзакцию: {e}")

        # Формируем ссылку QuickPay
        try:
            success_url = f"https://t.me/{TELEGRAM_BOT_USERNAME}" if TELEGRAM_BOT_USERNAME else None
        except Exception:
            success_url = None
        targets = checkout["payment_description"]
        pay_url = _build_yoomoney_quickpay_url(
            wallet=ym_wallet,
            amount=final_price_float,
            label=payment_id,
            success_url=success_url,
            targets=targets,
        )

        await state.clear()
        try:
            await _safe_edit_or_send(callback.message, 
                "Нажмите на кнопку ниже для оплаты. После оплаты нажмите 'Проверить оплату':",
                reply_markup=keyboards.create_payment_with_check_keyboard(pay_url, f"check_yoomoney_{payment_id}")
            )
        except TelegramBadRequest:
            await callback.message.answer(
                "Нажмите на кнопку ниже для оплаты. После оплаты нажмите 'Проверить оплату':",
                reply_markup=keyboards.create_payment_with_check_keyboard(pay_url, f"check_yoomoney_{payment_id}")
            )

    @user_router.callback_query(
        PaymentProcess.waiting_for_payment_method,
        (F.data == "pay_platega_sbp") | (F.data == "pay_platega_card") | (F.data == "pay_platega_crypto")
    )
    async def create_platega_payment_handler(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer("Создаю ссылку Platega…")
        data = await state.get_data()
        checkout = _resolve_checkout_context(callback.from_user.id, data)
        if not checkout:
            await _safe_edit_or_send(callback.message, "❌ Произошла ошибка при выборе тарифа.")
            await state.clear()
            return

        callback_method = (callback.data or "").strip()
        method_meta = {
            "pay_platega_sbp": {
                "setting": "platega_payment_method_sbp",
                "defaults": [2],
                "title": "Оплата через СБП",
                "method": "СБП",
            },
            "pay_platega_card": {
                "setting": "platega_payment_method_card",
                "defaults": [11],
                "title": "Оплата банковской картой",
                "method": "Банковская карта",
            },
            "pay_platega_crypto": {
                "setting": "platega_payment_method_crypto",
                "defaults": [13],
                "title": "Оплата криптовалютой",
                "method": "Криптовалюта",
            },
        }
        selected = method_meta.get(callback_method)
        if not selected:
            await _safe_edit_or_send(callback.message, "❌ Неверный способ оплаты.")
            return

        final_price_decimal = Decimal(str(checkout["price"])).quantize(Decimal("0.01"))
        final_price_float = float(final_price_decimal)
        user_id = callback.from_user.id
        try:
            success_url = f"https://t.me/{TELEGRAM_BOT_USERNAME}" if TELEGRAM_BOT_USERNAME else None
        except Exception:
            success_url = None

        payload_obj = {
            "kind": checkout["kind"],
            "user_id": user_id,
            "action": data.get('action'),
        }
        if checkout["kind"] == "subscription":
            payload_obj["months"] = checkout["months"]
            payload_obj["plan_id"] = data.get('plan_id')
        else:
            payload_obj["traffic_package_id"] = data.get('traffic_package_id')
            payload_obj["traffic_gb"] = checkout["package_gb"]
        description_text = checkout["description"]
        result = await _platega_create_for_method_candidates(
            amount_rub=final_price_float,
            description=description_text,
            payload=json.dumps(payload_obj, ensure_ascii=False, separators=(",", ":")),
            setting_key=selected["setting"],
            default_values=selected["defaults"],
            success_url=success_url,
            failed_url=success_url,
        )
        if not result:
            await _safe_edit_or_send(callback.message, "❌ Не удалось создать ссылку Platega. Попробуйте позже.")
            await state.clear()
            return

        pay_url, transaction_id, method_code_used, method_name_used = result
        metadata = _checkout_metadata_for_payment(checkout, data, "Platega", extra={"payment_id": transaction_id, "user_id": user_id, "price": final_price_float})
        try:
            create_pending_transaction(transaction_id, user_id, final_price_float, metadata)
        except Exception as e:
            logger.warning(f"Platega покупка: не удалось создать ожидающую транзакцию: {e}")

        await state.clear()
        logger.info(
            "Platega subscription: method='%s', provider_method='%s', code=%s",
            selected["method"], method_name_used, method_code_used
        )
        invoice_text = (
            f"💳 {selected['title']}\n\n"
            f"Тариф: {checkout['title']}\n"
            f"Сумма: {final_price_float:.2f} RUB\n"
            f"Способ: {selected['method']}"
        )
        try:
            await _safe_edit_or_send(
                callback.message,
                invoice_text,
                reply_markup=keyboards.create_payment_keyboard(pay_url)
            )
        except TelegramBadRequest:
            await callback.message.answer(
                invoice_text,
                reply_markup=keyboards.create_payment_keyboard(pay_url)
            )

    @user_router.callback_query(PaymentProcess.waiting_for_payment_method, F.data == "pay_stars")
    async def create_stars_invoice_handler(callback: types.CallbackQuery, state: FSMContext, bot: Bot):
        await callback.answer("Готовлю счёт в Stars…")
        data = await state.get_data()
        checkout = _resolve_checkout_context(callback.from_user.id, data)
        if not checkout:
            await _safe_edit_or_send(callback.message, "❌ Произошла ошибка при выборе тарифа.")
            await state.clear()
            return
        price_decimal = Decimal(str(checkout["price"])).quantize(Decimal("0.01"))
        stars_count = _calc_stars_amount(price_decimal)
        # Для Stars ограничим payload до UUID, метаданные сохраним в pending‑транзакцию
        payment_id = str(uuid.uuid4())
        metadata = _checkout_metadata_for_payment(checkout, data, "Stars", extra={"user_id": callback.from_user.id, "price": float(price_decimal)})
        try:
            create_pending_transaction(payment_id, callback.from_user.id, float(price_decimal), metadata)
        except Exception as e:
            logger.warning(f"Stars покупка: не удалось создать ожидающую транзакцию: {e}")
        payload = payment_id

        title = (get_setting("stars_title") or "Покупка VPN")
        description = checkout["payment_description"]
        try:
            await bot.send_invoice(
                chat_id=callback.message.chat.id,
                title=title,
                description=description,
                payload=payload,
                currency="XTR",
                prices=[types.LabeledPrice(label=checkout["title"], amount=stars_count)],
            )
            await state.clear()
        except Exception as e:
            logger.error(f"Не удалось отправить счет Stars: {e}")
            await _safe_edit_or_send(callback.message, "❌ Не удалось создать счёт Stars. Попробуйте другой способ оплаты.")
            await state.clear()

    @user_router.callback_query(PaymentProcess.waiting_for_payment_method, F.data == "pay_cryptobot")
    async def create_cryptobot_invoice_handler(callback: types.CallbackQuery, state: FSMContext):
        await callback.answer("Создаю счет в Crypto Pay...")
        
        data = await state.get_data()
        checkout = _resolve_checkout_context(callback.from_user.id, data)
        if not checkout:
            await _safe_edit_or_send(callback.message, "❌ Произошла ошибка при выборе тарифа.")
            await state.clear()
            return
        user_id = data.get('user_id', callback.from_user.id)

        cryptobot_token = get_setting('cryptobot_token')
        if not cryptobot_token:
            logger.error(f"Попытка создания счета Crypto Pay не удалась для пользователя {user_id}: cryptobot_token не установлен.")
            await _safe_edit_or_send(callback.message, "❌ Оплата криптовалютой временно недоступна. (Администратор не указал токен).")
            await state.clear()
            return
        final_price_float = float(Decimal(str(checkout["price"])).quantize(Decimal("0.01")))
        payment_id = str(uuid.uuid4())
        metadata = _checkout_metadata_for_payment(checkout, data, "CryptoBot", extra={"payment_id": payment_id, "user_id": callback.from_user.id, "price": final_price_float})
        try:
            create_pending_transaction(payment_id, callback.from_user.id, final_price_float, metadata)
        except Exception as e:
            logger.warning(f"CryptoBot покупка: не удалось создать ожидающую транзакцию: {e}")

        result = await _create_cryptobot_invoice(
            user_id=callback.from_user.id,
            price_rub=final_price_float,
            months=int(checkout.get('months') or 0),
            host_name=data.get('host_name'),
            state_data={"payment_id": payment_id},
        )
        
        if result:
            pay_url, invoice_id = result
            # Сохраняем invoice_id в состояние для последующей проверки
            await state.update_data(cryptobot_invoice_id=invoice_id)
            await state.set_state(PaymentProcess.waiting_for_cryptobot_payment)
            
            await _safe_edit_or_send(callback.message, 
                "Нажмите на кнопку ниже для оплаты:\n\n"
                "💡 После оплаты нажмите «Проверить платёж» для подтверждения.",
                reply_markup=keyboards.create_payment_with_check_keyboard(pay_url, "check_cryptobot_payment")
            )
        else:
            await _safe_edit_or_send(callback.message, "❌ Не удалось создать счет CryptoBot. Попробуйте другой способ оплаты.")
            await state.clear()

    @user_router.callback_query(PaymentProcess.waiting_for_cryptobot_payment, F.data == "check_cryptobot_payment")
    async def check_cryptobot_payment_handler(callback: types.CallbackQuery, state: FSMContext, bot: Bot):
        """Обработчик проверки статуса платежа CryptoBot"""
        await callback.answer("Проверяю статус платежа...")
        
        data = await state.get_data()
        invoice_id = data.get('cryptobot_invoice_id')
        
        if not invoice_id:
            await _safe_edit_or_send(callback.message, "❌ Не найден ID счета для проверки.")
            await state.clear()
            return
        
        cryptobot_token = get_setting('cryptobot_token')
        if not cryptobot_token:
            logger.error("CryptoBot: не задан cryptobot_token для проверки платежа")
            await _safe_edit_or_send(callback.message, "❌ Ошибка конфигурации. Обратитесь к администратору.")
            await state.clear()
            return
        
        try:
            cp = CryptoPay(cryptobot_token)
            # Получаем информацию о счете
            invoices = await cp.get_invoices(invoice_ids=[invoice_id])
            
            if not invoices or len(invoices) == 0:
                await callback.answer("❌ Счет не найден", show_alert=True)
                return
            
            invoice = invoices[0]
            
            # Получаем статус счета
            status = None
            try:
                status = getattr(invoice, "status", None)
            except Exception:
                pass
            
            if not status and isinstance(invoice, dict):
                status = invoice.get("status")
            
            logger.info(f"CryptoBot проверка платежа: invoice_id={invoice_id}, status={status}")
            
            if status == "paid":
                # Платеж оплачен! Обрабатываем его
                await callback.answer("✅ Платеж найден! Обрабатываю...", show_alert=True)
                
                # Получаем payload из счета
                payload_string = None
                try:
                    payload_string = getattr(invoice, "payload", None)
                except Exception:
                    pass
                
                if not payload_string and isinstance(invoice, dict):
                    payload_string = invoice.get("payload")
                
                if not payload_string:
                    logger.error(f"CryptoBot проверка: не найден payload для счета {invoice_id}")
                    await _safe_edit_or_send(callback.message, "❌ Ошибка обработки платежа. Обратитесь в поддержку.")
                    await state.clear()
                    return
                
                metadata = find_and_complete_pending_transaction(
                    payment_id=payload_string,
                    amount_rub=None,
                    payment_method="CryptoBot",
                    currency_name="USDT",
                    amount_currency=None,
                )
                if not metadata:
                    logger.error(f"CryptoBot проверка: не удалось завершить pending transaction '{payload_string}'")
                    await _safe_edit_or_send(callback.message, "❌ Ошибка обработки платежа. Обратитесь в поддержку.")
                    await state.clear()
                    return
                
                # Обрабатываем успешный платеж
                await process_successful_payment(bot, metadata)
                await _safe_edit_or_send(callback.message, "✅ Платеж успешно обработан!")
                await state.clear()
                
            elif status == "active":
                # Счет создан, но еще не оплачен
                await callback.answer("⏳ Платеж еще не получен. Пожалуйста, завершите оплату и нажмите кнопку снова.", show_alert=True)
                
            else:
                # Другие статусы (expired, cancelled и т.д.)
                await callback.answer(f"❌ Статус платежа: {status}. Пожалуйста, создайте новый счет.", show_alert=True)
                await state.clear()
                
        except Exception as e:
            logger.error(f"CryptoBot: ошибка при проверке счёта {invoice_id}: {e}", exc_info=True)
            await callback.answer("❌ Ошибка при проверке платежа. Попробуйте позже.", show_alert=True)

    @user_router.callback_query(PaymentProcess.waiting_for_payment_method, F.data == "pay_tonconnect")
    async def create_ton_invoice_handler(callback: types.CallbackQuery, state: FSMContext):
        logger.info(f"Пользователь {callback.from_user.id}: Вход в create_ton_invoice_handler.")
        data = await state.get_data()
        user_id = callback.from_user.id
        wallet_address = get_setting("ton_wallet_address")
        checkout = _resolve_checkout_context(callback.from_user.id, data)
        if not wallet_address or not checkout:
            await _safe_edit_or_send(callback.message, "❌ Оплата через TON временно недоступна.")
            await state.clear()
            return

        await callback.answer("Создаю ссылку и QR-код для TON Connect...")
            
        price_rub = Decimal(str(checkout["price"]))

        usdt_rub_rate = await get_usdt_rub_rate()
        ton_usdt_rate = await get_ton_usdt_rate()

        if not usdt_rub_rate or not ton_usdt_rate:
            await _safe_edit_or_send(callback.message, "❌ Не удалось получить курс TON. Попробуйте позже.")
            await state.clear()
            return

        price_ton = (price_rub / usdt_rub_rate / ton_usdt_rate).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP)
        amount_nanoton = int(price_ton * 1_000_000_000)
        
        payment_id = str(uuid.uuid4())
        metadata = _checkout_metadata_for_payment(checkout, data, "TON Connect", extra={"user_id": user_id, "price": float(price_rub)})
        create_pending_transaction(payment_id, user_id, float(price_rub), metadata)

        transaction_payload = {
            'messages': [{'address': wallet_address, 'amount': str(amount_nanoton), 'payload': payment_id}],
            'valid_until': int(datetime.now().timestamp()) + 600
        }

        try:
            connect_url = await _start_ton_connect_process(user_id, transaction_payload)
            
            qr_img = qrcode.make(connect_url)
            bio = BytesIO()
            qr_img.save(bio, "PNG")
            qr_file = BufferedInputFile(bio.getvalue(), "ton_qr.png")

            # Удаляем предыдущее сообщение безопасно (если нельзя удалить, просто пропустим)
            try:
                await callback.message.delete()
            except Exception:
                pass
            await callback.message.answer_photo(
                photo=qr_file,
                caption=(
                    f"💎 **Оплата через TON Connect**\n\n"
                    f"Сумма к оплате: `{price_ton}` **TON**\n\n"
                    f"✅ **Способ 1 (на телефоне):** Нажмите кнопку **'Открыть кошелек'** ниже.\n"
                    f"✅ **Способ 2 (на компьютере):** Отсканируйте QR-код кошельком.\n\n"
                    f"После подключения кошелька подтвердите транзакцию."
                ),
                parse_mode="Markdown",
                reply_markup=keyboards.create_ton_connect_keyboard(connect_url)
            )
            await state.clear()

        except Exception as e:
            logger.error(f"Не удалось сгенерировать ссылку TON Connect для пользователя {user_id}: {e}", exc_info=True)
            await callback.message.answer("❌ Не удалось создать ссылку для TON Connect. Попробуйте позже.")
            await state.clear()

    @user_router.callback_query(PaymentProcess.waiting_for_payment_method, F.data == "pay_balance")
    async def pay_with_main_balance_handler(callback: types.CallbackQuery, state: FSMContext, bot: Bot):
        await callback.answer()
        data = await state.get_data()
        user_id = callback.from_user.id
        checkout = _resolve_checkout_context(callback.from_user.id, data)
        if not checkout:
            await _safe_edit_or_send(callback.message, "❌ Ошибка: объект оплаты не найден.")
            await state.clear()
            return
        price = float(Decimal(str(checkout["price"])))

        # Пытаемся списать средства с основного баланса
        if not deduct_from_balance(user_id, price):
            await callback.answer("Недостаточно средств на основном балансе.", show_alert=True)
            return

        metadata = _checkout_metadata_for_payment(
            checkout, data, "Balance",
            extra={"user_id": user_id, "price": price, "chat_id": callback.message.chat.id, "message_id": callback.message.message_id}
        )

        await state.clear()
        await process_successful_payment(bot, metadata)

    # Telegram Payments: подтверждаем pre_checkout
    @user_router.pre_checkout_query()
    async def pre_checkout_handler(pre_checkout_query: types.PreCheckoutQuery, bot: Bot):
        try:
            await bot.answer_pre_checkout_query(pre_checkout_query.id, ok=True)
        except Exception as e:
            logger.warning(f"pre_checkout_handler не удался: {e}")

    # Сообщение об успешной оплате (в т.ч. Stars)
    @user_router.message(F.successful_payment)
    async def successful_payment_handler(message: types.Message, bot: Bot):
        try:
            sp = message.successful_payment
            payload = sp.invoice_payload or ""
            metadata = {}
            # 1) Пытаемся трактовать payload как JSON (на случай старых инвойсов)
            if payload:
                try:
                    parsed = json.loads(payload)
                    if isinstance(parsed, dict):
                        metadata = parsed
                except Exception:
                    metadata = {}
            # 2) Если JSON не получился — считаем, что payload это payment_id для pending‑транзакции
            if not metadata and payload:
                try:
                    currency = getattr(sp, 'currency', None)
                    total_amount = getattr(sp, 'total_amount', None)
                    payment_method = "Stars" if str(currency).upper() == "XTR" else "Card"
                    md = find_and_complete_pending_transaction(
                        payment_id=payload,
                        amount_rub=None,  # оставляем исходную сумму из pending
                        payment_method=payment_method,
                        currency_name=currency,
                        amount_currency=(float(total_amount) if total_amount is not None else None),
                    )
                    if md:
                        metadata = md
                except Exception as e:
                    logger.error(f"Не удалось разрешить ожидающую транзакцию по payload '{payload}': {e}")
        except Exception as e:
            logger.error(f"Не удалось разобрать payload успешного платежа: {e}")
            metadata = {}
        if not metadata:
            try:
                await message.answer("✅ Оплата получена, но нет данных заказа. Обратитесь в поддержку, если ключ не выдан.")
            except Exception:
                pass
            return
        await process_successful_payment(bot, metadata)

    return user_router

async def _create_heleket_payment_request(
    user_id: int,
    price: float,
    months: int,
    host_name: str,
    state_data: dict,
) -> Optional[str]:
    """Создать счёт через Heleket и вернуть ссылку на оплату.

    Формирует payload с подписью по той же схеме, которой пользуется вебхук:
    sign = md5( base64( json.dumps(data_sorted) ) + api_key ).

    Возвращает URL на оплату или None при ошибке.
    """
    try:
        merchant_id = get_setting("heleket_merchant_id")
        api_key = get_setting("heleket_api_key")
        if not merchant_id or not api_key:
            logger.error("Heleket: отсутствуют merchant_id/api_key в настройках.")
            return None

        # Метаданные, которые затем будут разобраны в webhook (`description` JSON)
        metadata = {
            "payment_id": str(uuid.uuid4()),
            "user_id": user_id,
            "months": months,
            "price": float(price),
            "action": state_data.get("action"),
            "key_id": state_data.get("key_id"),
            "host_name": host_name,
            "plan_id": state_data.get("plan_id"),
            "customer_email": state_data.get("customer_email"),
            "payment_method": "Crypto",
            "promo_code": state_data.get("promo_code"),
            "promo_discount_percent": state_data.get('promo_discount_percent'),
            "promo_discount_amount": state_data.get('promo_discount_amount'),
        }

        # Базовые поля счёта для Heleket
        dom_val = get_setting("domain")
        domain = (dom_val or "").strip() if isinstance(dom_val, str) else dom_val
        callback_url = None
        try:
            if domain:
                callback_url = f"{str(domain).rstrip('/')}/heleket-webhook"
        except Exception:
            callback_url = None

        # Укажем success_url как возврат в бота
        success_url = None
        try:
            if TELEGRAM_BOT_USERNAME:
                success_url = f"https://t.me/{TELEGRAM_BOT_USERNAME}"
        except Exception:
            success_url = None

        data: Dict[str, object] = {
            "merchant_id": merchant_id,
            "order_id": str(uuid.uuid4()),
            "amount": float(price),
            "currency": "RUB",
            "description": json.dumps(metadata, ensure_ascii=False, separators=(",", ":")),
        }
        if callback_url:
            data["callback_url"] = callback_url
        if success_url:
            data["success_url"] = success_url

        # Формируем подпись в соответствии с обработчиком вебхука
        sorted_data_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
        base64_encoded = base64.b64encode(sorted_data_str.encode()).decode()
        raw_string = f"{base64_encoded}{api_key}"
        sign = hashlib.md5(raw_string.encode()).hexdigest()

        payload = dict(data)
        payload["sign"] = sign

        # Базовый URL API Heleket. Делаем настраиваемым через (необязательную) настройку heleket_api_base.
        api_base_val = get_setting("heleket_api_base")
        api_base = (api_base_val or "https://api.heleket.com").rstrip("/")
        endpoint = f"{api_base}/invoice/create"

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(endpoint, json=payload, timeout=15) as resp:
                    text = await resp.text()
                    if resp.status not in (200, 201):
                        logger.error(f"Heleket: не удалось создать счёт (HTTP {resp.status}): {text}")
                        return None
                    try:
                        data_json = await resp.json()
                    except Exception:
                        # Если провайдер вернул не JSON
                        logger.warning(f"Heleket: неожиданный ответ (не JSON): {text}")
                        return None
                    pay_url = (
                        data_json.get("payment_url")
                        or data_json.get("pay_url")
                        or data_json.get("url")
                    )
                    if not pay_url:
                        logger.error(f"Heleket: не найдено поле URL в ответе: {data_json}")
                        return None
                    return str(pay_url)
            except Exception as e:
                logger.error(f"Heleket: ошибка HTTP при создании счёта: {e}", exc_info=True)
                return None
    except Exception as e:
        logger.error(f"Heleket: общая ошибка при создании счёта: {e}", exc_info=True)
        return None

async def _create_cryptobot_invoice(
    user_id: int,
    price_rub: float,
    months: int,
    host_name: str,
    state_data: dict,
) -> Optional[tuple[str, int]]:
    """Создать счёт в Telegram Crypto Pay и вернуть ссылку на оплату и ID счета.

    - Конвертирует RUB в USDT по рыночному курсу.
    - Использует короткий payload = payment_id ожидающей транзакции.
    
    Returns:
        tuple[str, int] | None: (pay_url, invoice_id) или None при ошибке
    """
    try:
        token = get_setting("cryptobot_token")
        if not token:
            logger.error("CryptoBot: не задан cryptobot_token")
            return None

        rate = await get_usdt_rub_rate()
        if not rate or rate <= 0:
            logger.error("CryptoBot: не удалось получить курс USDT/RUB")
            return None

        amount_usdt = (Decimal(str(price_rub)) / rate).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        payload = str(state_data.get("payment_id") or "").strip()
        if not payload:
            logger.error("CryptoBot: отсутствует payment_id для payload")
            return None

        cp = CryptoPay(token)
        # Пытаемся создать инвойс в USDT; описание — краткое
        invoice = await cp.create_invoice(
            asset="USDT",
            amount=float(amount_usdt),
            description="VPN оплата",
            payload=payload,
        )

        pay_url = None
        invoice_id = None
        
        try:
            # У разных обёрток могут отличаться имена полей
            pay_url = getattr(invoice, "pay_url", None) or getattr(invoice, "bot_invoice_url", None)
            invoice_id = getattr(invoice, "invoice_id", None)
        except Exception:
            pass
        
        if not pay_url and isinstance(invoice, dict):
            pay_url = invoice.get("pay_url") or invoice.get("bot_invoice_url") or invoice.get("url")
            
        if not invoice_id and isinstance(invoice, dict):
            invoice_id = invoice.get("invoice_id")
            
        if not pay_url:
            logger.error(f"CryptoBot: не удалось получить ссылку на оплату из ответа: {invoice}")
            return None
            
        if not invoice_id:
            logger.error(f"CryptoBot: не удалось получить invoice_id из ответа: {invoice}")
            return None
            
        return (str(pay_url), int(invoice_id))
    except Exception as e:
        logger.error(f"CryptoBot: ошибка при создании счёта: {e}", exc_info=True)
        return None

async def get_usdt_rub_rate() -> Optional[Decimal]:
    """Получить курс USDT→RUB. Возвращает Decimal или None при ошибке."""
    try:
        url = "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=rub"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as resp:
                if resp.status != 200:
                    logger.warning(f"USDT/RUB: HTTP {resp.status}")
                    return None
                data = await resp.json()
                val = data.get("tether", {}).get("rub")
                if val is None:
                    return None
                return Decimal(str(val))
    except Exception as e:
        logger.warning(f"USDT/RUB: ошибка получения курса: {e}")
        return None

async def get_ton_usdt_rate() -> Optional[Decimal]:
    """Получить курс TON→USDT (через USD). Возвращает Decimal или None при ошибке."""
    try:
        url = "https://api.coingecko.com/api/v3/simple/price?ids=toncoin&vs_currencies=usd"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as resp:
                if resp.status != 200:
                    logger.warning(f"TON/USD: HTTP {resp.status}")
                    return None
                data = await resp.json()
                usd = data.get("toncoin", {}).get("usd")
                if usd is None:
                    return None
                return Decimal(str(usd))
    except Exception as e:
        logger.warning(f"TON/USD: ошибка получения курса: {e}")
        return None

async def _start_ton_connect_process(user_id: int, transaction_payload: Dict) -> str:
    """Упростённый генератор deep‑link для TON перевода.

    Вместо полноценного протокола TON Connect формируем ссылку вида:
    ton://transfer/<address>?amount=<nanoton>&text=<payload>
    Поддерживается большинством TON-кошельков и удобна для QR.
    """
    try:
        messages = transaction_payload.get("messages") or []
        if not messages:
            raise ValueError("transaction_payload.messages is empty")
        msg = messages[0]
        address = msg.get("address")
        amount = msg.get("amount")  # в нанотонах как строка
        payload_text = msg.get("payload") or ""
        if not address or not amount:
            raise ValueError("address/amount are required in transaction message")
        # Сформируем ton://transfer ...
        params = {"amount": amount}
        if payload_text:
            params["text"] = str(payload_text)
        query = urlencode(params)
        return f"ton://transfer/{address}?{query}"
    except Exception as e:
        logger.error(f"TON генерация deep link не удалась: {e}")
        # Фолбэк: без параметров
        return "ton://transfer"

def _build_yoomoney_quickpay_url(
    wallet: str,
    amount: float,
    label: str,
    success_url: Optional[str] = None,
    targets: Optional[str] = None,
) -> str:
    try:
        params = {
            "receiver": wallet,
            "quickpay-form": "shop",
            "sum": f"{float(amount):.2f}",
            "label": label,
        }
        if success_url:
            params["successURL"] = success_url
        if targets:
            params["targets"] = targets
        base = "https://yoomoney.ru/quickpay/confirm.xml"
        return f"{base}?{urlencode(params)}"
    except Exception:
        return "https://yoomoney.ru/"

async def _yoomoney_find_payment(label: str) -> Optional[dict]:
    token = (get_setting("yoomoney_api_token") or "").strip()
    if not token:
        logger.warning("YooMoney: API токен не задан в настройках.")
        return None
    url = "https://yoomoney.ru/api/operation-history"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "label": label,
        "records": "5",
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=data, headers=headers, timeout=15) as resp:
                text = await resp.text()
                if resp.status != 200:
                    logger.warning(f"YooMoney: operation-history HTTP {resp.status}: {text}")
                    return None
                try:
                    payload = await resp.json()
                except Exception:
                    try:
                        payload = json.loads(text)
                    except Exception:
                        logger.warning("YooMoney: не удалось распарсить JSON operation-history")
                        return None
                ops = payload.get("operations") or []
                for op in ops:
                    if str(op.get("label")) == str(label) and str(op.get("direction")) == "in":
                        status = str(op.get("status") or "").lower()
                        if status == "success":
                            try:
                                amount = float(op.get("amount"))
                            except Exception:
                                amount = None
                            return {
                                "operation_id": op.get("operation_id"),
                                "amount": amount,
                                "datetime": op.get("datetime"),
                            }
                return None
    except Exception as e:
        logger.error(f"YooMoney: ошибка запроса operation-history: {e}", exc_info=True)
        return None

def _platega_api_base() -> str:
    base = (get_setting("platega_api_base") or "").strip()
    if not base:
        base = "https://app.platega.io"
    return base.rstrip("/")

async def _platega_create_transaction(
    amount_rub: float,
    description: str,
    payload: str,
    payment_method: Optional[int] = None,
    success_url: Optional[str] = None,
    failed_url: Optional[str] = None,
) -> Optional[tuple[str, str, str]]:
    merchant_id = (get_setting("platega_merchant_id") or "").strip()
    secret_key = (get_setting("platega_secret_key") or "").strip()
    if not merchant_id or not secret_key:
        logger.error("Platega: не заданы platega_merchant_id/platega_secret_key")
        return None
    if payment_method is None:
        try:
            payment_method = int((get_setting("platega_payment_method") or "2").strip())
        except Exception:
            payment_method = 2

    req_data = {
        "paymentMethod": payment_method,
        "paymentDetails": {
            "amount": float(amount_rub),
            "currency": "RUB",
        },
        "description": (description or "VPN payment")[:255],
        "payload": payload,
    }
    if success_url:
        req_data["return"] = success_url
    if failed_url:
        req_data["failedUrl"] = failed_url

    headers = {
        "Content-Type": "application/json",
        "X-MerchantId": merchant_id,
        "X-Secret": secret_key,
    }
    endpoint = f"{_platega_api_base()}/transaction/process"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(endpoint, json=req_data, headers=headers, timeout=20) as resp:
                text = await resp.text()
                if resp.status not in (200, 201):
                    logger.error(f"Platega: create transaction HTTP {resp.status}: {text}")
                    return None
                try:
                    data = await resp.json()
                except Exception:
                    logger.error(f"Platega: create transaction invalid JSON: {text}")
                    return None
                tx_id = str(data.get("transactionId") or data.get("id") or "").strip()
                redirect_url = str(data.get("redirect") or data.get("url") or "").strip()
                method_name = str(data.get("paymentMethod") or "").strip().upper()
                if not tx_id or not redirect_url:
                    logger.error(f"Platega: missing transactionId/redirect in response: {data}")
                    return None
                return redirect_url, tx_id, method_name
    except Exception as e:
        logger.error(f"Platega: create transaction exception: {e}", exc_info=True)
        return None

def _platega_parse_method_candidates(setting_key: str, default_values: list[int]) -> list[int]:
    raw = (get_setting(setting_key) or "").strip()
    values: list[int] = []
    if raw:
        for chunk in raw.replace(";", ",").split(","):
            part = chunk.strip()
            if not part:
                continue
            try:
                values.append(int(part))
            except Exception:
                continue
    values.extend(int(v) for v in default_values)
    # unique, keep order
    seen: set[int] = set()
    uniq: list[int] = []
    for v in values:
        if v in seen:
            continue
        seen.add(v)
        uniq.append(v)
    return uniq

async def _platega_create_for_method_candidates(
    amount_rub: float,
    description: str,
    payload: str,
    setting_key: str,
    default_values: list[int],
    success_url: Optional[str] = None,
    failed_url: Optional[str] = None,
) -> Optional[tuple[str, str, int, str]]:
    candidates = _platega_parse_method_candidates(setting_key, default_values)
    for method_code in candidates:
        created = await _platega_create_transaction(
            amount_rub=amount_rub,
            description=description,
            payload=payload,
            payment_method=method_code,
            success_url=success_url,
            failed_url=failed_url,
        )
        if not created:
            continue
        redirect_url, tx_id, method_name = created
        return redirect_url, tx_id, method_code, method_name
    return None

async def _platega_get_transaction_status(transaction_id: str) -> Optional[dict]:
    merchant_id = (get_setting("platega_merchant_id") or "").strip()
    secret_key = (get_setting("platega_secret_key") or "").strip()
    if not merchant_id or not secret_key:
        logger.error("Platega: не заданы platega_merchant_id/platega_secret_key")
        return None
    tx_id = (transaction_id or "").strip()
    if not tx_id:
        return None
    headers = {
        "accept": "application/json",
        "X-MerchantId": merchant_id,
        "X-Secret": secret_key,
    }
    endpoint = f"{_platega_api_base()}/transaction/{tx_id}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(endpoint, headers=headers, timeout=20) as resp:
                text = await resp.text()
                if resp.status not in (200, 201):
                    logger.warning(f"Platega: status HTTP {resp.status}: {text}")
                    return None
                try:
                    return await resp.json()
                except Exception:
                    logger.warning(f"Platega: status invalid JSON: {text}")
                    return None
    except Exception as e:
        logger.warning(f"Platega: status exception: {e}")
        return None

async def notify_admin_of_purchase(bot: Bot, metadata: dict):
    try:
        admin_id_raw = get_setting("admin_telegram_id")
        if not admin_id_raw:
            return
        admin_id = int(admin_id_raw)
        user_id = metadata.get('user_id')
        action = metadata.get('action')
        if action == "traffic_package":
            traffic_gb = float(metadata.get('traffic_gb') or 0)
            price = float(metadata.get('price') or 0)
            payment_method = metadata.get('payment_method') or 'Unknown'
            await bot.send_message(
                admin_id,
                "📥 Новая оплата\n"
                f"👤 Пользователь: {user_id}\n"
                f"📦 Пакет трафика: {traffic_gb:.0f} ГБ\n"
                f"💳 Метод: {payment_method}\n"
                f"💰 Сумма: {price:.2f} RUB\n"
                "⚙️ Действие: Докупка трафика"
            )
            return
        host_name = metadata.get('host_name')
        months = metadata.get('months')
        price = metadata.get('price')
        payment_method = metadata.get('payment_method') or 'Unknown'
        # Локализация методов оплаты для уведомления админу
        payment_method_map = {
            'Balance': 'Баланс',
            'Card': 'Карта',
            'Crypto': 'Крипто',
            'USDT': 'USDT',
            'TON': 'TON',
        }
        payment_method_display = payment_method_map.get(payment_method, payment_method)
        plan_id = metadata.get('plan_id')
        plan = get_plan_by_id(plan_id)
        plan_name = plan.get('plan_name', 'Unknown') if plan else 'Unknown'

        text = (
            "📥 Новая оплата\n"
            f"👤 Пользователь: {user_id}\n"
            f"🗺️ Хост: {host_name}\n"
            f"📦 Тариф: {plan_name} ({months} мес.)\n"
            f"💳 Метод: {payment_method_display}\n"
            f"💰 Сумма: {float(price):.2f} RUB\n"
            f"⚙️ Действие: {'Новый ключ' if action == 'new' else 'Продление'}"
        )
        await bot.send_message(admin_id, text)
    except Exception as e:
        logger.warning(f"notify_admin_of_purchase не удался: {e}")

async def process_successful_payment(bot: Bot, metadata: dict):
    try:
        action = metadata.get('action')
        user_id = int(metadata.get('user_id'))
        price = float(metadata.get('price'))
        # Поля ниже нужны только для покупок ключей/продлений
        months = int(metadata.get('months', 0))
        key_id = int(metadata.get('key_id', 0)) if metadata.get('key_id') is not None else 0
        host_name = metadata.get('host_name', '')
        plan_id = int(metadata.get('plan_id', 0)) if metadata.get('plan_id') is not None else 0
        customer_email = metadata.get('customer_email')
        payment_method = metadata.get('payment_method')

        chat_id_to_delete = metadata.get('chat_id')
        message_id_to_delete = metadata.get('message_id')
        
    except (ValueError, TypeError) as e:
        logger.error(f"КРИТИЧЕСКАЯ ОШИБКА: Не удалось разобрать метаданные. Ошибка: {e}. Метаданные: {metadata}")
        return

    if chat_id_to_delete and message_id_to_delete:
        try:
            await bot.delete_message(chat_id=chat_id_to_delete, message_id=message_id_to_delete)
        except TelegramBadRequest as e:
            logger.warning(f"Не удалось удалить сообщение о платеже: {e}")

    # Спец-ветка: пополнение баланса
    if action == "top_up":
        try:
            ok = add_to_balance(user_id, float(price))
        except Exception as e:
            logger.error(f"Не удалось добавить к балансу для пользователя {user_id}: {e}", exc_info=True)
            ok = False
        # Лог транзакции
        try:
            user_info = get_user(user_id)
            log_username = user_info.get('username', 'N/A') if user_info else 'N/A'
            log_transaction(
                username=log_username,
                transaction_id=None,
                payment_id=str(uuid.uuid4()),
                user_id=user_id,
                status='paid',
                amount_rub=float(price),
                amount_currency=None,
                currency_name=None,
                payment_method=payment_method or 'Unknown',
                metadata=json.dumps({"action": "top_up"})
            )
        except Exception:
            pass
        try:
            current_balance = 0.0
            try:
                current_balance = float(get_balance(user_id))
            except Exception:
                pass
            if ok:
                await bot.send_message(
                    chat_id=user_id,
                    text=(
                        f"✅ Оплата получена!\n"
                        f"💼 Баланс пополнен на {float(price):.2f} RUB.\n"
                        f"Текущий баланс: {current_balance:.2f} RUB."
                    ),
                    reply_markup=keyboards.create_profile_keyboard()
                )
            else:
                await bot.send_message(
                    chat_id=user_id,
                    text=(
                        "⚠️ Оплата получена, но не удалось обновить баланс. "
                        "Обратитесь в поддержку."
                    ),
                    reply_markup=keyboards.create_support_keyboard()
                )
        except Exception:
            pass
        # Админ-уведомление о пополнении (по возможности)
        try:
            admins = [u for u in (get_all_users() or []) if is_admin(u.get('telegram_id') or 0)]
            for a in admins:
                admin_id = a.get('telegram_id')
                if admin_id:
                    await bot.send_message(admin_id, f"📥 Пополнение: пользователь {user_id}, сумма {float(price):.2f} RUB")
        except Exception:
            pass
        return

    if action == "traffic_package":
        package_gb = float(metadata.get("traffic_gb") or 0)
        processed, success = await _apply_traffic_package_to_user(user_id, package_gb)
        try:
            user_info = get_user(user_id)
            log_username = user_info.get('username', 'N/A') if user_info else 'N/A'
            log_transaction(
                username=log_username,
                transaction_id=None,
                payment_id=str(uuid.uuid4()),
                user_id=user_id,
                status='paid',
                amount_rub=float(price),
                amount_currency=None,
                currency_name=None,
                payment_method=payment_method or 'Unknown',
                metadata=json.dumps({"action": "traffic_package", "traffic_gb": package_gb})
            )
        except Exception:
            pass
        if success > 0:
            await bot.send_message(
                chat_id=user_id,
                text=(
                    "✅ Пакет трафика успешно подключён!\n"
                    f"📦 Добавлено: {package_gb:.0f} ГБ\n"
                    f"🌐 Лимит обновлён на серверах: {success}"
                ),
                reply_markup=keyboards.create_subscription_traffic_keyboard()
            )
        else:
            await bot.send_message(
                chat_id=user_id,
                text=(
                    "⚠️ Оплата получена, но не удалось обновить лимит трафика автоматически.\n"
                    "Обратитесь в поддержку."
                ),
                reply_markup=keyboards.create_support_keyboard()
            )
        try:
            await notify_admin_of_purchase(bot, metadata)
        except Exception:
            pass
        return

    processing_message = await bot.send_message(
        chat_id=user_id,
        text="✅ Оплата получена! Обрабатываю вашу подписку..."
    )
    try:
        # Цена нужна ниже вне зависимости от ветки
        price = float(metadata.get('price'))
        result = None
        created_key_ids: list[int] = []
        user_uuid = get_or_create_user_subscription_uuid(user_id)
        hosts = _get_regular_hosts()
        host_names = [h.get("host_name") for h in hosts if h.get("host_name")]
        if not host_names:
            await processing_message.edit_text("❌ Нет доступных серверов для выдачи подписки.")
            return

        successful_results = []
        tariff_months = int(months or 0)
        try:
            if plan_id:
                plan_row = get_plan_by_id(plan_id)
                if plan_row and plan_row.get("months") is not None:
                    tariff_months = int(plan_row.get("months"))
        except Exception:
            pass
        if tariff_months <= 0:
            tariff_months = 1
        rotated_after_expiry = False

        async def _create_or_update_for_host(current_host_name: str) -> tuple[dict | None, int | None, bool]:
            stable_email = _subscription_email_for_user_host(user_id, current_host_name)
            host_email = stable_email
            existing_key = get_key_by_email(stable_email)
            now_dt = datetime.now()
            base_expiry_dt = now_dt
            should_rotate_sub_id = False
            local_rotated = False
            if existing_key:
                try:
                    raw_expiry = existing_key.get("expiry_date")
                    if raw_expiry:
                        existing_expiry_dt = datetime.fromisoformat(str(raw_expiry))
                        if existing_expiry_dt > base_expiry_dt:
                            base_expiry_dt = existing_expiry_dt
                        else:
                            # Expired subscription path: recreate like first purchase.
                            try:
                                await xui_api.delete_client_on_host(current_host_name, stable_email)
                            except Exception:
                                pass
                            try:
                                key_id_to_delete = existing_key.get("key_id")
                                if key_id_to_delete:
                                    delete_key_by_id(int(key_id_to_delete))
                            except Exception:
                                pass
                            existing_key = None
                            host_email = stable_email
                            should_rotate_sub_id = True
                            local_rotated = True
                    else:
                        should_rotate_sub_id = True
                except Exception:
                    should_rotate_sub_id = True
            target_expiry_dt = _add_calendar_months(base_expiry_dt, tariff_months)
            target_expiry_ms = int(target_expiry_dt.timestamp() * 1000)
            host_result = await xui_api.create_or_update_key_on_host(
                host_name=current_host_name,
                email=host_email,
                days_to_add=None,
                expiry_timestamp_ms=target_expiry_ms,
                preferred_uuid=user_uuid,
                rotate_sub_token=should_rotate_sub_id,
            )
            if not host_result:
                logger.warning(
                    f"Не удалось создать/обновить клиента для user={user_id} "
                    f"на хосте '{current_host_name}' в операции '{action}'."
                )
                return None, None, local_rotated
            existing_key = get_key_by_email(host_result['email'])
            if existing_key:
                update_key_info(existing_key['key_id'], host_result['client_uuid'], host_result['expiry_timestamp_ms'])
                current_key_id = existing_key['key_id']
            else:
                current_key_id = add_new_key(
                    user_id=user_id,
                    host_name=current_host_name,
                    xui_client_uuid=host_result['client_uuid'],
                    key_email=host_result['email'],
                    expiry_timestamp_ms=host_result['expiry_timestamp_ms']
                )
            return host_result, current_key_id, local_rotated

        success_hosts: set[str] = set()
        for current_host_name in host_names:
            host_result, current_key_id, local_rotated = await _create_or_update_for_host(current_host_name)
            if not host_result:
                continue
            successful_results.append((current_host_name, host_result))
            success_hosts.add(current_host_name)
            if current_key_id:
                created_key_ids.append(current_key_id)
            if local_rotated:
                rotated_after_expiry = True

        # Extra reconcile pass: after expiry and repurchase some panels may fail on first attempt.
        # Retry missing hosts once so unified subscription includes all available servers.
        missing_hosts = [h for h in host_names if h not in success_hosts]
        if missing_hosts:
            logger.warning(
                f"Повторная попытка создания подписки для user={user_id} на хостах: {', '.join(missing_hosts)}"
            )
            for current_host_name in missing_hosts:
                host_result, current_key_id, local_rotated = await _create_or_update_for_host(current_host_name)
                if not host_result:
                    continue
                successful_results.append((current_host_name, host_result))
                success_hosts.add(current_host_name)
                if current_key_id:
                    created_key_ids.append(current_key_id)
                if local_rotated:
                    rotated_after_expiry = True

        if not successful_results:
            await processing_message.edit_text("❌ Не удалось создать/обновить подписку на серверах.")
            return
        result = successful_results[0][1]
        await _remove_expired_hosts_clients(user_id)
        if rotated_after_expiry:
            try:
                rotate_user_subscription_token(user_id)
            except Exception:
                pass
        if created_key_ids:
            key_id = created_key_ids[0]

        # Начисляем реферальное вознаграждение по покупке — применяется для new и extend
        user_data = get_user(user_id)
        referrer_id = user_data.get('referred_by') if user_data else None
        if referrer_id:
            try:
                referrer_id = int(referrer_id)
            except Exception:
                logger.warning(f"Referral: invalid referrer_id={referrer_id} for user {user_id}")
                referrer_id = None
        if referrer_id:
            # Выбор логики по типу: процент, фикс за покупку; для fixed_start_referrer — вознаграждение по покупке не начисляем
            try:
                reward_type = (get_setting("referral_reward_type") or "percent_purchase").strip()
            except Exception:
                reward_type = "percent_purchase"
            reward = Decimal("0")
            if reward_type == "fixed_start_referrer":
                reward = Decimal("0")
            elif reward_type == "bonus_days_start":
                reward = Decimal("0")
            elif reward_type == "fixed_purchase":
                try:
                    amount_raw = get_setting("fixed_referral_bonus_amount") or "50"
                    reward = Decimal(str(amount_raw)).quantize(Decimal("0.01"))
                except Exception:
                    reward = Decimal("50.00")
            else:
                # percent_purchase (по умолчанию)
                try:
                    percentage = Decimal(get_setting("referral_percentage") or "0")
                except Exception:
                    percentage = Decimal("0")
                reward = (Decimal(str(price)) * percentage / 100).quantize(Decimal("0.01"))
            logger.info(f"Referral: user={user_id}, referrer={referrer_id}, type={reward_type}, reward={float(reward):.2f}")
            if float(reward) > 0:
                try:
                    ok = add_to_balance(referrer_id, float(reward))
                except Exception as e:
                    logger.warning(f"Referral: add_to_balance failed for referrer {referrer_id}: {e}")
                    ok = False
                try:
                    add_to_referral_balance_all(referrer_id, float(reward))
                except Exception as e:
                    logger.warning(f"Failed to increment referral_balance_all for {referrer_id}: {e}")
                referrer_username = user_data.get('username', 'пользователь') if user_data else 'пользователь'
                if ok:
                    try:
                        await bot.send_message(
                            chat_id=referrer_id,
                            text=(
                                "💰 Вам начислено реферальное вознаграждение!\n"
                                f"Пользователь: {referrer_username} (ID: {user_id})\n"
                                f"Сумма: {float(reward):.2f} RUB"
                            )
                        )
                    except Exception as e:
                        logger.warning(f"Could not send referral reward notification to {referrer_id}: {e}")

        # Не учитываем в "Потрачено всего" покупки, оплаченные с внутреннего баланса
        try:
            pm_lower = (payment_method or '').strip().lower()
        except Exception:
            pm_lower = ''
        spent_for_stats = 0.0 if pm_lower == 'balance' else float(price)
        update_user_stats(user_id, spent_for_stats, months)
        
        user_info = get_user(user_id)

        log_username = user_info.get('username', 'N/A') if user_info else 'N/A'
        log_status = 'paid'
        log_amount_rub = float(price)
        log_method = metadata.get('payment_method', 'Unknown')
        
        log_metadata = json.dumps({
            "plan_id": metadata.get('plan_id'),
            "plan_name": get_plan_by_id(metadata.get('plan_id')).get('plan_name', 'Unknown') if get_plan_by_id(metadata.get('plan_id')) else 'Unknown',
            "host_name": metadata.get('host_name'),
            "customer_email": metadata.get('customer_email')
        })

        # Определяем payment_id для лога: берём из metadata, если есть (например, при отложенных транзакциях), иначе генерируем новый UUID
        payment_id_for_log = metadata.get('payment_id') or str(uuid.uuid4())

        log_transaction(
            username=log_username,
            transaction_id=None,
            payment_id=payment_id_for_log,
            user_id=user_id,
            status=log_status,
            amount_rub=log_amount_rub,
            amount_currency=None,
            currency_name=None,
            payment_method=log_method,
            metadata=log_metadata
        )
        # Если был применён промокод, фиксируем использование и при необходимости отключаем по лимиту
        try:
            promo_code_used = (metadata.get('promo_code') or '').strip()
            if promo_code_used:
                try:
                    # Пытаемся оценить применённую скидку, если доступна фиксированная сумма
                    applied_amt = 0.0
                    try:
                        if metadata.get('promo_discount_amount') is not None:
                            applied_amt = float(metadata.get('promo_discount_amount') or 0.0)
                    except Exception:
                        applied_amt = 0.0
                    redeemed = redeem_promo_code(
                        promo_code_used,
                        user_id,
                        applied_amount=float(applied_amt or 0.0),
                        order_id=payment_id_for_log,
                    )
                    if redeemed:
                        # Определяем причины для автоматической деактивации
                        limit_total = redeemed.get('usage_limit_total')
                        per_user_limit = redeemed.get('usage_limit_per_user')
                        used_total_now = redeemed.get('used_total') or 0
                        user_usage_count = redeemed.get('user_usage_count')
                        should_deactivate = False
                        reason_lines: list[str] = []

                        if limit_total:
                            try:
                                if used_total_now >= int(limit_total):
                                    should_deactivate = True
                                    reason_lines.append("достигнут общий лимит использования")
                            except Exception:
                                pass

                        if per_user_limit:
                            try:
                                if (user_usage_count or 0) >= int(per_user_limit):
                                    should_deactivate = True
                                    reason_lines.append("исчерпан лимит на пользователя")
                            except Exception:
                                pass

                        # Если не достигнуты лимиты, всё равно выключаем по требованию (при наличии любого лимита)
                        if not should_deactivate and (limit_total or per_user_limit):
                            should_deactivate = True
                            if per_user_limit and not reason_lines:
                                reason_lines.append("лимит на пользователя выставлен (код погашён)")
                            elif limit_total and not reason_lines:
                                reason_lines.append("лимит по количеству использований выставлен (код погашён)")

                        if should_deactivate:
                            try:
                                update_promo_code_status(promo_code_used, is_active=False)
                            except Exception:
                                pass

                        # Уведомим администраторов о факте использования
                        try:
                            plan = get_plan_by_id(plan_id)
                            plan_name = plan.get('plan_name', 'Unknown') if plan else 'Unknown'
                            admins = list(get_admin_ids() or [])
                            if should_deactivate:
                                status_line = "Статус: деактивирован"
                                if reason_lines:
                                    status_line += " (" + ", ".join(reason_lines) + ")"
                            else:
                                status_line = "Статус: активен"
                                if limit_total:
                                    status_line += f" (использовано {used_total_now} из {limit_total})"
                                else:
                                    status_line += f" (использовано {used_total_now})"
                            text = (
                                "🎟️ Промокод использован\n"
                                f"Код: {promo_code_used}\n"
                                f"Пользователь: {user_id}\n"
                                f"Тариф: {plan_name} ({months} мес.)\n"
                                f"{status_line}"
                            )
                            for aid in admins:
                                try:
                                    await bot.send_message(int(aid), text)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                except Exception as e:
                    logger.warning(f"Promo redeem failed for user {user_id}, code {promo_code_used}: {e}")
        except Exception:
            pass
        
        # Аккуратно удаляем служебное сообщение о обработке, если возможно
        try:
            await processing_message.delete()
        except Exception:
            pass
        
        connection_string = _get_unified_subscription_url_for_user(user_id)
        new_expiry_date = None
        try:
            if not connection_string:
                connection_string = result.get('connection_string') if isinstance(result, dict) else None
            new_expiry_date = datetime.fromtimestamp(result['expiry_timestamp_ms'] / 1000) if isinstance(result, dict) and 'expiry_timestamp_ms' in result else None
        except Exception:
            connection_string = None
            new_expiry_date = None

        if connection_string or new_expiry_date:
            try:
                update_user_subscription_state(
                    user_id,
                    subscription_link=connection_string,
                    subscription_status="active",
                    subscription_type="paid",
                    subscription_expires_at=new_expiry_date
                )
            except Exception:
                pass
        
        all_user_keys = get_user_keys(user_id)
        key_number = next((i + 1 for i, key in enumerate(all_user_keys) if key['key_id'] == key_id), len(all_user_keys))

        if action == "renewdays":
            period_text = f"{tariff_months} мес."
            await bot.send_message(
                chat_id=user_id,
                text=f"✅ Вы успешно продлили свою подписку на тариф {period_text}.",
                reply_markup=keyboards.create_back_to_menu_keyboard()
            )
        else:
            final_text = (
                "✅ <b>Покупка прошла успешно!</b>\n\n"
                "🎉 <b>Ваша подписка готова.</b>\n"
                f"⏳ <b>Действует до:</b> {(new_expiry_date or datetime.now()).strftime('%d.%m.%Y в %H:%M')}\n\n"
                "Выберите устройство для подключения:"
            )
            await bot.send_message(
                chat_id=user_id,
                text=final_text,
                reply_markup=keyboards.create_connect_devices_keyboard_with_back_only()
            )

        try:
            await notify_admin_of_purchase(bot, metadata)
        except Exception as e:
            logger.warning(f"Failed to notify admin of purchase: {e}")
        
    except Exception as e:
        logger.error(f"Error processing payment for user {user_id} on host {host_name}: {e}", exc_info=True)
        try:
            await processing_message.edit_text("❌ Ошибка при выдаче подписки.")
        except Exception:
            try:
                await bot.send_message(chat_id=user_id, text="❌ Ошибка при выдаче подписки.")
            except Exception:
                pass
