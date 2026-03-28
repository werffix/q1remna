import logging
import hashlib
import re
from urllib.parse import quote, urlparse

from datetime import datetime
from typing import Callable

from aiogram.types import ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.utils.keyboard import InlineKeyboardBuilder

from shop_bot.data_manager.database import get_setting, normalize_host_name

logger = logging.getLogger(__name__)

main_reply_keyboard = ReplyKeyboardMarkup(
    keyboard=[[KeyboardButton(text="🏠 Главное меню")]],
    resize_keyboard=True
)

def _buy_subscription_label(default_label: str = "💳 Купить подписку") -> str:
    value = (get_setting("btn_buy_key") or default_label).strip()
    if "Купить ключ" in value:
        return value.replace("Купить ключ", "Купить подписку")
    return value or default_label


def _normalize_button_text(value: str) -> str:
    text = (value or "").strip()
    if "Купить ключ" in text:
        text = text.replace("Купить ключ", "Купить подписку")
    if "Мои ключи" in text:
        text = text.replace("Мои ключи", "Моя подписка")
    return text


def encode_host_callback_token(host_name: str) -> str:
    """Сформировать короткий ASCII-токен для host_name для использования в callback_data."""
    normalized = normalize_host_name(host_name)
    slug = re.sub(r"[^a-z0-9]+", "-", normalized.lower()).strip("-")
    slug = slug[:24]
    digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:8]
    if slug:
        return f"{slug}-{digest}"
    return digest


def parse_host_callback_data(data: str) -> tuple[str, str, str] | None:
    if not data or not data.startswith("select_host:"):
        return None
    parts = data.split(":", 3)
    if len(parts) != 4:
        return None
    _, action, extra, token = parts
    return action, extra or "-", token


def find_host_by_callback_token(hosts: list[dict], token: str) -> dict | None:
    if not token:
        return None
    for host in hosts or []:
        if encode_host_callback_token(host.get('host_name', '')) == token:
            return host
    return None


# --- Generic builder from DB configs ---
def _build_keyboard_from_db(
    menu_type: str,
    text_replacements: dict[str, str] | None = None,
    filter_func: Callable[[dict], bool] | None = None,
) -> InlineKeyboardMarkup | None:
    """Build InlineKeyboardMarkup from button configs for a given menu_type.
    Returns None if configs are missing or on error.
    """
    try:
        from shop_bot.data_manager.database import get_button_configs
        configs = get_button_configs(menu_type)
    except Exception as e:
        logger.warning(f"DB configs for {menu_type} not available: {e}")
        return None

    if not configs:
        return None

    builder = InlineKeyboardBuilder()

    # Group by row, keep positions and widths
    rows: dict[int, list[dict]] = {}
    added: set[str] = set()

    for cfg in configs:
        if not cfg.get('is_active', True):
            continue
        if filter_func and not filter_func(cfg):
            continue

        text = _normalize_button_text(cfg.get('text', '') or '')
        callback_data = cfg.get('callback_data')
        url = cfg.get('url')
        button_id = (cfg.get('button_id') or '').strip()
        if button_id == "btn_admin":
            callback_data = "admin_menu"
        elif "админ" in text.lower() and callback_data:
            callback_data = "admin_menu"

        if not callback_data and not url:
            continue

        # Deduplicate by button_id if provided
        if button_id:
            if button_id in added:
                continue
            added.add(button_id)

        # Apply text replacements (e.g., counts)
        if text_replacements:
            try:
                for k, v in text_replacements.items():
                    text = text.replace(k, str(v))
            except Exception:
                pass

        row_pos = int(cfg.get('row_position', 0) or 0)
        col_pos = int(cfg.get('column_position', 0) or 0)
        sort_order = int(cfg.get('sort_order', 0) or 0)
        width = int(cfg.get('button_width', 1) or 1)

        rows.setdefault(row_pos, []).append({
            'text': text,
            'callback_data': callback_data,
            'url': url,
            'width': max(1, min(width, 3)),
            'col': col_pos,
            'sort': sort_order,
        })

    if not rows:
        return None

    # Build keyboard respecting row positions and button widths
    # In Telegram: width 1 = half row, width 2+ = full row
    for row_idx in sorted(rows.keys()):
        row_buttons = sorted(rows[row_idx], key=lambda b: (b['col'], b['sort']))
        
        # Process buttons for this row position
        i = 0
        while i < len(row_buttons):
            btn = row_buttons[i]
            button_width = btn['width']
            
            # Width 2+ means full row
            if button_width >= 2:
                # Add as single button in row
                if btn['callback_data']:
                    builder.row(InlineKeyboardButton(text=btn['text'], callback_data=btn['callback_data']))
                elif btn['url']:
                    builder.row(InlineKeyboardButton(text=btn['text'], url=btn['url']))
                i += 1
            else:
                # Width 1 - try to pair with next button if it also has width 1
                if i + 1 < len(row_buttons) and row_buttons[i + 1]['width'] == 1:
                    # Add two buttons in one row
                    btn2 = row_buttons[i + 1]
                    buttons = []
                    
                    if btn['callback_data']:
                        buttons.append(InlineKeyboardButton(text=btn['text'], callback_data=btn['callback_data']))
                    elif btn['url']:
                        buttons.append(InlineKeyboardButton(text=btn['text'], url=btn['url']))
                    
                    if btn2['callback_data']:
                        buttons.append(InlineKeyboardButton(text=btn2['text'], callback_data=btn2['callback_data']))
                    elif btn2['url']:
                        buttons.append(InlineKeyboardButton(text=btn2['text'], url=btn2['url']))
                    
                    builder.row(*buttons)
                    i += 2
                else:
                    # Single button with width 1 - add alone
                    if btn['callback_data']:
                        builder.row(InlineKeyboardButton(text=btn['text'], callback_data=btn['callback_data']))
                    elif btn['url']:
                        builder.row(InlineKeyboardButton(text=btn['text'], url=btn['url']))
                    i += 1

    return builder.as_markup()


def create_main_menu_keyboard(
    user_keys: list,
    trial_available: bool,
    is_admin: bool,
    has_active_subscription: bool = False
) -> InlineKeyboardMarkup:
    # Prepare filters and replacements for main menu
    def _filter(cfg: dict) -> bool:
        button_id = (cfg.get('button_id') or '').strip()
        # Filter trial button
        if button_id == 'btn_try':
            if not trial_available or get_setting("trial_enabled") != "true":
                return False
        # Filter admin button
        if button_id == 'btn_admin' and not is_admin:
            return False
        return True
    
    # Text replacements for key count
    subscription_count = 1 if user_keys else 0
    replacements = {
        '{count}': str(subscription_count),
        '((count))': f'({subscription_count})'
    }
    
    # Try DB-driven keyboard first
    kb = _build_keyboard_from_db('main_menu', text_replacements=replacements, filter_func=_filter)
    if kb:
        if not has_active_subscription:
            return kb
        # Replace buy button with connect button for active subscriptions.
        builder = InlineKeyboardBuilder()
        builder.row(InlineKeyboardButton(text="🔌 Подключиться", callback_data="show_connect_menu"))
        for row in kb.inline_keyboard:
            filtered = [
                btn for btn in row
                if getattr(btn, "callback_data", None) != "buy_new_key"
            ]
            if filtered:
                builder.row(*filtered)
        return builder.as_markup()
    
    # Fallback to original implementation if DB config not available
    builder = InlineKeyboardBuilder()
    
    # Try to get button configurations from database first
    try:
        from shop_bot.data_manager.database import get_button_configs
        button_configs = get_button_configs('main_menu')

        logger.info(f"Loaded {len(button_configs)} button configs from database")

        if button_configs:
            # Группируем по строкам с учётом позиций
            rows: dict[int, list[dict]] = {}
            added_buttons: set[str] = set()

            for cfg in button_configs:
                if not cfg.get('is_active', True):
                    continue

                text = cfg.get('text', '') or ''
                callback_data = cfg.get('callback_data')
                url = cfg.get('url')
                button_id = cfg.get('button_id', '') or ''

                # Пропускаем пустые действия
                if not callback_data and not url:
                    continue

                # Фильтры по условиям (trial/admin)
                if button_id == 'btn_try':
                    if not trial_available or get_setting("trial_enabled") != "true":
                        continue
                if button_id == 'btn_admin' and not is_admin:
                    continue

                # Подстановка счётчика ключей
                if button_id == 'btn_my_keys':
                    try:
                        text = _normalize_button_text(text)
                        text = text.replace('{count}', str(subscription_count)).replace('((count))', f'({subscription_count})')
                    except Exception:
                        pass

                # Исключаем дубликаты по button_id
                if button_id:
                    if button_id in added_buttons:
                        logger.warning(f"Duplicate button detected: {button_id}, skipping")
                        continue
                    added_buttons.add(button_id)

                row_pos = int(cfg.get('row_position', 0) or 0)
                col_pos = int(cfg.get('column_position', 0) or 0)
                sort_order = int(cfg.get('sort_order', 0) or 0)
                width = int(cfg.get('button_width', 1) or 1)

                rows.setdefault(row_pos, []).append({
                    'text': text,
                    'callback_data': callback_data,
                    'url': url,
                    'width': max(1, min(int(width), 3)),
                    'col': col_pos,
                    'sort': sort_order,
                })

            # Функция добавления кнопки в билдер
            def _add(btn: dict):
                if btn['callback_data']:
                    builder.button(text=btn['text'], callback_data=btn['callback_data'])
                elif btn['url']:
                    builder.button(text=btn['text'], url=btn['url'])

            # Build keyboard respecting row positions and button widths
            # In Telegram: width 1 = half row, width 2+ = full row
            for row_idx in sorted(rows.keys()):
                row_buttons = sorted(rows[row_idx], key=lambda b: (b['col'], b['sort']))
                
                # Process buttons for this row position
                i = 0
                while i < len(row_buttons):
                    btn = row_buttons[i]
                    button_width = btn['width']
                    
                    # Width 2+ means full row
                    if button_width >= 2:
                        # Add as single button in row
                        if btn['callback_data']:
                            builder.row(InlineKeyboardButton(text=btn['text'], callback_data=btn['callback_data']))
                        elif btn['url']:
                            builder.row(InlineKeyboardButton(text=btn['text'], url=btn['url']))
                        i += 1
                    else:
                        # Width 1 - try to pair with next button if it also has width 1
                        if i + 1 < len(row_buttons) and row_buttons[i + 1]['width'] == 1:
                            # Add two buttons in one row
                            btn2 = row_buttons[i + 1]
                            buttons = []
                            
                            if btn['callback_data']:
                                buttons.append(InlineKeyboardButton(text=btn['text'], callback_data=btn['callback_data']))
                            elif btn['url']:
                                buttons.append(InlineKeyboardButton(text=btn['text'], url=btn['url']))
                            
                            if btn2['callback_data']:
                                buttons.append(InlineKeyboardButton(text=btn2['text'], callback_data=btn2['callback_data']))
                            elif btn2['url']:
                                buttons.append(InlineKeyboardButton(text=btn2['text'], url=btn2['url']))
                            
                            builder.row(*buttons)
                            i += 2
                        else:
                            # Single button with width 1 - add alone
                            if btn['callback_data']:
                                builder.row(InlineKeyboardButton(text=btn['text'], callback_data=btn['callback_data']))
                            elif btn['url']:
                                builder.row(InlineKeyboardButton(text=btn['text'], url=btn['url']))
                            i += 1


            if has_active_subscription:
                out = InlineKeyboardBuilder()
                out.row(InlineKeyboardButton(text="🔌 Подключиться", callback_data="show_connect_menu"))
                for row in builder.as_markup().inline_keyboard:
                    filtered = [
                        btn for btn in row
                        if getattr(btn, "callback_data", None) != "buy_new_key"
                    ]
                    if filtered:
                        out.row(*filtered)
                return out.as_markup()
            return builder.as_markup()
    except Exception as e:
        logger.warning(f"Failed to load button configs from database: {e}, falling back to settings")
    
    # Fallback to original hardcoded logic
    logger.info("Using fallback hardcoded button logic")
    if has_active_subscription:
        builder.button(text="🔌 Подключиться", callback_data="show_connect_menu")
    if trial_available and get_setting("trial_enabled") == "true":
        builder.button(text=(get_setting("btn_try") or "🎁 Попробовать бесплатно"), callback_data="get_trial")

    builder.button(text=(get_setting("btn_profile") or "👤 Мой профиль"), callback_data="show_profile")
    keys_label_tpl = _normalize_button_text(get_setting("btn_my_keys") or "🔑 Моя подписка ({count})")
    builder.button(text=keys_label_tpl.replace("{count}", str(subscription_count)), callback_data="manage_keys")
    if not has_active_subscription:
        builder.button(text=_buy_subscription_label("💳 Купить подписку"), callback_data="buy_new_key")
    builder.button(text=(get_setting("btn_top_up") or "➕ Пополнить баланс"), callback_data="top_up_start")
    builder.button(text=(get_setting("btn_referral") or "🤝 Реферальная программа"), callback_data="show_referral_program")
    builder.button(text=(get_setting("btn_support") or "🆘 Поддержка"), callback_data="show_help")
    builder.button(text=(get_setting("btn_about") or "ℹ️ О проекте"), callback_data="show_about")
    builder.button(text=(get_setting("btn_howto") or "❓ Как использовать"), callback_data="howto_vless")
    builder.button(text=(get_setting("btn_speed") or "⚡ Тест скорости"), callback_data="user_speedtest")
    if is_admin:
        builder.button(text=(get_setting("btn_admin") or "⚙️ Админка"), callback_data="admin_menu")

    layout = [
        1 if has_active_subscription else 0,  # подключиться (вверх)
        1 if trial_available and get_setting("trial_enabled") == "true" else 0,  # триал
        2,  # профиль + мои ключи
        2,  # купить подписку (если нет активной) + пополнить баланс
        1,  # рефералка
        2,  # поддержка + о проекте
        2,  # как использовать + тест скорости
        1 if is_admin else 0,  # админка
    ]
    actual_layout = [size for size in layout if size > 0]
    builder.adjust(*actual_layout)
    
    return builder.as_markup()

def create_admin_menu_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="👥 Пользователи", callback_data="admin_users")
    builder.button(text="🌐 Веб-панель", url="https://q1.servernux.com:8443/")
    builder.button(text="📢 Рассылка", callback_data="start_broadcast")
    builder.button(text="⬅️ Назад в меню", callback_data="back_to_main_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_admins_menu_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="➕ Добавить админа", callback_data="admin_add_admin")
    builder.button(text="➖ Снять админа", callback_data="admin_remove_admin")
    builder.button(text="📋 Список админов", callback_data="admin_view_admins")
    builder.button(text="⬅️ В админ-меню", callback_data="admin_menu")
    builder.adjust(2, 2)
    return builder.as_markup()


def create_admin_monitor_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="🔄 Обновить", callback_data="admin_monitor_refresh")
    builder.button(text="⬅️ В админ-меню", callback_data="admin_menu")
    builder.adjust(1, 1)
    return builder.as_markup()

def create_admin_users_keyboard(users: list[dict], page: int = 0, page_size: int = 5) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    start = page * page_size
    end = start + page_size
    for u in users[start:end]:
        user_id = u.get('telegram_id') or u.get('user_id') or u.get('id')
        username = u.get('username') or '—'
        title = f"@{username} - {user_id}" if username != '—' else f"{user_id}"
        builder.button(text=title, callback_data=f"admin_view_user_{user_id}")
    builder.button(text="🎁 Выдать всем подписку", callback_data="admin_grant_all_subscriptions")
    builder.button(text="🔍 Поиск", callback_data="admin_users_search")
    # pagination
    total = len(users)
    have_prev = page > 0
    have_next = end < total
    if have_prev:
        builder.button(text="⬅️ Назад", callback_data=f"admin_users_page_{page-1}")
    if have_next:
        builder.button(text="Вперёд ➡️", callback_data=f"admin_users_page_{page+1}")
    builder.button(text="⬅️ В админ-меню", callback_data="admin_menu")
    # layout: list, search, pagination, back
    rows = [1] * len(users[start:end])
    tail = [1, 1]
    if have_prev or have_next:
        tail.append(2 if (have_prev and have_next) else 1)
    tail.append(1)
    builder.adjust(*(rows + tail if rows else ([2] if (have_prev or have_next) else []) + [1]))
    return builder.as_markup()

def create_admin_user_actions_keyboard(user_id: int, is_banned: bool | None = None) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="🔄 Продлить подписку", callback_data=f"admin_gift_key_{user_id}")
    builder.button(text="📅 Изменить дату", callback_data=f"admin_change_expiry_{user_id}")
    builder.button(text="♻️ Сбросить пользователя", callback_data=f"admin_reset_user_{user_id}")
    builder.button(text="🗑 Отозвать подписку", callback_data=f"admin_revoke_user_{user_id}")
    builder.button(text="💼 Изменить баланс", callback_data=f"admin_balance_menu_{user_id}")
    builder.button(text="✉️ Написать от бота", callback_data=f"admin_message_user_{user_id}")
    builder.button(text="🤝 Рефералы пользователя", callback_data=f"admin_user_referrals_{user_id}")
    if is_banned is True:
        builder.button(text="✅ Разбанить", callback_data=f"admin_unban_user_{user_id}")
    else:
        builder.button(text="🚫 Выдать бан", callback_data=f"admin_ban_user_{user_id}")
    builder.button(text="🔑 Подписки пользователя", callback_data=f"admin_user_keys_{user_id}")
    builder.button(text="⬅️ К списку", callback_data="admin_users")
    builder.button(text="⬅️ В админ-меню", callback_data="admin_menu")
    builder.adjust(2, 2, 2, 2, 1, 1)
    return builder.as_markup()

def create_admin_user_balance_keyboard(user_id: int) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="➕ Начислить баланс", callback_data=f"admin_add_balance_{user_id}")
    builder.button(text="➖ Списать баланс", callback_data=f"admin_deduct_balance_{user_id}")
    builder.button(text="⬅️ К пользователю", callback_data=f"admin_view_user_{user_id}")
    builder.adjust(2, 1)
    return builder.as_markup()

def create_admin_user_keys_keyboard(user_id: int, keys: list[dict]) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    if keys:
        for k in keys:
            kid = k.get('key_id')
            host = k.get('host_name') or '—'
            email = k.get('key_email') or '—'
            title = f"#{kid} • {host} • {email[:20]}"
            builder.button(text=title, callback_data=f"admin_edit_key_{kid}")
    else:
        builder.button(text="Ключей нет", callback_data="noop")
    builder.button(text="⬅️ Назад", callback_data=f"admin_view_user_{user_id}")
    builder.adjust(1)
    return builder.as_markup()

def create_admin_key_actions_keyboard(key_id: int, user_id: int | None = None) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="🌍 Изменить сервер", callback_data=f"admin_key_edit_host_{key_id}")
    builder.button(text="➕ Добавить дни", callback_data=f"admin_key_extend_{key_id}")
    builder.button(text="🗑 Удалить ключ", callback_data=f"admin_key_delete_{key_id}")
    builder.button(text="⬅️ Назад к ключам", callback_data=f"admin_key_back_{key_id}")
    if user_id is not None:
        builder.button(text="👤 Перейти к пользователю", callback_data=f"admin_view_user_{user_id}")
        builder.adjust(2, 2, 1)
    else:
        builder.adjust(2, 2)
    return builder.as_markup()

def create_admin_delete_key_confirm_keyboard(key_id: int) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="✅ Подтвердить удаление", callback_data=f"admin_key_delete_confirm_{key_id}")
    builder.button(text="❌ Отмена", callback_data=f"admin_key_delete_cancel_{key_id}")
    builder.adjust(1)
    return builder.as_markup()

def create_admin_cancel_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="❌ Отмена", callback_data="admin_cancel")
    return builder.as_markup()

def create_admin_promo_code_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="🎲 Сгенерировать код", callback_data="admin_promo_gen_code")
    builder.button(text="❌ Отмена", callback_data="admin_cancel")
    builder.adjust(1)
    return builder.as_markup()

def create_broadcast_options_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="➕ Добавить кнопку", callback_data="broadcast_add_button")
    builder.button(text="➡️ Пропустить", callback_data="broadcast_skip_button")
    builder.button(text="❌ Отмена", callback_data="cancel_broadcast")
    builder.adjust(2, 1)
    return builder.as_markup()

def create_broadcast_audience_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="Все пользователи", callback_data="broadcast_audience_all")
    builder.button(text="С активной подпиской", callback_data="broadcast_audience_active")
    builder.button(text="Без активной подписки", callback_data="broadcast_audience_no_active")
    builder.button(text="Никогда не покупали", callback_data="broadcast_audience_never_bought")
    builder.button(text="Подписка", callback_data="broadcast_audience_has_subscription")
    builder.button(text="❌ Отмена", callback_data="cancel_broadcast")
    builder.adjust(1)
    return builder.as_markup()

def create_broadcast_confirmation_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="✅ Отправить всем", callback_data="confirm_broadcast")
    builder.button(text="❌ Отмена", callback_data="cancel_broadcast")
    builder.adjust(2)
    return builder.as_markup()

def create_broadcast_cancel_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="❌ Отмена", callback_data="cancel_broadcast")
    return builder.as_markup()

def create_about_keyboard(channel_url: str | None, terms_url: str | None, privacy_url: str | None) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    if channel_url:
        builder.button(text=(get_setting("btn_channel") or "📰 Наш канал"), url=channel_url)
    if terms_url:
        builder.button(text=(get_setting("btn_terms") or "📄 Условия использования"), url=terms_url)
    if privacy_url:
        builder.button(text=(get_setting("btn_privacy") or "🔒 Политика конфиденциальности"), url=privacy_url)
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    builder.adjust(1)
    return builder.as_markup()
    
def create_support_keyboard(support_user: str | None = None) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    # Определяем username для поддержки
    username = (support_user or "").strip()
    if not username:
        username = (get_setting("support_bot_username") or get_setting("support_user") or "").strip()
    # Преобразуем в tg:// ссылку, если есть username/ссылка
    url: str | None = None
    if username:
        if username.startswith("@"):  # @username
            url = f"tg://resolve?domain={username[1:]}"
        elif username.startswith("tg://"):  # уже tg-схема
            url = username
        elif username.startswith("http://") or username.startswith("https://"):
            # http(s) ссылки на t.me/telegram.me -> в tg://
            # Попробуем извлечь domain
            try:
                # простое извлечение последнего сегмента
                part = username.split("/")[-1].split("?")[0]
                if part:
                    url = f"tg://resolve?domain={part}"
            except Exception:
                url = username
        else:
            # просто username без @
            url = f"tg://resolve?domain={username}"

    if url:
        builder.button(text=(get_setting("btn_support") or "🆘 Поддержка"), url=url)
        builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    else:
        # Фолбэк: встроенное меню поддержки
        builder.button(text=(get_setting("btn_support") or "🆘 Поддержка"), callback_data="show_help")
        builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_support_bot_link_keyboard(support_bot_username: str) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    username = support_bot_username.lstrip("@")
    deep_link = f"tg://resolve?domain={username}&start=new"
    builder.button(text=(get_setting("btn_support_open") or "🆘 Открыть поддержку"), url=deep_link)
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_support_menu_keyboard(has_external: bool = False) -> InlineKeyboardMarkup:
    def _filter(cfg: dict) -> bool:
        # Если внешняя поддержка недоступна, скрыть кнопку support_external
        if not has_external:
            cd = (cfg.get('callback_data') or '').strip()
            bid = (cfg.get('button_id') or '').strip()
            if cd == 'support_external' or bid == 'btn_support_external':
                return False
        return True

    kb = _build_keyboard_from_db('support_menu', filter_func=_filter)
    if kb:
        return kb

    builder = InlineKeyboardBuilder()
    builder.button(text=(get_setting("btn_support_new_ticket") or "✍️ Новое обращение"), callback_data="support_new_ticket")
    builder.button(text=(get_setting("btn_support_my_tickets") or "📨 Мои обращения"), callback_data="support_my_tickets")
    if has_external:
        builder.button(text=(get_setting("btn_support_external") or "🆘 Внешняя поддержка"), callback_data="support_external")
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_tickets_list_keyboard(tickets: list[dict]) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    if tickets:
        for t in tickets:
            title = f"#{t['ticket_id']} • {t.get('status','open')}"
            if t.get('subject'):
                title += f" • {t['subject'][:20]}"
            builder.button(text=title, callback_data=f"support_view_{t['ticket_id']}")
    builder.button(text="⬅️ Назад", callback_data="support_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_ticket_actions_keyboard(ticket_id: int, is_open: bool = True) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    if is_open:
        builder.button(text="💬 Ответить", callback_data=f"support_reply_{ticket_id}")
        builder.button(text="✅ Закрыть", callback_data=f"support_close_{ticket_id}")
    builder.button(text="⬅️ К списку", callback_data="support_my_tickets")
    builder.adjust(1)
    return builder.as_markup()

def create_host_selection_keyboard(hosts: list, action: str) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    base_action = action
    extra = "-"
    if action.startswith("switch_"):
        base_action = "switch"
        extra = action[len("switch_"):] or "-"
    elif action in {"trial", "new"}:
        base_action = action
    else:
        base_action = action
    prefix = f"select_host:{base_action}:{extra}:"
    for host in hosts:
        token = encode_host_callback_token(host['host_name'])
        builder.button(text=host['host_name'], callback_data=f"{prefix}{token}")
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="manage_keys" if action == 'new' else "back_to_main_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_plans_keyboard(plans: list[dict], action: str, host_name: str, key_id: int = 0) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    host_token = encode_host_callback_token(host_name or "")
    for plan in plans:
        callback_data = f"buy:{host_token}:{plan['plan_id']}:{action}:{key_id}"
        builder.button(text=f"{plan['plan_name']} - {plan['price']:.0f} RUB", callback_data=callback_data)
    if action == "extend":
        back_callback = "manage_keys"
    elif action == "renewdays":
        back_callback = "buy_traffic_start"
    else:
        back_callback = "buy_new_key"
    builder.button(text=(get_setting("btn_back") or "⬅️ Назад"), callback_data=back_callback)
    builder.adjust(1) 
    return builder.as_markup()

def create_skip_email_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text=(get_setting("btn_skip_email") or "➡️ Продолжить без почты"), callback_data="skip_email")
    builder.button(text=(get_setting("btn_back_to_plans") or "⬅️ Назад к тарифам"), callback_data="back_to_plans")
    builder.adjust(1)
    return builder.as_markup()

def create_payment_method_keyboard(
    payment_methods: dict,
    action: str,
    key_id: int,
    show_balance: bool | None = None,
    main_balance: float | None = None,
    price: float | None = None,
    has_promo_applied: bool | None = None,
    allow_promo: bool = True,
) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()

    # Промокод: ввести/убрать
    if allow_promo:
        if has_promo_applied:
            builder.button(text="❌ Убрать промокод", callback_data="remove_promo_code")
        else:
            builder.button(text="🎟️ Ввести промокод", callback_data="enter_promo_code")

    # Кнопки оплаты с балансов (если разрешено/достаточно средств)
    if show_balance:
        label = get_setting("btn_pay_with_balance") or "💼 Оплатить с баланса"
        if main_balance is not None:
            try:
                label += f" ({main_balance:.0f} RUB)"
            except Exception:
                pass
        builder.button(text=label, callback_data="pay_balance")

    # Внешние способы оплаты
    if payment_methods and payment_methods.get("yookassa"):
        if get_setting("sbp_enabled"):
            builder.button(text="🏦 СБП / Банковская карта", callback_data="pay_yookassa")
        else:
            builder.button(text="🏦 Банковская карта", callback_data="pay_yookassa")
    if payment_methods and payment_methods.get("heleket"):
        builder.button(text="💎 Криптовалюта", callback_data="pay_heleket")
    if payment_methods and payment_methods.get("platega"):
        builder.button(text="🏦 Оплата через СБП", callback_data="pay_platega_sbp")
        builder.button(text="💳 Оплата банковской картой", callback_data="pay_platega_card")
        builder.button(text="💎 Оплата криптовалютой", callback_data="pay_platega_crypto")
    if payment_methods and payment_methods.get("cryptobot"):
        builder.button(text="🤖 CryptoBot", callback_data="pay_cryptobot")
    if payment_methods and payment_methods.get("yoomoney"):
        builder.button(text="💜 ЮMoney (кошелёк)", callback_data="pay_yoomoney")
    if payment_methods and payment_methods.get("stars"):
        builder.button(text="⭐ Telegram Stars", callback_data="pay_stars")
    if payment_methods and payment_methods.get("tonconnect"):
        callback_data_ton = "pay_tonconnect"
        logger.info(f"Creating TON button with callback_data: '{callback_data_ton}'")
        builder.button(text="🪙 TON Connect", callback_data=callback_data_ton)

    builder.button(text=(get_setting("btn_back") or "⬅️ Назад"), callback_data="back_to_email_prompt")
    builder.adjust(1)
    return builder.as_markup()


def create_admin_promos_menu_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="➕ Создать промокод", callback_data="admin_promo_create")
    builder.button(text="📋 Список промокодов", callback_data="admin_promo_list")
    builder.button(text="⬅️ В админ-меню", callback_data="admin_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_admin_promo_discount_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    # Первый шаг: выбрать тип скидки
    builder.button(text="Процент", callback_data="admin_promo_discount_type_percent")
    builder.button(text="Фикс (RUB)", callback_data="admin_promo_discount_type_amount")
    builder.button(text="❌ Отмена", callback_data="admin_cancel")
    builder.adjust(2, 1)
    return builder.as_markup()

def create_admin_promo_discount_percent_menu_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    # Пресеты процентов
    for p in (5, 10, 15, 20, 25, 30):
        builder.button(text=f"{p}%", callback_data=f"admin_promo_discount_percent_{p}")
    # Ручной ввод обоих типов и переключение меню
    builder.button(text="🖊 Ввести процент", callback_data="admin_promo_discount_manual_percent")
    builder.button(text="🖊 Ввести фикс RUB", callback_data="admin_promo_discount_manual_amount")
    builder.button(text="↔️ Фикс-меню", callback_data="admin_promo_discount_show_amount_menu")
    builder.button(text="❌ Отмена", callback_data="admin_cancel")
    builder.adjust(3, 3, 1, 1, 1)
    return builder.as_markup()

def create_admin_promo_discount_amount_menu_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    # Пресеты сумм в рублях
    for a in (50, 100, 150, 200, 300, 500):
        builder.button(text=f"{a} RUB", callback_data=f"admin_promo_discount_amount_{a}")
    builder.button(text="🖊 Ввести фикс RUB", callback_data="admin_promo_discount_manual_amount")
    builder.button(text="🖊 Ввести процент", callback_data="admin_promo_discount_manual_percent")
    builder.button(text="↔️ Процент-меню", callback_data="admin_promo_discount_show_percent_menu")
    builder.button(text="❌ Отмена", callback_data="admin_cancel")
    builder.adjust(3, 3, 1, 1, 1)
    return builder.as_markup()

def create_admin_promo_limits_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    # СТАРАЯ клавиатура оставлена для совместимости, но не используется в новом мастере
    builder.button(text="Пропустить", callback_data="admin_promo_limits_skip")
    builder.button(text="❌ Отмена", callback_data="admin_cancel")
    builder.adjust(1, 1)
    return builder.as_markup()

def create_admin_promo_limits_type_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="Общий лимит", callback_data="admin_promo_limits_type_total")
    builder.button(text="Лимит на пользователя", callback_data="admin_promo_limits_type_per")
    builder.button(text="Оба лимита", callback_data="admin_promo_limits_type_both")
    builder.button(text="Пропустить", callback_data="admin_promo_limits_skip")
    builder.button(text="❌ Отмена", callback_data="admin_cancel")
    builder.adjust(2, 1, 1, 1)
    return builder.as_markup()

def create_admin_promo_limits_total_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    for n in (10, 50, 100, 200, 500, 1000):
        builder.button(text=str(n), callback_data=f"admin_promo_limits_total_preset_{n}")
    builder.button(text="🖊 Ввести значение", callback_data="admin_promo_limits_total_manual")
    builder.button(text="⬅️ Назад", callback_data="admin_promo_limits_back_to_type")
    builder.button(text="❌ Отмена", callback_data="admin_cancel")
    builder.adjust(3, 3, 1, 1)
    return builder.as_markup()

def create_admin_promo_limits_per_user_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    for n in (1, 2, 3, 5, 10):
        builder.button(text=str(n), callback_data=f"admin_promo_limits_per_preset_{n}")
    builder.button(text="🖊 Ввести значение", callback_data="admin_promo_limits_per_manual")
    builder.button(text="⬅️ Назад", callback_data="admin_promo_limits_back_to_type")
    builder.button(text="❌ Отмена", callback_data="admin_cancel")
    builder.adjust(3, 2, 1, 1)
    return builder.as_markup()

def create_admin_promo_dates_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    # Быстрые пресеты по дням
    builder.button(text="3 дня", callback_data="admin_promo_dates_days_3")
    builder.button(text="7 дней", callback_data="admin_promo_dates_days_7")
    builder.button(text="14 дней", callback_data="admin_promo_dates_days_14")
    builder.button(text="30 дней", callback_data="admin_promo_dates_days_30")
    builder.button(text="90 дней", callback_data="admin_promo_dates_days_90")
    # Альтернативы по периодам
    builder.button(text="Неделя", callback_data="admin_promo_dates_week")
    builder.button(text="Месяц", callback_data="admin_promo_dates_month")
    # Ручной ввод количества дней и пропуск
    builder.button(text="🖊 Ввести число дней", callback_data="admin_promo_dates_custom_days")
    builder.button(text="Пропустить", callback_data="admin_promo_dates_skip")
    builder.button(text="❌ Отмена", callback_data="admin_cancel")
    builder.adjust(2, 2, 1, 2, 1)
    return builder.as_markup()

def create_admin_promo_description_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="Пропустить", callback_data="admin_promo_desc_skip")
    builder.button(text="❌ Отмена", callback_data="admin_cancel")
    builder.adjust(1)
    return builder.as_markup()

def create_admin_promo_confirm_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="✅ Создать", callback_data="admin_promo_confirm_create")
    builder.button(text="❌ Отмена", callback_data="admin_cancel")
    builder.adjust(2)
    return builder.as_markup()

def create_ton_connect_keyboard(connect_url: str) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="🚀 Открыть кошелек", url=connect_url)
    return builder.as_markup()

def create_payment_keyboard(payment_url: str) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text=(get_setting("btn_go_to_payment") or "Перейти к оплате"), url=payment_url)
    return builder.as_markup()

def create_payment_with_check_keyboard(payment_url: str, check_callback: str) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text=(get_setting("btn_go_to_payment") or "Перейти к оплате"), url=payment_url)
    builder.button(text=(get_setting("btn_check_payment") or "✅ Проверить оплату"), callback_data=check_callback)
    builder.adjust(1)
    return builder.as_markup()

def create_topup_payment_method_keyboard(payment_methods: dict) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    # Только внешние способы оплаты, без оплаты с баланса
    if payment_methods and payment_methods.get("yookassa"):
        if get_setting("sbp_enabled"):
            builder.button(text="🏦 СБП / Банковская карта", callback_data="topup_pay_yookassa")
        else:
            builder.button(text="🏦 Банковская карта", callback_data="topup_pay_yookassa")
    if payment_methods and payment_methods.get("heleket"):
        builder.button(text="💎 Криптовалюта", callback_data="topup_pay_heleket")
    if payment_methods and payment_methods.get("platega"):
        builder.button(text="🏦 СБП (Platega)", callback_data="topup_pay_platega_sbp")
        builder.button(text="💳 Карта (Platega)", callback_data="topup_pay_platega_card")
        builder.button(text="💎 Криптовалюта (Platega)", callback_data="topup_pay_platega_crypto")
    if payment_methods and payment_methods.get("cryptobot"):
        builder.button(text="🤖 CryptoBot", callback_data="topup_pay_cryptobot")
    if payment_methods and payment_methods.get("yoomoney"):
        builder.button(text="💜 ЮMoney (кошелёк)", callback_data="topup_pay_yoomoney")
    if payment_methods and payment_methods.get("stars"):
        builder.button(text="⭐ Telegram Stars", callback_data="topup_pay_stars")
    if payment_methods and payment_methods.get("tonconnect"):
        builder.button(text="🪙 TON Connect", callback_data="topup_pay_tonconnect")

    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="show_profile")
    builder.adjust(1)
    return builder.as_markup()

def create_keys_management_keyboard(keys: list) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    if keys:
        for i, key in enumerate(keys):
            expiry_date = datetime.fromisoformat(key['expiry_date'])
            status_icon = "✅" if expiry_date > datetime.now() else "❌"
            button_text = f"{status_icon} Подписка #{i+1} (до {expiry_date.strftime('%d.%m.%Y')})"
            builder.button(text=button_text, callback_data=f"show_key_{key['key_id']}")
    builder.button(text=_buy_subscription_label("➕ Купить подписку"), callback_data="buy_new_key")
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_key_info_keyboard(key_id: int) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text=(get_setting("btn_extend_key") or "➕ Продлить этот ключ"), callback_data=f"extend_key_{key_id}")
    builder.button(text=(get_setting("btn_show_qr") or "📱 Показать QR-код"), callback_data=f"show_qr_{key_id}")
    builder.button(text=(get_setting("btn_instruction") or "📖 Инструкция"), callback_data=f"howto_vless_{key_id}")
    builder.button(text=(get_setting("btn_back_to_keys") or "⬅️ Назад к списку ключей"), callback_data="manage_keys")
    builder.adjust(1)
    return builder.as_markup()

def create_subscription_result_keyboard(subscription_url: str, key_id: int | None = None) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    if subscription_url:
        builder.button(text="📋 Скопировать подписку", callback_data="copy_subscription_link")
        builder.button(text="🔗 Открыть subscription", url=subscription_url)
    if key_id:
        builder.button(text=(get_setting("btn_instruction") or "📖 Инструкция"), callback_data=f"howto_vless_{key_id}")
    builder.button(text="👤 Моя ссылка подписки", callback_data="profile_subscription_link")
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_howto_vless_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text=(get_setting("btn_howto_android") or "📱 Android"), callback_data="howto_android")
    builder.button(text=(get_setting("btn_howto_ios") or "📱 iOS"), callback_data="howto_ios")
    builder.button(text=(get_setting("btn_howto_windows") or "💻 Windows"), callback_data="howto_windows")
    builder.button(text=(get_setting("btn_howto_linux") or "🐧 Linux"), callback_data="howto_linux")
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    builder.adjust(2, 2, 1)
    return builder.as_markup()

def create_howto_vless_keyboard_key(key_id: int) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text=(get_setting("btn_howto_android") or "📱 Android"), callback_data="howto_android")
    builder.button(text=(get_setting("btn_howto_ios") or "📱 iOS"), callback_data="howto_ios")
    builder.button(text=(get_setting("btn_howto_windows") or "💻 Windows"), callback_data="howto_windows")
    builder.button(text=(get_setting("btn_howto_linux") or "🐧 Linux"), callback_data="howto_linux")
    builder.button(text=(get_setting("btn_back_to_key") or "⬅️ Назад к ключу"), callback_data=f"show_key_{key_id}")
    builder.adjust(2, 2, 1)
    return builder.as_markup()

def create_back_to_menu_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    return builder.as_markup()

def create_profile_keyboard(show_renew_button: bool = True) -> InlineKeyboardMarkup:
    kb = _build_keyboard_from_db('profile_menu')
    if kb:
        has_traffic_button = any(
            (getattr(btn, "callback_data", None) == "buy_traffic_start")
            for row in kb.inline_keyboard for btn in row
        )
        # Remove legacy "Моя ссылка подписки" button from profile menu.
        builder = InlineKeyboardBuilder()
        builder.button(
            text=("🔌 Подключиться" if show_renew_button else "💳 Купить подписку"),
            callback_data=("show_connect_menu" if show_renew_button else "buy_new_key")
        )
        if show_renew_button:
            builder.button(text="⚙️ Управление подпиской", callback_data="manage_subscription")
        for row in kb.inline_keyboard:
            filtered = [
                btn for btn in row
                if getattr(btn, "callback_data", None) not in {
                    "profile_subscription_link",
                    "show_connect_menu",
                    "buy_new_key",
                    "buy_traffic_start",
                    "manage_subscription",
                }
            ]
            if filtered:
                builder.row(*filtered)
        builder.adjust(1)
        return builder.as_markup()

    builder = InlineKeyboardBuilder()
    if show_renew_button:
        builder.button(text="🔌 Подключиться", callback_data="show_connect_menu")
        builder.button(text="⚙️ Управление подпиской", callback_data="manage_subscription")
    else:
        builder.button(text="💳 Купить подписку", callback_data="buy_new_key")
    builder.button(text=(get_setting("btn_top_up") or "➕ Пополнить баланс"), callback_data="top_up_start")
    builder.button(text=(get_setting("btn_referral") or "🤝 Реферальная программа"), callback_data="show_referral_program")
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_subscription_management_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="🔄 Продлить подписку", callback_data="buy_traffic_start")
    builder.button(text="📊 Информация о трафике", callback_data="subscription_traffic_info")
    builder.button(text="⬅️ Назад", callback_data="show_profile")
    builder.adjust(1)
    return builder.as_markup()

def create_subscription_traffic_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="➕ Докупить трафик", callback_data="subscription_buy_traffic")
    builder.button(text="⬅️ Назад", callback_data="manage_subscription")
    builder.adjust(1)
    return builder.as_markup()

def create_traffic_packages_keyboard(packages: list[dict]) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    for package in packages:
        try:
            gb = float(package.get("package_gb") or 0)
            price = float(package.get("price") or 0)
        except Exception:
            continue
        builder.button(
            text=f"{gb:.0f} ГБ - {price:.0f} RUB",
            callback_data=f"trafficpack:{int(package['package_id'])}"
        )
    builder.button(text="⬅️ Назад", callback_data="subscription_traffic_info")
    builder.adjust(1)
    return builder.as_markup()

def create_connect_devices_keyboard_with_back_only() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="📱 Android", callback_data="howto_android")
    builder.button(text="🍎 iOS/MacOS", callback_data="howto_ios")
    builder.button(text="💻 Windows", callback_data="howto_windows")
    builder.button(text="🐧 Linux", callback_data="howto_linux")
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    builder.adjust(2, 2, 1)
    return builder.as_markup()

def create_connect_devices_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text="📱 Android", callback_data="howto_android")
    builder.button(text="🍎 iOS/MacOS", callback_data="howto_ios")
    builder.button(text="💻 Windows", callback_data="howto_windows")
    builder.button(text="🐧 Linux", callback_data="howto_linux")
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    builder.adjust(2, 2, 1)
    return builder.as_markup()

def create_referral_keyboard(referral_link: str) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    share_url = f"https://t.me/share/url?url={quote(referral_link, safe='')}"
    builder.button(text="📤 Поделиться ссылкой", url=share_url)
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_platform_download_keyboard(
    platform: str,
    subscription_url: str | None = None,
) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    p = (platform or "").lower()
    if p == "android":
        builder.button(
            text="📥 Скачать приложение",
            url="https://play.google.com/store/apps/details?id=com.v2raytun.android&hl=ru"
        )
    elif p == "ios":
        builder.button(
            text="📥 Скачать из AppStore",
            url="https://apps.apple.com/ru/app/v2raytun/id6476628951"
        )
    elif p == "windows":
        builder.button(
            text="📥 Скачать программу",
            url="https://github.com/mdf45/v2raytun/releases"
        )
    elif p == "linux":
        builder.button(
            text="📥 Скачать программу",
            url="https://github.com/hiddify/hiddify-app/releases/download/v2.0.5/Hiddify-Linux-x64.AppImage"
        )
    # Activation button should use redirect endpoint for instant jump to Happ.
    if subscription_url:
        try:
            activate_url = None
            if p in {"android", "ios", "windows"}:
                clean_subscription_url = (subscription_url or "").strip()
                if clean_subscription_url:
                    parsed = urlparse(clean_subscription_url)
                    if parsed.scheme and parsed.netloc:
                        deeplink = f"v2raytun://import/{clean_subscription_url}"
                        activate_url = f"{parsed.scheme}://{parsed.netloc}/url?url={quote(deeplink, safe='')}"
            else:
                parsed = urlparse(subscription_url)
                token = (parsed.path or "").rstrip("/").split("/")[-1].strip()
                if token and parsed.scheme and parsed.netloc:
                    activate_url = f"{parsed.scheme}://{parsed.netloc}/redirect?token={token}"
            if activate_url:
                builder.button(text="🔗 Активировать подписку", url=activate_url)
        except Exception:
            pass
    builder.button(text="⬅️ Назад", callback_data="show_connect_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_vpn_benefits_keyboard(mode: str) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    if mode == "trial":
        builder.button(text="🎁 Попробовать", callback_data="trial_confirm")
    else:
        builder.button(text="💳 Купить подписку", callback_data="buy_subscription_start")
    builder.button(text=(get_setting("btn_back_to_menu") or "⬅️ Назад в меню"), callback_data="back_to_main_menu")
    builder.adjust(1)
    return builder.as_markup()

def create_welcome_keyboard(channel_url: str | None, is_subscription_forced: bool = False) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    
    if channel_url and is_subscription_forced:
        builder.button(text="📢 Перейти в канал", url=channel_url)
        builder.button(text="✅ Я подписался", callback_data="check_subscription_and_agree")
    elif channel_url:
        builder.button(text="📢 Наш канал (не обязательно)", url=channel_url)
        builder.button(text="✅ Принимаю условия", callback_data="check_subscription_and_agree")
    else:
        builder.button(text="✅ Принимаю условия", callback_data="check_subscription_and_agree")
        
    builder.adjust(1)
    return builder.as_markup()

def get_main_menu_button() -> InlineKeyboardButton:
    return InlineKeyboardButton(text="🏠 В главное меню", callback_data="show_main_menu")

def get_buy_button() -> InlineKeyboardButton:
    return InlineKeyboardButton(text="💳 Купить подписку", callback_data="buy_vpn")


def create_admin_users_pick_keyboard(users: list[dict], page: int = 0, page_size: int = 10, action: str = "gift") -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    start = page * page_size
    end = start + page_size
    for u in users[start:end]:
        user_id = u.get('telegram_id') or u.get('user_id') or u.get('id')
        username = u.get('username') or '—'
        title = f"{user_id} • @{username}" if username != '—' else f"{user_id}"
        builder.button(text=title, callback_data=f"admin_{action}_pick_user_{user_id}")
    total = len(users)
    have_prev = page > 0
    have_next = end < total
    if have_prev:
        builder.button(text="⬅️ Назад", callback_data=f"admin_{action}_pick_user_page_{page-1}")
    if have_next:
        builder.button(text="Вперёд ➡️", callback_data=f"admin_{action}_pick_user_page_{page+1}")
    builder.button(text="⬅️ В админ-меню", callback_data="admin_menu")
    rows = [1] * len(users[start:end])
    tail = []
    if have_prev or have_next:
        tail.append(2 if (have_prev and have_next) else 1)
    tail.append(1)
    builder.adjust(*(rows + tail if rows else ([2] if (have_prev or have_next) else []) + [1]))
    return builder.as_markup()

def create_admin_hosts_pick_keyboard(hosts: list[dict], action: str = "gift") -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    if hosts:
        for h in hosts:
            name = h.get('host_name')
            title = name or "—"
            if action == "speedtest":
                token = encode_host_callback_token(name or "")
                builder.button(text=title, callback_data=f"admin_{action}_pick_host_{token}")
                builder.button(text="🛠 Автоустановка", callback_data=f"admin_speedtest_autoinstall_{token}")
            else:
                builder.button(text=title, callback_data=f"admin_{action}_pick_host_{title}")
    else:
        builder.button(text="Хостов нет", callback_data="noop")
    # Дополнительные опции для speedtest
    if action == "speedtest":
        builder.button(text="🚀 Запустить для всех", callback_data="admin_speedtest_run_all")
    builder.button(text="⬅️ Назад", callback_data=f"admin_{action}_back_to_users")
    # Сетка: по 2 в ряд для speedtest (хост + автоустановка), иначе по 1
    if action == "speedtest":
        rows = [2] * (len(hosts) if hosts else 1)
        tail = [1, 1]
    else:
        rows = [1] * (len(hosts) if hosts else 1)
        tail = [1]
    builder.adjust(*(rows + tail))
    return builder.as_markup()

def create_admin_keys_for_host_keyboard(
    host_name: str,
    keys: list[dict],
    page: int = 0,
    page_size: int = 20,
) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    # Если ключей нет — показываем заглушку и кнопки назад
    if not keys:
        builder.button(text="Ключей на хосте нет", callback_data="noop")
        builder.button(text="⬅️ К выбору хоста", callback_data="admin_hostkeys_back_to_hosts")
        builder.button(text="⬅️ В админ-меню", callback_data="admin_menu")
        builder.adjust(1)
        return builder.as_markup()

    # Пагинация
    start = page * page_size
    end = start + page_size
    for k in keys[start:end]:
        kid = k.get('key_id')
        email = k.get('key_email') or '—'
        expiry = k.get('expiry_date') or '—'
        title = f"#{kid} • {email[:24]} • до {expiry}"
        builder.button(text=title, callback_data=f"admin_edit_key_{kid}")

    total = len(keys)
    have_prev = page > 0
    have_next = end < total
    if have_prev:
        builder.button(text="⬅️ Назад", callback_data=f"admin_hostkeys_page_{page-1}")
    if have_next:
        builder.button(text="Вперёд ➡️", callback_data=f"admin_hostkeys_page_{page+1}")

    # Кнопки навигации
    builder.button(text="⬅️ К выбору хоста", callback_data="admin_hostkeys_back_to_hosts")
    builder.button(text="⬅️ В админ-меню", callback_data="admin_menu")

    # Сетка: список (по 1 в ряд) + пагинация (1 или 2 в ряд) + две кнопки назад
    rows = [1] * len(keys[start:end])
    tail = []
    if have_prev or have_next:
        tail.append(2 if (have_prev and have_next) else 1)
    tail.extend([1, 1])
    builder.adjust(*(rows + tail if rows else ([2] if (have_prev or have_next) else []) + [1, 1]))
    return builder.as_markup()

def create_admin_months_pick_keyboard(action: str = "gift") -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    for m in (1, 3, 6, 12):
        builder.button(text=f"{m} мес.", callback_data=f"admin_{action}_pick_months_{m}")
    builder.button(text="⬅️ Назад", callback_data=f"admin_{action}_back_to_hosts")
    builder.adjust(2, 2, 1)
    return builder.as_markup()


def create_back_to_main_menu_keyboard() -> InlineKeyboardMarkup:
    """Создать клавиатуру с кнопкой возврата в главное меню"""
    builder = InlineKeyboardBuilder()
    builder.button(text="⬅️ Назад в меню", callback_data="back_to_main_menu")
    builder.adjust(1)
    return builder.as_markup()
