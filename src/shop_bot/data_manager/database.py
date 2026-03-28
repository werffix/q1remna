import sqlite3
import uuid
from datetime import datetime
import logging
from pathlib import Path
import json
import re
import hashlib

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path("/app/project")
DB_FILE = PROJECT_ROOT / "users.db"
GLOBAL_PLAN_HOST = "__GLOBAL__"

def normalize_host_name(name: str | None) -> str:
    """Normalize host name by trimming and removing invisible/unicode spaces.
    Removes: NBSP(\u00A0), ZERO WIDTH SPACE(\u200B), ZWNJ(\u200C), ZWJ(\u200D), BOM(\uFEFF).
    """
    s = (name or "").strip()
    for ch in ("\u00A0", "\u200B", "\u200C", "\u200D", "\uFEFF"):
        s = s.replace(ch, "")
    return s

def default_remna_tag(host_name: str | None) -> str:
    base = normalize_host_name(host_name).encode("utf-8")
    return f"SB_{hashlib.sha1(base).hexdigest()[:12].upper()}"

def initialize_db():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    telegram_id INTEGER PRIMARY KEY, username TEXT, total_spent REAL DEFAULT 0,
                    total_months INTEGER DEFAULT 0, trial_used BOOLEAN DEFAULT 0,
                    agreed_to_terms BOOLEAN DEFAULT 0,
                    registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_banned BOOLEAN DEFAULT 0,
                    device_limit INTEGER DEFAULT 3,
                    balance REAL DEFAULT 0,
                    referred_by INTEGER,
                    referral_balance REAL DEFAULT 0,
                    referral_balance_all REAL DEFAULT 0,
                    referral_start_bonus_received BOOLEAN DEFAULT 0,
                    subscription_uuid TEXT,
                    subscription_token TEXT,
                    subscription_link TEXT,
                    subscription_status TEXT,
                    subscription_type TEXT,
                    subscription_expires_at TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vpn_keys (
                    key_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    host_name TEXT NOT NULL,
                    xui_client_uuid TEXT NOT NULL,
                    key_email TEXT NOT NULL UNIQUE,
                    expiry_date TIMESTAMP,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    comment TEXT,
                    is_gift BOOLEAN DEFAULT 0
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS promo_codes (
                    promo_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT NOT NULL UNIQUE,
                    discount_percent REAL,
                    discount_amount REAL,
                    months_bonus INTEGER,
                    max_uses INTEGER,
                    used_count INTEGER DEFAULT 0,
                    active INTEGER NOT NULL DEFAULT 1,
                    valid_from TIMESTAMP,
                    valid_to TIMESTAMP,
                    comment TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bot_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS xui_hosts(
                    host_name TEXT NOT NULL,
                    host_url TEXT NOT NULL,
                    host_username TEXT NOT NULL,
                    host_pass TEXT NOT NULL,
                    host_inbound_id INTEGER NOT NULL,
                    remna_api_token TEXT,
                    remna_internal_squads TEXT,
                    remna_external_squad_uuid TEXT,
                    remna_tag TEXT,
                    host_order INTEGER,
                    is_expired_host INTEGER NOT NULL DEFAULT 0,
                    is_sub_host INTEGER NOT NULL DEFAULT 0,
                    subscription_url TEXT,
                    client_monthly_traffic_gb REAL,
                    ssh_host TEXT,
                    ssh_port INTEGER,
                    ssh_user TEXT,
                    ssh_password TEXT,
                    ssh_key_path TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS plans (
                    plan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_name TEXT NOT NULL,
                    plan_name TEXT NOT NULL,
                    months INTEGER NOT NULL,
                    price REAL NOT NULL,
                    visible_for_all INTEGER NOT NULL DEFAULT 1,
                    allowed_user_ids TEXT,
                    FOREIGN KEY (host_name) REFERENCES xui_hosts (host_name)
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_packages (
                    package_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_gb REAL NOT NULL,
                    price REAL NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    sort_order INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_package_purchases (
                    purchase_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    host_name TEXT NOT NULL,
                    key_email TEXT NOT NULL,
                    purchase_token TEXT,
                    extra_gb REAL NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            try:
                cursor.execute("PRAGMA table_info(traffic_package_purchases)")
                tpp_cols = {row[1] for row in cursor.fetchall()}
                if "purchase_token" not in tpp_cols:
                    cursor.execute("ALTER TABLE traffic_package_purchases ADD COLUMN purchase_token TEXT")
            except Exception:
                pass
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS support_tickets (
                    ticket_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    subject TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS support_messages (
                    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id INTEGER NOT NULL,
                    sender TEXT NOT NULL, -- 'user' | 'admin'
                    content TEXT NOT NULL,
                    media TEXT, -- JSON with Telegram file_id(s), type, caption, mime, size, etc.
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (ticket_id) REFERENCES support_tickets (ticket_id)
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS host_speedtests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_name TEXT NOT NULL,
                    method TEXT NOT NULL, -- 'ssh' | 'net'
                    ping_ms REAL,
                    jitter_ms REAL,
                    download_mbps REAL,
                    upload_mbps REAL,
                    server_name TEXT,
                    server_id TEXT,
                    ok INTEGER NOT NULL DEFAULT 1,
                    error TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_host_speedtests_host_time ON host_speedtests(host_name, created_at DESC)")
            
            # Таблица для метрик ресурсов
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS resource_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT NOT NULL,                -- 'local' | 'host' | 'target'
                    object_name TEXT NOT NULL,          -- 'panel' | host_name | target_name
                    cpu_percent REAL,
                    mem_percent REAL,
                    disk_percent REAL,
                    load1 REAL,
                    net_bytes_sent INTEGER,
                    net_bytes_recv INTEGER,
                    raw_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_resource_metrics_scope_time ON resource_metrics(scope, object_name, created_at DESC)")
            
            # Таблица для конфигураций кнопок
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS button_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    menu_type TEXT NOT NULL DEFAULT 'main_menu',
                    button_id TEXT NOT NULL,
                    text TEXT NOT NULL,
                    callback_data TEXT,
                    url TEXT,
                    row_position INTEGER DEFAULT 0,
                    column_position INTEGER DEFAULT 0,
                    button_width INTEGER DEFAULT 1,
                    sort_order INTEGER DEFAULT 0,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(menu_type, button_id)
                )
            ''')
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_button_configs_menu_type ON button_configs(menu_type, sort_order)")
            
            default_settings = {
                "panel_login": "admin",
                "panel_password": "admin",
                "about_text": None,
                "terms_url": None,
                "privacy_url": None,
                "support_user": None,
                "support_text": None,
                # Editable content
                "main_menu_text": None,
                "howto_android_text": None,
                "howto_ios_text": None,
                "howto_windows_text": None,
                "howto_linux_text": None,
                # Button texts (customizable)
                "btn_try": "🎁 Попробовать бесплатно",
                "btn_profile": "👤 Мой профиль",
                "btn_my_keys": "🔑 Моя подписка ({count})",
                "btn_buy_key": "💳 Купить подписку",
                "btn_top_up": "➕ Пополнить баланс",
                "btn_referral": "🤝 Реферальная программа",
                "btn_support": "🆘 Поддержка",
                "btn_about": "ℹ️ О проекте",
                "btn_howto": "❓ Как использовать",
                "btn_speed": "⚡ Тест скорости",
                "btn_admin": "⚙️ Админка",
                "btn_back_to_menu": "⬅️ Назад в меню",
                "btn_back": "⬅️ Назад",
                "btn_back_to_plans": "⬅️ Назад к тарифам",
                "btn_back_to_key": "⬅️ Назад к ключу",
                "btn_back_to_keys": "⬅️ Назад к списку ключей",
                "btn_extend_key": "➕ Продлить этот ключ",
                "btn_show_qr": "📱 Показать QR-код",
                "btn_instruction": "📖 Инструкция",
                "btn_switch_server": "🌍 Сменить сервер",
                "btn_skip_email": "➡️ Продолжить без почты",
                "btn_go_to_payment": "Перейти к оплате",
                "btn_check_payment": "✅ Проверить оплату",
                "btn_pay_with_balance": "💼 Оплатить с баланса",
                # About/links
                "btn_channel": "📰 Наш канал",
                "btn_terms": "📄 Условия использования",
                "btn_privacy": "🔒 Политика конфиденциальности",
                # Howto platform buttons
                "btn_howto_android": "📱 Android",
                "btn_howto_ios": "📱 iOS",
                "btn_howto_windows": "💻 Windows",
                "btn_howto_linux": "🐧 Linux",
                # Support menu
                "btn_support_open": "🆘 Открыть поддержку",
                "btn_support_new_ticket": "✍️ Новое обращение",
                "btn_support_my_tickets": "📨 Мои обращения",
                "btn_support_external": "🆘 Внешняя поддержка",
                "channel_url": None,
                "force_subscription": "true",
                "receipt_email": "example@example.com",
                "telegram_bot_token": None,
                "telegram_bot_username": None,
                "trial_enabled": "true",
                "trial_duration_days": "3",
                "enable_referrals": "true",
                "referral_percentage": "10",
                "referral_discount": "5",
                "minimum_withdrawal": "100",
                "admin_telegram_id": None,
                "admin_telegram_ids": None,
                "yookassa_shop_id": None,
                "yookassa_secret_key": None,
                "sbp_enabled": "false",
                "cryptobot_token": None,
                "heleket_merchant_id": None,
                "heleket_api_key": None,
                "platega_enabled": "false",
                "platega_merchant_id": None,
                "platega_secret_key": None,
                "platega_api_base": "https://app.platega.io",
                "platega_payment_method": "2",
                "platega_payment_method_sbp": "2",
                "platega_payment_method_card": "11",
                "platega_payment_method_crypto": "13",
                "default_device_limit": "3",
                "domain": None,
                "ton_wallet_address": None,
                "tonapi_key": None,
                "support_forum_chat_id": None,
                # Referral program advanced
                "enable_fixed_referral_bonus": "false",
                "fixed_referral_bonus_amount": "50",
                "referral_reward_type": "percent_purchase",  # percent_purchase | fixed_purchase | fixed_start_referrer | bonus_days_start
                "referral_on_start_referrer_amount": "20",
                "referral_on_start_referrer_days": "3",
                "referral_on_start_new_user_days": "1",
                # Backups
                "backup_interval_days": "1",
                # Telegram Stars payments
                "stars_enabled": "false",
                # Сколько звёзд списывать за 1 RUB (напр., 1.5 звезды за 1 рубль)
                "stars_per_rub": "1",
                # Заголовок/описание инвойсов Stars
                "stars_title": "VPN подписка",
                "stars_description": "Оплата в Telegram Stars",
                # YooMoney separate payments
                "yoomoney_enabled": "false",
                "yoomoney_wallet": None,
                "yoomoney_api_token": None,
                "yoomoney_client_id": None,
                "yoomoney_client_secret": None,
                "yoomoney_redirect_uri": None,
            }
            run_migration()
            for key, value in default_settings.items():
                cursor.execute("INSERT OR IGNORE INTO bot_settings (key, value) VALUES (?, ?)", (key, value))
            conn.commit()
            
            # Check if button configs exist, if not - migrate them
            cursor.execute("SELECT COUNT(*) FROM button_configs")
            button_count = cursor.fetchone()[0]
            
            if button_count == 0:
                logging.info("Конфигурации кнопок не найдены, запускаю начальную миграцию...")
                migrate_existing_buttons()
                cleanup_duplicate_buttons()
            else:
                logging.info(f"Найдено {button_count} существующих конфигураций кнопок, пропускаю миграцию")
            
            # Миграция: добавить колонку created_date в vpn_keys если её нет
            try:
                cursor.execute("PRAGMA table_info(vpn_keys)")
                columns = [row[1] for row in cursor.fetchall()]
                if 'created_date' not in columns:
                    cursor.execute("ALTER TABLE vpn_keys ADD COLUMN created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                    logging.info("Добавлена колонка created_date в таблицу vpn_keys")
                if 'xui_client_uuid' not in columns:
                    cursor.execute("ALTER TABLE vpn_keys ADD COLUMN xui_client_uuid TEXT")
                    logging.info("Добавлена колонка xui_client_uuid в таблицу vpn_keys")
            except Exception as e:
                logging.warning(f"Ошибка при добавлении колонок в таблицу vpn_keys: {e}")

            try:
                cursor.execute("PRAGMA table_info(users)")
                user_columns = [row[1] for row in cursor.fetchall()]
                if 'subscription_uuid' not in user_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN subscription_uuid TEXT")
                    logging.info("Добавлена колонка subscription_uuid в таблицу users")
                if 'subscription_token' not in user_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN subscription_token TEXT")
                    logging.info("Добавлена колонка subscription_token в таблицу users")
                if 'subscription_link' not in user_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN subscription_link TEXT")
                if 'subscription_status' not in user_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN subscription_status TEXT")
                if 'subscription_type' not in user_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN subscription_type TEXT")
                if 'subscription_expires_at' not in user_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN subscription_expires_at TIMESTAMP")
                if 'device_limit' not in user_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN device_limit INTEGER DEFAULT 3")
                    cursor.execute("UPDATE users SET device_limit = 3 WHERE device_limit IS NULL OR device_limit < 1")
            except Exception as e:
                logging.warning(f"Ошибка при добавлении колонки subscription_uuid в таблицу users: {e}")
            
            logging.info("База данных успешно инициализирована.")
    except sqlite3.Error as e:
        logging.error(f"Ошибка базы данных при инициализации: {e}")

# --- Promo codes API (unified) ---
def _promo_columns(conn: sqlite3.Connection) -> set[str]:
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(promo_codes)")
    return {row[1] for row in cursor.fetchall()}


def create_promo_code(
    code: str,
    *,
    discount_percent: float | None = None,
    discount_amount: float | None = None,
    usage_limit_total: int | None = None,
    usage_limit_per_user: int | None = None,
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
    created_by: int | None = None,  # ignored in 3xui schema
    description: str | None = None,
) -> bool:
    code_s = (code or "").strip().upper()
    if not code_s:
        raise ValueError("code is required")
    if (discount_percent or 0) <= 0 and (discount_amount or 0) <= 0:
        raise ValueError("discount must be positive")
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cols = _promo_columns(conn)
            # prefer valid_to in this project; migration didn't add valid_until
            vf = valid_from.isoformat() if isinstance(valid_from, datetime) else valid_from
            vu = valid_until.isoformat() if isinstance(valid_until, datetime) else valid_until
            fields = [
                ("code", code_s),
                ("discount_percent", float(discount_percent) if discount_percent is not None else None),
                ("discount_amount", float(discount_amount) if discount_amount is not None else None),
                ("usage_limit_total", usage_limit_total),
                ("usage_limit_per_user", usage_limit_per_user),
                ("valid_from", vf),
                ("description", description),
            ]
            if "valid_until" in cols:
                fields.append(("valid_until", vu))
            else:
                fields.append(("valid_to", vu))
            columns = ", ".join([f for f, _ in fields])
            placeholders = ", ".join(["?" for _ in fields])
            values = [v for _, v in fields]
            cursor.execute(
                f"INSERT INTO promo_codes ({columns}) VALUES ({placeholders})",
                values,
            )
            conn.commit()
            return True
    except sqlite3.IntegrityОшибка:
        return False
    except sqlite3.Error as e:
        logging.error(f"Ошибка создания промокода: {e}")
        return False


def get_promo_code(code: str) -> dict | None:
    code_s = (code or "").strip().upper()
    if not code_s:
        return None
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM promo_codes WHERE code = ?", (code_s,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logging.error(f"Ошибка получения промокода: {e}")
        return None


def list_promo_codes(include_inactive: bool = True) -> list[dict]:
    query = "SELECT * FROM promo_codes"
    if not include_inactive:
        # use is_active if present, else active
        query += " WHERE COALESCE(is_active, active, 1) = 1"
    query += " ORDER BY created_at DESC"
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)
            return [dict(r) for r in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Ошибка получения списка промокодов: {e}")
        return []


def check_promo_code_available(code: str, user_id: int) -> tuple[dict | None, str | None]:
    code_s = (code or "").strip().upper()
    if not code_s:
        return None, "empty_code"
    user_id_i = int(user_id)
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cols = _promo_columns(conn)
            used_expr = (
                "COALESCE(used_total, used_count, 0)" if "used_total" in cols and "used_count" in cols
                else ("COALESCE(used_total, 0)" if "used_total" in cols
                      else ("COALESCE(used_count, 0)" if "used_count" in cols else "0"))
            )
            vu_expr = "valid_until" if "valid_until" in cols else "valid_to"
            active_expr = "is_active" if "is_active" in cols else "active"
            query = f"""
                SELECT code, discount_percent, discount_amount,
                       usage_limit_total, usage_limit_per_user,
                       {used_expr} AS used_total,
                       valid_from, {vu_expr} AS valid_until,
                       {active_expr} AS is_active
                FROM promo_codes
                WHERE code = ?
            """
            cursor.execute(query, (code_s,))
            row = cursor.fetchone()
            if row is None:
                return None, "not_found"
            promo = dict(row)
            if not promo.get("is_active"):
                return None, "inactive"
            now = datetime.utcnow()
            vf = promo.get("valid_from")
            if vf:
                try:
                    if datetime.fromisoformat(str(vf)) > now:
                        return None, "not_started"
                except Exception:
                    pass
            vu = promo.get("valid_until")
            if vu:
                try:
                    if datetime.fromisoformat(str(vu)) < now:
                        return None, "expired"
                except Exception:
                    pass
            limit_total = promo.get("usage_limit_total")
            used_total = promo.get("used_total") or 0
            if limit_total and used_total >= limit_total:
                return None, "total_limit_reached"
            per_user = promo.get("usage_limit_per_user")
            if per_user:
                cursor.execute(
                    "SELECT COUNT(1) FROM promo_code_usages WHERE code = ? AND user_id = ?",
                    (code_s, user_id_i),
                )
                count = cursor.fetchone()[0]
                if count >= per_user:
                    return None, "user_limit_reached"
            return promo, None
    except sqlite3.Error as e:
        logging.error(f"Ошибка проверки доступности промокода: {e}")
        return None, "db_error"


def update_promo_code_status(code: str, *, is_active: bool | None = None) -> bool:
    code_s = (code or "").strip().upper()
    if not code_s:
        return False
    sets = []
    params: list = []
    if is_active is not None:
        sets.append("is_active = ?")
        params.append(1 if is_active else 0)
        # Update legacy column too for compatibility
        sets.append("active = ?")
        params.append(1 if is_active else 0)
    if not sets:
        return False
    params.append(code_s)
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE promo_codes SET {', '.join(sets)} WHERE code = ?", params)
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Ошибка обновления статуса промокода: {e}")
        return False


def redeem_promo_code(
    code: str,
    user_id: int,
    *,
    applied_amount: float,
    order_id: str | None = None,
) -> dict | None:
    code_s = (code or "").strip().upper()
    if not code_s:
        return None
    user_id_i = int(user_id)
    applied_amount_f = float(applied_amount)
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cols = _promo_columns(conn)
            used_expr = (
                "COALESCE(used_total, used_count, 0)" if "used_total" in cols and "used_count" in cols
                else ("COALESCE(used_total, 0)" if "used_total" in cols
                      else ("COALESCE(used_count, 0)" if "used_count" in cols else "0"))
            )
            vu_expr = "valid_until" if "valid_until" in cols else "valid_to"
            active_expr = "is_active" if "is_active" in cols else "active"
            query = f"""
                SELECT code, discount_percent, discount_amount,
                       usage_limit_total, usage_limit_per_user,
                       {used_expr} AS used_total,
                       valid_from, {vu_expr} AS valid_until,
                       {active_expr} AS is_active
                FROM promo_codes
                WHERE code = ?
            """
            cursor.execute(query, (code_s,))
            row = cursor.fetchone()
            if row is None:
                return None
            promo = dict(row)
            if not promo.get("is_active"):
                return None
            now = datetime.utcnow()
            vf = promo.get("valid_from")
            if vf:
                try:
                    if datetime.fromisoformat(str(vf)) > now:
                        return None
                except Exception:
                    pass
            vu = promo.get("valid_until")
            if vu:
                try:
                    if datetime.fromisoformat(str(vu)) < now:
                        return None
                except Exception:
                    pass
            limit_total = promo.get("usage_limit_total")
            used_total = promo.get("used_total") or 0
            if limit_total and used_total >= limit_total:
                return None
            per_user = promo.get("usage_limit_per_user")
            if per_user:
                cursor.execute(
                    "SELECT COUNT(1) FROM promo_code_usages WHERE code = ? AND user_id = ?",
                    (code_s, user_id_i),
                )
                count = cursor.fetchone()[0]
                if count >= per_user:
                    return None
            else:
                count = None
            # redeem
            cursor.execute(
                """
                INSERT INTO promo_code_usages (code, user_id, applied_amount, order_id)
                VALUES (?, ?, ?, ?)
                """,
                (code_s, user_id_i, applied_amount_f, order_id),
            )
            # increment counters
            cursor.execute(
                "UPDATE promo_codes SET used_total = COALESCE(used_total, 0) + 1, used_count = COALESCE(used_count, 0) + 1 WHERE code = ?",
                (code_s,),
            )
            conn.commit()
            promo["used_total"] = (used_total or 0) + 1
            promo["redeemed_by"] = user_id_i
            promo["applied_amount"] = applied_amount_f
            promo["order_id"] = order_id
            if per_user:
                promo["user_usage_count"] = (count or 0) + 1
            else:
                promo["user_usage_count"] = None
            return promo
    except sqlite3.Error as e:
        logging.error(f"Ошибка использования промокода: {e}")
        return None

def run_migration():
    if not DB_FILE.exists():
        logging.error("Файл базы данных users.db не найден. Мигрировать нечего.")
        return

    logging.info(f"Начинаю миграцию базы данных: {DB_FILE}")

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        logging.info("Миграция таблицы 'users' ...")
    
        cursor.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'referred_by' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN referred_by INTEGER")
            logging.info(" -> Столбец 'referred_by' успешно добавлен.")
        else:
            logging.info(" -> Столбец 'referred_by' уже существует.")
            
        if 'balance' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
            logging.info(" -> Столбец 'balance' успешно добавлен.")
        else:
            logging.info(" -> Столбец 'balance' уже существует.")
        
        if 'referral_balance' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN referral_balance REAL DEFAULT 0")
            logging.info(" -> Столбец 'referral_balance' успешно добавлен.")
        else:
            logging.info(" -> Столбец 'referral_balance' уже существует.")
        
        if 'referral_balance_all' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN referral_balance_all REAL DEFAULT 0")
            logging.info(" -> Столбец 'referral_balance_all' успешно добавлен.")
        else:
            logging.info(" -> Столбец 'referral_balance_all' уже существует.")

        if 'referral_start_bonus_received' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN referral_start_bonus_received BOOLEAN DEFAULT 0")
            logging.info(" -> Столбец 'referral_start_bonus_received' успешно добавлен.")
        else:
            logging.info(" -> Столбец 'referral_start_bonus_received' уже существует.")
        if 'subscription_uuid' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN subscription_uuid TEXT")
            logging.info(" -> Столбец 'subscription_uuid' успешно добавлен.")
        else:
            logging.info(" -> Столбец 'subscription_uuid' уже существует.")
        if 'subscription_token' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN subscription_token TEXT")
            logging.info(" -> Столбец 'subscription_token' успешно добавлен.")
        else:
            logging.info(" -> Столбец 'subscription_token' уже существует.")
        if 'subscription_link' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN subscription_link TEXT")
        if 'subscription_status' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN subscription_status TEXT")
        if 'subscription_type' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN subscription_type TEXT")
        if 'subscription_expires_at' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN subscription_expires_at TIMESTAMP")
        if 'device_limit' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN device_limit INTEGER DEFAULT 3")
            cursor.execute("UPDATE users SET device_limit = 3 WHERE device_limit IS NULL OR device_limit < 1")
        
        logging.info("Таблица 'users' успешно обновлена.")

        # Индексы для ускорения фильтрации/сортировки пользователей
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_reg_date ON users(registration_date)")
            conn.commit()
            logging.info(" -> Индексы для 'users' созданы/проверены.")
        except sqlite3.Error as e:
            logging.warning(f" -> Не удалось создать индексы для 'users': {e}")

        logging.info("Миграция таблицы 'transactions' ...")

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='transactions'")
        table_exists = cursor.fetchone()

        if table_exists:
            cursor.execute("PRAGMA table_info(transactions)")
            trans_columns = [row[1] for row in cursor.fetchall()]
            
            if 'payment_id' in trans_columns and 'status' in trans_columns and 'username' in trans_columns:
                logging.info("Таблица 'transactions' уже имеет новую структуру. Миграция не требуется.")
            else:
                backup_name = f"transactions_backup_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                logging.warning(f"Обнаружена старая структура таблицы 'transactions'. Переименовываю в '{backup_name}' ...")
                cursor.execute(f"ALTER TABLE transactions RENAME TO {backup_name}")
                
                logging.info("Создаю новую таблицу 'transactions' с корректной структурой ...")
                create_new_transactions_table(cursor)
                logging.info("Новая таблица 'transactions' успешно создана. Старые данные сохранены.")
        else:
            logging.info("Таблица 'transactions' не найдена. Создаю новую ...")
            create_new_transactions_table(cursor)
            logging.info("Новая таблица 'transactions' успешно создана.")

        logging.info("Миграция таблицы 'support_tickets' ...")
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='support_tickets'")
        table_exists = cursor.fetchone()
        if table_exists:
            cursor.execute("PRAGMA table_info(support_tickets)")
            st_columns = [row[1] for row in cursor.fetchall()]
            if 'forum_chat_id' not in st_columns:
                cursor.execute("ALTER TABLE support_tickets ADD COLUMN forum_chat_id TEXT")
                logging.info(" -> Столбец 'forum_chat_id' успешно добавлен в 'support_tickets'.")
            else:
                logging.info(" -> Столбец 'forum_chat_id' уже существует в 'support_tickets'.")
            if 'message_thread_id' not in st_columns:
                cursor.execute("ALTER TABLE support_tickets ADD COLUMN message_thread_id INTEGER")
                logging.info(" -> Столбец 'message_thread_id' успешно добавлен в 'support_tickets'.")
            else:
                logging.info(" -> Столбец 'message_thread_id' уже существует в 'support_tickets'.")
        else:
            logging.warning("Таблица 'support_tickets' не найдена, пропускаю её миграцию.")

        conn.commit()
        
        logging.info("Миграция таблицы 'support_messages' ...")
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='support_messages'")
        table_exists = cursor.fetchone()
        if table_exists:
            cursor.execute("PRAGMA table_info(support_messages)")
            sm_columns = [row[1] for row in cursor.fetchall()]
            if 'media' not in sm_columns:
                cursor.execute("ALTER TABLE support_messages ADD COLUMN media TEXT")
                logging.info(" -> Столбец 'media' успешно добавлен в 'support_messages'.")
            else:
                logging.info(" -> Столбец 'media' уже существует в 'support_messages'.")
        else:
            logging.warning("Таблица 'support_messages' не найдена, пропускаю её миграцию.")
        
        logging.info("Миграция таблицы 'xui_hosts' ...")
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='xui_hosts'")
        table_exists = cursor.fetchone()
        if table_exists:
            cursor.execute("PRAGMA table_info(xui_hosts)")
            xh_columns = [row[1] for row in cursor.fetchall()]
            if 'subscription_url' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN subscription_url TEXT")
                logging.info(" -> Столбец 'subscription_url' успешно добавлен в 'xui_hosts'.")
            else:
                logging.info(" -> Столбец 'subscription_url' уже существует в 'xui_hosts'.")
            if 'host_order' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN host_order INTEGER")
                logging.info(" -> Столбец 'host_order' успешно добавлен в 'xui_hosts'.")
                cursor.execute(
                    """
                    UPDATE xui_hosts
                    SET host_order = rowid
                    WHERE host_order IS NULL
                    """
                )
                logging.info(" -> Инициализирован порядок хостов в 'xui_hosts'.")
            else:
                cursor.execute(
                    """
                    UPDATE xui_hosts
                    SET host_order = rowid
                    WHERE host_order IS NULL
                    """
                )
            if 'is_expired_host' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN is_expired_host INTEGER NOT NULL DEFAULT 0")
                logging.info(" -> Столбец 'is_expired_host' успешно добавлен в 'xui_hosts'.")
            if 'remna_api_token' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN remna_api_token TEXT")
                logging.info(" -> Столбец 'remna_api_token' успешно добавлен в 'xui_hosts'.")
            if 'remna_internal_squads' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN remna_internal_squads TEXT")
                logging.info(" -> Столбец 'remna_internal_squads' успешно добавлен в 'xui_hosts'.")
            if 'remna_external_squad_uuid' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN remna_external_squad_uuid TEXT")
                logging.info(" -> Столбец 'remna_external_squad_uuid' успешно добавлен в 'xui_hosts'.")
            if 'remna_tag' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN remna_tag TEXT")
                logging.info(" -> Столбец 'remna_tag' успешно добавлен в 'xui_hosts'.")
            if 'client_monthly_traffic_gb' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN client_monthly_traffic_gb REAL")
                logging.info(" -> Столбец 'client_monthly_traffic_gb' успешно добавлен в 'xui_hosts'.")
            else:
                logging.info(" -> Столбец 'client_monthly_traffic_gb' уже существует в 'xui_hosts'.")
            if 'is_sub_host' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN is_sub_host INTEGER NOT NULL DEFAULT 0")
                logging.info(" -> Столбец 'is_sub_host' успешно добавлен в 'xui_hosts'.")
            # SSH settings for speedtests (optional)
            if 'ssh_host' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN ssh_host TEXT")
                logging.info(" -> Столбец 'ssh_host' успешно добавлен в 'xui_hosts'.")
            if 'ssh_port' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN ssh_port INTEGER")
                logging.info(" -> Столбец 'ssh_port' успешно добавлен в 'xui_hosts'.")
            if 'ssh_user' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN ssh_user TEXT")
                logging.info(" -> Столбец 'ssh_user' успешно добавлен в 'xui_hosts'.")
            if 'ssh_password' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN ssh_password TEXT")
                logging.info(" -> Столбец 'ssh_password' успешно добавлен в 'xui_hosts'.")
            if 'ssh_key_path' not in xh_columns:
                cursor.execute("ALTER TABLE xui_hosts ADD COLUMN ssh_key_path TEXT")
                logging.info(" -> Столбец 'ssh_key_path' успешно добавлен в 'xui_hosts'.")
            # Clean up host_name values from invisible spaces and trim
            try:
                cursor.execute(
                    """
                    UPDATE xui_hosts
                    SET host_name = TRIM(
                        REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(host_name,
                            char(160), ''),      -- NBSP
                            char(8203), ''),     -- ZERO WIDTH SPACE
                            char(8204), ''),     -- ZWNJ
                            char(8205), ''),     -- ZWJ
                            char(65279), ''      -- BOM
                        )
                    )
                    """
                )
                conn.commit()
                logging.info(" -> Нормализованы существующие значения host_name в 'xui_hosts'.")
            except Exception as e:
                logging.warning(f" -> Не удалось нормализовать существующие значения host_name: {e}")
        else:
            logging.warning("Таблица 'xui_hosts' не найдена, пропускаю её миграцию.")

        logging.info("Миграция таблицы 'plans' ...")
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='plans'")
        table_exists = cursor.fetchone()
        if table_exists:
            try:
                cursor.execute("PRAGMA table_info(plans)")
                plan_columns = [row[1] for row in cursor.fetchall()]
                if 'visible_for_all' not in plan_columns:
                    cursor.execute("ALTER TABLE plans ADD COLUMN visible_for_all INTEGER NOT NULL DEFAULT 1")
                if 'allowed_user_ids' not in plan_columns:
                    cursor.execute("ALTER TABLE plans ADD COLUMN allowed_user_ids TEXT")
                cursor.execute(
                    """
                    UPDATE plans
                    SET host_name = ?
                    WHERE TRIM(host_name) != TRIM(?)
                    """,
                    (GLOBAL_PLAN_HOST, GLOBAL_PLAN_HOST)
                )
                conn.commit()
                logging.info(" -> Тарифы переведены в глобальный режим (без привязки к хостам).")
            except sqlite3.Error as e:
                logging.error(f" -> Не удалось перевести тарифы в глобальный режим: {e}")
        else:
            logging.warning("Таблица 'plans' не найдена, пропускаю её миграцию.")

        # Create table for host speedtests
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                CREATE TABLE IF NOT EXISTS host_speedtests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_name TEXT NOT NULL,
                    method TEXT NOT NULL, -- 'ssh' | 'net'
                    ping_ms REAL,
                    jitter_ms REAL,
                    download_mbps REAL,
                    upload_mbps REAL,
                    server_name TEXT,
                    server_id TEXT,
                    ok INTEGER NOT NULL DEFAULT 1,
                    error TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                '''
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_host_speedtests_host_time ON host_speedtests(host_name, created_at DESC)")
            conn.commit()
            logging.info("Таблица 'host_speedtests' готова к использованию.")
        except sqlite3.Error as e:
            logging.error(f"Не удалось создать 'host_speedtests': {e}")

        # Create table for host resource metrics (monitor history)
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                CREATE TABLE IF NOT EXISTS host_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_name TEXT NOT NULL,
                    cpu_percent REAL,
                    mem_percent REAL,
                    mem_used INTEGER,
                    mem_total INTEGER,
                    disk_percent REAL,
                    disk_used INTEGER,
                    disk_total INTEGER,
                    load1 REAL,
                    load5 REAL,
                    load15 REAL,
                    uptime_seconds REAL,
                    ok INTEGER NOT NULL DEFAULT 1,
                    error TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                '''
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_host_metrics_host_time ON host_metrics(host_name, created_at DESC)")
            conn.commit()
            logging.info("Таблица 'host_metrics' готова к использованию.")
        except sqlite3.Error as e:
            logging.error(f"Не удалось создать 'host_metrics': {e}")

        # Ensure extra columns for standalone keys and promo table
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(vpn_keys)")
            vk_cols = [row[1] for row in cursor.fetchall()]
            if 'comment' not in vk_cols:
                cursor.execute("ALTER TABLE vpn_keys ADD COLUMN comment TEXT")
                logging.info(" -> Добавлен столбец 'comment' в 'vpn_keys'.")
            if 'is_gift' not in vk_cols:
                cursor.execute("ALTER TABLE vpn_keys ADD COLUMN is_gift BOOLEAN DEFAULT 0")
                logging.info(" -> Добавлен столбец 'is_gift' в 'vpn_keys'.")
            conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Не удалось мигрировать 'vpn_keys': {e}")

        # Ensure promo code tables and columns (new flexible scheme)
        try:
            cursor = conn.cursor()
            # Base table (create if not exists; old columns may exist — we'll extend with new ones)
            cursor.execute(
                '''
                CREATE TABLE IF NOT EXISTS promo_codes (
                    promo_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT NOT NULL UNIQUE,
                    discount_percent REAL,
                    discount_amount REAL,
                    -- legacy names below may exist in older DBs
                    months_bonus INTEGER,
                    max_uses INTEGER,
                    used_count INTEGER DEFAULT 0,
                    active INTEGER NOT NULL DEFAULT 1,
                    valid_from TIMESTAMP,
                    valid_to TIMESTAMP,
                    comment TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                '''
            )
            # Ensure new columns used by unified promo API
            try:
                cursor.execute("PRAGMA table_info(promo_codes)")
                cols = {row[1] for row in cursor.fetchall()}
                # New canonical columns
                if 'usage_limit_total' not in cols:
                    cursor.execute("ALTER TABLE promo_codes ADD COLUMN usage_limit_total INTEGER")
                if 'usage_limit_per_user' not in cols:
                    cursor.execute("ALTER TABLE promo_codes ADD COLUMN usage_limit_per_user INTEGER")
                if 'used_total' not in cols:
                    cursor.execute("ALTER TABLE promo_codes ADD COLUMN used_total INTEGER DEFAULT 0")
                if 'is_active' not in cols:
                    cursor.execute("ALTER TABLE promo_codes ADD COLUMN is_active INTEGER DEFAULT 1")
                if 'description' not in cols:
                    cursor.execute("ALTER TABLE promo_codes ADD COLUMN description TEXT")
                if 'valid_until' not in cols and 'valid_to' in cols:
                    # Keep using valid_to for backward compatibility; unified API will read either
                    pass
            except Exception as e:
                logging.warning(f"Предупреждение миграции промокодов (колонки): {e}")

            # Mirror legacy counters to new ones if new ones are zero
            try:
                # If used_total is null but used_count exists, initialize used_total from used_count
                cursor.execute("UPDATE promo_codes SET used_total = COALESCE(used_total, 0) + COALESCE(used_count, 0) WHERE used_total IS NULL")
            except Exception:
                pass

            # Usages table
            cursor.execute(
                '''
                CREATE TABLE IF NOT EXISTS promo_code_usages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    applied_amount REAL NOT NULL,
                    order_id TEXT,
                    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                '''
            )
            conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Не удалось подготовить таблицы промокодов: {e}")

        conn.close()
        
        logging.info("--- Миграция базы данных успешно завершена! ---")

    except sqlite3.Error as e:
        logging.error(f"Ошибка во время миграции: {e}")

def create_new_transactions_table(cursor: sqlite3.Cursor):
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            username TEXT,
            transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            amount_rub REAL NOT NULL,
            amount_currency REAL,
            currency_name TEXT,
            payment_method TEXT,
            metadata TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

def create_host(
    name: str,
    url: str,
    user: str,
    passwd: str,
    inbound: int,
    remna_api_token: str | None = None,
    remna_internal_squads: str | None = None,
    remna_external_squad_uuid: str | None = None,
    remna_tag: str | None = None,
    subscription_url: str | None = None,
    client_monthly_traffic_gb: float | None = None,
    is_expired_host: bool | int = False,
    is_sub_host: bool | int = False,
):
    try:
        name = normalize_host_name(name)
        url = (url or "").strip()
        user = (user or "").strip()
        passwd = passwd or ""
        try:
            inbound = int(inbound)
        except Exception:
            inbound = 0
        remna_api_token = (remna_api_token or "").strip() or None
        remna_internal_squads = (remna_internal_squads or "").strip() or None
        remna_external_squad_uuid = (remna_external_squad_uuid or "").strip() or None
        remna_tag = (remna_tag or "").strip().upper() or default_remna_tag(name)
        subscription_url = (subscription_url or None)
        try:
            client_monthly_traffic_gb = float(client_monthly_traffic_gb) if client_monthly_traffic_gb not in (None, "", "null") else None
        except Exception:
            client_monthly_traffic_gb = None
        is_expired_host = 1 if str(is_expired_host).lower() in ("1", "true", "on", "yes") else 0
        is_sub_host = 1 if str(is_sub_host).lower() in ("1", "true", "on", "yes") else 0

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COALESCE(MAX(host_order), 0) + 1 FROM xui_hosts")
            next_order = cursor.fetchone()[0] or 1
            if is_sub_host:
                cursor.execute("UPDATE xui_hosts SET is_sub_host = 0")
            try:
                cursor.execute(
                    "INSERT INTO xui_hosts (host_name, host_url, host_username, host_pass, host_inbound_id, remna_api_token, remna_internal_squads, remna_external_squad_uuid, remna_tag, host_order, is_expired_host, subscription_url, client_monthly_traffic_gb, is_sub_host) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (name, url, user, passwd, inbound, remna_api_token, remna_internal_squads, remna_external_squad_uuid, remna_tag, next_order, is_expired_host, subscription_url, client_monthly_traffic_gb, is_sub_host)
                )
            except sqlite3.OperationalОшибка:
                cursor.execute(
                    "INSERT INTO xui_hosts (host_name, host_url, host_username, host_pass, host_inbound_id) VALUES (?, ?, ?, ?, ?)",
                    (name, url, user, passwd, inbound)
                )
            conn.commit()
            logging.info(f"Успешно создан новый хост: {name}")
    except sqlite3.Error as e:
        logging.error(f"Ошибка при создании хоста '{name}': {e}")

def update_host_subscription_url(host_name: str, subscription_url: str | None) -> bool:
    try:
        host_name = normalize_host_name(host_name)
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM xui_hosts WHERE TRIM(host_name) = TRIM(?)", (host_name,))
            exists = cursor.fetchone() is not None
            if not exists:
                logging.warning(f"update_host_subscription_url: хост с именем '{host_name}' не найден (после TRIM)")
                return False

            cursor.execute(
                "UPDATE xui_hosts SET subscription_url = ? WHERE TRIM(host_name) = TRIM(?)",
                (subscription_url, host_name)
            )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить subscription_url для хоста '{host_name}': {e}")
        return False

def update_host_client_monthly_traffic_limit(host_name: str, traffic_gb: float | None) -> bool:
    try:
        host_name = normalize_host_name(host_name)
        value = None
        if traffic_gb not in (None, "", "null"):
            try:
                value = max(0.0, float(traffic_gb))
            except Exception:
                value = None
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM xui_hosts WHERE TRIM(host_name) = TRIM(?)", (host_name,))
            exists = cursor.fetchone() is not None
            if not exists:
                logging.warning(f"update_host_client_monthly_traffic_limit: хост '{host_name}' не найден")
                return False
            cursor.execute(
                "UPDATE xui_hosts SET client_monthly_traffic_gb = ? WHERE TRIM(host_name) = TRIM(?)",
                (value, host_name)
            )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить client_monthly_traffic_gb для хоста '{host_name}': {e}")
        return False

def update_host_remna_settings(
    host_name: str,
    remna_api_token: str | None = None,
    remna_internal_squads: str | None = None,
    remna_external_squad_uuid: str | None = None,
    remna_tag: str | None = None,
) -> bool:
    try:
        host_name = normalize_host_name(host_name)
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM xui_hosts WHERE TRIM(host_name) = TRIM(?)", (host_name,))
            exists = cursor.fetchone() is not None
            if not exists:
                logging.warning(f"update_host_remna_settings: хост '{host_name}' не найден")
                return False
            cursor.execute(
                """
                UPDATE xui_hosts
                SET remna_api_token = ?,
                    remna_internal_squads = ?,
                    remna_external_squad_uuid = ?,
                    remna_tag = ?
                WHERE TRIM(host_name) = TRIM(?)
                """,
                (
                    (remna_api_token or None),
                    (remna_internal_squads or None),
                    (remna_external_squad_uuid or None),
                    ((remna_tag or "").strip().upper() or default_remna_tag(host_name)),
                    host_name,
                )
            )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить Remnawave-настройки для хоста '{host_name}': {e}")
        return False

def update_host_is_expired(host_name: str, is_expired_host: bool | int) -> bool:
    try:
        host_name = normalize_host_name(host_name)
        value = 1 if str(is_expired_host).lower() in ("1", "true", "on", "yes") else 0
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM xui_hosts WHERE TRIM(host_name) = TRIM(?)", (host_name,))
            exists = cursor.fetchone() is not None
            if not exists:
                logging.warning(f"update_host_is_expired: хост '{host_name}' не найден")
                return False
            cursor.execute(
                "UPDATE xui_hosts SET is_expired_host = ? WHERE TRIM(host_name) = TRIM(?)",
                (value, host_name)
            )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить is_expired_host для хоста '{host_name}': {e}")
        return False

def update_host_is_sub(host_name: str, is_sub_host: bool | int) -> bool:
    try:
        host_name = normalize_host_name(host_name)
        value = 1 if str(is_sub_host).lower() in ("1", "true", "on", "yes") else 0
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM xui_hosts WHERE TRIM(host_name) = TRIM(?)", (host_name,))
            exists = cursor.fetchone() is not None
            if not exists:
                logging.warning(f"update_host_is_sub: хост '{host_name}' не найден")
                return False
            if value:
                cursor.execute("UPDATE xui_hosts SET is_sub_host = 0")
            cursor.execute(
                "UPDATE xui_hosts SET is_sub_host = ? WHERE TRIM(host_name) = TRIM(?)",
                (value, host_name)
            )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить is_sub_host для хоста '{host_name}': {e}")
        return False

def get_sub_host() -> dict | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM xui_hosts
                WHERE COALESCE(is_sub_host, 0) = 1
                ORDER BY COALESCE(host_order, 999999999), rowid
                LIMIT 1
                """
            )
            row = cursor.fetchone()
            if not row:
                return None
            d = dict(row)
            d["host_name"] = normalize_host_name(d.get("host_name"))
            return d
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить САБ-хост: {e}")
        return None

def set_referral_start_bonus_received(user_id: int) -> bool:
    """Пометить, что пользователь получил стартовый бонус за реферальную регистрацию."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET referral_start_bonus_received = 1 WHERE telegram_id = ?",
                (user_id,)
            )
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось пометить получение стартового реферального бонуса для пользователя {user_id}: {e}")
        return False

def update_host_url(host_name: str, new_url: str) -> bool:
    """Обновить URL панели XUI для указанного хоста."""
    try:
        host_name = normalize_host_name(host_name)
        new_url = (new_url or "").strip()
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM xui_hosts WHERE TRIM(host_name) = TRIM(?)", (host_name,))
            if cursor.fetchone() is None:
                logging.warning(f"update_host_url: хост с именем '{host_name}' не найден")
                return False

            cursor.execute(
                "UPDATE xui_hosts SET host_url = ? WHERE TRIM(host_name) = TRIM(?)",
                (new_url, host_name)
            )
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить host_url для хоста '{host_name}': {e}")
        return False

def update_host_name(old_name: str, new_name: str) -> bool:
    """Переименовать хост во всех связанных таблицах (xui_hosts, vpn_keys)."""
    try:
        old_name_n = normalize_host_name(old_name)
        new_name_n = normalize_host_name(new_name)
        if not new_name_n:
            logging.warning("update_host_name: новое имя хоста пустое после нормализации")
            return False
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM xui_hosts WHERE TRIM(host_name) = TRIM(?)", (old_name_n,))
            if cursor.fetchone() is None:
                logging.warning(f"update_host_name: исходный хост не найден '{old_name_n}'")
                return False
            cursor.execute("SELECT 1 FROM xui_hosts WHERE TRIM(host_name) = TRIM(?)", (new_name_n,))
            exists_target = cursor.fetchone() is not None
            if exists_target and old_name_n.lower() != new_name_n.lower():
                logging.warning(f"update_host_name: целевое имя '{new_name_n}' уже используется")
                return False

            cursor.execute(
                "UPDATE xui_hosts SET host_name = TRIM(?) WHERE TRIM(host_name) = TRIM(?)",
                (new_name_n, old_name_n)
            )
            cursor.execute(
                "UPDATE vpn_keys SET host_name = TRIM(?) WHERE TRIM(host_name) = TRIM(?)",
                (new_name_n, old_name_n)
            )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось переименовать хост с '{old_name}' на '{new_name}': {e}")
        return False

def delete_host(host_name: str):
    try:
        host_name = normalize_host_name(host_name)
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM xui_hosts WHERE TRIM(host_name) = TRIM(?)", (host_name,))
            conn.commit()
            logging.info(f"Хост '{host_name}' успешно удален.")
    except sqlite3.Error as e:
        logging.error(f"Ошибка удаления хоста '{host_name}': {e}")

def get_host(host_name: str) -> dict | None:
    try:
        host_name = normalize_host_name(host_name)
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM xui_hosts WHERE TRIM(host_name) = TRIM(?)", (host_name,))
            result = cursor.fetchone()
            return dict(result) if result else None
    except sqlite3.Error as e:
        logging.error(f"Ошибка получения хоста '{host_name}': {e}")
        return None

def update_host_ssh_settings(
    host_name: str,
    ssh_host: str | None = None,
    ssh_port: int | None = None,
    ssh_user: str | None = None,
    ssh_password: str | None = None,
    ssh_key_path: str | None = None,
) -> bool:
    """Обновить SSH-параметры для speedtest/maintenance по хосту.
    Переданные None значения очищают соответствующие поля (ставят NULL).
    """
    try:
        host_name_n = normalize_host_name(host_name)
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM xui_hosts WHERE TRIM(host_name) = TRIM(?)", (host_name_n,))
            if cursor.fetchone() is None:
                logging.warning(f"update_host_ssh_settings: хост не найден '{host_name_n}'")
                return False

            cursor.execute(
                """
                UPDATE xui_hosts
                SET ssh_host = ?, ssh_port = ?, ssh_user = ?, ssh_password = ?, ssh_key_path = ?
                WHERE TRIM(host_name) = TRIM(?)
                """,
                (
                    (ssh_host or None),
                    (int(ssh_port) if ssh_port is not None else None),
                    (ssh_user or None),
                    (ssh_password if ssh_password is not None else None),
                    (ssh_key_path or None),
                    host_name_n,
                ),
            )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить SSH-настройки для хоста '{host_name}': {e}")
        return False

def delete_key_by_id(key_id: int) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vpn_keys WHERE key_id = ?", (key_id,))
            affected = cursor.rowcount
            conn.commit()
            return affected > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось удалить ключ по id {key_id}: {e}")
        return False

def update_key_comment(key_id: int, comment: str) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE vpn_keys SET comment = ? WHERE key_id = ?", (comment, key_id))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить комментарий ключа для {key_id}: {e}")
        return False

def get_all_hosts() -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM xui_hosts
                ORDER BY COALESCE(host_order, 999999999), rowid
                """
            )
            hosts = cursor.fetchall()
            # Normalize host_name in returned dicts to avoid trailing/invisible chars in runtime
            result = []
            for row in hosts:
                d = dict(row)
                d['host_name'] = normalize_host_name(d.get('host_name'))
                result.append(d)
            return result
    except sqlite3.Error as e:
        logging.error(f"Ошибка получения списка всех хостов: {e}")
        return []

def move_host_order(host_name: str, direction: str) -> bool:
    try:
        host_name_n = normalize_host_name(host_name)
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT rowid, host_name, COALESCE(host_order, rowid) AS ord
                FROM xui_hosts
                ORDER BY COALESCE(host_order, rowid), rowid
                """
            )
            rows = [dict(r) for r in cursor.fetchall()]
            if not rows:
                return False

            idx = next((i for i, r in enumerate(rows) if normalize_host_name(r.get("host_name")) == host_name_n), None)
            if idx is None:
                return False
            if direction == "up" and idx > 0:
                swap_idx = idx - 1
            elif direction == "down" and idx < len(rows) - 1:
                swap_idx = idx + 1
            else:
                return False

            rows[idx]["ord"], rows[swap_idx]["ord"] = rows[swap_idx]["ord"], rows[idx]["ord"]

            for r in rows:
                cursor.execute(
                    "UPDATE xui_hosts SET host_order = ? WHERE rowid = ?",
                    (int(r["ord"]), int(r["rowid"]))
                )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось изменить порядок хоста '{host_name}': {e}")
        return False

def get_speedtests(host_name: str, limit: int = 20) -> list[dict]:
    """Получить последние результаты спидтестов по хосту (ssh/net), новые сверху."""
    try:
        host_name_n = normalize_host_name(host_name)
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            try:
                limit_int = int(limit)
            except Exception:
                limit_int = 20
            cursor.execute(
                """
                SELECT id, host_name, method, ping_ms, jitter_ms, download_mbps, upload_mbps,
                       server_name, server_id, ok, error, created_at
                FROM host_speedtests
                WHERE TRIM(host_name) = TRIM(?)
                ORDER BY datetime(created_at) DESC
                LIMIT ?
                """,
                (host_name_n, limit_int),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить speedtest-данные для хоста '{host_name}': {e}")
        return []

def get_latest_speedtest(host_name: str) -> dict | None:
    """Получить последний по времени спидтест для хоста."""
    try:
        host_name_n = normalize_host_name(host_name)
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, host_name, method, ping_ms, jitter_ms, download_mbps, upload_mbps,
                       server_name, server_id, ok, error, created_at
                FROM host_speedtests
                WHERE TRIM(host_name) = TRIM(?)
                ORDER BY datetime(created_at) DESC
                LIMIT 1
                """,
                (host_name_n,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить последний speedtest для хоста '{host_name}': {e}")
        return None

def find_and_complete_pending_transaction(
    payment_id: str,
    amount_rub: float | None,
    payment_method: str,
    currency_name: str | None = None,
    amount_currency: float | None = None,
) -> dict | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM transactions WHERE payment_id = ? AND status = 'pending'", (payment_id,))
            transaction = cursor.fetchone()
            if not transaction:
                logger.warning(f"Ожидающая транзакция не найдена для payment_id={payment_id}")
                return None

            cursor.execute(
                """
                UPDATE transactions
                SET status = 'paid',
                    amount_rub = COALESCE(?, amount_rub),
                    amount_currency = COALESCE(?, amount_currency),
                    currency_name = COALESCE(?, currency_name),
                    payment_method = COALESCE(?, payment_method)
                WHERE payment_id = ?
                """,
                (amount_rub, amount_currency, currency_name, payment_method, payment_id)
            )
            conn.commit()

            try:
                raw_md = None
                try:
                    raw_md = transaction['metadata']
                except Exception:
                    raw_md = None
                md = json.loads(raw_md) if raw_md else {}
            except Exception:
                md = {}
            return md
    except sqlite3.Error as e:
        logging.error(f"Не удалось завершить ожидающую транзакцию {payment_id}: {e}")
        return None

def insert_host_speedtest(
    host_name: str,
    method: str,
    ping_ms: float | None = None,
    jitter_ms: float | None = None,
    download_mbps: float | None = None,
    upload_mbps: float | None = None,
    server_name: str | None = None,
    server_id: str | None = None,
    ok: bool = True,
    error: str | None = None,
) -> bool:
    """Сохранить результат спидтеста в таблицу host_speedtests."""
    try:
        host_name_n = normalize_host_name(host_name)
        method_s = (method or '').strip().lower()
        if method_s not in ('ssh', 'net'):
            method_s = 'ssh'
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO host_speedtests
                (host_name, method, ping_ms, jitter_ms, download_mbps, upload_mbps, server_name, server_id, ok, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                '''
                , (
                    host_name_n,
                    method_s,
                    ping_ms,
                    jitter_ms,
                    download_mbps,
                    upload_mbps,
                    server_name,
                    server_id,
                    1 if ok else 0,
                    (error or None)
                )
            )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось сохранить запись speedtest для '{host_name}': {e}")
        return False

def get_admin_stats() -> dict:
    """Return aggregated statistics for the admin dashboard.
    Includes:
    - total_users: count of users
    - total_keys: count of unique users with at least one key (subscriptions)
    - active_keys: unique users with active keys (expiry_date in the future)
    - total_income: sum of amount_rub for successful transactions
    """
    stats = {
        "total_users": 0,
        "total_keys": 0,
        "active_keys": 0,
        "total_income": 0.0,
        # today's metrics
        "today_new_users": 0,
        "today_income": 0.0,
        "today_issued_keys": 0,
        # current month metrics
        "month_new_users": 0,
        "month_income": 0.0,
        "month_issued_keys": 0,
    }
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            # users
            cursor.execute("SELECT COUNT(*) FROM users")
            row = cursor.fetchone()
            stats["total_users"] = (row[0] or 0) if row else 0

            # total subscriptions (1 subscription = 1 user)
            cursor.execute("SELECT COUNT(DISTINCT user_id) FROM vpn_keys")
            row = cursor.fetchone()
            stats["total_keys"] = (row[0] or 0) if row else 0

            # active subscriptions (unique users with any active key)
            cursor.execute("SELECT COUNT(DISTINCT user_id) FROM vpn_keys WHERE expiry_date > CURRENT_TIMESTAMP")
            row = cursor.fetchone()
            stats["active_keys"] = (row[0] or 0) if row else 0

            # income: consider common success markers (total)
            cursor.execute(
                "SELECT COALESCE(SUM(amount_rub), 0) FROM transactions WHERE status IN ('paid','success','succeeded') AND LOWER(COALESCE(payment_method, '')) <> 'balance'"
            )
            row = cursor.fetchone()
            stats["total_income"] = float(row[0] or 0.0) if row else 0.0

            # today's metrics
            # new users today
            cursor.execute(
                "SELECT COUNT(*) FROM users WHERE date(registration_date) = date('now')"
            )
            row = cursor.fetchone()
            stats["today_new_users"] = (row[0] or 0) if row else 0

            # today's income
            cursor.execute(
                """
                SELECT COALESCE(SUM(amount_rub), 0)
                FROM transactions
                WHERE status IN ('paid','success','succeeded')
                  AND LOWER(COALESCE(payment_method, '')) <> 'balance'
                  AND date(created_date) = date('now')
                """
            )
            row = cursor.fetchone()
            stats["today_income"] = float(row[0] or 0.0) if row else 0.0

            # today's issued subscriptions (unique users)
            cursor.execute(
                "SELECT COUNT(DISTINCT user_id) FROM vpn_keys WHERE date(created_date) = date('now')"
            )
            row = cursor.fetchone()
            stats["today_issued_keys"] = (row[0] or 0) if row else 0

            # current month new users
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM users
                WHERE strftime('%Y-%m', registration_date) = strftime('%Y-%m', 'now')
                """
            )
            row = cursor.fetchone()
            stats["month_new_users"] = (row[0] or 0) if row else 0

            # current month income
            cursor.execute(
                """
                SELECT COALESCE(SUM(amount_rub), 0)
                FROM transactions
                WHERE status IN ('paid','success','succeeded')
                  AND LOWER(COALESCE(payment_method, '')) <> 'balance'
                  AND strftime('%Y-%m', created_date) = strftime('%Y-%m', 'now')
                """
            )
            row = cursor.fetchone()
            stats["month_income"] = float(row[0] or 0.0) if row else 0.0

            # current month issued subscriptions (unique users)
            cursor.execute(
                """
                SELECT COUNT(DISTINCT user_id)
                FROM vpn_keys
                WHERE strftime('%Y-%m', created_date) = strftime('%Y-%m', 'now')
                """
            )
            row = cursor.fetchone()
            stats["month_issued_keys"] = (row[0] or 0) if row else 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить статистику администратора: {e}")
    return stats

def get_all_keys() -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT k.*
                FROM vpn_keys k
                LEFT JOIN xui_hosts h ON TRIM(h.host_name) = TRIM(k.host_name)
                WHERE COALESCE(h.is_expired_host, 0) = 0
                """
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить все ключи: {e}")
        return []

def get_keys_for_user(user_id: int) -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT k.*
                FROM vpn_keys k
                LEFT JOIN xui_hosts h ON TRIM(h.host_name) = TRIM(k.host_name)
                WHERE k.user_id = ? AND COALESCE(h.is_expired_host, 0) = 0
                ORDER BY k.created_date DESC
                """,
                (user_id,)
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Не удалось get keys for user {user_id}: {e}")
        return []

def get_key_by_id(key_id: int) -> dict | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vpn_keys WHERE key_id = ?", (key_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить ключ по id {key_id}: {e}")
        return None

def update_key_email(key_id: int, new_email: str) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE vpn_keys SET key_email = ? WHERE key_id = ?", (new_email, key_id))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.IntegrityОшибка as e:
        logging.error(f"Нарушение уникальности email для ключа {key_id}: {e}")
        return False
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить email ключа для {key_id}: {e}")
        return False

def update_key_host(key_id: int, new_host_name: str) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE vpn_keys SET host_name = ? WHERE key_id = ?", (normalize_host_name(new_host_name), key_id))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить хост ключа для {key_id}: {e}")
        return False

def create_gift_key(user_id: int, host_name: str, key_email: str, months: int, xui_client_uuid: str | None = None) -> int | None:
    """Создать подарочный ключ: задаёт expiry_date = now + months, host_name нормализуется.
    Возвращает key_id или None при ошибке."""
    try:
        host_name = normalize_host_name(host_name)
        from datetime import timedelta
        expiry = datetime.now() + timedelta(days=30 * int(months or 1))
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO vpn_keys (user_id, host_name, xui_client_uuid, key_email, expiry_date) VALUES (?, ?, ?, ?, ?)",
                (user_id, host_name, xui_client_uuid or f"GIFT-{user_id}-{int(datetime.now().timestamp())}", key_email, expiry.isoformat())
            )
            conn.commit()
            return cursor.lastrowid
    except sqlite3.IntegrityОшибка as e:
        logging.error(f"Не удалось создать подарочный ключ для пользователя {user_id}: дублирующийся email {key_email}: {e}")
        return None
    except sqlite3.Error as e:
        logging.error(f"Не удалось создать подарочный ключ для пользователя {user_id}: {e}")
        return None

def get_setting(key: str) -> str | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM bot_settings WHERE key = ?", (key,))
            result = cursor.fetchone()
            return result[0] if result else None
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить настройку '{key}': {e}")
        return None

def get_admin_ids() -> set[int]:
    """Возвращает множество ID администраторов из настроек.
    Поддерживает оба варианта: одиночный 'admin_telegram_id' и список 'admin_telegram_ids'
    через запятую/пробелы или JSON-массив.
    """
    ids: set[int] = set()
    try:
        single = get_setting("admin_telegram_id")
        if single:
            try:
                ids.add(int(single))
            except Exception:
                pass
        multi_raw = get_setting("admin_telegram_ids")
        if multi_raw:
            s = (multi_raw or "").strip()
            # Попробуем как JSON-массив
            try:
                arr = json.loads(s)
                if isinstance(arr, list):
                    for v in arr:
                        try:
                            ids.add(int(v))
                        except Exception:
                            pass
                    return ids
            except Exception:
                pass
            # Иначе как строка с разделителями (запятая/пробел)
            parts = [p for p in re.split(r"[\s,]+", s) if p]
            for p in parts:
                try:
                    ids.add(int(p))
                except Exception:
                    pass
    except Exception as e:
        logging.warning(f"Не удалось получить ID администраторов: {e}")
    return ids

def is_admin(user_id: int) -> bool:
    """Проверка прав администратора по списку ID из настроек."""
    try:
        return int(user_id) in get_admin_ids()
    except Exception:
        return False
        
def get_referrals_for_user(user_id: int) -> list[dict]:
    """Возвращает список пользователей, которых пригласил данный user_id.
    Поля: telegram_id, username, registration_date, total_spent.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT telegram_id, username, registration_date, total_spent
                FROM users
                WHERE referred_by = ?
                ORDER BY registration_date DESC
                """,
                (user_id,)
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить рефералов для пользователя {user_id}: {e}")
        return []
        
def get_all_settings() -> dict:
    settings = {}
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM bot_settings")
            rows = cursor.fetchall()
            for row in rows:
                settings[row['key']] = row['value']
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить все настройки: {e}")
    return settings

def update_setting(key: str, value: str):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO bot_settings (key, value) VALUES (?, ?)", (key, value))
            conn.commit()
            logging.info(f"Настройка '{key}' обновлена.")
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить настройку '{key}': {e}")

def create_plan(host_name: str, plan_name: str, months: int, price: float):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO plans (host_name, plan_name, months, price, visible_for_all, allowed_user_ids) VALUES (?, ?, ?, ?, 1, NULL)",
                (GLOBAL_PLAN_HOST, plan_name, months, price)
            )
            conn.commit()
            logging.info(f"Создан новый глобальный план '{plan_name}'.")
    except sqlite3.Error as e:
        logging.error(f"Не удалось создать глобальный план '{plan_name}': {e}")

def get_all_plans() -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM plans
                WHERE TRIM(host_name) = TRIM(?)
                ORDER BY months, plan_id
                """,
                (GLOBAL_PLAN_HOST,)
            )
            plans = cursor.fetchall()
            return [dict(plan) for plan in plans]
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить глобальные планы: {e}")
        return []

def get_all_plans_for_user(user_id: int) -> list[dict]:
    plans = get_all_plans() or []
    uid = int(user_id)
    visible_plans: list[dict] = []
    for plan in plans:
        if int(plan.get("visible_for_all") or 0) == 1:
            visible_plans.append(plan)
            continue
        allowed_raw = str(plan.get("allowed_user_ids") or "").strip()
        if not allowed_raw:
            continue
        allowed = {x.strip() for x in re.split(r"[\s,;]+", allowed_raw) if x.strip()}
        if str(uid) in allowed:
            visible_plans.append(plan)
    return visible_plans

def get_plans_for_host(host_name: str) -> list[dict]:
    try:
        host_name = normalize_host_name(host_name)
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Глобальные тарифы имеют приоритет; для обратной совместимости
            # добавляем legacy-тарифы конкретного хоста.
            cursor.execute(
                """
                SELECT * FROM plans
                WHERE TRIM(host_name) = TRIM(?)
                   OR TRIM(host_name) = TRIM(?)
                ORDER BY months, plan_id
                """,
                (GLOBAL_PLAN_HOST, host_name)
            )
            plans = cursor.fetchall()
            return [dict(plan) for plan in plans]
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить планы для хоста '{host_name}': {e}")
        return []

def get_plan_by_id(plan_id: int) -> dict | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM plans WHERE plan_id = ?", (plan_id,))
            plan = cursor.fetchone()
            return dict(plan) if plan else None
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить план по id '{plan_id}': {e}")
        return None

def delete_plan(plan_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM plans WHERE plan_id = ?", (plan_id,))
            conn.commit()
            logging.info(f"Удален план с id {plan_id}.")
    except sqlite3.Error as e:
        logging.error(f"Не удалось удалить план с id {plan_id}: {e}")

def update_plan(plan_id: int, plan_name: str, months: int, price: float) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE plans SET plan_name = ?, months = ?, price = ? WHERE plan_id = ?",
                (plan_name, months, price, plan_id)
            )
            conn.commit()
            if cursor.rowcount == 0:
                logging.warning(f"План с id {plan_id} не найден для обновления.")
                return False
            logging.info(f"Обновлен план {plan_id}: название='{plan_name}', месяцы={months}, цена={price}.")
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить план {plan_id}: {e}")
        return False

def update_plan_visibility(plan_id: int, visible_for_all: bool, allowed_user_ids: str | None) -> bool:
    try:
        allowed = (allowed_user_ids or "").strip() or None
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE plans SET visible_for_all = ?, allowed_user_ids = ? WHERE plan_id = ?",
                (1 if visible_for_all else 0, allowed, plan_id)
            )
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить видимость плана {plan_id}: {e}")
        return False

def create_traffic_package(package_gb: float, price: float, is_active: bool = True, sort_order: int | None = None) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            if sort_order is None:
                cursor.execute("SELECT COALESCE(MAX(sort_order), 0) + 1 FROM traffic_packages")
                sort_order = int(cursor.fetchone()[0] or 1)
            cursor.execute(
                """
                INSERT INTO traffic_packages (package_gb, price, is_active, sort_order)
                VALUES (?, ?, ?, ?)
                """,
                (float(package_gb), float(price), 1 if is_active else 0, int(sort_order)),
            )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось создать пакет трафика: {e}")
        return False

def get_all_traffic_packages() -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM traffic_packages
                ORDER BY sort_order, package_gb, package_id
                """
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить пакеты трафика: {e}")
        return []

def get_active_traffic_packages() -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM traffic_packages
                WHERE is_active = 1
                ORDER BY sort_order, package_gb, package_id
                """
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить активные пакеты трафика: {e}")
        return []

def get_traffic_package_by_id(package_id: int) -> dict | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM traffic_packages WHERE package_id = ?", (package_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить пакет трафика {package_id}: {e}")
        return None

def update_traffic_package(package_id: int, package_gb: float, price: float, is_active: bool, sort_order: int = 0) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE traffic_packages
                SET package_gb = ?, price = ?, is_active = ?, sort_order = ?
                WHERE package_id = ?
                """,
                (float(package_gb), float(price), 1 if is_active else 0, int(sort_order), int(package_id)),
            )
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить пакет трафика {package_id}: {e}")
        return False

def delete_traffic_package(package_id: int) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM traffic_packages WHERE package_id = ?", (int(package_id),))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось удалить пакет трафика {package_id}: {e}")
        return False

def create_traffic_package_purchase(user_id: int, host_name: str, key_email: str, extra_gb: float, purchase_token: str | None = None) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO traffic_package_purchases (user_id, host_name, key_email, extra_gb, purchase_token)
                VALUES (?, ?, ?, ?, ?)
                """,
                (int(user_id), str(host_name), str(key_email), float(extra_gb), (str(purchase_token).strip() if purchase_token else None)),
            )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось сохранить покупку пакета трафика для пользователя {user_id}: {e}")
        return False

def clear_all_traffic_package_purchases() -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM traffic_package_purchases")
            conn.commit()
            return int(cursor.rowcount or 0)
    except sqlite3.Error as e:
        logging.error(f"Не удалось очистить покупки пакетов трафика: {e}")
        return 0

def get_total_extra_traffic_gb_for_user(user_id: int) -> float:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COALESCE(SUM(extra_gb_once), 0) FROM (
                    SELECT COALESCE(MAX(extra_gb), 0) AS extra_gb_once
                    FROM traffic_package_purchases
                    WHERE user_id = ?
                    GROUP BY COALESCE(purchase_token, CAST(purchase_id AS TEXT))
                )
                """,
                (int(user_id),),
            )
            row = cursor.fetchone()
            return float((row[0] if row else 0.0) or 0.0)
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить докупленный трафик пользователя {user_id}: {e}")
        return 0.0

def get_extra_traffic_gb_for_user_key(user_id: int, host_name: str, key_email: str) -> float:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COALESCE(SUM(extra_gb), 0)
                FROM traffic_package_purchases
                WHERE user_id = ? AND host_name = ? AND key_email = ?
                """,
                (int(user_id), str(host_name), str(key_email)),
            )
            row = cursor.fetchone()
            return float((row[0] if row else 0.0) or 0.0)
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить докупленный трафик пользователя {user_id} для ключа {key_email}: {e}")
        return 0.0


def register_user_if_not_exists(telegram_id: int, username: str, referrer_id):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT referred_by FROM users WHERE telegram_id = ?", (telegram_id,))
            row = cursor.fetchone()
            if not row:
                # Новый пользователь — сразу сохраняем возможного реферера
                cursor.execute(
                    "INSERT INTO users (telegram_id, username, registration_date, referred_by) VALUES (?, ?, ?, ?)",
                    (telegram_id, username, datetime.now(), referrer_id)
                )
            else:
                # Пользователь уже есть — обновим username, и если есть реферер и поле пустое, допишем
                cursor.execute("UPDATE users SET username = ? WHERE telegram_id = ?", (username, telegram_id))
                current_ref = row[0]
                if referrer_id and (current_ref is None or str(current_ref).strip() == "") and int(referrer_id) != int(telegram_id):
                    try:
                        cursor.execute("UPDATE users SET referred_by = ? WHERE telegram_id = ?", (int(referrer_id), telegram_id))
                    except Exception:
                        # best-effort
                        pass
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось зарегистрировать пользователя {telegram_id}: {e}")

def add_to_referral_balance(user_id: int, amount: float):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET referral_balance = referral_balance + ? WHERE telegram_id = ?", (amount, user_id))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось добавить к реферальному балансу для пользователя {user_id}: {e}")

def set_referral_balance(user_id: int, value: float):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET referral_balance = ? WHERE telegram_id = ?", (value, user_id))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось установить реферальный баланс для пользователя {user_id}: {e}")

def set_referral_balance_all(user_id: int, value: float):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET referral_balance_all = ? WHERE telegram_id = ?", (value, user_id))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось установить общий реферальный баланс для пользователя {user_id}: {e}")

def add_to_referral_balance_all(user_id: int, amount: float):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET referral_balance_all = referral_balance_all + ? WHERE telegram_id = ?",
                (amount, user_id)
            )
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось добавить к общему реферальному балансу для пользователя {user_id}: {e}")

def get_referral_balance_all(user_id: int) -> float:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT referral_balance_all FROM users WHERE telegram_id = ?", (user_id,))
            row = cursor.fetchone()
            return row[0] if row else 0.0
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить общий реферальный баланс для пользователя {user_id}: {e}")
        return 0.0

def get_referral_balance(user_id: int) -> float:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT referral_balance FROM users WHERE telegram_id = ?", (user_id,))
            result = cursor.fetchone()
            return result[0] if result else 0.0
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить реферальный баланс для пользователя {user_id}: {e}")
        return 0.0

def get_balance(user_id: int) -> float:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT balance FROM users WHERE telegram_id = ?", (user_id,))
            result = cursor.fetchone()
            return result[0] if result else 0.0
    except sqlite3.Error as e:
        logging.error(f"Не удалось get balance for user {user_id}: {e}")
        return 0.0

def adjust_user_balance(user_id: int, delta: float) -> bool:
    """Скорректировать баланс пользователя на указанную дельту (может быть отрицательной)."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET balance = COALESCE(balance, 0) + ? WHERE telegram_id = ?", (float(delta), user_id))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось adjust balance for user {user_id}: {e}")
        return False

def set_balance(user_id: int, value: float) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET balance = ? WHERE telegram_id = ?", (value, user_id))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось set balance for user {user_id}: {e}")
        return False

def add_to_balance(user_id: int, amount: float) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET balance = balance + ? WHERE telegram_id = ?", (amount, user_id))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось add to balance for user {user_id}: {e}")
        return False

def deduct_from_balance(user_id: int, amount: float) -> bool:
    """Атомарное списание с основного баланса при достаточности средств."""
    if amount <= 0:
        return True
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            cursor.execute("SELECT balance FROM users WHERE telegram_id = ?", (user_id,))
            row = cursor.fetchone()
            current = row[0] if row else 0.0
            if current < amount:
                conn.rollback()
                return False
            cursor.execute("UPDATE users SET balance = balance - ? WHERE telegram_id = ?", (amount, user_id))
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось deduct from balance for user {user_id}: {e}")
        return False

def deduct_from_referral_balance(user_id: int, amount: float) -> bool:
    """Атомарное списание с реферального баланса при достаточности средств."""
    if amount <= 0:
        return True
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            cursor.execute("SELECT referral_balance FROM users WHERE telegram_id = ?", (user_id,))
            row = cursor.fetchone()
            current = row[0] if row else 0.0
            if current < amount:
                conn.rollback()
                return False
            cursor.execute("UPDATE users SET referral_balance = referral_balance - ? WHERE telegram_id = ?", (amount, user_id))
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось deduct from referral balance for user {user_id}: {e}")
        return False

def get_referral_count(user_id: int) -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE referred_by = ?", (user_id,))
            return cursor.fetchone()[0] or 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось get referral count for user {user_id}: {e}")
        return 0

def get_user(telegram_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE telegram_id = ?", (telegram_id,))
            user_data = cursor.fetchone()
            return dict(user_data) if user_data else None
    except sqlite3.Error as e:
        logging.error(f"Не удалось get user {telegram_id}: {e}")
        return None

def get_user_device_limit(telegram_id: int, default_limit: int = 3) -> int:
    try:
        user = get_user(telegram_id)
        if not user:
            return int(default_limit)
        raw = user.get("device_limit")
        value = int(raw) if raw is not None else int(default_limit)
        return value if value > 0 else int(default_limit)
    except Exception:
        return int(default_limit)

def set_user_device_limit(telegram_id: int, limit: int) -> bool:
    try:
        value = max(1, int(limit))
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET device_limit = ? WHERE telegram_id = ?", (value, telegram_id))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось set device_limit for user {telegram_id}: {e}")
        return False

def adjust_user_device_limit(telegram_id: int, delta: int, min_limit: int = 1) -> int | None:
    try:
        current = get_user_device_limit(telegram_id)
        new_value = max(int(min_limit), int(current) + int(delta))
        ok = set_user_device_limit(telegram_id, new_value)
        return new_value if ok else None
    except Exception as e:
        logging.error(f"Не удалось adjust device_limit for user {telegram_id}: {e}")
        return None

def get_or_create_user_subscription_uuid(telegram_id: int) -> str:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT subscription_uuid FROM users WHERE telegram_id = ?", (telegram_id,))
            row = cursor.fetchone()
            existing = (row["subscription_uuid"] if row else None) if row is not None else None
            existing_str = (str(existing).strip() if existing else "")
            if existing_str:
                return existing_str

            new_uuid = str(uuid.uuid4())
            cursor.execute(
                "UPDATE users SET subscription_uuid = ? WHERE telegram_id = ?",
                (new_uuid, telegram_id),
            )
            conn.commit()
            return new_uuid
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить/создать subscription_uuid для пользователя {telegram_id}: {e}")
        return str(uuid.uuid4())

def get_or_create_user_subscription_token(telegram_id: int) -> str:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT subscription_token FROM users WHERE telegram_id = ?", (telegram_id,))
            row = cursor.fetchone()
            existing = (row["subscription_token"] if row else None) if row is not None else None
            existing_str = (str(existing).strip() if existing else "")
            if existing_str:
                return existing_str

            new_token = uuid.uuid4().hex[:24]
            cursor.execute(
                "UPDATE users SET subscription_token = ? WHERE telegram_id = ?",
                (new_token, telegram_id),
            )
            conn.commit()
            return new_token
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить/создать subscription_token для пользователя {telegram_id}: {e}")
        return uuid.uuid4().hex[:24]

def rotate_user_subscription_token(telegram_id: int) -> str:
    """Force-generate a new persistent subscription token for user."""
    new_token = uuid.uuid4().hex[:24]
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET subscription_token = ? WHERE telegram_id = ?",
                (new_token, telegram_id),
            )
            conn.commit()
        return new_token
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить subscription_token для пользователя {telegram_id}: {e}")
        return new_token

def get_user_id_by_subscription_token(subscription_token: str) -> int | None:
    token = (subscription_token or "").strip()
    if not token:
        return None
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT telegram_id FROM users WHERE subscription_token = ?", (token,))
            row = cursor.fetchone()
            if not row:
                return None
            return int(row[0])
    except sqlite3.Error as e:
        logging.error(f"Не удалось получить пользователя по subscription_token: {e}")
        return None

def update_user_subscription_state(
    telegram_id: int,
    *,
    subscription_link: str | None = None,
    subscription_status: str | None = None,
    subscription_type: str | None = None,
    subscription_expires_at: datetime | str | None = None,
) -> bool:
    try:
        updates: list[str] = []
        params: list = []
        if subscription_link is not None:
            updates.append("subscription_link = ?")
            params.append(subscription_link)
        if subscription_status is not None:
            updates.append("subscription_status = ?")
            params.append(subscription_status)
        if subscription_type is not None:
            updates.append("subscription_type = ?")
            params.append(subscription_type)
        if subscription_expires_at is not None:
            updates.append("subscription_expires_at = ?")
            if isinstance(subscription_expires_at, datetime):
                params.append(subscription_expires_at.isoformat())
            else:
                params.append(str(subscription_expires_at))
        if not updates:
            return False

        params.append(telegram_id)
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE telegram_id = ?",
                params,
            )
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось обновить состояние подписки пользователя {telegram_id}: {e}")
        return False

def set_terms_agreed(telegram_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET agreed_to_terms = 1 WHERE telegram_id = ?", (telegram_id,))
            conn.commit()
            logging.info(f"Пользователь {telegram_id} согласился с условиями.")
    except sqlite3.Error as e:
        logging.error(f"Не удалось set terms agreed for user {telegram_id}: {e}")

def update_user_stats(telegram_id: int, amount_spent: float, months_purchased: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET total_spent = total_spent + ?, total_months = total_months + ? WHERE telegram_id = ?", (amount_spent, months_purchased, telegram_id))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось update user stats for {telegram_id}: {e}")

def get_user_count() -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            return cursor.fetchone()[0] or 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось get user count: {e}")
        return 0

def get_total_keys_count() -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM vpn_keys")
            return cursor.fetchone()[0] or 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось get total keys count: {e}")
        return 0

def get_total_subscriptions_count() -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(DISTINCT user_id) FROM vpn_keys")
            return cursor.fetchone()[0] or 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось get total subscriptions count: {e}")
        return 0

def get_total_spent_sum() -> float:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            # Consider only completed/paid transactions when summing total spent
            cursor.execute(
                """
                SELECT COALESCE(SUM(amount_rub), 0.0)
                FROM transactions
                WHERE LOWER(COALESCE(status, '')) IN ('paid', 'completed', 'success')
                  AND LOWER(COALESCE(payment_method, '')) <> 'balance'
                """
            )
            val = cursor.fetchone()
            return (val[0] if val else 0.0) or 0.0
    except sqlite3.Error as e:
        logging.error(f"Не удалось get total spent sum: {e}")
        return 0.0

def create_pending_transaction(payment_id: str, user_id: int, amount_rub: float, metadata: dict) -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO transactions (payment_id, user_id, status, amount_rub, metadata) VALUES (?, ?, ?, ?, ?)",
                (payment_id, user_id, 'pending', amount_rub, json.dumps(metadata))
            )
            conn.commit()
            return cursor.lastrowid
    except sqlite3.Error as e:
        logging.error(f"Не удалось create pending transaction: {e}")
        return 0

def find_and_complete_ton_transaction(payment_id: str, amount_ton: float) -> dict | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM transactions WHERE payment_id = ? AND status = 'pending'", (payment_id,))
            transaction = cursor.fetchone()
            if not transaction:
                logger.warning(f"TON Webhook: Получен платеж для неизвестного или завершенного payment_id: {payment_id}")
                return None
            
            
            cursor.execute(
                "UPDATE transactions SET status = 'paid', amount_currency = ?, currency_name = 'TON', payment_method = 'TON' WHERE payment_id = ?",
                (amount_ton, payment_id)
            )
            conn.commit()
            
            return json.loads(transaction['metadata'])
    except sqlite3.Error as e:
        logging.error(f"Не удалось complete TON transaction {payment_id}: {e}")
        return None

def log_transaction(username: str, transaction_id: str | None, payment_id: str | None, user_id: int, status: str, amount_rub: float, amount_currency: float | None, currency_name: str | None, payment_method: str, metadata: str):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO transactions
                   (username, transaction_id, payment_id, user_id, status, amount_rub, amount_currency, currency_name, payment_method, metadata, created_date)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (username, transaction_id, payment_id, user_id, status, amount_rub, amount_currency, currency_name, payment_method, metadata, datetime.now())
            )
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось log transaction for user {user_id}: {e}")

def get_paginated_transactions(page: int = 1, per_page: int = 15) -> tuple[list[dict], int]:
    offset = (page - 1) * per_page
    transactions = []
    total = 0
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM transactions")
            total = cursor.fetchone()[0]

            query = "SELECT * FROM transactions ORDER BY created_date DESC LIMIT ? OFFSET ?"
            cursor.execute(query, (per_page, offset))
            
            for row in cursor.fetchall():
                transaction_dict = dict(row)
                
                metadata_str = transaction_dict.get('metadata')
                if metadata_str:
                    try:
                        metadata = json.loads(metadata_str)
                        transaction_dict['host_name'] = metadata.get('host_name', 'N/A')
                        transaction_dict['plan_name'] = metadata.get('plan_name', 'N/A')
                    except json.JSONDecodeОшибка:
                        transaction_dict['host_name'] = 'Ошибка'
                        transaction_dict['plan_name'] = 'Ошибка'
                else:
                    transaction_dict['host_name'] = 'N/A'
                    transaction_dict['plan_name'] = 'N/A'
                
                transactions.append(transaction_dict)
            
    except sqlite3.Error as e:
        logging.error(f"Не удалось get paginated transactions: {e}")
    
    return transactions, total

def set_trial_used(telegram_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET trial_used = 1 WHERE telegram_id = ?", (telegram_id,))
            conn.commit()
            logging.info(f"Пробный период отмечен как использованный для пользователя {telegram_id}.")
    except sqlite3.Error as e:
        logging.error(f"Не удалось отметить пробный период как использованный для пользователя {telegram_id}: {e}")

def add_new_key(user_id: int, host_name: str, xui_client_uuid: str, key_email: str, expiry_timestamp_ms: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            expiry_date = datetime.fromtimestamp(expiry_timestamp_ms / 1000)
            cursor.execute(
                "INSERT INTO vpn_keys (user_id, host_name, xui_client_uuid, key_email, expiry_date) VALUES (?, ?, ?, ?, ?)",
                (user_id, host_name, xui_client_uuid, key_email, expiry_date)
            )
            new_key_id = cursor.lastrowid
            conn.commit()
            return new_key_id
    except sqlite3.Error as e:
        logging.error(f"Не удалось add new key for user {user_id}: {e}")
        return None

def delete_key_by_email(email: str) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vpn_keys WHERE key_email = ?", (email,))
            affected = cursor.rowcount
            conn.commit()
            logger.debug(f"delete_key_by_email('{email}') затронуто={affected}")
            return affected > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось delete key '{email}': {e}")
        return False

def get_user_keys(user_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT k.*
                FROM vpn_keys k
                LEFT JOIN xui_hosts h ON TRIM(h.host_name) = TRIM(k.host_name)
                WHERE k.user_id = ? AND COALESCE(h.is_expired_host, 0) = 0
                ORDER BY k.key_id
                """,
                (user_id,)
            )
            keys = cursor.fetchall()
            return [dict(key) for key in keys]
    except sqlite3.Error as e:
        logging.error(f"Не удалось get keys for user {user_id}: {e}")
        return []

def get_key_by_id(key_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vpn_keys WHERE key_id = ?", (key_id,))
            key_data = cursor.fetchone()
            return dict(key_data) if key_data else None
    except sqlite3.Error as e:
        logging.error(f"Не удалось get key by ID {key_id}: {e}")
        return None

def get_key_by_email(key_email: str):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vpn_keys WHERE key_email = ?", (key_email,))
            key_data = cursor.fetchone()
            return dict(key_data) if key_data else None
    except sqlite3.Error as e:
        logging.error(f"Не удалось get key by email {key_email}: {e}")
        return None

def update_key_info(key_id: int, new_xui_uuid: str, new_expiry_ms: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            expiry_date = datetime.fromtimestamp(new_expiry_ms / 1000)
            cursor.execute("UPDATE vpn_keys SET xui_client_uuid = ?, expiry_date = ? WHERE key_id = ?", (new_xui_uuid, expiry_date, key_id))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось update key {key_id}: {e}")
 
def update_key_host_and_info(key_id: int, new_host_name: str, new_xui_uuid: str, new_expiry_ms: int):
    """Update key's host, UUID and expiry in a single transaction."""
    try:
        new_host_name = normalize_host_name(new_host_name)
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            expiry_date = datetime.fromtimestamp(new_expiry_ms / 1000)
            cursor.execute(
                "UPDATE vpn_keys SET host_name = ?, xui_client_uuid = ?, expiry_date = ? WHERE key_id = ?",
                (new_host_name, new_xui_uuid, expiry_date, key_id)
            )
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось update key {key_id} host and info: {e}")

def get_next_key_number(user_id: int) -> int:
    keys = get_user_keys(user_id)
    return len(keys) + 1

def get_keys_for_host(host_name: str) -> list[dict]:
    try:
        host_name = normalize_host_name(host_name)
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vpn_keys WHERE TRIM(host_name) = TRIM(?)", (host_name,))
            keys = cursor.fetchall()
            return [dict(key) for key in keys]
    except sqlite3.Error as e:
        logging.error(f"Не удалось get keys for host '{host_name}': {e}")
        return []

def get_all_vpn_users():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT user_id FROM vpn_keys")
            users = cursor.fetchall()
            return [dict(user) for user in users]
    except sqlite3.Error as e:
        logging.error(f"Не удалось get all vpn users: {e}")
        return []

def update_key_status_from_server(key_email: str, xui_client_data):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            if xui_client_data:
                expiry_date = datetime.fromtimestamp(xui_client_data.expiry_time / 1000)
                cursor.execute("UPDATE vpn_keys SET xui_client_uuid = ?, expiry_date = ? WHERE key_email = ?", (xui_client_data.id, expiry_date, key_email))
            else:
                cursor.execute("DELETE FROM vpn_keys WHERE key_email = ?", (key_email,))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось update key status for {key_email}: {e}")

def get_daily_stats_for_charts(days: int = 30) -> dict:
    stats = {'users': {}, 'keys': {}}
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            query_users = """
                SELECT date(registration_date) as day, COUNT(*)
                FROM users
                WHERE registration_date >= date('now', ?)
                GROUP BY day
                ORDER BY day;
            """
            cursor.execute(query_users, (f'-{days} days',))
            for row in cursor.fetchall():
                stats['users'][row[0]] = row[1]
            
            query_keys = """
                SELECT date(created_date) as day, COUNT(DISTINCT user_id)
                FROM vpn_keys
                WHERE created_date >= date('now', ?)
                GROUP BY day
                ORDER BY day;
            """
            cursor.execute(query_keys, (f'-{days} days',))
            for row in cursor.fetchall():
                stats['keys'][row[0]] = row[1]
    except sqlite3.Error as e:
        logging.error(f"Не удалось get daily stats for charts: {e}")
    return stats


def get_recent_transactions(limit: int = 15) -> list[dict]:
    transactions = []
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            query = """
                SELECT
                    k.key_id,
                    k.host_name,
                    k.created_date,
                    u.telegram_id,
                    u.username
                FROM vpn_keys k
                JOIN users u ON k.user_id = u.telegram_id
                ORDER BY k.created_date DESC
                LIMIT ?;
            """
            cursor.execute(query, (limit,))
    except sqlite3.Error as e:
        logging.error(f"Не удалось get recent transactions: {e}")
    return transactions


def get_all_users() -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users ORDER BY registration_date DESC")
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Не удалось get all users: {e}")
        return []

def get_users_paginated(page: int = 1, per_page: int = 20, q: str | None = None) -> tuple[list[dict], int]:
    """Возвращает страницу пользователей и общее количество под фильтр.
    Фильтрация: по вхождению в telegram_id (как текст) или username (регистр не важен).
    Сортировка: по дате регистрации (новые сверху).
    """
    try:
        page = max(1, int(page or 1))
        per_page = max(1, min(100, int(per_page or 20)))
    except Exception:
        page, per_page = 1, 20
    offset = (page - 1) * per_page

    users: list[dict] = []
    total = 0
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if q:
                q = (q or '').strip()
                like = f"%{q}%"
                # total
                cursor.execute(
                    """
                    SELECT COUNT(*)
                    FROM users
                    WHERE CAST(telegram_id AS TEXT) LIKE ? OR username LIKE ? COLLATE NOCASE
                    """,
                    (like, like)
                )
                total = cursor.fetchone()[0] or 0
                # page
                cursor.execute(
                    """
                    SELECT * FROM users
                    WHERE CAST(telegram_id AS TEXT) LIKE ? OR username LIKE ? COLLATE NOCASE
                    ORDER BY datetime(registration_date) DESC
                    LIMIT ? OFFSET ?
                    """,
                    (like, like, per_page, offset)
                )
            else:
                cursor.execute("SELECT COUNT(*) FROM users")
                total = cursor.fetchone()[0] or 0
                cursor.execute(
                    """
                    SELECT * FROM users
                    ORDER BY datetime(registration_date) DESC
                    LIMIT ? OFFSET ?
                    """,
                    (per_page, offset)
                )
            users = [dict(r) for r in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Не удалось get paginated users: {e}")
        return [], 0
    return users, total

def ban_user(telegram_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET is_banned = 1 WHERE telegram_id = ?", (telegram_id,))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось ban user {telegram_id}: {e}")

def unban_user(telegram_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET is_banned = 0 WHERE telegram_id = ?", (telegram_id,))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось unban user {telegram_id}: {e}")

def delete_user_keys(user_id: int):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vpn_keys WHERE user_id = ?", (user_id,))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Не удалось delete keys for user {user_id}: {e}")

def reset_user_state(user_id: int) -> bool:
    """Reset user state to first-start defaults and remove all local keys."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vpn_keys WHERE user_id = ?", (user_id,))
            cursor.execute(
                """
                UPDATE users
                SET total_spent = 0,
                    total_months = 0,
                    trial_used = 0,
                    agreed_to_terms = 0,
                    is_banned = 0,
                    device_limit = 3,
                    balance = 0,
                    referred_by = NULL,
                    referral_balance = 0,
                    referral_balance_all = 0,
                    referral_start_bonus_received = 0,
                    subscription_uuid = NULL,
                    subscription_token = NULL,
                    subscription_link = NULL,
                    subscription_status = NULL,
                    subscription_type = NULL,
                    subscription_expires_at = NULL
                WHERE telegram_id = ?
                """,
                (user_id,)
            )
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось reset user state for {user_id}: {e}")
        return False

def create_support_ticket(user_id: int, subject: str | None = None) -> int | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO support_tickets (user_id, subject) VALUES (?, ?)",
                (user_id, subject)
            )
            conn.commit()
            return cursor.lastrowid
    except sqlite3.Error as e:
        logging.error(f"Не удалось create support ticket for user {user_id}: {e}")
        return None

def add_support_message(ticket_id: int, sender: str, content: str) -> int | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO support_messages (ticket_id, sender, content) VALUES (?, ?, ?)",
                (ticket_id, sender, content)
            )
            cursor.execute(
                "UPDATE support_tickets SET updated_at = CURRENT_TIMESTAMP WHERE ticket_id = ?",
                (ticket_id,)
            )
            conn.commit()
            return cursor.lastrowid
    except sqlite3.Error as e:
        logging.error(f"Не удалось add support message to ticket {ticket_id}: {e}")
        return None

def update_ticket_thread_info(ticket_id: int, forum_chat_id: str | None, message_thread_id: int | None) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE support_tickets SET forum_chat_id = ?, message_thread_id = ?, updated_at = CURRENT_TIMESTAMP WHERE ticket_id = ?",
                (forum_chat_id, message_thread_id, ticket_id)
            )
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось update thread info for ticket {ticket_id}: {e}")
        return False

def get_ticket(ticket_id: int) -> dict | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM support_tickets WHERE ticket_id = ?", (ticket_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logging.error(f"Не удалось get ticket {ticket_id}: {e}")
        return None

def get_ticket_by_thread(forum_chat_id: str, message_thread_id: int) -> dict | None:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM support_tickets WHERE forum_chat_id = ? AND message_thread_id = ?",
                (str(forum_chat_id), int(message_thread_id))
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logging.error(f"Не удалось get ticket by thread {forum_chat_id}/{message_thread_id}: {e}")
        return None

def get_user_tickets(user_id: int, status: str | None = None) -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if status:
                cursor.execute(
                    "SELECT * FROM support_tickets WHERE user_id = ? AND status = ? ORDER BY updated_at DESC",
                    (user_id, status)
                )
            else:
                cursor.execute(
                    "SELECT * FROM support_tickets WHERE user_id = ? ORDER BY updated_at DESC",
                    (user_id,)
                )
            return [dict(r) for r in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Не удалось get tickets for user {user_id}: {e}")
        return []

def get_ticket_messages(ticket_id: int) -> list[dict]:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM support_messages WHERE ticket_id = ? ORDER BY created_at ASC",
                (ticket_id,)
            )
            return [dict(r) for r in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Не удалось get messages for ticket {ticket_id}: {e}")
        return []

def set_ticket_status(ticket_id: int, status: str) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE support_tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE ticket_id = ?",
                (status, ticket_id)
            )
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось set status '{status}' for ticket {ticket_id}: {e}")
        return False

def update_ticket_subject(ticket_id: int, subject: str) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE support_tickets SET subject = ?, updated_at = CURRENT_TIMESTAMP WHERE ticket_id = ?",
                (subject, ticket_id)
            )
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось update subject for ticket {ticket_id}: {e}")
        return False

def delete_ticket(ticket_id: int) -> bool:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM support_messages WHERE ticket_id = ?",
                (ticket_id,)
            )
            cursor.execute(
                "DELETE FROM support_tickets WHERE ticket_id = ?",
                (ticket_id,)
            )
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось delete ticket {ticket_id}: {e}")
        return False

def get_tickets_paginated(page: int = 1, per_page: int = 20, status: str | None = None) -> tuple[list[dict], int]:
    offset = (page - 1) * per_page
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if status:
                cursor.execute("SELECT COUNT(*) FROM support_tickets WHERE status = ?", (status,))
                total = cursor.fetchone()[0] or 0
                cursor.execute(
                    "SELECT * FROM support_tickets WHERE status = ? ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                    (status, per_page, offset)
                )
            else:
                cursor.execute("SELECT COUNT(*) FROM support_tickets")
                total = cursor.fetchone()[0] or 0
                cursor.execute(
                    "SELECT * FROM support_tickets ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                    (per_page, offset)
                )
            return [dict(r) for r in cursor.fetchall()], total
    except sqlite3.Error as e:
        logging.error("Не удалось get paginated support tickets: %s", e)
        return [], 0

def get_open_tickets_count() -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM support_tickets WHERE status = 'open'")
            return cursor.fetchone()[0] or 0
    except sqlite3.Error as e:
        logging.error("Не удалось get open tickets count: %s", e)
        return 0

def get_closed_tickets_count() -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM support_tickets WHERE status = 'closed'")
            return cursor.fetchone()[0] or 0
    except sqlite3.Error as e:
        logging.error("Не удалось get closed tickets count: %s", e)
        return 0

def get_all_tickets_count() -> int:
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM support_tickets")
            return cursor.fetchone()[0] or 0
    except sqlite3.Error as e:
        logging.error("Не удалось get all tickets count: %s", e)
        return 0
# --- Host metrics helpers ---
def insert_host_metrics(host_name: str, metrics: dict) -> bool:
    """Insert a resource metrics row for host_name using dict from resource_monitor.get_host_metrics_via_ssh."""
    try:
        host_name_n = normalize_host_name(host_name)
        m = metrics or {}
        load = m.get('loadavg') or {}
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO host_metrics (
                    host_name, cpu_percent, mem_percent, mem_used, mem_total,
                    disk_percent, disk_used, disk_total, load1, load5, load15,
                    uptime_seconds, ok, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    host_name_n,
                    float(m.get('cpu_percent')) if m.get('cpu_percent') is not None else None,
                    float(m.get('mem_percent')) if m.get('mem_percent') is not None else None,
                    int(m.get('mem_used')) if m.get('mem_used') is not None else None,
                    int(m.get('mem_total')) if m.get('mem_total') is not None else None,
                    float(m.get('disk_percent')) if m.get('disk_percent') is not None else None,
                    int(m.get('disk_used')) if m.get('disk_used') is not None else None,
                    int(m.get('disk_total')) if m.get('disk_total') is not None else None,
                    float(load.get('1m')) if load.get('1m') is not None else None,
                    float(load.get('5m')) if load.get('5m') is not None else None,
                    float(load.get('15m')) if load.get('15m') is not None else None,
                    float(m.get('uptime_seconds')) if m.get('uptime_seconds') is not None else None,
                    1 if (m.get('ok') in (True, 1, '1')) else 0,
                    str(m.get('error')) if m.get('error') else None,
                )
            )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"insert_host_metrics failed for '{host_name}': {e}")
        return False


def get_host_metrics_recent(host_name: str, limit: int = 60) -> list[dict]:
    try:
        host_name_n = normalize_host_name(host_name)
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT host_name, cpu_percent, mem_percent, mem_used, mem_total,
                       disk_percent, disk_used, disk_total,
                       load1, load5, load15, uptime_seconds, ok, error, created_at
                FROM host_metrics
                WHERE TRIM(host_name) = TRIM(?)
                ORDER BY datetime(created_at) DESC
                LIMIT ?
                ''', (host_name_n, int(limit))
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
    except sqlite3.Error as e:
        logging.error(f"get_host_metrics_recent failed for '{host_name}': {e}")
        return []


def get_latest_host_metrics(host_name: str) -> dict | None:
    try:
        host_name_n = normalize_host_name(host_name)
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT * FROM host_metrics
                WHERE TRIM(host_name) = TRIM(?)
                ORDER BY datetime(created_at) DESC
                LIMIT 1
                ''', (host_name_n,)
            )
            r = cursor.fetchone()
            return dict(r) if r else None
    except sqlite3.Error as e:
        logging.error(f"get_latest_host_metrics failed for '{host_name}': {e}")
        return None

# --- Button Configs Functions ---
def get_button_configs(menu_type: str = None) -> list[dict]:
    """Get all button configurations, optionally filtered by menu_type."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if menu_type:
                cursor.execute(
                    "SELECT * FROM button_configs WHERE menu_type = ? ORDER BY sort_order, id",
                    (menu_type,)
                )
            else:
                cursor.execute(
                    "SELECT * FROM button_configs ORDER BY menu_type, sort_order, id"
                )
            
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Не удалось get button configs: {e}")
        return []

def get_button_config(button_id: int) -> dict | None:
    """Get a specific button configuration by ID."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM button_configs WHERE id = ?", (button_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logging.error(f"Не удалось get button config {button_id}: {e}")
        return None

def create_button_config(config: dict) -> int | None:
    """Create a new button configuration. Returns the new ID or None on error."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO button_configs (
                    menu_type, button_id, text, callback_data, url,
                    row_position, column_position, button_width, sort_order, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    config.get('menu_type', 'main_menu'),
                    config.get('button_id', ''),
                    config.get('text', ''),
                    config.get('callback_data'),
                    config.get('url'),
                    config.get('row_position', 0),
                    config.get('column_position', 0),
                    config.get('button_width', 1),
                    config.get('sort_order', 0),
                    config.get('is_active', True)
                )
            )
            return cursor.lastrowid
    except sqlite3.Error as e:
        logging.error(f"Не удалось create button config: {e}")
        return None

def update_button_config(button_id: int, config: dict) -> bool:
    """Update an existing button configuration."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                UPDATE button_configs SET
                    text = ?, callback_data = ?, url = ?,
                    row_position = ?, column_position = ?, button_width = ?,
                    sort_order = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                ''',
                (
                    config.get('text', ''),
                    config.get('callback_data'),
                    config.get('url'),
                    config.get('row_position', 0),
                    config.get('column_position', 0),
                    config.get('button_width', 1),
                    config.get('sort_order', 0),
                    config.get('is_active', True),
                    button_id
                )
            )
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось update button config {button_id}: {e}")
        return False

def delete_button_config(button_id: int) -> bool:
    """Delete a button configuration."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM button_configs WHERE id = ?", (button_id,))
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logging.error(f"Не удалось delete button config {button_id}: {e}")
        return False

def reorder_button_configs(menu_type: str, button_orders: list[dict]) -> bool:
    """Reorder and reposition button configurations for a specific menu type.
    Accepts items with either 'id' or 'button_id'. Updates sort_order, row_position,
    column_position, and button_width.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            for order_data in button_orders:
                sort_order = int(order_data.get('sort_order', 0) or 0)
                row_pos = int(order_data.get('row_position', 0) or 0)
                col_pos = int(order_data.get('column_position', 0) or 0)
                btn_width = int(order_data.get('button_width', 1) or 1)

                # Try resolve target id
                btn_id = order_data.get('id')
                if not btn_id:
                    btn_key = order_data.get('button_id')
                    if not btn_key:
                        continue
                    cursor.execute(
                        "SELECT id FROM button_configs WHERE menu_type = ? AND button_id = ?",
                        (menu_type, btn_key)
                    )
                    row = cursor.fetchone()
                    if not row:
                        continue
                    btn_id = row[0]

                cursor.execute(
                    """
                    UPDATE button_configs
                    SET sort_order = ?, row_position = ?, column_position = ?, button_width = ?
                    WHERE id = ? AND menu_type = ?
                    """,
                    (sort_order, row_pos, col_pos, btn_width, btn_id, menu_type)
                )
            conn.commit()
            return True
    except sqlite3.Error as e:
        logging.error(f"Не удалось reorder button configs for {menu_type}: {e}")
        return False

def migrate_existing_buttons() -> bool:
    """Migrate existing button configurations from settings to button_configs table."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Define button configurations for all menu types
            menu_configs = {
                'main_menu': [
                    # Row 0: Wide buttons (full width)
                    {'button_id': 'btn_try', 'callback_data': 'get_trial', 'text': '🎁 Попробовать бесплатно', 'row_position': 0, 'column_position': 0, 'button_width': 2},
                    {'button_id': 'btn_profile', 'callback_data': 'show_profile', 'text': '👤 Мой профиль', 'row_position': 1, 'column_position': 0, 'button_width': 2},
                    
                    # Row 2: Two buttons
                    {'button_id': 'btn_my_keys', 'callback_data': 'manage_keys', 'text': '🔑 Моя подписка ({count})', 'row_position': 2, 'column_position': 0, 'button_width': 1},
                    {'button_id': 'btn_buy_key', 'callback_data': 'buy_new_key', 'text': '💳 Купить подписку', 'row_position': 2, 'column_position': 1, 'button_width': 1},
                    
                    # Row 3: Two buttons
                    {'button_id': 'btn_top_up', 'callback_data': 'top_up_start', 'text': '➕ Пополнить баланс', 'row_position': 3, 'column_position': 0, 'button_width': 1},
                    {'button_id': 'btn_referral', 'callback_data': 'show_referral_program', 'text': '🤝 Реферальная программа', 'row_position': 3, 'column_position': 1, 'button_width': 1},
                    
                    # Row 4: Two buttons
                    {'button_id': 'btn_support', 'callback_data': 'show_help', 'text': '🆘 Поддержка', 'row_position': 4, 'column_position': 0, 'button_width': 1},
                    {'button_id': 'btn_about', 'callback_data': 'show_about', 'text': 'ℹ️ О проекте', 'row_position': 4, 'column_position': 1, 'button_width': 1},
                    
                    # Row 5: Two buttons
                    {'button_id': 'btn_howto', 'callback_data': 'howto_vless', 'text': '❓ Как использовать', 'row_position': 5, 'column_position': 0, 'button_width': 1},
                    {'button_id': 'btn_speed', 'callback_data': 'user_speedtest', 'text': '⚡ Тест скорости', 'row_position': 5, 'column_position': 1, 'button_width': 1},
                    
                    # Row 6: Wide button
                    {'button_id': 'btn_admin', 'callback_data': 'admin_menu', 'text': '⚙️ Админка', 'row_position': 6, 'column_position': 0, 'button_width': 2},
                ],
                'admin_menu': [
                    # Row 1: Two buttons
                    {'button_id': 'admin_users', 'callback_data': 'admin_users', 'text': '👥 Пользователи', 'row_position': 0, 'column_position': 0, 'button_width': 1},
                    {'button_id': 'admin_keys', 'callback_data': 'admin_host_keys', 'text': '🔑 Ключи', 'row_position': 0, 'column_position': 1, 'button_width': 1},
                    
                    # Row 2: Two buttons
                    {'button_id': 'admin_issue_key', 'callback_data': 'admin_gift_key', 'text': '🎁 Выдать ключ', 'row_position': 1, 'column_position': 0, 'button_width': 1},
                    {'button_id': 'admin_speed_test', 'callback_data': 'admin_speed_test', 'text': '⚡ Тест скорости', 'row_position': 1, 'column_position': 1, 'button_width': 1},
                    
                    # Row 3: Two buttons
                    {'button_id': 'admin_monitoring', 'callback_data': 'admin_monitoring', 'text': '📊 Мониторинг', 'row_position': 2, 'column_position': 0, 'button_width': 1},
                    {'button_id': 'admin_db_backup', 'callback_data': 'admin_backup_db', 'text': '💾 Бэкап БД', 'row_position': 2, 'column_position': 1, 'button_width': 1},
                    
                    # Row 4: Two buttons
                    {'button_id': 'admin_restore_db', 'callback_data': 'admin_restore_db', 'text': '🔄 Восстановить БД', 'row_position': 3, 'column_position': 0, 'button_width': 1},
                    {'button_id': 'admin_administrators', 'callback_data': 'admin_administrators', 'text': '👮 Администраторы', 'row_position': 3, 'column_position': 1, 'button_width': 1},
                    
                    # Row 5: Wide button
                    {'button_id': 'admin_promo_codes', 'callback_data': 'admin_promo_codes', 'text': '🏷️ Промокоды', 'row_position': 4, 'column_position': 0, 'button_width': 2},
                    
                    # Row 6: Wide button
                    {'button_id': 'admin_mailing', 'callback_data': 'admin_mailing', 'text': '📢 Рассылка', 'row_position': 5, 'column_position': 0, 'button_width': 2},
                    
                    # Row 7: Wide button
                    {'button_id': 'back_to_main', 'callback_data': 'main_menu', 'text': '⬅️ Назад в меню', 'row_position': 6, 'column_position': 0, 'button_width': 2},
                ],
                'profile_menu': [
                    {'button_id': 'profile_info', 'callback_data': 'profile_info', 'text': 'ℹ️ Информация', 'row_position': 0, 'column_position': 0, 'button_width': 1},
                    {'button_id': 'profile_balance', 'callback_data': 'profile_balance', 'text': '💰 Баланс', 'row_position': 0, 'column_position': 1, 'button_width': 1},
                    {'button_id': 'profile_keys', 'callback_data': 'manage_keys', 'text': '🔑 Моя подписка', 'row_position': 1, 'column_position': 0, 'button_width': 1},
                    {'button_id': 'profile_referrals', 'callback_data': 'show_referral_program', 'text': '🤝 Рефералы', 'row_position': 1, 'column_position': 1, 'button_width': 1},
                    {'button_id': 'back_to_main', 'callback_data': 'main_menu', 'text': '🏠 Главное меню', 'row_position': 2, 'column_position': 0, 'button_width': 2},
                ],
                'support_menu': [
                    {'button_id': 'support_new', 'callback_data': 'support_new_ticket', 'text': '📝 Новое обращение', 'row_position': 0, 'column_position': 0, 'button_width': 1},
                    {'button_id': 'support_my', 'callback_data': 'support_my_tickets', 'text': '📋 Мои обращения', 'row_position': 0, 'column_position': 1, 'button_width': 1},
                ]
            }
            
            # Only reset if this is a fresh migration (no existing configs)
            cursor.execute("SELECT COUNT(*) FROM button_configs")
            existing_count = cursor.fetchone()[0]
            
            if existing_count > 0:
                logging.info(f"Найдено {existing_count} existing button configs, skipping migration to preserve user settings")
                return True
            
            logging.info("Существующие конфигурации кнопок не найдены, создаю конфигурации по умолчанию")
            
            # Migrate buttons for each menu type
            for menu_type, button_settings in menu_configs.items():
                sort_order = 0
                for button_data in button_settings:
                    # Get the text from settings or use default
                    text = get_setting(button_data['button_id']) or button_data['text']
                    
                    cursor.execute(
                        '''
                        INSERT INTO button_configs (
                            menu_type, button_id, text, callback_data, row_position, column_position, button_width, sort_order, is_active
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''',
                        (menu_type, button_data['button_id'], text, button_data['callback_data'], 
                         button_data['row_position'], button_data['column_position'], button_data['button_width'], sort_order, True)
                    )
                    sort_order += 1
                
                logging.info(f"Успешно migrated {len(button_settings)} buttons for {menu_type}")
            
            # Clean up any duplicates that might have been created
            cursor.execute("""
                DELETE FROM button_configs 
                WHERE id NOT IN (
                    SELECT MIN(id) 
                    FROM button_configs 
                    GROUP BY menu_type, button_id
                )
            """)
            
            return True
            
    except sqlite3.Error as e:
        logging.error(f"Не удалось migrate existing buttons: {e}")
        return False

def cleanup_duplicate_buttons() -> bool:
    """Remove duplicate button configurations."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Remove duplicates, keeping the first occurrence
            cursor.execute("""
                DELETE FROM button_configs 
                WHERE id NOT IN (
                    SELECT MIN(id) 
                    FROM button_configs 
                    WHERE menu_type = 'main_menu'
                    GROUP BY button_id
                )
            """)
            
            deleted_count = cursor.rowcount
            if deleted_count > 0:
                logging.info(f"Удалено {deleted_count} дублирующихся конфигураций кнопок")
            
            return True
            
    except sqlite3.Error as e:
        logging.error(f"Не удалось очистить дублирующиеся кнопки: {e}")
        return False

def reset_button_migration() -> bool:
    """Reset button migration to re-run with correct layout."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Only delete if explicitly requested (for force migration)
            cursor.execute("SELECT COUNT(*) FROM button_configs")
            existing_count = cursor.fetchone()[0]
            
            if existing_count > 0:
                logging.warning(f"Найдено {existing_count} существующих конфигураций кнопок. Используйте force_button_migration() для их сброса.")
                return False
            
            logging.info("Существующие конфигурации кнопок не найдены, готов к миграции")
            return True
            
    except sqlite3.Error as e:
        logging.error(f"Не удалось сбросить миграцию кнопок: {e}")
        return False

def force_button_migration() -> bool:
    """Force button migration by resetting and re-migrating."""
    try:
        logging.info("Начинаю принудительную миграцию кнопок...")
        
        # Force delete all existing button configs
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM button_configs")
            deleted_count = cursor.rowcount
            logging.info(f"Принудительно удалено {deleted_count} существующих конфигураций кнопок")
            conn.commit()
        
        # Now migrate with fresh data
        migrate_existing_buttons()
        logging.info("Принудительная миграция кнопок успешно завершена")
        return True
    except Exception as e:
        logging.error(f"Ошибка при принудительной миграции кнопок: {e}")
        return False


# Resource metrics functions
def insert_resource_metric(
    scope: str,
    object_name: str,
    *,
    cpu_percent: float | None = None,
    mem_percent: float | None = None,
    disk_percent: float | None = None,
    load1: float | None = None,
    net_bytes_sent: int | None = None,
    net_bytes_recv: int | None = None,
    raw_json: str | None = None,
) -> int | None:
    """Insert a resource metric record."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO resource_metrics (
                    scope, object_name, cpu_percent, mem_percent, disk_percent, load1,
                    net_bytes_sent, net_bytes_recv, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    (scope or '').strip(),
                    (object_name or '').strip(),
                    cpu_percent, mem_percent, disk_percent, load1,
                    net_bytes_sent, net_bytes_recv, raw_json,
                )
            )
            conn.commit()
            return cursor.lastrowid
    except sqlite3.Error as e:
        logging.error("Не удалось insert resource metric for %s/%s: %s", scope, object_name, e)
        return None


def get_latest_resource_metric(scope: str, object_name: str) -> dict | None:
    """Get the latest resource metric for a scope/object."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT * FROM resource_metrics
                WHERE scope = ? AND object_name = ?
                ORDER BY created_at DESC
                LIMIT 1
                ''',
                ((scope or '').strip(), (object_name or '').strip())
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logging.error("Не удалось get latest resource metric for %s/%s: %s", scope, object_name, e)
        return None


def get_metrics_series(scope: str, object_name: str, *, since_hours: int = 24, limit: int = 500) -> list[dict]:
    """Get a series of resource metrics for a scope/object."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Ensure we have at least some data for the requested period
            if since_hours == 1:
                hours_filter = 2
            else:
                hours_filter = max(1, int(since_hours))
            
            cursor.execute(
                f'''
                SELECT created_at, cpu_percent, mem_percent, disk_percent, load1
                FROM resource_metrics
                WHERE scope = ? AND object_name = ?
                  AND created_at >= datetime('now', ?)
                ORDER BY created_at ASC
                LIMIT ?
                ''',
                (
                    (scope or '').strip(),
                    (object_name or '').strip(),
                    f'-{hours_filter} hours',
                    max(10, int(limit)),
                )
            )
            rows = cursor.fetchall() or []
            
            # Debug logging
            logging.debug(f"get_metrics_series: {scope}/{object_name}, since_hours={since_hours}, found {len(rows)} records")
            
            return [dict(r) for r in rows]
    except sqlite3.Error as e:
        logging.error("Не удалось get metrics series for %s/%s: %s", scope, object_name, e)
        return []
