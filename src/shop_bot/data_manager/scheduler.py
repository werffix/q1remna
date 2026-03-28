import asyncio
import logging
import json
import hashlib
import re

from datetime import datetime, timedelta

from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram import Bot

from shop_bot.bot_controller import BotController
from shop_bot.data_manager import database
from shop_bot.data_manager import backup_manager
from shop_bot.data_manager import resource_monitor

from shop_bot.modules import xui_api
from shop_bot.bot import keyboards

SCHEDULER_TICK_SECONDS = 20
EXPIRY_CHECK_INTERVAL_SECONDS = 300
PANEL_SYNC_INTERVAL_SECONDS = 320
MONTHLY_RESET_CHECK_INTERVAL_SECONDS = 340
METRICS_CHECK_INTERVAL_SECONDS = 360
BACKUP_CHECK_INTERVAL_SECONDS = 380
NOTIFY_BEFORE_HOURS = {48}
notified_users = {}
notified_user_marks: dict[int, set[int]] = {}
expired_notified_users: set[int] = set()

logger = logging.getLogger(__name__)

_last_backup_run_at: datetime | None = None
_last_expiry_check_run_at: datetime | None = None
_last_panel_sync_run_at: datetime | None = None
_last_monthly_reset_check_run_at: datetime | None = None

_last_metrics_run_at: datetime | None = None

# Monthly traffic reset marker key in bot_settings
MONTHLY_TRAFFIC_RESET_KEY = "last_monthly_traffic_reset_ym"

def format_time_left(hours: int) -> str:
    if hours >= 24:
        days = hours // 24
        if days % 10 == 1 and days % 100 != 11:
            return f"{days} день"
        elif 2 <= days % 10 <= 4 and (days % 100 < 10 or days % 100 >= 20):
            return f"{days} дня"
        else:
            return f"{days} дней"
    else:
        if hours % 10 == 1 and hours % 100 != 11:
            return f"{hours} час"
        elif 2 <= hours % 10 <= 4 and (hours % 100 < 10 or hours % 100 >= 20):
            return f"{hours} часа"
        else:
            return f"{hours} часов"

def _subscription_email_for_user_host(user_id: int, host_name: str) -> str:
    host_part = re.sub(r"[^a-z0-9]+", "", (host_name or "").lower())[:8] or "host"
    digest = hashlib.sha1(f"{user_id}:{host_name}".encode("utf-8")).hexdigest()[:10]
    return f"u{user_id}.{host_part}.{digest}@bot.local"

async def send_subscription_notification(bot: Bot, user_id: int, key_id: int, time_left_hours: int, expiry_date: datetime):
    try:
        bot_username = (database.get_setting("telegram_bot_username") or "").strip()
        if not bot_username:
            try:
                bot_username = (await bot.get_me()).username or ""
            except Exception:
                bot_username = ""
        referral_link = f"https://t.me/{bot_username}?start=ref_{user_id}" if bot_username else "https://t.me/"
        message = (
            "📢 Срок действия вашей подписки на q1 vpn истекает через 2 дня!\n"
            "Пожалуйста, продлите подписку заранее, чтобы сохранить доступ к сервису без перерывов.\n\n"
            "Вы также можете пригласить друзей в бота и получить 7 дней бесплатной подписки "
            "за каждого приглашённого по вашей ссылке:\n\n"
            f"{referral_link}"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="🔄 Продлить подписку", callback_data="buy_traffic_start")
        builder.button(text="🤝 Реферальная программа", callback_data="show_referral_program")
        builder.adjust(1)
        
        await bot.send_message(chat_id=user_id, text=message, reply_markup=builder.as_markup())
        logger.debug(f"Scheduler: Отправлено уведомление пользователю {user_id} по ключу {key_id} (осталось {time_left_hours} ч).")
        
    except Exception as e:
        logger.error(f"Scheduler: Ошибка отправки уведомления пользователю {user_id}: {e}")

async def send_subscription_expired_notification(bot: Bot, user_id: int):
    try:
        message = (
            "❗ Срок действия подписки истек\n\n"
            "Срок действия вашей VPN-подписки завершён.\n"
            "Доступ к сервису приостановлен до момента продления.\n\n"
            "Пожалуйста, продлите подписку, чтобы восстановить доступ\n"
            "или пригласите своих друзей - за одного друга вы получите 7 дней."
        )
        builder = InlineKeyboardBuilder()
        builder.button(text="🔄 Продлить подписку", callback_data="buy_traffic_start")
        builder.button(text="🤝 Пригласить друга", callback_data="show_referral_program")
        builder.adjust(1)
        await bot.send_message(chat_id=user_id, text=message, reply_markup=builder.as_markup())
        logger.info(f"Scheduler: Отправлено уведомление об окончании подписки пользователю {user_id}.")
    except Exception as e:
        logger.error(f"Scheduler: Ошибка отправки уведомления об окончании пользователю {user_id}: {e}")

def _cleanup_notified_users(all_db_keys: list[dict]):
    if not notified_users:
        # keep user-level cache in sync too
        active_users = {int(k.get('user_id')) for k in all_db_keys if k.get('user_id') is not None}
        for uid in list(notified_user_marks.keys()):
            if uid not in active_users:
                notified_user_marks.pop(uid, None)
        return

    logger.debug("Scheduler: Очищаю кэш уведомлений...")
    
    active_key_ids = {key['key_id'] for key in all_db_keys}
    active_users = {int(key.get('user_id')) for key in all_db_keys if key.get('user_id') is not None}
    
    users_to_check = list(notified_users.keys())
    
    cleaned_users = 0
    cleaned_keys = 0

    for user_id in users_to_check:
        keys_to_check = list(notified_users[user_id].keys())
        for key_id in keys_to_check:
            if key_id not in active_key_ids:
                del notified_users[user_id][key_id]
                cleaned_keys += 1
        
        if not notified_users[user_id]:
            del notified_users[user_id]
            cleaned_users += 1
    
    if cleaned_users > 0 or cleaned_keys > 0:
        logger.debug(f"Scheduler: Очистка завершена. Удалено записей пользователей: {cleaned_users}, ключей: {cleaned_keys}.")
    for uid in list(notified_user_marks.keys()):
        if uid not in active_users:
            notified_user_marks.pop(uid, None)
    for uid in list(expired_notified_users):
        if uid not in active_users:
            expired_notified_users.discard(uid)

async def check_expiring_subscriptions(bot: Bot):
    logger.debug("Scheduler: Проверяю истекающие подписки...")
    current_time = datetime.now()
    all_keys = database.get_all_keys()
    
    _cleanup_notified_users(all_keys)
    
    user_state: dict[int, dict[str, bool]] = {}

    for key in all_keys:
        try:
            expiry_date = datetime.fromisoformat(key['expiry_date'])
            time_left = expiry_date - current_time

            total_hours_left = int(time_left.total_seconds() / 3600)
            user_id = key['user_id']
            key_id = key['key_id']
            if user_id is not None:
                st = user_state.setdefault(int(user_id), {"has_any": True, "has_active": False})
                st["has_any"] = True
                if time_left.total_seconds() > 0:
                    st["has_active"] = True

            if time_left.total_seconds() < 0:
                continue

            for hours_mark in NOTIFY_BEFORE_HOURS:
                if hours_mark - 1 < total_hours_left <= hours_mark:
                    notified_users.setdefault(user_id, {}).setdefault(key_id, set())
                    notified_user_marks.setdefault(user_id, set())
                    
                    if (
                        hours_mark not in notified_users[user_id][key_id]
                        and hours_mark not in notified_user_marks[user_id]
                    ):
                        await send_subscription_notification(bot, user_id, key_id, hours_mark, expiry_date)
                        notified_users[user_id][key_id].add(hours_mark)
                        notified_user_marks[user_id].add(hours_mark)
                    break 
                    
        except Exception as e:
            logger.error(f"Scheduler: Ошибка обработки истечения для ключа {key.get('key_id')}: {e}")

    for uid, st in user_state.items():
        if st.get("has_active"):
            expired_notified_users.discard(uid)
            continue
        if st.get("has_any") and uid not in expired_notified_users:
            await send_subscription_expired_notification(bot, uid)
            expired_notified_users.add(uid)

async def sync_keys_with_panels():
    logger.debug("Scheduler: Запускаю синхронизацию с панелями...")
    total_affected_records = 0
    
    all_hosts = database.get_all_hosts()
    if not all_hosts:
        logger.debug("Scheduler: Хосты в базе не настроены. Синхронизация пропущена.")
        return

    for host in all_hosts:
        host_name = host['host_name']
        is_expired_host = int(host.get("is_expired_host") or 0) == 1
        logger.debug(f"Scheduler: Обрабатываю хост: '{host_name}'")

        if is_expired_host:
            try:
                for key in database.get_keys_for_host(host_name) or []:
                    email = str(key.get("key_email") or "").strip()
                    if not email:
                        continue
                    try:
                        await xui_api.delete_client_on_host(host_name, email)
                    except Exception:
                        pass
            except Exception as e:
                logger.error(f"Scheduler: Ошибка обработки expired-host '{host_name}': {e}", exc_info=True)
            continue

        try:
            keys_in_db = database.get_keys_for_host(host_name)

            for db_key in keys_in_db:
                key_email = db_key['key_email']
                expiry_date = datetime.fromisoformat(db_key['expiry_date'])
                now = datetime.now()
                is_expired = expiry_date <= now

                if is_expired:
                    try:
                        await xui_api.delete_client_on_host(host_name, key_email)
                    except Exception as e:
                        logger.warning(f"Scheduler: Не удалось удалить истекший ключ '{key_email}' на '{host_name}': {e}")
                    try:
                        key_id = db_key.get("key_id")
                        if key_id:
                            database.delete_key_by_id(int(key_id))
                            total_affected_records += 1
                    except Exception as e:
                        logger.warning(f"Scheduler: Не удалось удалить запись истекшего ключа key_id={db_key.get('key_id')}: {e}")
                    continue

                local_expiry_ms = int(expiry_date.timestamp() * 1000)
                usage = await xui_api.get_key_usage_stats_from_host(db_key)
                remote_expiry_ms = int((usage or {}).get("expiry_timestamp_ms") or 0)

                if remote_expiry_ms <= 0 or abs(remote_expiry_ms - local_expiry_ms) > 1000:
                    try:
                        repaired = await xui_api.create_or_update_key_on_host(
                            host_name=host_name,
                            email=key_email,
                            days_to_add=None,
                            expiry_timestamp_ms=local_expiry_ms,
                            preferred_uuid=db_key.get("xui_client_uuid"),
                        )
                        if repaired and repaired.get("expiry_timestamp_ms"):
                            database.update_key_info(
                                int(db_key.get("key_id")),
                                repaired.get("client_uuid") or db_key.get("xui_client_uuid") or "",
                                int(repaired.get("expiry_timestamp_ms") or local_expiry_ms),
                            )
                            total_affected_records += 1
                    except Exception as e:
                        logger.warning(
                            f"Scheduler: Не удалось синхронизировать срок ключа '{key_email}' с локальной БД "
                            f"на '{host_name}': {e}"
                        )

                try:
                    await xui_api.set_client_enabled_on_host(host_name, key_email, enabled=True)
                except Exception as e:
                    logger.warning(f"Scheduler: Не удалось включить активный ключ '{key_email}' на '{host_name}': {e}")

        except Exception as e:
            logger.error(f"Scheduler: Непредвиденная ошибка при обработке хоста '{host_name}': {e}", exc_info=True)

    logger.debug(f"Scheduler: Синхронизация с панелями завершена. Затронуто записей: {total_affected_records}.")


async def _maybe_run_monthly_traffic_reset():
    """Reset traffic counters on 3x-ui host inbounds once each month on day 1."""
    now = datetime.now()
    if now.day != 1:
        return

    current_ym = now.strftime("%Y-%m")
    last_done = str(database.get_setting(MONTHLY_TRAFFIC_RESET_KEY) or "").strip()
    if last_done == current_ym:
        return

    hosts = database.get_all_hosts() or []
    hosts = [h for h in hosts if int(h.get("is_expired_host") or 0) != 1]
    if not hosts:
        logger.info("Scheduler: Ежемесячный сброс трафика пропущен — нет активных хостов.")
        database.update_setting(MONTHLY_TRAFFIC_RESET_KEY, current_ym)
        return

    total_clients = 0
    reset_clients = 0
    reverted_limits = 0
    logger.info(f"Scheduler: Запускаю ежемесячный сброс трафика (дата: {now.strftime('%Y-%m-%d')})...")
    for host in hosts:
        host_name = str(host.get("host_name") or "").strip()
        if not host_name:
            continue
        try:
            host_total, host_reset = await xui_api.reset_all_clients_traffic_on_host(host_name)
            total_clients += int(host_total or 0)
            reset_clients += int(host_reset or 0)
        except Exception as e:
            logger.error(f"Scheduler: Ошибка ежемесячного сброса трафика на хосте '{host_name}': {e}", exc_info=True)

        try:
            base_limit_gb = xui_api.resolve_host_client_traffic_limit_gb(host)
            if base_limit_gb in (None, "", "null"):
                continue
            keys = database.get_keys_for_host(host_name) or []
            for key in keys:
                expiry_raw = key.get("expiry_date")
                if not expiry_raw:
                    continue
                try:
                    expiry_dt = datetime.fromisoformat(str(expiry_raw))
                except Exception:
                    continue
                if expiry_dt <= now:
                    continue
                key_email = (key.get("key_email") or "").strip()
                if not key_email:
                    continue
                try:
                    ok = await xui_api.set_client_traffic_limit_on_host(host_name, key_email, base_limit_gb)
                except Exception:
                    ok = False
                if ok:
                    reverted_limits += 1
        except Exception as e:
            logger.error(f"Scheduler: Ошибка восстановления базовых лимитов трафика на хосте '{host_name}': {e}", exc_info=True)

    cleared_packages = 0
    try:
        cleared_packages = database.clear_all_traffic_package_purchases()
    except Exception as e:
        logger.error(f"Scheduler: Ошибка очистки временных пакетов трафика: {e}", exc_info=True)

    logger.info(
        f"Scheduler: Ежемесячный сброс трафика завершён. "
        f"Сброшено клиентов: {reset_clients}/{total_clients}. "
        f"Восстановлено базовых лимитов: {reverted_limits}. "
        f"Сгорело пакетов трафика: {cleared_packages}."
    )
    database.update_setting(MONTHLY_TRAFFIC_RESET_KEY, current_ym)

async def periodic_subscription_check(bot_controller: BotController):
    global _last_expiry_check_run_at, _last_panel_sync_run_at, _last_monthly_reset_check_run_at
    logger.info("Scheduler: Планировщик фоновых задач запущен.")
    await asyncio.sleep(10)

    while True:
        try:
            now = datetime.now()
            bot = bot_controller.get_bot_instance() if bot_controller.get_status().get("is_running") else None
            if bot and (
                _last_expiry_check_run_at is None
                or (now - _last_expiry_check_run_at).total_seconds() >= EXPIRY_CHECK_INTERVAL_SECONDS
            ):
                await check_expiring_subscriptions(bot)
                _last_expiry_check_run_at = now
            elif not bot:
                logger.debug("Scheduler: Бот остановлен, уведомления пользователям пропущены.")

            if (
                _last_panel_sync_run_at is None
                or (now - _last_panel_sync_run_at).total_seconds() >= PANEL_SYNC_INTERVAL_SECONDS
            ):
                await sync_keys_with_panels()
                _last_panel_sync_run_at = now

            if (
                _last_monthly_reset_check_run_at is None
                or (now - _last_monthly_reset_check_run_at).total_seconds() >= MONTHLY_RESET_CHECK_INTERVAL_SECONDS
            ):
                await _maybe_run_monthly_traffic_reset()
                _last_monthly_reset_check_run_at = now

            if (
                _last_metrics_run_at is None
                or (now - _last_metrics_run_at).total_seconds() >= METRICS_CHECK_INTERVAL_SECONDS
            ):
                await _maybe_collect_host_metrics()

            if (
                bot
                and (
                    _last_backup_run_at is None
                    or (now - _last_backup_run_at).total_seconds() >= BACKUP_CHECK_INTERVAL_SECONDS
                )
            ):
                await _maybe_run_daily_backup(bot)

        except Exception as e:
            logger.error(f"Scheduler: Необработанная ошибка в основном цикле: {e}", exc_info=True)
            
        logger.info(f"Scheduler: Тик завершён. Следующая проверка через {SCHEDULER_TICK_SECONDS} сек.")
        await asyncio.sleep(SCHEDULER_TICK_SECONDS)

async def _maybe_run_daily_backup(bot: Bot):
    global _last_backup_run_at
    now = datetime.now()
    # Считаем интервал из настроек (в днях). 0 или пусто — автобэкап выключен.
    try:
        s = database.get_setting("backup_interval_days") or "1"
        days = int(str(s).strip() or "1")
    except Exception:
        days = 1
    if days <= 0:
        return
    interval_seconds = max(1, days) * 24 * 3600
    if _last_backup_run_at and (now - _last_backup_run_at).total_seconds() < interval_seconds:
        return
    try:
        zip_path = backup_manager.create_backup_file()
        if zip_path and zip_path.exists():
            try:
                sent = await backup_manager.send_backup_to_admins(bot, zip_path)
                logger.info(f"Scheduler: Создан бэкап {zip_path.name}, отправлен {sent} адм.")
            except Exception as e:
                logger.error(f"Scheduler: Не удалось отправить бэкап: {e}")
            try:
                backup_manager.cleanup_old_backups(keep=7)
            except Exception:
                pass
        _last_backup_run_at = now
    except Exception as e:
        logger.error(f"Scheduler: Критическая ошибка при создании и отправке бэкапа: {e}", exc_info=True)
async def _maybe_collect_host_metrics():
    global _last_metrics_run_at
    now = datetime.now()
    
    # Собираем локальные метрики
    try:
        local_metrics = await asyncio.wait_for(asyncio.to_thread(resource_monitor.get_local_metrics), timeout=10)
        if local_metrics and local_metrics.get('ok'):
            database.insert_resource_metric(
                'local', 'panel',
                cpu_percent=local_metrics.get('cpu_percent'),
                mem_percent=local_metrics.get('mem_percent'),
                disk_percent=local_metrics.get('disk_percent'),
                load1=local_metrics.get('loadavg', {}).get('1m') if local_metrics.get('loadavg') else None,
                net_bytes_sent=local_metrics.get('network_sent'),
                net_bytes_recv=local_metrics.get('network_recv'),
                raw_json=json.dumps(local_metrics, ensure_ascii=False)
            )
    except Exception as e:
        logger.error(f"Scheduler: Ошибка сбора локальных метрик: {e}")
    
    # Собираем метрики хостов
    hosts = database.get_all_hosts()
    if not hosts:
        _last_metrics_run_at = now
        return
    for h in hosts:
        host_name = h.get('host_name')
        if not host_name:
            continue
        if not (h.get('ssh_host') and h.get('ssh_user')):
            continue
        try:
            try:
                m = await asyncio.wait_for(asyncio.to_thread(resource_monitor.get_host_metrics_via_ssh, h), timeout=30)
            except AttributeError:
                m = await asyncio.wait_for(asyncio.to_thread(resource_monitor.get_host_metrics_via_ssh, h), timeout=30)
            try:
                database.insert_host_metrics(host_name, m)
                # Также сохраняем в resource_metrics для графиков
                if m and m.get('ok'):
                    database.insert_resource_metric(
                        'host', host_name,
                        cpu_percent=m.get('cpu_percent'),
                        mem_percent=m.get('mem_percent'),
                        disk_percent=m.get('disk_percent'),
                        load1=m.get('loadavg', {}).get('1m') if m.get('loadavg') else None,
                        raw_json=json.dumps(m, ensure_ascii=False)
                    )
            except Exception as e:
                logger.warning(f"Scheduler: insert_host_metrics failed for {host_name}: {e}")
        except asyncio.TimeoutError:
            logger.warning(f"Scheduler: Таймаут сбора метрик для хоста '{host_name}'")
        except Exception as e:
            logger.error(f"Scheduler: Ошибка сбора метрик для '{host_name}': {e}")
    _last_metrics_run_at = now
