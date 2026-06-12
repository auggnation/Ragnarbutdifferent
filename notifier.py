# notifier.py — email notifications for Mild-Viking network events

import logging
import smtplib
import threading
from email.mime.text import MIMEText

logger = logging.getLogger('notifier')


def _send(cfg: dict, subject: str, body: str):
    """Send one email using SMTP settings from config. Non-blocking caller should thread this."""
    host  = cfg.get('smtp_host', '').strip()
    port  = int(cfg.get('smtp_port', 587) or 587)
    user  = cfg.get('smtp_user', '').strip()
    pw    = cfg.get('smtp_pass', '').strip()
    to    = cfg.get('notify_email', '').strip()
    if not all([host, user, pw, to]):
        logger.debug('Email not configured — skipping notification')
        return
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From']    = user
        msg['To']      = to
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.starttls()
            s.login(user, pw)
            s.send_message(msg)
        logger.info(f'Notification sent: {subject}')
    except Exception as e:
        logger.warning(f'Email failed: {e}')


def notify_disconnect(cfg: dict, device_name: str):
    if not cfg.get('notify_enabled') or not cfg.get('notify_on_disconnect', True):
        return
    threading.Thread(
        target=_send, daemon=True,
        args=(cfg, f'[{device_name}] Network disconnected',
              f'{device_name} has lost its network connection.'),
    ).start()


def notify_reconnect(cfg: dict, device_name: str, ip: str, conn_type: str):
    if not cfg.get('notify_enabled') or not cfg.get('notify_on_reconnect', True):
        return
    threading.Thread(
        target=_send, daemon=True,
        args=(cfg, f'[{device_name}] Network reconnected',
              f'{device_name} is back online.\nIP: {ip}\nType: {conn_type}'),
    ).start()
