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


def send_monthly_report(cfg: dict, devices: list):
    """Email top-10 devices by total traffic for the month."""
    from datetime import datetime
    report_cfg = dict(cfg)
    # Use monthly_report_email if set, else fall back to notify_email
    report_email = cfg.get('monthly_report_email', '').strip() or cfg.get('notify_email', '').strip()
    report_cfg['notify_email'] = report_email

    month_label = datetime.now().strftime('%B %Y')
    lines = [
        f'Mild-Viking Monthly Device Report — {month_label}',
        f'Top {min(10, len(devices))} devices by traffic:',
        '',
        f'{"#":<3} {"Hostname":<22} {"MAC":<19} {"IP":<17} {"In":>10} {"Out":>10}',
        '-' * 85,
    ]
    top = sorted(devices, key=lambda d: d.get('bytes_in', 0) + d.get('bytes_out', 0), reverse=True)[:10]
    for i, d in enumerate(top, 1):
        def _fmt(b):
            b = int(b or 0)
            if b >= 1_073_741_824: return f'{b/1_073_741_824:.1f} GB'
            if b >= 1_048_576:     return f'{b/1_048_576:.1f} MB'
            if b >= 1024:          return f'{b/1024:.1f} KB'
            return f'{b} B'
        lines.append(
            f'{i:<3} {(d.get("hostname") or "unknown")[:22]:<22} '
            f'{(d.get("mac") or "—")[:19]:<19} '
            f'{(d.get("ip") or "—")[:17]:<17} '
            f'{_fmt(d.get("bytes_in",0)):>10} {_fmt(d.get("bytes_out",0)):>10}'
        )

    if not top:
        lines.append('No device data available yet.')

    lines += ['', '—', 'Mild-Viking Network Monitor']
    body = '\n'.join(lines)
    _send(report_cfg, f'[Mild-Viking] Monthly Report — {month_label}', body)
