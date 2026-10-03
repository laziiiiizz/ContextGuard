# OS toast notifications; best-effort, never raises.
from plyer import notification


def notify(title: str, message: str) -> None:
    try:
        notification.notify(title=title, message=message, app_name='ContextGuard')
    except Exception:
        print(f'[ContextGuard] (notify failed) {title}: {message}')
