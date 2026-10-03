"""Makes new dashboard and control tokens from the command line, for when
ContextGuard isn't running (the tray menu does the same while it runs).
Works at once; open dashboard tabs must be reopened."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy.control import rotate_control_token, rotate_dashboard_token


def main() -> None:
    rotate_dashboard_token()
    rotate_control_token()
    print('Dashboard and control-plane tokens rotated. Any already-open dashboard tab will need '
          'to be reopened via the tray menu\'s "Open Dashboard".')


if __name__ == '__main__':
    main()
