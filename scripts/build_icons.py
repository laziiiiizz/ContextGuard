"""Regenerates assets/icon.ico and assets/logo.png from the logo drawing code
in tray/app.py. Run after changing the mark: `python scripts/build_icons.py`.
assets/logo.svg is the hand-written vector copy of the same geometry.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy.paths import get_app_root
from tray.app import make_app_icon

ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]


def main() -> None:
    assets = get_app_root() / 'assets'
    assets.mkdir(exist_ok=True)
    frames = [make_app_icon(size) for size in ICO_SIZES]
    frames[-1].save(assets / 'icon.ico', format='ICO',
                    sizes=[(s, s) for s in ICO_SIZES], append_images=frames[:-1])
    make_app_icon(512).save(assets / 'logo.png')
    print(f'wrote {assets / "icon.ico"} and {assets / "logo.png"}')


if __name__ == '__main__':
    main()
