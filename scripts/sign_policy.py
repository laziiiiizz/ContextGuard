"""Run after any change to policy.yaml, domains.yaml, or allowlist.yaml; signs
whichever of them exist and writes/overwrites their .sig files."""
import os
import sys
from pathlib import Path

import keyring

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.policy_signing import KEYRING_KEY_NAME, KEYRING_SERVICE, POLICY_DIR, load_private_key, sign_policy

REPO_ROOT = POLICY_DIR.parent
SIGNED_FILES = [
    POLICY_DIR / 'policy.yaml',
    REPO_ROOT / 'proxy' / 'domains.yaml',
    POLICY_DIR / 'allowlist.yaml',
]


def main() -> None:
    hex_key = keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_NAME)
    if not hex_key:
        print('No signing key found. Run scripts/generate_signing_key.py first.')
        sys.exit(1)

    private_key = load_private_key(hex_key)
    for path in SIGNED_FILES:
        if not path.exists():
            print(f'Skipping {path} (does not exist).')
            continue
        sign_policy(path, private_key)
        print(f'Signed {path} -> {path}.sig')


if __name__ == '__main__':
    main()
