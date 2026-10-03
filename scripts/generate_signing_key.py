"""One-time: generates the Ed25519 keypair used to sign policy.yaml."""
import os
import sys

import keyring
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.policy_signing import KEYRING_KEY_NAME, KEYRING_SERVICE, PUBKEY_PATH


def main() -> None:
    force = '--force' in sys.argv
    existing = keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_NAME)
    if existing and not force:
        print('Signing key already exists in the OS credential store. '
              'Pass --force to regenerate (invalidates all existing signatures).')
        return

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_NAME, private_bytes.hex())

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PUBKEY_PATH.write_bytes(public_bytes)
    print(f'Signing key generated. Public key written to {PUBKEY_PATH} -- commit this file.')
    print()
    print('IMPORTANT: verify_policy_signature() pins the public key as the '
          'PINNED_PUBLIC_KEY_PEM constant in engine/policy_signing.py, NOT by reading '
          f'{PUBKEY_PATH} at runtime (a pin sitting in the same user-writable directory as '
          'the files it authenticates would provide zero defense against a local attacker). '
          'You must manually copy the PEM text below into that constant -- writing the .pem '
          'file alone is NOT enough for the new key to actually take effect:')
    print()
    print(public_bytes.decode('ascii'))
    print('Private key is in the OS credential store only. Run scripts/sign_policy.py '
          'after any change to policy/policy.yaml.')


if __name__ == '__main__':
    main()
