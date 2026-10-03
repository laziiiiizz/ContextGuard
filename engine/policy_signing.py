"""Signs/verifies policy.yaml (Ed25519, pinned public key) so tampering is rejected."""
import base64
import binascii
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from proxy.paths import get_app_root

KEYRING_SERVICE = 'contextguard'
KEYRING_KEY_NAME = 'policy_signing_private_key'

POLICY_DIR = get_app_root() / 'policy'
# Kept only as a human-readable reference copy (scripts/generate_signing_key.py
# still writes it, and it stays committed so the constant below is auditable
# against it in review/diff) -- verification itself does NOT read this file.
PUBKEY_PATH = POLICY_DIR / 'policy_signing_pubkey.pem'

# The public key that checks the signatures, built into the code. If it were
# only a file next to policy.yaml, anyone able to edit policy.yaml could also
# swap the key and sign their own weaker policy. Inside the exe, they would
# have to rebuild the app instead. If the signing key is ever regenerated,
# update this too (scripts/generate_signing_key.py says so).
PINNED_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAzWJTOtT7lmXMu7V9mXx2KwzPA8hmBBbIk10IPG2vYIM=
-----END PUBLIC KEY-----
"""


class PolicyIntegrityError(Exception):
    """Raised when policy.yaml is missing a valid signature. Fail-safe: the
    caller must not load the policy content when this is raised."""


def load_private_key(hex_bytes: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_bytes))


def sign_policy(policy_path: Path, private_key: Ed25519PrivateKey) -> None:
    data = policy_path.read_bytes()
    signature = private_key.sign(data)
    sig_path = policy_path.with_suffix(policy_path.suffix + '.sig')
    sig_path.write_text(base64.b64encode(signature).decode('ascii'))


def verify_policy_signature(policy_path: Path) -> None:
    sig_path = policy_path.with_suffix(policy_path.suffix + '.sig')
    if not sig_path.exists():
        raise PolicyIntegrityError(f'signature missing at {sig_path}')

    try:
        public_key = load_pem_public_key(PINNED_PUBLIC_KEY_PEM)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise PolicyIntegrityError('pinned public key constant is corrupted') from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise PolicyIntegrityError('pinned public key is not Ed25519')

    try:
        signature = base64.b64decode(sig_path.read_text(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PolicyIntegrityError(f'{sig_path} is corrupted -- not valid base64') from exc

    data = policy_path.read_bytes()
    try:
        public_key.verify(signature, data)
    except InvalidSignature as exc:
        raise PolicyIntegrityError(
            f'{policy_path} failed signature verification -- '
            'file may have been tampered with, or is stale relative to its .sig'
        ) from exc
