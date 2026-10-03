import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from engine.policy_signing import PolicyIntegrityError, sign_policy, verify_policy_signature


@pytest.fixture
def signed_policy(tmp_path, monkeypatch):
    # verify_policy_signature() reads the pin from the PINNED_PUBLIC_KEY_PEM
    # module constant, not from a file (see that constant's own docstring
    # for why: a pin sitting in the same user-writable directory as the
    # files it authenticates provides zero defense against a local
    # attacker). Monkeypatching the constant itself, per test, is what lets
    # these tests use a fresh throwaway keypair instead of the real pinned
    # one.
    private_key = Ed25519PrivateKey.generate()
    pubkey_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    monkeypatch.setattr('engine.policy_signing.PINNED_PUBLIC_KEY_PEM', pubkey_pem)

    policy_path = tmp_path / 'policy.yaml'
    policy_path.write_text('- category: secret.aws_access_token\n  action: block\n')
    sign_policy(policy_path, private_key)
    return policy_path


def test_correctly_signed_policy_verifies(signed_policy):
    verify_policy_signature(signed_policy)  # should not raise


def test_tampered_policy_is_rejected(signed_policy):
    signed_policy.write_text(signed_policy.read_text() + '\n# tampered')
    with pytest.raises(PolicyIntegrityError):
        verify_policy_signature(signed_policy)


def test_missing_signature_is_rejected(signed_policy):
    sig_path = signed_policy.with_suffix('.yaml.sig')
    sig_path.unlink()
    with pytest.raises(PolicyIntegrityError):
        verify_policy_signature(signed_policy)


def test_signature_from_wrong_key_is_rejected(signed_policy):
    other_key = Ed25519PrivateKey.generate()
    sign_policy(signed_policy, other_key)  # re-sign with a different key than the pinned pubkey
    with pytest.raises(PolicyIntegrityError):
        verify_policy_signature(signed_policy)


def test_corrupted_signature_file_is_rejected(signed_policy):
    sig_path = signed_policy.with_suffix('.yaml.sig')
    sig_path.write_text('not valid base64 !!! ###')
    with pytest.raises(PolicyIntegrityError):
        verify_policy_signature(signed_policy)


def test_corrupted_pinned_public_key_constant_is_rejected(signed_policy, monkeypatch):
    # The pinned constant itself being corrupted (a bad build, a bad merge)
    # must fail safe, not raise some other unhandled exception type.
    monkeypatch.setattr('engine.policy_signing.PINNED_PUBLIC_KEY_PEM', b'not a real PEM file')
    with pytest.raises(PolicyIntegrityError):
        verify_policy_signature(signed_policy)


def test_pinned_public_key_constant_matches_the_committed_reference_file():
    # PUBKEY_PATH (policy/policy_signing_pubkey.pem) is kept only as a
    # human-readable, diffable reference copy -- verification itself never
    # reads it (see PINNED_PUBLIC_KEY_PEM's own docstring). This guards
    # against the two ever silently drifting apart, which would otherwise
    # go unnoticed since nothing at runtime would catch it.
    from engine.policy_signing import PINNED_PUBLIC_KEY_PEM, PUBKEY_PATH
    assert PUBKEY_PATH.read_bytes().strip() == PINNED_PUBLIC_KEY_PEM.strip()


def test_verify_works_on_any_signed_file_not_just_policy_yaml(tmp_path, monkeypatch):
    """domains.yaml and allowlist.yaml reuse this same function -- confirm it's
    genuinely path-generic, not accidentally coupled to policy.yaml's name."""
    private_key = Ed25519PrivateKey.generate()
    pubkey_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    monkeypatch.setattr('engine.policy_signing.PINNED_PUBLIC_KEY_PEM', pubkey_pem)

    domains_path = tmp_path / 'domains.yaml'
    domains_path.write_text('- hostname: example.com\n  enabled: true\n')
    sign_policy(domains_path, private_key)
    verify_policy_signature(domains_path)  # should not raise

    domains_path.write_text(domains_path.read_text() + '\n- hostname: evil.example.com\n  enabled: true\n')
    with pytest.raises(PolicyIntegrityError):
        verify_policy_signature(domains_path)
