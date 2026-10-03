import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from engine.detectors.allowlist import filter_findings, load_allowlist
from engine.finding import Finding
from engine.policy_signing import PolicyIntegrityError, sign_policy


def test_missing_allowlist_file_returns_empty_set(tmp_path):
    assert load_allowlist(str(tmp_path / 'nonexistent.yaml')) == set()


def test_present_but_unsigned_allowlist_is_rejected(tmp_path):
    """An allowlist can silently suppress real findings, so a present file
    with no .sig must fail closed, not be trusted by default."""
    path = tmp_path / 'allowlist.yaml'
    path.write_text('- value: "AKIAINTENTIONALLYPUBLICTESTKEY"\n  reason: "test"\n')
    with pytest.raises(PolicyIntegrityError):
        load_allowlist(str(path))


def test_signed_allowlist_loads(tmp_path, monkeypatch):
    # verify_policy_signature() pins the public key via the
    # PINNED_PUBLIC_KEY_PEM constant, not PUBKEY_PATH (a file-based pin
    # sitting next to what it authenticates provides zero defense against a
    # local attacker -- see that constant's own docstring). Monkeypatching
    # the constant itself is what lets this test use a throwaway keypair.
    private_key = Ed25519PrivateKey.generate()
    pubkey_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    monkeypatch.setattr('engine.policy_signing.PINNED_PUBLIC_KEY_PEM', pubkey_pem)

    path = tmp_path / 'allowlist.yaml'
    path.write_text('- value: "AKIAINTENTIONALLYPUBLICTESTKEY"\n  reason: "test"\n')
    sign_policy(path, private_key)

    assert load_allowlist(str(path)) == {'AKIAINTENTIONALLYPUBLICTESTKEY'}


def test_tampered_signed_allowlist_is_rejected(tmp_path, monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    pubkey_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    monkeypatch.setattr('engine.policy_signing.PINNED_PUBLIC_KEY_PEM', pubkey_pem)

    path = tmp_path / 'allowlist.yaml'
    path.write_text('- value: "AKIAINTENTIONALLYPUBLICTESTKEY"\n  reason: "test"\n')
    sign_policy(path, private_key)
    path.write_text(path.read_text() + '\n- value: "sk-live-attacker-added-this"\n  reason: "sneaky"\n')

    with pytest.raises(PolicyIntegrityError):
        load_allowlist(str(path))


def test_filter_findings_drops_allowlisted_values():
    findings = [
        Finding(span_start=0, span_end=11, category='secret.aws_access_token',
                confidence=0.9, detector_id='regex', raw_value='AKIAALLOWED'),
        Finding(span_start=0, span_end=14, category='secret.aws_access_token',
                confidence=0.9, detector_id='regex', raw_value='AKIAREALSECRET'),
    ]
    result = filter_findings(findings, {'AKIAALLOWED'})
    assert [f.raw_value for f in result] == ['AKIAREALSECRET']
