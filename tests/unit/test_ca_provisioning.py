import os

import pytest

from proxy.ca_provisioning import (
    PUBLIC_FILES,
    SENSITIVE_FILES,
    cleanup_runtime_confdir,
    ensure_provisioned,
    provision_runtime_confdir,
    reset_ca,
)


@pytest.fixture(autouse=True)
def fake_keyring(monkeypatch):
    fake_store = {}
    monkeypatch.setattr('proxy.ca_provisioning.keyring.get_password',
                         lambda service, key: fake_store.get((service, key)))
    monkeypatch.setattr('proxy.ca_provisioning.keyring.set_password',
                         lambda service, key, value: fake_store.__setitem__((service, key), value))


def test_ensure_provisioned_never_leaves_plaintext_private_key(tmp_path):
    store_dir = tmp_path / 'ca_store'
    ensure_provisioned(store_dir)

    for name in SENSITIVE_FILES:
        assert not (store_dir / name).exists(), f'{name} should never exist in plaintext'
        assert (store_dir / f'{name}.enc').exists()

    for name in PUBLIC_FILES:
        assert (store_dir / name).exists()


def test_ensure_provisioned_is_idempotent(tmp_path):
    store_dir = tmp_path / 'ca_store'
    ensure_provisioned(store_dir)
    first = (store_dir / f'{SENSITIVE_FILES[0]}.enc').read_bytes()
    ensure_provisioned(store_dir)  # should not regenerate
    second = (store_dir / f'{SENSITIVE_FILES[0]}.enc').read_bytes()
    assert first == second


def test_runtime_confdir_decrypts_to_a_loadable_private_key(tmp_path):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    store_dir = tmp_path / 'ca_store'
    confdir = provision_runtime_confdir(store_dir)
    try:
        data = open(os.path.join(confdir, SENSITIVE_FILES[0]), 'rb').read()
        key_pem = data.split(b'-----BEGIN CERTIFICATE')[0]
        key = load_pem_private_key(key_pem, password=None)
        assert key is not None
    finally:
        cleanup_runtime_confdir(confdir)


def test_cleanup_removes_the_runtime_directory(tmp_path):
    store_dir = tmp_path / 'ca_store'
    confdir = provision_runtime_confdir(store_dir)
    assert os.path.exists(confdir)
    cleanup_runtime_confdir(confdir)
    assert not os.path.exists(confdir)


def test_reset_ca_forces_a_genuinely_new_ca_on_next_provision(tmp_path):
    # Real-world precedent: Fiddler's own troubleshooting docs recommend a
    # "Reset All Certificates" action as the standard recovery path when a
    # client's trust store and the proxy's actual CA have drifted apart --
    # this is that escape hatch. Must actually force fresh key material, not
    # just look like it did.
    store_dir = tmp_path / 'ca_store'
    ensure_provisioned(store_dir)
    original = (store_dir / f'{SENSITIVE_FILES[0]}.enc').read_bytes()

    reset_ca(store_dir)
    for name in SENSITIVE_FILES:
        assert not (store_dir / f'{name}.enc').exists()
    for name in PUBLIC_FILES:
        assert not (store_dir / name).exists()

    ensure_provisioned(store_dir)  # regenerates since the files are gone
    regenerated = (store_dir / f'{SENSITIVE_FILES[0]}.enc').read_bytes()
    assert regenerated != original


def test_reset_ca_on_a_never_provisioned_store_does_not_raise(tmp_path):
    store_dir = tmp_path / 'ca_store'  # never created at all
    reset_ca(store_dir)  # must not raise just because there was nothing to delete
