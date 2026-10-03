import pytest

from scripts import install_ca_cert


class FakeResult:
    def __init__(self, returncode=0, stdout=''):
        self.returncode = returncode
        self.stdout = stdout


@pytest.fixture(autouse=True)
def no_real_side_effects(monkeypatch, tmp_path):
    # Never let these tests touch the real certutil/certificate store.
    monkeypatch.setattr(install_ca_cert, 'ensure_provisioned', lambda: None)
    fake_store_dir = tmp_path
    (fake_store_dir / install_ca_cert.CERT_FILENAME).write_bytes(b'fake cert bytes')
    monkeypatch.setattr(install_ca_cert, 'STORE_DIR', fake_store_dir)


def test_install_provisions_then_calls_certutil_with_correct_scope(monkeypatch):
    calls = []
    monkeypatch.setattr(install_ca_cert, 'ensure_provisioned', lambda: calls.append('provisioned'))
    monkeypatch.setattr(install_ca_cert.subprocess, 'run', lambda args, **k: calls.append(args) or FakeResult())

    install_ca_cert.install()

    assert calls[0] == 'provisioned'  # provisioning happens before the certutil call
    args = calls[1]
    assert args[0] == 'certutil'
    assert '-user' in args  # CurrentUser scope -- no admin elevation needed
    assert '-addstore' in args
    assert 'Root' in args
    assert str(install_ca_cert.STORE_DIR / install_ca_cert.CERT_FILENAME) in args


def test_install_raises_if_cert_file_missing_after_provisioning(monkeypatch, tmp_path):
    empty_dir = tmp_path / 'empty'
    empty_dir.mkdir()
    monkeypatch.setattr(install_ca_cert, 'STORE_DIR', empty_dir)
    monkeypatch.setattr(install_ca_cert.subprocess, 'run', lambda *a, **k: FakeResult())

    with pytest.raises(FileNotFoundError):
        install_ca_cert.install()


def _mock_certutil(monkeypatch, dump_serial: str, store_stdout: str):
    def fake_run(args, **kwargs):
        if '-dump' in args:
            return FakeResult(stdout=f'Serial Number: {dump_serial}\nOther: stuff\n')
        return FakeResult(stdout=store_stdout)
    monkeypatch.setattr(install_ca_cert.subprocess, 'run', fake_run)


def test_is_installed_true_when_current_certs_exact_serial_is_in_the_store(monkeypatch):
    _mock_certutil(monkeypatch, dump_serial='abc123',
                   store_stdout='Issuer: O=mitmproxy, CN=mitmproxy\nSerial Number: abc123\n')
    assert install_ca_cert.is_installed() is True


def test_is_installed_false_when_absent(monkeypatch):
    _mock_certutil(monkeypatch, dump_serial='abc123',
                   store_stdout='Issuer: O=DigiCert, CN=DigiCert Root\nSerial Number: deadbeef\n')
    assert install_ca_cert.is_installed() is False


def test_is_installed_false_for_a_stale_unrelated_cert_with_the_same_name(monkeypatch):
    # Regression test for a real, confirmed-live bug: is_installed() used to
    # check only whether the string "mitmproxy" appeared anywhere in the
    # store listing -- true even for a completely different, orphaned CA
    # left over from an earlier, unrelated generation (confirmed live: one
    # survived because Windows' own confirmation dialog for REMOVING a Root
    # cert -- see ContextGuard.iss's RemoveCaCert step -- was never
    # answered). That made main() believe trust was already set up and skip
    # calling install() entirely -- on a fresh install where ca_store didn't
    # exist yet, the CA was never even generated, let alone the real one
    # ever getting trusted, while an unrelated stale cert sat there looking
    # like success. The fix matches by exact serial number instead.
    _mock_certutil(monkeypatch, dump_serial='the-real-current-serial',
                   store_stdout='Issuer: O=mitmproxy, CN=mitmproxy\nSerial Number: some-old-orphaned-serial\n')
    assert install_ca_cert.is_installed() is False


def test_main_skips_install_when_already_installed(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(install_ca_cert, 'is_installed', lambda: True)
    monkeypatch.setattr(install_ca_cert, 'install', lambda: calls.append('installed'))

    install_ca_cert.main()

    assert calls == []
    assert 'already trusted' in capsys.readouterr().out


def test_main_installs_when_not_already_installed(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(install_ca_cert, 'is_installed', lambda: False)
    monkeypatch.setattr(install_ca_cert, 'install', lambda: calls.append('installed'))

    install_ca_cert.main()

    assert calls == ['installed']
    assert 'installed' in capsys.readouterr().out.lower()
