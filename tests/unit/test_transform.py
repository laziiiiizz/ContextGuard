import pytest

from engine.alias_vault import AliasVault
from engine.finding import Finding
from engine.transform import generalize, mask, remove, tokenize


def make_finding(category='pii.email', raw_value='john@acme.com'):
    return Finding(span_start=0, span_end=len(raw_value), category=category,
                   confidence=0.9, detector_id='test', raw_value=raw_value)


def test_mask_returns_category_placeholder():
    assert mask(make_finding('pii.email')) == '[EMAIL]'


def test_remove_returns_empty_string():
    assert remove(make_finding()) == ''


def test_generalize_without_buckets_returns_generic_label():
    result = generalize(make_finding('business.revenue_figure', '127842'))
    assert result == '[GENERALIZED REVENUE_FIGURE]'


def test_generalize_with_buckets_picks_matching_label():
    buckets = [(100000, 'revenue above $100K'), (0, 'revenue below $100K')]
    result = generalize(make_finding('business.revenue_figure', '127842'), buckets)
    assert result == 'revenue above $100K'


@pytest.fixture
def vault(tmp_path, monkeypatch):
    fake_store = {}
    monkeypatch.setattr('engine.alias_vault.keyring.get_password',
                         lambda service, key: fake_store.get((service, key)))
    monkeypatch.setattr('engine.alias_vault.keyring.set_password',
                         lambda service, key, value: fake_store.__setitem__((service, key), value))
    return AliasVault(db_path=str(tmp_path / 'test_vault.db'))


def test_tokenize_same_value_same_session_returns_same_alias(vault):
    finding = make_finding('pii.customer_name', 'Jane Smith')
    first = tokenize(finding, vault, 'sess_1')
    second = tokenize(finding, vault, 'sess_1')
    assert first == second


def test_tokenize_different_values_get_different_aliases(vault):
    alias_a = tokenize(make_finding('pii.customer_name', 'Jane Smith'), vault, 'sess_1')
    alias_b = tokenize(make_finding('pii.customer_name', 'John Doe'), vault, 'sess_1')
    assert alias_a != alias_b
