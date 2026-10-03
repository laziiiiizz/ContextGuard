import json

import pytest

from engine import user_settings


@pytest.fixture
def isolated_settings():
    # tests/conftest.py already points settings_path() at a temp file.
    return user_settings.settings_path()


def test_everything_is_enabled_when_no_settings_file_exists():
    assert user_settings.disabled_groups() == frozenset()
    assert user_settings.is_category_enabled('secret.aws_access_token')
    assert user_settings.is_category_enabled('pii.credit_card')


@pytest.mark.parametrize('category, group', [
    ('secret.aws_access_token', 'api_keys'),
    ('secret.generic_private_key', 'api_keys'),
    ('secret.high_entropy_token', 'unknown_secrets'),
    ('pii.credit_card', 'credit_cards'),
    ('pii.ssn', 'ssn'),
    ('pii.ssn_context', 'ssn'),
    ('pii.email', 'emails'),
    ('infra.internal_ip', 'internal_network'),
    ('infra.internal_hostname', 'internal_network'),
])
def test_each_category_maps_to_its_settings_group(category, group):
    assert user_settings.group_for_category(category) == group


def test_every_policy_category_belongs_to_a_settings_group():
    # A category with no group could never be switched off from Settings.
    import yaml

    from proxy.paths import get_app_root
    rules = yaml.safe_load((get_app_root() / 'policy' / 'policy.yaml').read_text(encoding='utf-8'))
    ungrouped = [r['category'] for r in rules if user_settings.group_for_category(r['category']) is None]
    assert ungrouped == []


def test_turning_a_group_off_and_on_round_trips(isolated_settings):
    user_settings.set_group_enabled('emails', False)
    assert json.loads(isolated_settings.read_text()) == {'disabled_groups': ['emails']}
    assert not user_settings.is_category_enabled('pii.email')
    assert user_settings.is_category_enabled('pii.credit_card')  # other groups untouched

    user_settings.set_group_enabled('emails', True)
    assert user_settings.is_category_enabled('pii.email')


def test_a_corrupt_settings_file_leaves_everything_enabled(isolated_settings):
    isolated_settings.write_text('{not json')
    assert user_settings.disabled_groups() == frozenset()

    isolated_settings.write_text('["a", "list", "not", "a", "dict"]')
    assert user_settings.disabled_groups() == frozenset()


def test_unknown_group_names_in_the_file_are_ignored(isolated_settings):
    isolated_settings.write_text(json.dumps({'disabled_groups': ['emails', 'everything']}))
    assert user_settings.disabled_groups() == frozenset({'emails'})


def test_setting_an_unknown_group_is_rejected():
    with pytest.raises(ValueError):
        user_settings.set_group_enabled('everything', False)
