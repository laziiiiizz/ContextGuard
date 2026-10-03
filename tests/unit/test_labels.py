from datetime import datetime, timedelta, timezone

from engine.labels import describe_event, friendly_category, friendly_time


def test_known_categories_get_plain_names():
    assert friendly_category('secret.aws_access_token') == 'AWS access token'
    assert friendly_category('secret.github_pat') == 'GitHub access token'
    assert friendly_category('pii.credit_card') == 'Credit card number'
    assert friendly_category('secret.high_entropy_token') == 'Unknown-format secret'
    assert friendly_category('infra.internal_ip') == 'Internal IP address'


def test_unlisted_secret_categories_are_still_readable():
    assert friendly_category('secret.slack_bot_token') == 'Slack bot token'
    assert friendly_category('secret.openai_api_key') == 'OpenAI API key'


def test_every_policy_category_gets_a_name_without_dots_or_underscores():
    import yaml

    from proxy.paths import get_app_root
    rules = yaml.safe_load((get_app_root() / 'policy' / 'policy.yaml').read_text(encoding='utf-8'))
    for rule in rules:
        name = friendly_category(rule['category'])
        assert '.' not in name and '_' not in name, (rule['category'], name)


def test_control_events_describe_what_happened_without_a_site():
    assert describe_event('contextguard.control', 'pause', 'local') == ('Protection paused', '', '')
    assert describe_event('pii.email', 'transform', 'chatgpt.com') == ('Masked', 'Email address', 'chatgpt.com')


def test_time_shows_the_date_only_when_it_is_not_today():
    now = datetime.now().astimezone()
    today = now.astimezone(timezone.utc).isoformat()
    last_week = (now - timedelta(days=7)).astimezone(timezone.utc).isoformat()
    assert ',' not in friendly_time(today, now)
    assert ',' in friendly_time(last_week, now)
    assert friendly_time('not a timestamp', now) == 'not a timestamp'


def test_upload_servers_are_named_after_the_site():
    from engine.labels import friendly_host
    from notify.confirm_dialog import dialog_text
    assert friendly_host('push.clients6.google.com') == 'Gemini (file upload)'
    assert friendly_host('chatgpt.com') == 'chatgpt.com'
    assert 'Gemini (file upload)' in dialog_text('secret.aws_access_token', 'push.clients6.google.com')[1]
