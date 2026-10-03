"""Tests for keyword-context detection (engine/detectors/context_rules.py)."""
import time

import pytest

from engine.detectors.context_rules import CONTEXT_RULES, run

_UUID = '01234567-89ab-cdef-0123-456789abcdef'

_EXAMPLE_VALUE_BY_CATEGORY = {
    'secret.discord_bot_token': 'a' * 64,
    'secret.twilio_api_key': 'SK' + 'a' * 32,
    'secret.dropbox_api_secret': 'a' * 15,
    'secret.cloudflare_api_key': 'a' * 40,
    'secret.hubspot_api_key': _UUID,
    'secret.heroku_api_key': _UUID,
    'secret.mailgun_api_token': 'key-' + 'a' * 32,
    'secret.mailchimp_api_key': 'a' * 32 + '-us12',
    'secret.sentry_access_token': 'a' * 64,
    'secret.coinbase_access_token': 'a' * 64,
    'secret.netlify_access_token': 'a' * 40,
    'secret.travisci_access_token': 'a' * 22,
    'secret.twitch_api_token': 'a' * 30,
    'secret.zendesk_secret_key': 'a' * 40,
    'secret.yandex_access_token': 't1.' + 'a' * 10 + '.' + 'a' * 86,
    'secret.okta_access_token': '00' + 'a' * 40,
    'secret.datadog_access_token': 'a' * 40,
    'secret.launchdarkly_access_token': 'a' * 40,
    'secret.mapbox_api_token': 'pk.' + 'a' * 60 + '.' + 'a' * 22,
    'secret.codecov_access_token': 'a' * 32,
    'secret.airtable_api_key': 'a' * 17,
    'secret.asana_client_secret': 'a' * 32,
    'secret.bitbucket_client_id': 'a' * 32,
    'secret.fastly_api_token': 'a' * 32,
    'secret.gitter_access_token': 'a' * 40,
    'secret.kraken_access_token': 'a' * 85,
    'secret.kucoin_access_token': 'a' * 24,
    'secret.mattermost_access_token': 'a' * 26,
    'secret.confluent_access_token': 'a' * 16,
    'secret.contentful_api_token': 'a' * 43,
    'secret.droneci_access_token': 'a' * 32,
    'secret.etsy_access_token': 'a' * 24,
    'secret.finicity_api_token': 'a' * 32,
    'secret.finnhub_access_token': 'a' * 20,
    'secret.flickr_access_token': 'a' * 32,
    'secret.cisco_meraki_api_key': 'a' * 40,
    'secret.beamer_api_token': 'b_' + 'a' * 44,
    'secret.cohere_api_token': 'a' * 40,
    'secret.rapidapi_access_token': 'a' * 50,
    'secret.sendbird_access_token': 'a' * 40,
    'secret.squarespace_access_token': _UUID,
    'secret.jfrog_api_key': 'a' * 73,
    'secret.adafruit_api_key': 'a' * 32,
    'secret.adobe_client_id': 'a' * 32,
    'secret.algolia_api_key': 'a' * 32,
    'secret.alibaba_secret_key': 'a' * 30,
    'secret.asana_client_id': '1' * 16,
    'secret.bitbucket_client_secret': 'a' * 64,
    'secret.bittrex_access_key': 'a' * 32,
    'secret.bittrex_secret_key': 'a' * 32,
    'secret.cloudflare_global_api_key': 'a' * 37,
    'secret.confluent_secret_key': 'a' * 64,
    'secret.discord_client_id': '1' * 18,
    'secret.discord_client_secret': 'a' * 32,
    'secret.dropbox_long_lived_api_token': 'a' * 11 + 'AAAAAAAAAA' + 'a' * 43,
    'secret.dropbox_short_lived_api_token': 'sl.' + 'a' * 135,
    'secret.facebook_secret': 'a' * 32,
    'secret.finicity_client_secret': 'a' * 20,
    'secret.freshbooks_access_token': 'a' * 64,
    'secret.gocardless_api_token': 'live_' + 'a' * 40,
    'secret.intercom_api_key': 'a' * 60,
    'secret.jfrog_identity_token': 'a' * 64,
    'secret.kucoin_secret_key': _UUID,
    'secret.linear_client_secret': 'a' * 32,
    'secret.linkedin_client_id': 'a' * 14,
    'secret.linkedin_client_secret': 'a' * 16,
    'secret.looker_client_id': 'a' * 20,
    'secret.looker_client_secret': 'a' * 24,
    'secret.mailgun_pub_key': 'pubkey-' + 'a' * 32,
    'secret.mailgun_signing_key': 'a' * 32 + '-' + 'a' * 8 + '-' + 'a' * 8,
    'secret.messagebird_api_token': 'a' * 25,
    'secret.messagebird_client_id': _UUID,
    'secret.new_relic_browser_api_token': 'NRJS-' + 'a' * 19,
    'secret.new_relic_user_api_id': 'a' * 64,
    'secret.new_relic_user_api_key': 'NRAK-' + 'a' * 27,
    'secret.nytimes_access_token': 'a' * 32,
    'secret.plaid_api_token': 'access-sandbox-' + _UUID,
    'secret.plaid_client_id': 'a' * 24,
    'secret.plaid_secret_key': 'a' * 30,
    'secret.privateai_api_token': 'a' * 32,
    'secret.sendbird_access_id': _UUID,
    'secret.snyk_api_token': _UUID,
    'secret.sonar_api_token': 'squ_' + 'a' * 36,
    'secret.sumologic_access_id': 'su' + 'a' * 12,
    'secret.sumologic_access_token': 'a' * 64,
    'secret.twitter_access_secret': 'a' * 45,
    'secret.twitter_api_key': 'a' * 25,
    'secret.twitter_api_secret': 'a' * 50,
    'infra.internal_ip': '10.0.0.5',
    'infra.internal_hostname': 'db1.internal',
    'pii.ssn_context': '123456789',
}


def test_detects_value_near_keyword():
    findings = run('here is my sentry token abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123')
    assert any(f.category == 'secret.sentry_access_token' for f in findings)


def test_no_match_without_keyword_nearby():
    # The exact same value-shaped string, but no service keyword anywhere near it.
    findings = run('here is a random string ' + 'a' * 64 + ' with no service name around it')
    assert findings == []


def test_no_match_when_keyword_and_value_too_far_apart():
    far_padding = 'x' * 200
    findings = run('sentry' + far_padding + 'a' * 64)
    assert findings == []


def test_discord_bot_token_detected_with_keyword():
    findings = run('my discord bot token is ' + 'a' * 64)
    assert any(f.category == 'secret.discord_bot_token' for f in findings)


def test_twilio_requires_sk_prefix_shape():
    # bare 32 hex chars near "twilio" without the SK prefix should not match
    findings = run('twilio key: ' + 'a' * 32)
    assert not any(f.category == 'secret.twilio_api_key' for f in findings)
    findings2 = run('twilio key: SK' + 'a' * 32)
    assert any(f.category == 'secret.twilio_api_key' for f in findings2)


def test_confidence_is_lower_than_prefix_based_rules():
    findings = run('sentry token ' + 'a' * 64)
    assert all(f.confidence == 0.65 for f in findings)


def test_span_matches_actual_value_not_keyword():
    text = 'my sentry secret is ' + 'a' * 64 + ' ok'
    finding = run(text)[0]
    assert text[finding.span_start:finding.span_end] == finding.raw_value
    assert finding.raw_value == 'a' * 64


def test_no_duplicate_findings_for_same_span():
    # "sentry" appears twice near the same value -- should only report it once.
    findings = run('sentry sentry ' + 'a' * 64)
    assert len(findings) == 1


def test_internal_ip_flagged_near_infra_keyword():
    findings = run('the prod database is on 10.44.12.7, ssh in to debug')
    assert any(f.category == 'infra.internal_ip' and f.raw_value == '10.44.12.7' for f in findings)


def test_public_ip_not_flagged_as_internal():
    # A real public IP (Google's public DNS) is not private-range -- must not
    # be flagged even right next to an infra keyword, or this would fire on
    # completely ordinary text (e.g. "our DNS server is 8.8.8.8").
    findings = run('our dns server is 8.8.8.8')
    assert not any(f.category == 'infra.internal_ip' for f in findings)


def test_private_ip_without_infra_keyword_not_flagged():
    # A private-range IP with no infra keyword nearby (e.g. a home-router
    # tutorial) is exactly the false-positive case this rule is gated
    # against -- same reasoning as the credential rules above.
    findings = run('set your router to 192.168.1.1 to log in')
    assert not any(f.category == 'infra.internal_ip' for f in findings)


def test_internal_hostname_flagged_near_infra_keyword():
    findings = run('the deploy target is api-01.internal, check it')
    assert any(f.category == 'infra.internal_hostname' and f.raw_value == 'api-01.internal'
               for f in findings)


def test_public_hostname_not_flagged_as_internal():
    findings = run('the backend host is example.com')
    assert not any(f.category == 'infra.internal_hostname' for f in findings)


def test_no_catastrophic_backtracking_regardless_of_keyword_repetition():
    # The bounded window should keep this fast even with many keyword hits
    # and a very long overall input -- this is the whole point of the design.
    text = ('sentry ' * 5000) + ('a' * 100000)
    start = time.perf_counter()
    run(text)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f'context detection took {elapsed:.2f}s -- possible ReDoS'


# A few keyword patterns use regex metacharacters (optional separators) that
# don't split cleanly into a literal word for test text -- give those an
# explicit literal instead of trying to parse the regex.
_KEYWORD_LITERAL_OVERRIDE = {
    'linked[_-]?in': 'linkedin',
    'message[_-]?bird': 'messagebird',
    'private[_-]?ai': 'privateai',
    (r'\b(?:server|host(?:name)?|prod(?:uction)?|database|db|ssh|deploy(?:ed|ment)?|'
     r'endpoint|internal|backend|cluster|instance|vpc|subnet|gateway|k8s|kubernetes|'
     r'docker|container|vm|node)\b'): 'server',
    r'\b(?:ssn|social security)\b': 'ssn',
}


@pytest.mark.parametrize('category,keyword_pattern,value_pattern', CONTEXT_RULES)
def test_every_rule_fires_end_to_end(category, keyword_pattern, value_pattern):
    import re
    if keyword_pattern in _KEYWORD_LITERAL_OVERRIDE:
        keyword = _KEYWORD_LITERAL_OVERRIDE[keyword_pattern]
    else:
        keyword = re.split(r'\|', keyword_pattern)[0]
    value = _EXAMPLE_VALUE_BY_CATEGORY[category]
    assert re.fullmatch(value_pattern, value), f'{category}: example value does not match its own pattern'
    text = f'here is my {keyword} secret: {value}'
    findings = run(text)
    assert any(f.category == category and f.raw_value == value for f in findings), (
        f'{category}: rule did not fire on its own example')


def test_every_category_covered_by_example_table():
    all_categories = {category for category, _, _ in CONTEXT_RULES}
    assert set(_EXAMPLE_VALUE_BY_CATEGORY) == all_categories


# pii.ssn_context: the weaker, keyword-gated fallback for a bare (no dash/
# space) 9-digit SSN -- see regex_rules.py's pii.ssn for the strict
# standalone case. Separate tests since it needs a real "ssn"/"social
# security" keyword nearby, which the generic parametrized test above
# already covers via the override table; these check the never-issued-range
# exclusions specifically, and that the keyword gate is actually load-bearing.
def test_bare_ssn_near_keyword_is_flagged():
    findings = run('for the form, my ssn is 123456789 thanks')
    assert any(f.category == 'pii.ssn_context' and f.raw_value == '123456789' for f in findings)


def test_bare_9_digit_number_without_an_ssn_keyword_is_not_flagged():
    findings = run('tracking number 123456789 for your package')
    assert not any(f.category == 'pii.ssn_context' for f in findings)


@pytest.mark.parametrize('bad_ssn', [
    '000456789',  # area 000 never issued
    '666456789',  # area 666 never issued
    '900456789',  # area 900-999 never issued
    '123006789',  # group 00 never issued
    '123450000',  # serial 0000 never issued
])
def test_never_issued_ssn_ranges_are_not_flagged_even_near_keyword(bad_ssn):
    findings = run(f'my ssn is {bad_ssn} on the account')
    assert not any(f.category == 'pii.ssn_context' for f in findings)
