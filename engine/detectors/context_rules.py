"""Secrets that only count when a service name is close by: for example
"stripe" near a 32-character value. The value alone is too ordinary to
flag. Adapted from gitleaks, but matched by nearness in a small window
instead of code syntax like `key = "value"`, since chat text is prose.

The small window also keeps matching fast on long text. These rules are
less certain than prefix rules, so they warn by default instead of
blocking. About 90 services; very generic ones (a bare "password") are
left out because they would flag too much ordinary text.
"""
import re

from engine.finding import Finding
from engine.normalize import strip_line_breaks_for_detection

WINDOW = 150  # chars searched on each side of a keyword match for the value;
# must exceed the longest value pattern (~90 chars for kraken/yandex) plus
# realistic prose between the keyword and the value, or legit long secrets
# get truncated out of the search window before they can match at all.
CONFIDENCE = 0.65

CONTEXT_RULES = [
    ('secret.discord_bot_token', r'discord', r'[a-fA-F0-9]{64}'),
    ('secret.twilio_api_key', r'twilio', r'SK[0-9a-fA-F]{32}'),
    ('secret.dropbox_api_secret', r'dropbox', r'[a-z0-9]{15}'),
    ('secret.cloudflare_api_key', r'cloudflare', r'[a-z0-9_-]{40}'),
    ('secret.hubspot_api_key', r'hubspot', r'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'),
    ('secret.heroku_api_key', r'heroku', r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    ('secret.mailgun_api_token', r'mailgun', r'key-[a-f0-9]{32}'),
    ('secret.mailchimp_api_key', r'mailchimp', r'[a-f0-9]{32}-us\d{2}'),
    ('secret.sentry_access_token', r'sentry', r'[a-f0-9]{64}'),
    ('secret.coinbase_access_token', r'coinbase', r'[a-z0-9_-]{64}'),
    ('secret.netlify_access_token', r'netlify', r'[a-z0-9=_-]{40,46}'),
    ('secret.travisci_access_token', r'travis', r'[a-z0-9]{22}'),
    ('secret.twitch_api_token', r'twitch', r'[a-z0-9]{30}'),
    ('secret.zendesk_secret_key', r'zendesk', r'[a-z0-9]{40}'),
    ('secret.yandex_access_token', r'yandex', r't1\.[A-Za-z0-9_-]{1,200}\.[A-Za-z0-9_-]{86}'),
    ('secret.okta_access_token', r'okta', r'00[\w=-]{40}'),
    ('secret.datadog_access_token', r'datadog', r'[a-z0-9]{40}'),
    ('secret.launchdarkly_access_token', r'launchdarkly', r'[a-z0-9=_-]{40}'),
    ('secret.mapbox_api_token', r'mapbox', r'pk\.[a-z0-9]{60}\.[a-z0-9]{22}'),
    ('secret.codecov_access_token', r'codecov', r'[a-z0-9]{32}'),
    ('secret.airtable_api_key', r'airtable', r'[a-z0-9]{17}'),
    ('secret.asana_client_secret', r'asana', r'[a-z0-9]{32}'),
    ('secret.bitbucket_client_id', r'bitbucket', r'[a-z0-9]{32}'),
    ('secret.fastly_api_token', r'fastly', r'[a-z0-9=_-]{32}'),
    ('secret.gitter_access_token', r'gitter', r'[a-z0-9_-]{40}'),
    ('secret.kraken_access_token', r'kraken', r'[a-z0-9/=_+-]{80,90}'),
    ('secret.kucoin_access_token', r'kucoin', r'[a-f0-9]{24}'),
    ('secret.mattermost_access_token', r'mattermost', r'[a-z0-9]{26}'),
    ('secret.confluent_access_token', r'confluent', r'[a-z0-9]{16}'),
    ('secret.contentful_api_token', r'contentful', r'[a-z0-9=_-]{43}'),
    ('secret.droneci_access_token', r'droneci', r'[a-z0-9]{32}'),
    ('secret.etsy_access_token', r'etsy', r'[a-z0-9]{24}'),
    ('secret.finicity_api_token', r'finicity', r'[a-f0-9]{32}'),
    ('secret.finnhub_access_token', r'finnhub', r'[a-z0-9]{20}'),
    ('secret.flickr_access_token', r'flickr', r'[a-z0-9]{32}'),
    ('secret.cisco_meraki_api_key', r'meraki', r'[0-9a-f]{40}'),
    ('secret.beamer_api_token', r'beamer', r'b_[a-z0-9=_-]{44}'),
    ('secret.cohere_api_token', r'cohere', r'[a-zA-Z0-9]{40}'),
    ('secret.rapidapi_access_token', r'rapidapi', r'[a-z0-9_-]{50}'),
    ('secret.sendbird_access_token', r'sendbird', r'[a-f0-9]{40}'),
    ('secret.squarespace_access_token', r'squarespace',
     r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    ('secret.jfrog_api_key', r'jfrog|artifactory|bintray|xray', r'[a-z0-9]{73}'),
    ('secret.adafruit_api_key', r'adafruit', r'[a-z0-9_-]{32}'),
    ('secret.adobe_client_id', r'adobe', r'[a-f0-9]{32}'),
    ('secret.algolia_api_key', r'algolia', r'[a-z0-9]{32}'),
    ('secret.alibaba_secret_key', r'alibaba', r'[a-z0-9]{30}'),
    ('secret.asana_client_id', r'asana', r'[0-9]{16}'),
    ('secret.bitbucket_client_secret', r'bitbucket', r'[a-z0-9=_-]{64}'),
    ('secret.bittrex_access_key', r'bittrex', r'[a-z0-9]{32}'),
    ('secret.bittrex_secret_key', r'bittrex', r'[a-z0-9]{32}'),
    ('secret.cloudflare_global_api_key', r'cloudflare', r'[a-f0-9]{37}'),
    ('secret.confluent_secret_key', r'confluent', r'[a-z0-9]{64}'),
    ('secret.discord_client_id', r'discord', r'[0-9]{18}'),
    ('secret.discord_client_secret', r'discord', r'[a-z0-9=_-]{32}'),
    ('secret.dropbox_long_lived_api_token', r'dropbox', r'[a-z0-9]{11}AAAAAAAAAA[a-z0-9=_-]{43}'),
    ('secret.dropbox_short_lived_api_token', r'dropbox', r'sl\.[a-z0-9=_-]{135}'),
    ('secret.facebook_secret', r'facebook', r'[a-f0-9]{32}'),
    ('secret.finicity_client_secret', r'finicity', r'[a-z0-9]{20}'),
    ('secret.freshbooks_access_token', r'freshbooks', r'[a-z0-9]{64}'),
    ('secret.gocardless_api_token', r'gocardless', r'live_[a-z0-9=_-]{40}'),
    ('secret.intercom_api_key', r'intercom', r'[a-z0-9=_-]{60}'),
    ('secret.jfrog_identity_token', r'jfrog|artifactory|bintray|xray', r'[a-z0-9]{64}'),
    ('secret.kucoin_secret_key', r'kucoin',
     r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
    ('secret.linear_client_secret', r'linear', r'[a-f0-9]{32}'),
    ('secret.linkedin_client_id', r'linked[_-]?in', r'[a-z0-9]{14}'),
    ('secret.linkedin_client_secret', r'linked[_-]?in', r'[a-z0-9]{16}'),
    ('secret.looker_client_id', r'looker', r'[a-z0-9]{20}'),
    ('secret.looker_client_secret', r'looker', r'[a-z0-9]{24}'),
    ('secret.mailgun_pub_key', r'mailgun', r'pubkey-[a-f0-9]{32}'),
    ('secret.mailgun_signing_key', r'mailgun', r'[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}'),
    ('secret.messagebird_api_token', r'message[_-]?bird', r'[a-z0-9]{25}'),
    ('secret.messagebird_client_id', r'message[_-]?bird',
     r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
    ('secret.new_relic_browser_api_token', r'new-relic|newrelic|new_relic', r'NRJS-[a-f0-9]{19}'),
    ('secret.new_relic_user_api_id', r'new-relic|newrelic|new_relic', r'[a-z0-9]{64}'),
    ('secret.new_relic_user_api_key', r'new-relic|newrelic|new_relic', r'NRAK-[a-z0-9]{27}'),
    ('secret.nytimes_access_token', r'nytimes|new-york-times|newyorktimes', r'[a-z0-9=_-]{32}'),
    ('secret.plaid_api_token', r'plaid',
     r'access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    ('secret.plaid_client_id', r'plaid', r'[a-z0-9]{24}'),
    ('secret.plaid_secret_key', r'plaid', r'[a-z0-9]{30}'),
    ('secret.privateai_api_token', r'private[_-]?ai', r'[a-z0-9]{32}'),
    ('secret.sendbird_access_id', r'sendbird',
     r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
    ('secret.snyk_api_token', r'snyk',
     r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
    ('secret.sonar_api_token', r'sonar', r'(?:squ_|sqp_|sqa_)?[a-z0-9=_-]{40}'),
    ('secret.sumologic_access_id', r'sumo', r'su[a-zA-Z0-9]{12}'),
    ('secret.sumologic_access_token', r'sumo', r'[a-z0-9]{64}'),
    ('secret.twitter_access_secret', r'twitter', r'[a-z0-9]{45}'),
    ('secret.twitter_api_key', r'twitter', r'[a-z0-9]{25}'),
    ('secret.twitter_api_secret', r'twitter', r'[a-z0-9]{50}'),

    # Internal network details: a private IP or internal host name next to
    # words like "server" or "database". Not a password, but not something to
    # paste into a public AI either. A bare IP alone is too common to flag.
    ('infra.internal_ip',
     r'\b(?:server|host(?:name)?|prod(?:uction)?|database|db|ssh|deploy(?:ed|ment)?|'
     r'endpoint|internal|backend|cluster|instance|vpc|subnet|gateway|k8s|kubernetes|'
     r'docker|container|vm|node)\b',
     r'\b(?:10(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|'
     r'172\.(?:1[6-9]|2\d|3[01])(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}|'
     r'192\.168(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2})\b'),
    ('infra.internal_hostname',
     r'\b(?:server|host(?:name)?|prod(?:uction)?|database|db|ssh|deploy(?:ed|ment)?|'
     r'endpoint|internal|backend|cluster|instance|vpc|subnet|gateway|k8s|kubernetes|'
     r'docker|container|vm|node)\b',
     r'\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*'
     r'\.(?:internal|corp|local|lan|intra)\b'),

    # A 9-digit number without dashes only counts as an SSN right next to the
    # word "SSN" or "social security"; alone it is usually a phone or order
    # number. Numbers the SSA never issues are still left out.
    ('pii.ssn_context', r'\b(?:ssn|social security)\b',
     r'\b(?!000|666|9\d\d)[0-8]\d{2}(?!00)\d{2}(?!0000)\d{4}\b'),
]

_COMPILED = [
    (category, re.compile(keyword, re.IGNORECASE), re.compile(value))
    for category, keyword, value in CONTEXT_RULES
]


def run(text: str) -> list[Finding]:
    findings = []
    seen_spans = set()
    for category, keyword_re, value_re in _COMPILED:
        for kw_match in keyword_re.finditer(text):
            window_start = max(0, kw_match.start() - WINDOW)
            window_end = min(len(text), kw_match.end() + WINDOW)
            # Remove line breaks inside this small window only, so a value
            # wrapped onto two lines still matches. Doing it for the whole
            # message would glue unrelated lines together.
            window_text, window_index_map = strip_line_breaks_for_detection(text[window_start:window_end])
            value_match = value_re.search(window_text)
            if value_match is None:
                continue
            span_start = window_start + window_index_map[value_match.start()]
            span_end = window_start + window_index_map[value_match.end() - 1] + 1
            key = (span_start, span_end, category)
            if key in seen_spans:
                continue
            seen_spans.add(key)
            findings.append(Finding(
                span_start=span_start,
                span_end=span_end,
                category=category,
                confidence=CONFIDENCE,
                detector_id=f'context.{category}',
                raw_value=text[span_start:span_end],
            ))
    return findings
