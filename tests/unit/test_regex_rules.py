"""Tests for the gitleaks-derived detector patterns."""
import time

import pytest

from engine.detectors.regex_rules import RULES, run


def test_detects_aws_access_token_shape():
    findings = run('here is my key AKIAABCDEFGHIJKLMNOP please help')
    assert any(f.category == 'secret.aws_access_token' for f in findings)


def test_detects_github_pat():
    findings = run('token: ghp_' + 'a' * 36)
    assert any(f.category == 'secret.github_pat' for f in findings)


def test_detects_gitlab_pat():
    findings = run('token: glpat-' + 'a' * 20)
    assert any(f.category == 'secret.gitlab_pat' for f in findings)


def test_detects_slack_bot_token():
    findings = run('xoxb-1234567890-1234567890123-abcdefghijklmnop')
    assert any(f.category == 'secret.slack_bot_token' for f in findings)


def test_detects_stripe_key():
    findings = run('sk_live_' + 'a' * 24)
    assert any(f.category == 'secret.stripe_key' for f in findings)


def test_detects_generic_private_key_header():
    findings = run('-----BEGIN RSA PRIVATE KEY-----')
    assert any(f.category == 'secret.generic_private_key' for f in findings)


def test_detects_openai_api_key():
    findings = run('here is sk-' + 'a' * 20 + 'T3BlbkFJ' + 'b' * 20)
    assert any(f.category == 'secret.openai_api_key' for f in findings)


def test_detects_npm_access_token():
    findings = run('npm_' + 'a1B2' * 9)
    assert any(f.category == 'secret.npm_access_token' for f in findings)


def test_detects_slack_webhook_url():
    findings = run('https://hooks.slack.com/services/' + 'A' * 44)
    assert any(f.category == 'secret.slack_webhook_url' for f in findings)


def test_detects_sendgrid_api_key():
    findings = run('SG.' + 'a' * 66)
    assert any(f.category == 'secret.sendgrid_api_key' for f in findings)


def test_detects_jwt():
    findings = run('ey' + 'a' * 20 + '.ey' + 'b' * 20 + '.' + 'c' * 15)
    assert any(f.category == 'secret.jwt' for f in findings)


def test_detects_digitalocean_pat():
    findings = run('dop_v1_' + 'a' * 64)
    assert any(f.category == 'secret.digitalocean_pat' for f in findings)


def test_detects_databricks_api_token():
    findings = run('dapi' + 'a' * 32)
    assert any(f.category == 'secret.databricks_api_token' for f in findings)


def test_detects_planetscale_api_token():
    findings = run('pscale_tkn_' + 'a' * 32)
    assert any(f.category == 'secret.planetscale_api_token' for f in findings)


def test_detects_postman_api_token():
    findings = run('PMAK-' + 'a' * 24 + '-' + 'b' * 34)
    assert any(f.category == 'secret.postman_api_token' for f in findings)


def test_detects_pypi_upload_token():
    findings = run('pypi-AgEIcHlwaS5vcmc' + 'a' * 60)
    assert any(f.category == 'secret.pypi_upload_token' for f in findings)


def test_detects_square_access_token():
    findings = run('sq0atp-' + 'a' * 22)
    assert any(f.category == 'secret.square_access_token' for f in findings)


def test_detects_shopify_access_token():
    findings = run('shpat_' + 'a1b2c3d4' * 4)
    assert any(f.category == 'secret.shopify_access_token' for f in findings)


def test_detects_shopify_custom_access_token():
    findings = run('shpca_' + 'a1b2c3d4' * 4)
    assert any(f.category == 'secret.shopify_custom_access_token' for f in findings)


def test_detects_shopify_private_app_access_token():
    findings = run('shppa_' + 'a1b2c3d4' * 4)
    assert any(f.category == 'secret.shopify_private_app_access_token' for f in findings)


def test_detects_hashicorp_tf_api_token():
    findings = run('a' * 14 + '.atlasv1.' + 'b' * 65)
    assert any(f.category == 'secret.hashicorp_tf_api_token' for f in findings)


def test_detects_cloudflare_origin_ca_key():
    findings = run('v1.0-' + 'a' * 24 + '-' + 'b' * 146)
    assert any(f.category == 'secret.cloudflare_origin_ca_key' for f in findings)


def test_detects_grafana_api_key():
    findings = run('eyJrIjoi' + 'a' * 80)
    assert any(f.category == 'secret.grafana_api_key' for f in findings)


def test_detects_grafana_cloud_api_token():
    findings = run('glc_' + 'a' * 40)
    assert any(f.category == 'secret.grafana_cloud_api_token' for f in findings)


def test_detects_age_secret_key():
    charset = 'QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L'
    findings = run('AGE-SECRET-KEY-1' + (charset * 2)[:58])
    assert any(f.category == 'secret.age_secret_key' for f in findings)


def test_detects_gcp_api_key():
    findings = run('AIza' + 'a' * 35)
    assert any(f.category == 'secret.gcp_api_key' for f in findings)


def test_detects_linear_api_key():
    findings = run('lin_api_' + 'a' * 40)
    assert any(f.category == 'secret.linear_api_key' for f in findings)


def test_detects_notion_api_token():
    findings = run('ntn_' + '1' * 11 + 'a' * 35)
    assert any(f.category == 'secret.notion_api_token' for f in findings)


def test_detects_rubygems_api_token():
    findings = run('rubygems_' + 'a' * 48)
    assert any(f.category == 'secret.rubygems_api_token' for f in findings)


def test_detects_vault_batch_token():
    findings = run('hvb.' + 'a' * 138)
    assert any(f.category == 'secret.vault_batch_token' for f in findings)


def test_detects_vault_service_token():
    findings = run('hvs.' + 'a' * 90)
    assert any(f.category == 'secret.vault_service_token' for f in findings)


def test_detects_new_relic_insert_key():
    findings = run('NRII-' + 'a' * 32)
    assert any(f.category == 'secret.new_relic_insert_key' for f in findings)


def test_detects_telegram_bot_token():
    findings = run('123456789:A' + 'a' * 34)
    assert any(f.category == 'secret.telegram_bot_token' for f in findings)


def test_detects_twitter_bearer_token():
    findings = run('A' * 22 + 'a' * 90)
    assert any(f.category == 'secret.twitter_bearer_token' for f in findings)


def test_detects_anthropic_api_key():
    findings = run('sk-ant-api03-' + 'a' * 93 + 'AA')
    assert any(f.category == 'secret.anthropic_api_key' for f in findings)


def test_detects_anthropic_admin_api_key():
    findings = run('sk-ant-admin01-' + 'a' * 93 + 'AA')
    assert any(f.category == 'secret.anthropic_admin_api_key' for f in findings)


def test_detects_aws_bedrock_api_key():
    findings = run('ABSK' + 'a' * 109)
    assert any(f.category == 'secret.aws_bedrock_api_key' for f in findings)


def test_detects_onepassword_secret_key():
    findings = run('A3-' + 'A' * 6 + '-' + 'A' * 11 + '-' + 'A' * 5 + '-' + 'A' * 5 + '-' + 'A' * 5)
    assert any(f.category == 'secret.onepassword_secret_key' for f in findings)


def test_detects_onepassword_service_account_token():
    findings = run('ops_eyJ' + 'a' * 250)
    assert any(f.category == 'secret.onepassword_service_account_token' for f in findings)


def test_detects_artifactory_reference_token():
    findings = run('cmVmd' + 'a' * 59)
    assert any(f.category == 'secret.artifactory_reference_token' for f in findings)


def test_detects_clojars_api_token():
    findings = run('CLOJARS_' + 'a' * 60)
    assert any(f.category == 'secret.clojars_api_token' for f in findings)


def test_detects_digitalocean_access_token():
    findings = run('doo_v1_' + 'a' * 64)
    assert any(f.category == 'secret.digitalocean_access_token' for f in findings)


def test_detects_digitalocean_refresh_token():
    findings = run('dor_v1_' + 'a' * 64)
    assert any(f.category == 'secret.digitalocean_refresh_token' for f in findings)


def test_detects_doppler_api_token():
    findings = run('dp.pt.' + 'a' * 43)
    assert any(f.category == 'secret.doppler_api_token' for f in findings)


def test_detects_dynatrace_api_token():
    findings = run('dt0c01.' + 'a' * 24 + '.' + 'b' * 64)
    assert any(f.category == 'secret.dynatrace_api_token' for f in findings)


def test_detects_easypost_api_token():
    findings = run('EZAK' + 'a' * 54)
    assert any(f.category == 'secret.easypost_api_token' for f in findings)


def test_detects_perplexity_api_key():
    findings = run('pplx-' + 'a' * 48)
    assert any(f.category == 'secret.perplexity_api_key' for f in findings)


def test_detects_huggingface_access_token():
    findings = run('hf_' + 'a' * 34)
    assert any(f.category == 'secret.huggingface_access_token' for f in findings)


def test_detects_github_fine_grained_pat():
    findings = run('github_pat_' + 'a' * 82)
    assert any(f.category == 'secret.github_fine_grained_pat' for f in findings)


def test_detects_github_oauth():
    findings = run('gho_' + 'a' * 36)
    assert any(f.category == 'secret.github_oauth' for f in findings)


def test_detects_github_refresh_token():
    findings = run('ghr_' + 'a' * 36)
    assert any(f.category == 'secret.github_refresh_token' for f in findings)


def test_detects_gitlab_deploy_token():
    findings = run('gldt-' + 'a' * 20)
    assert any(f.category == 'secret.gitlab_deploy_token' for f in findings)


def test_detects_grafana_service_account_token():
    findings = run('glsa_' + 'a' * 32 + '_' + 'a' * 8)
    assert any(f.category == 'secret.grafana_service_account_token' for f in findings)


def test_detects_planetscale_oauth_token():
    findings = run('pscale_oauth_' + 'a' * 32)
    assert any(f.category == 'secret.planetscale_oauth_token' for f in findings)


def test_detects_planetscale_password():
    findings = run('pscale_pw_' + 'a' * 32)
    assert any(f.category == 'secret.planetscale_password' for f in findings)


def test_detects_prefect_api_token():
    findings = run('pnu_' + 'a' * 36)
    assert any(f.category == 'secret.prefect_api_token' for f in findings)


def test_detects_pulumi_api_token():
    findings = run('pul-' + 'a' * 40)
    assert any(f.category == 'secret.pulumi_api_token' for f in findings)


def test_detects_scalingo_api_token():
    findings = run('tk-us-' + 'a' * 48)
    assert any(f.category == 'secret.scalingo_api_token' for f in findings)


def test_detects_shippo_api_token():
    findings = run('shippo_live_' + 'a' * 40)
    assert any(f.category == 'secret.shippo_api_token' for f in findings)


def test_detects_shopify_shared_secret():
    findings = run('shpss_' + 'a' * 32)
    assert any(f.category == 'secret.shopify_shared_secret' for f in findings)


def test_detects_slack_app_token():
    findings = run('xapp-1-' + 'A' * 10 + '-1234567890-' + 'a' * 10)
    assert any(f.category == 'secret.slack_app_token' for f in findings)


def test_detects_slack_legacy_token():
    findings = run('xox' + 'o' + '-1-2-3-' + 'a' * 10)
    assert any(f.category == 'secret.slack_legacy_token' for f in findings)


def test_detects_slack_user_token():
    findings = run('xoxp-1234567890-1234567890-1234567890-' + 'a' * 30)
    assert any(f.category == 'secret.slack_user_token' for f in findings)


def test_detects_sourcegraph_access_token():
    findings = run('sgp_' + 'a' * 40)
    assert any(f.category == 'secret.sourcegraph_access_token' for f in findings)


def test_detects_typeform_api_token():
    findings = run('tfp_' + 'a' * 59)
    assert any(f.category == 'secret.typeform_api_token' for f in findings)


def test_detects_yandex_api_key():
    findings = run('AQVN' + 'a' * 35)
    assert any(f.category == 'secret.yandex_api_key' for f in findings)


def test_detects_airtable_personal_access_token():
    findings = run('pat' + 'a' * 14 + '.' + 'a' * 64)
    assert any(f.category == 'secret.airtable_personal_access_token' for f in findings)


def test_detects_alibaba_access_key_id():
    findings = run('LTAI' + 'a' * 20)
    assert any(f.category == 'secret.alibaba_access_key_id' for f in findings)


def test_detects_atlassian_api_token():
    findings = run('ATATT3' + 'a' * 186)
    assert any(f.category == 'secret.atlassian_api_token' for f in findings)


def test_detects_clickhouse_cloud_api_secret_key():
    findings = run('4b1d' + 'a' * 38)
    assert any(f.category == 'secret.clickhouse_cloud_api_secret_key' for f in findings)


def test_detects_defined_networking_api_token():
    findings = run('dnkey-' + 'a' * 26 + '-' + 'a' * 52)
    assert any(f.category == 'secret.defined_networking_api_token' for f in findings)


def test_detects_duffel_api_token():
    findings = run('duffel_test_' + 'a' * 43)
    assert any(f.category == 'secret.duffel_api_token' for f in findings)


_BATCH3_EXAMPLES = {
    'secret.adobe_client_secret': 'p8e-' + 'a' * 32,
    'secret.artifactory_api_key': 'AKCp' + 'a' * 69,
    'secret.azure_ad_client_secret': 'abc1Q~' + 'a' * 32,
    'secret.facebook_page_access_token': 'EAAM' + 'a' * 100,
    'secret.facebook_access_token': '1' * 15 + '|' + 'a' * 27,
    'secret.flutterwave_encryption_key': 'FLWSECK_TEST-' + 'a' * 12,
    'secret.flutterwave_public_key': 'FLWPUBK_TEST-' + 'a' * 32 + '-X',
    'secret.flutterwave_secret_key': 'FLWSECK_TEST-' + 'a' * 32 + '-X',
    'secret.flyio_access_token': 'fo1_' + 'a' * 43,
    'secret.frameio_api_token': 'fio-u-' + 'a' * 64,
    'secret.heroku_api_key_v2': 'HRKU-AA' + 'a' * 58,
    'secret.huggingface_organization_api_token': 'api_org_' + 'a' * 34,
    'secret.infracost_api_token': 'ico-' + 'a' * 32,
    'secret.microsoft_teams_webhook': (
        'https://sub.webhook.office.com/webhookb2/'
        + 'a' * 8 + '-' + 'a' * 4 + '-' + 'a' * 4 + '-' + 'a' * 4 + '-' + 'a' * 12
        + '@' + 'a' * 8 + '-' + 'a' * 4 + '-' + 'a' * 4 + '-' + 'a' * 4 + '-' + 'a' * 12
        + '/IncomingWebhook/' + 'a' * 32 + '/'
        + 'a' * 8 + '-' + 'a' * 4 + '-' + 'a' * 4 + '-' + 'a' * 4 + '-' + 'a' * 12
    ),
    'secret.octopus_deploy_api_key': 'API-' + 'A' * 26,
    'secret.openshift_user_token': 'sha256~' + 'a' * 43,
    'secret.readme_api_token': 'rdme_' + 'a' * 70,
    'secret.sendinblue_api_token': 'xkeysib-' + 'a' * 64 + '-' + 'a' * 16,
    'secret.sentry_org_token': 'sntrys_eyJpYXQiO' + 'a' * 10 + '_' + 'a' * 43,
    'secret.sentry_user_token': 'sntryu_' + 'a' * 64,
    'secret.settlemint_application_access_token': 'sm_aat_' + 'a' * 16,
    'secret.settlemint_personal_access_token': 'sm_pat_' + 'a' * 16,
    'secret.settlemint_service_access_token': 'sm_sat_' + 'a' * 16,
    'secret.yandex_aws_access_token': 'YC' + 'a' * 38,
    'secret.slack_config_access_token': 'xoxe.xoxb-1-' + 'A' * 163,
    'secret.slack_config_refresh_token': 'xoxe-1-' + 'A' * 146,
    'secret.slack_legacy_bot_token': 'xoxb-' + '1' * 8 + '-' + 'a' * 18,
    'secret.slack_legacy_workspace_token': 'xoxa-' + 'a' * 8,
    'secret.gitlab_cicd_job_token': 'glcbt-abcde_' + 'a' * 20,
    'secret.gitlab_feature_flag_client_token': 'glffct-' + 'a' * 20,
    'secret.gitlab_feed_token': 'glft-' + 'a' * 20,
    'secret.gitlab_incoming_mail_token': 'glimt-' + 'a' * 25,
    'secret.gitlab_kubernetes_agent_token': 'glagent-' + 'a' * 50,
    'secret.gitlab_oauth_app_secret': 'gloas-' + 'a' * 64,
    'secret.gitlab_pat_routable': 'glpat-' + 'a' * 27 + '.' + 'aa' + 'a' * 7,
    'secret.gitlab_ptt': 'glptt-' + 'a' * 40,
    'secret.gitlab_rrt': 'GR1348941' + 'a' * 20,
    'secret.gitlab_runner_authentication_token': 'glrt-' + 'a' * 20,
    'secret.gitlab_runner_authentication_token_routable': 'glrt-t1_' + 'a' * 27 + '.' + 'aa' + 'a' * 7,
    'secret.gitlab_scim_token': 'glsoat-' + 'a' * 20,
    'secret.gitlab_session_cookie': '_gitlab_session=' + 'a' * 32,
    'secret.maxmind_license_key': 'a' * 6 + '_' + 'a' * 29 + '_mmk',
}


@pytest.mark.parametrize('category', sorted(_BATCH3_EXAMPLES))
def test_batch3_rule_fires_on_its_example(category):
    value = _BATCH3_EXAMPLES[category]
    findings = run(f'here it is: {value} thanks')
    assert any(f.category == category for f in findings), f'{category}: did not fire on its own example'


def test_batch3_covers_every_new_rule():
    known_before_batch3 = {
        'secret.aws_access_token', 'secret.github_pat', 'secret.gitlab_pat', 'secret.slack_bot_token',
        'secret.stripe_key', 'secret.generic_private_key', 'secret.openai_api_key', 'secret.npm_access_token',
        'secret.slack_webhook_url', 'secret.sendgrid_api_key', 'secret.jwt', 'secret.digitalocean_pat',
        'secret.databricks_api_token', 'secret.planetscale_api_token', 'secret.postman_api_token',
        'secret.pypi_upload_token', 'secret.square_access_token', 'secret.shopify_access_token',
        'secret.shopify_custom_access_token', 'secret.shopify_private_app_access_token',
        'secret.hashicorp_tf_api_token', 'secret.cloudflare_origin_ca_key', 'secret.grafana_api_key',
        'secret.grafana_cloud_api_token', 'secret.age_secret_key', 'secret.gcp_api_key', 'secret.linear_api_key',
        'secret.notion_api_token', 'secret.rubygems_api_token', 'secret.vault_batch_token',
        'secret.vault_service_token', 'secret.new_relic_insert_key', 'secret.telegram_bot_token',
        'secret.twitter_bearer_token', 'secret.anthropic_api_key', 'secret.anthropic_admin_api_key',
        'secret.aws_bedrock_api_key', 'secret.onepassword_secret_key', 'secret.onepassword_service_account_token',
        'secret.artifactory_reference_token', 'secret.clojars_api_token', 'secret.digitalocean_access_token',
        'secret.digitalocean_refresh_token', 'secret.doppler_api_token', 'secret.dynatrace_api_token',
        'secret.easypost_api_token', 'secret.perplexity_api_key', 'secret.huggingface_access_token',
        'secret.github_fine_grained_pat', 'secret.github_oauth', 'secret.github_refresh_token',
        'secret.gitlab_deploy_token', 'secret.grafana_service_account_token', 'secret.planetscale_oauth_token',
        'secret.planetscale_password', 'secret.prefect_api_token', 'secret.pulumi_api_token',
        'secret.scalingo_api_token', 'secret.shippo_api_token', 'secret.shopify_shared_secret',
        'secret.slack_app_token', 'secret.slack_legacy_token', 'secret.slack_user_token',
        'secret.sourcegraph_access_token', 'secret.typeform_api_token', 'secret.yandex_api_key',
        'secret.airtable_personal_access_token', 'secret.alibaba_access_key_id', 'secret.atlassian_api_token',
        'secret.clickhouse_cloud_api_secret_key', 'secret.defined_networking_api_token', 'secret.duffel_api_token',
        'pii.email',
    }
    # pii.ssn was added after batch3 (a PII-breadth pass, not a gitleaks
    # port), so it's excluded here rather than counted as a batch3 gap --
    # it has its own dedicated tests above (test_detects_ssn_with_dashes
    # etc.), not a _BATCH3_EXAMPLES entry.
    added_after_batch3 = {'pii.ssn'}
    all_categories = {category for category, _ in RULES}
    new_categories = all_categories - known_before_batch3 - added_after_batch3
    assert new_categories == set(_BATCH3_EXAMPLES)


def test_detects_email():
    findings = run('contact me at john@acme.com thanks')
    assert any(f.category == 'pii.email' for f in findings)


def test_no_false_positive_on_plain_text():
    findings = run('just a normal sentence with no secrets in it')
    assert findings == []


def test_span_matches_actual_match_position():
    text = 'prefix AKIAABCDEFGHIJKLMNOP suffix'
    finding = run(text)[0]
    assert text[finding.span_start:finding.span_end] == finding.raw_value


def test_no_catastrophic_backtracking_on_long_ambiguous_text():
    # Regression test for a real ReDoS: the original unbounded email regex
    # ([A-Za-z0-9._%+-]+@...) took 14+ seconds on 100KB of ordinary text with
    # no email in it, because the char class overlaps with plain letters/
    # digits/dots -- no adversarial intent needed, just a long message.
    text = 'a' * 100_000 + '.' + 'b' * 100_000
    start = time.perf_counter()
    run(text)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f'regex took {elapsed:.2f}s on ordinary long text -- possible ReDoS regression'


# Regression tests for corpus.json bx-006/bx-017: a single space or tab
# injected mid-token used to defeat every rule (none tolerate whitespace
# inside the token). Fixed via SPACE_TOLERANT_RULES, a small anchor-bounded
# space/tab-tolerant scan for a handful of high-value prefixes.
@pytest.mark.parametrize('category,text', [
    ('secret.aws_access_token', 'AKIA ABCDEFGHIJKLMNOP'),
    ('secret.aws_access_token', 'AKIA\tABCDEFGHIJKLMNOP'),
    ('secret.github_pat', 'ghp_' + 'a' * 18 + ' ' + 'a' * 18),
    ('secret.slack_bot_token', 'xoxb-1234567890-1234 567890123-abcdefghijklmnop'),
    ('secret.stripe_key', 'sk_live_abcdefg hijklmnopqrstuvwx'),
    ('secret.openai_api_key', 'sk-' + 'a' * 10 + ' ' + 'a' * 10 + 'T3BlbkFJ' + 'a' * 20),
    ('secret.anthropic_api_key', 'sk-ant-api03-' + 'a' * 46 + ' ' + 'a' * 47 + 'AA'),
    ('secret.npm_access_token', 'npm_abc def ghijklmnopqrstuvwxyz0123456789'),
])
def test_space_tolerant_rule_catches_whitespace_injected_token(category, text):
    findings = run(text)
    assert any(f.category == category for f in findings), f'{category}: did not fire on {text!r}'


def test_space_tolerant_scan_does_not_duplicate_an_already_clean_match():
    # A token with no whitespace should be found once by the normal pass,
    # not a second time by the space-tolerant pass.
    findings = run('here is AKIAABCDEFGHIJKLMNOP with no spaces')
    matches = [f for f in findings if f.category == 'secret.aws_access_token']
    assert len(matches) == 1


def test_space_tolerant_span_matches_actual_text():
    text = 'prefix AKIA ABCDEFGHIJKLMNOP suffix'
    finding = next(f for f in run(text) if f.category == 'secret.aws_access_token')
    assert text[finding.span_start:finding.span_end] == finding.raw_value
    assert finding.raw_value == 'AKIA ABCDEFGHIJKLMNOP'


def test_space_tolerant_scan_is_linear_not_quadratic():
    # Each anchor's scan window is a small bounded constant, so cost scales
    # with the number of anchor occurrences, not the window size squared --
    # confirms no ReDoS reintroduced via this newer code path. Asserts on the
    # *scaling ratio* between a 4x-larger and a baseline input rather than an
    # absolute wall-clock ceiling -- an absolute-ms threshold is machine-speed
    # dependent and was observed to flake (3.7-4.4s on a loaded/slower box vs.
    # a 2.0s ceiling tuned on a faster one). O(n) predicts ~4x; O(n^2) predicts
    # ~16x; 8x leaves headroom for scheduling noise while still catching real
    # quadratic blowup.
    unit = 'sk- some ordinary text here '  # one "sk-" anchor, no real match
    small_text = unit * 7_500
    large_text = unit * 30_000  # 4x the input size

    run(small_text)  # warm up (import/regex-compile caching) before timing either
    start = time.perf_counter()
    run(small_text)
    small_elapsed = time.perf_counter() - start

    start = time.perf_counter()
    run(large_text)
    large_elapsed = time.perf_counter() - start

    ratio = large_elapsed / max(small_elapsed, 1e-6)
    assert ratio < 8.0, (
        f'space-tolerant scan scaled {ratio:.1f}x for a 4x-larger input '
        f'({small_elapsed:.3f}s -> {large_elapsed:.3f}s) -- possible ReDoS'
    )


# Credit card detection (Luhn + real BIN-range validated). All numbers below
# are the actual, widely-published test card numbers issuers/processors
# (Stripe, PayPal, etc.) publish for integration testing -- never real cards,
# but real enough to genuinely exercise the network-prefix + Luhn logic
# rather than a hand-rolled fake that happens to pass.
@pytest.mark.parametrize('card,network', [
    ('4242424242424242', 'visa'),
    ('4111111111111111', 'visa'),
    ('5555555555554444', 'mastercard'),
    ('378282246310005', 'amex'),
    ('6011111111111117', 'discover'),
    ('30569309025904', 'diners'),
    ('3530111333300000', 'jcb'),
])
def test_detects_valid_credit_card_across_major_networks(card, network):
    findings = run(f'here is my card number {card} for the order')
    matches = [f for f in findings if f.category == 'pii.credit_card']
    assert len(matches) == 1, f'{network} test number {card} not detected'
    assert matches[0].raw_value == card


def test_credit_card_detection_tolerates_spaces_and_dashes():
    findings = run('card: 4242 4242 4242 4242')
    assert any(f.category == 'pii.credit_card' and f.raw_value == '4242 4242 4242 4242'
               for f in findings)
    findings = run('card: 4242-4242-4242-4242')
    assert any(f.category == 'pii.credit_card' and f.raw_value == '4242-4242-4242-4242'
               for f in findings)


def test_credit_card_shape_with_bad_checksum_is_not_flagged():
    # Same length + Visa prefix as the real test number above, but the last
    # digit is changed so the Luhn checksum fails -- proves the checksum
    # stage is actually load-bearing, not a no-op.
    findings = run('card: 4242424242424241')
    assert not any(f.category == 'pii.credit_card' for f in findings)


def test_random_16_digit_number_without_valid_bin_prefix_is_not_flagged():
    # Right length, Luhn-valid-or-not doesn't matter -- no real network
    # starts with "99", so this must never be flagged as a card regardless.
    findings = run('order number 9999999999999999')
    assert not any(f.category == 'pii.credit_card' for f in findings)


def test_phone_number_is_not_flagged_as_credit_card():
    findings = run('call me at 555-867-5309 anytime')
    assert not any(f.category == 'pii.credit_card' for f in findings)


def test_credit_card_span_matches_actual_text():
    text = 'prefix 4242424242424242 suffix'
    finding = next(f for f in run(text) if f.category == 'pii.credit_card')
    assert text[finding.span_start:finding.span_end] == finding.raw_value


def test_credit_card_scan_is_linear_not_quadratic():
    # Same ReDoS-regression shape as the space-tolerant scan above -- the
    # card-candidate regex is new and touches the whole message, so it gets
    # the same scaling check.
    unit = 'order 12345 shipped yesterday, thanks '  # no digit run near card length
    small_text = unit * 7_500
    large_text = unit * 30_000

    run(small_text)
    start = time.perf_counter()
    run(small_text)
    small_elapsed = time.perf_counter() - start

    start = time.perf_counter()
    run(large_text)
    large_elapsed = time.perf_counter() - start

    ratio = large_elapsed / max(small_elapsed, 1e-6)
    assert ratio < 8.0, (
        f'credit-card scan scaled {ratio:.1f}x for a 4x-larger input '
        f'({small_elapsed:.3f}s -> {large_elapsed:.3f}s) -- possible ReDoS'
    )


# Strict-format SSN (dash/space-separated, never-issued ranges excluded).
def test_detects_ssn_with_dashes():
    findings = run('my ssn is 123-45-6789 for the form')
    assert any(f.category == 'pii.ssn' and f.raw_value == '123-45-6789' for f in findings)


def test_detects_ssn_with_spaces():
    findings = run('my ssn is 123 45 6789 for the form')
    assert any(f.category == 'pii.ssn' and f.raw_value == '123 45 6789' for f in findings)


@pytest.mark.parametrize('bad_ssn', [
    '000-45-6789',  # area 000 never issued
    '666-45-6789',  # area 666 never issued
    '900-45-6789',  # area 900-999 never issued
    '123-00-6789',  # group 00 never issued
    '123-45-0000',  # serial 0000 never issued
])
def test_never_issued_ssn_ranges_are_not_flagged(bad_ssn):
    findings = run(f'reference number {bad_ssn} on file')
    assert not any(f.category == 'pii.ssn' for f in findings)


def test_bare_9_digit_number_without_separators_is_not_flagged_as_ssn():
    # By design -- see pii.ssn_context in context_rules.py for the weaker,
    # keyword-gated fallback that DOES catch this shape.
    findings = run('tracking number 123456789 for your package')
    assert not any(f.category == 'pii.ssn' for f in findings)
