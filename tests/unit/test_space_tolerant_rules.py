"""Per-rule verification for regex_rules.py's SPACE_TOLERANT_RULES (the
anchor-bounded space/tab-tolerant scan that fixes corpus.json bx-006/bx-017).
One real synthetic example per covered category, checked three ways: it
matches its own value_re standalone, the un-injected form is caught by the
normal exact-match pass, and a single space injected into the TAIL (the
realistic wrap/paste-artifact pattern) at several offsets is still caught
by the space-tolerant pass with the correct span. This exists because two
earlier window-sizing bugs (context_rules.py's WINDOW=50, and this module's
own tab-vs-space guard) were only caught by an end-to-end fire-test per
rule, never by eyeballing the pattern."""
import pytest

from engine.detectors.regex_rules import RULES, SPACE_TOLERANT_RULES, run

EXAMPLES = {
    'secret.aws_access_token': 'AKIA' + 'A' * 16,
    'secret.github_pat': 'ghp_' + 'a' * 36,
    'secret.github_fine_grained_pat': 'github_pat_' + 'a' * 82,
    'secret.slack_bot_token': 'xoxb-' + '1' * 10 + '-' + '1' * 10 + 'a',
    'secret.stripe_key': 'sk_test_' + 'a' * 10,
    'secret.openai_api_key': 'sk-' + 'a' * 20 + 'T3BlbkFJ' + 'a' * 20,
    'secret.anthropic_api_key': 'sk-ant-api03-' + 'a' * 93 + 'AA',
    'secret.anthropic_admin_api_key': 'sk-ant-admin01-' + 'a' * 93 + 'AA',
    'secret.npm_access_token': 'npm_' + 'a' * 36,
    'secret.gitlab_pat': 'glpat-' + 'a' * 20,
    'secret.sendgrid_api_key': 'SG.' + 'a' * 66,
    'secret.digitalocean_pat': 'dop_v1_' + 'a' * 64,
    'secret.digitalocean_access_token': 'doo_v1_' + 'a' * 64,
    'secret.digitalocean_refresh_token': 'dor_v1_' + 'a' * 64,
    'secret.databricks_api_token': 'dapi' + 'a' * 32,
    'secret.planetscale_api_token': 'pscale_tkn_' + 'a' * 32,
    'secret.planetscale_oauth_token': 'pscale_oauth_' + 'a' * 32,
    'secret.planetscale_password': 'pscale_pw_' + 'a' * 32,
    'secret.postman_api_token': 'PMAK-' + 'a' * 24 + '-' + 'a' * 34,
    'secret.square_access_token': 'EAAA' + 'a' * 22,
    'secret.shopify_access_token': 'shpat_' + 'a' * 32,
    'secret.shopify_custom_access_token': 'shpca_' + 'a' * 32,
    'secret.shopify_private_app_access_token': 'shppa_' + 'a' * 32,
    'secret.shopify_shared_secret': 'shpss_' + 'a' * 32,
    'secret.cloudflare_origin_ca_key': 'v1.0-' + 'a' * 24 + '-' + 'a' * 146,
    'secret.age_secret_key': 'AGE-SECRET-KEY-1' + 'Q' * 58,
    'secret.gcp_api_key': 'AIza' + 'a' * 35,
    'secret.linear_api_key': 'lin_api_' + 'a' * 40,
    'secret.notion_api_token': 'ntn_' + '1' * 11 + 'a' * 35,
    'secret.rubygems_api_token': 'rubygems_' + 'a' * 48,
    'secret.new_relic_insert_key': 'NRII-' + 'a' * 32,
    'secret.twitter_bearer_token': 'A' * 22 + 'a' * 80,
    'secret.aws_bedrock_api_key': 'ABSK' + 'a' * 109,
    'secret.artifactory_reference_token': 'cmVmd' + 'a' * 59,
    'secret.clojars_api_token': 'CLOJARS_' + 'a' * 60,
    'secret.doppler_api_token': 'dp.pt.' + 'a' * 43,
    'secret.dynatrace_api_token': 'dt0c01.' + 'a' * 24 + '.' + 'a' * 64,
    'secret.easypost_api_token': 'EZAK' + 'a' * 54,
    'secret.perplexity_api_key': 'pplx-' + 'a' * 48,
    'secret.huggingface_access_token': 'hf_' + 'a' * 34,
    'secret.github_oauth': 'gho_' + 'a' * 36,
    'secret.github_refresh_token': 'ghr_' + 'a' * 36,
    'secret.gitlab_deploy_token': 'gldt-' + 'a' * 20,
    'secret.grafana_service_account_token': 'glsa_' + 'a' * 32 + '_' + 'a' * 8,
    'secret.prefect_api_token': 'pnu_' + 'a' * 36,
    'secret.pulumi_api_token': 'pul-' + 'a' * 40,
    'secret.scalingo_api_token': 'tk-us-' + 'a' * 48,
    'secret.shippo_api_token': 'shippo_live_' + 'a' * 40,
    'secret.slack_app_token': 'xapp-1-' + 'a' * 10 + '-1-' + 'a' * 10,
    'secret.slack_legacy_token': 'xoxo-1-2-3-' + 'a' * 10,
    'secret.slack_user_token': 'xoxp-' + '1' * 10 + '-' + '1' * 10 + '-' + '1' * 10 + '-' + 'a' * 28,
    'secret.sourcegraph_access_token': 'sgp_' + 'a' * 16 + '_' + 'a' * 40,
    'secret.typeform_api_token': 'tfp_' + 'a' * 59,
    'secret.yandex_api_key': 'AQVN' + 'a' * 35,
    'secret.alibaba_access_key_id': 'LTAI' + 'a' * 20,
    'secret.atlassian_api_token': 'ATATT3' + 'a' * 186,
    'secret.clickhouse_cloud_api_secret_key': '4b1d' + 'a' * 38,
    'secret.defined_networking_api_token': 'dnkey-' + 'a' * 26 + '-' + 'a' * 52,
    'secret.duffel_api_token': 'duffel_test_' + 'a' * 43,
    'secret.adobe_client_secret': 'p8e-' + 'a' * 32,
    'secret.artifactory_api_key': 'AKCp' + 'a' * 69,
    'secret.facebook_page_access_token': 'EAAM' + 'a' * 100,
    'secret.flutterwave_encryption_key': 'FLWSECK_TEST-' + 'a' * 12,
    'secret.flutterwave_public_key': 'FLWPUBK_TEST-' + 'a' * 32 + '-X',
    'secret.flutterwave_secret_key': 'FLWSECK_TEST-' + 'a' * 32 + '-X',
    'secret.flyio_access_token': 'fo1_' + 'a' * 43,
    'secret.frameio_api_token': 'fio-u-' + 'a' * 64,
    'secret.heroku_api_key_v2': 'HRKU-AA' + 'a' * 58,
    'secret.huggingface_organization_api_token': 'api_org_' + 'a' * 34,
    'secret.infracost_api_token': 'ico-' + 'a' * 32,
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
    'secret.gitlab_cicd_job_token': 'glcbt-a_' + 'a' * 20,
    'secret.gitlab_feature_flag_client_token': 'glffct-' + 'a' * 20,
    'secret.gitlab_feed_token': 'glft-' + 'a' * 20,
    'secret.gitlab_incoming_mail_token': 'glimt-' + 'a' * 25,
    'secret.gitlab_kubernetes_agent_token': 'glagent-' + 'a' * 50,
    'secret.gitlab_oauth_app_secret': 'gloas-' + 'a' * 64,
    'secret.gitlab_pat_routable': 'glpat-' + 'a' * 27 + '.aa' + 'a' * 7,
    'secret.gitlab_ptt': 'glptt-' + 'a' * 40,
    'secret.gitlab_rrt': 'GR1348941' + 'a' * 20,
    'secret.gitlab_runner_authentication_token': 'glrt-' + 'a' * 20,
    'secret.gitlab_runner_authentication_token_routable': 'glrt-t1_' + 'a' * 27 + '.aa' + 'a' * 7,
    'secret.gitlab_scim_token': 'glsoat-' + 'a' * 20,
    'secret.gitlab_session_cookie': '_gitlab_session=' + 'a' * 32,
}

_SPACE_TOLERANT_BY_CATEGORY = {c: (anchor, value, window) for c, anchor, value, window in SPACE_TOLERANT_RULES}


def test_every_space_tolerant_rule_has_an_example():
    assert set(_SPACE_TOLERANT_BY_CATEGORY) == set(EXAMPLES)


def test_no_example_left_over_for_a_removed_rule():
    assert set(EXAMPLES) == set(_SPACE_TOLERANT_BY_CATEGORY)


@pytest.mark.parametrize('category', sorted(EXAMPLES))
def test_example_matches_its_own_value_regex(category):
    example = EXAMPLES[category]
    _, value_re, _ = _SPACE_TOLERANT_BY_CATEGORY[category]
    m = value_re.match(example)
    assert m is not None and m.end() == len(example), (
        f'{category}: example does not fully match its own value_re -- fix the example')


@pytest.mark.parametrize('category', sorted(EXAMPLES))
def test_unmodified_example_detected_by_exact_match_pass(category):
    example = EXAMPLES[category]
    findings = run(example)
    assert any(f.category == category for f in findings), (
        f'{category}: baseline (no whitespace injected) not detected at all -- '
        f'the example itself is wrong, not the space-tolerant scan')


@pytest.mark.parametrize('category', sorted(EXAMPLES))
def test_space_injected_into_tail_still_detected(category):
    # Realistic bx-006 pattern: a wrap/paste artifact lands somewhere in the
    # token's variable-length tail, not inside the short fixed anchor.
    example = EXAMPLES[category]
    anchor_re, _, _ = _SPACE_TOLERANT_BY_CATEGORY[category]
    anchor_end = anchor_re.search(example).end()
    tail_len = len(example) - anchor_end
    offsets = sorted({anchor_end + 1, anchor_end + tail_len // 2, len(example) - 1})
    for offset in offsets:
        if offset <= anchor_end or offset >= len(example):
            continue
        injected = example[:offset] + ' ' + example[offset:]
        findings = run(injected)
        assert any(f.category == category and f.raw_value == injected for f in findings), (
            f'{category}: space injected at offset {offset} not detected -- {injected[:70]!r}')


@pytest.mark.parametrize('category', sorted(EXAMPLES))
def test_window_covers_the_full_injected_length(category):
    example = EXAMPLES[category]
    anchor_re, _, window = _SPACE_TOLERANT_BY_CATEGORY[category]
    anchor_start = anchor_re.search(example).start()
    needed = (len(example) + 1) - anchor_start  # +1 for the injected space
    assert window >= needed, f'{category}: window {window} too small, need >= {needed}'


def test_space_tolerant_categories_are_a_subset_of_real_rules():
    all_regex_categories = {c for c, _ in RULES}
    missing = set(_SPACE_TOLERANT_BY_CATEGORY) - all_regex_categories
    assert not missing, f'space-tolerant categories with no matching entry in RULES: {missing}'
