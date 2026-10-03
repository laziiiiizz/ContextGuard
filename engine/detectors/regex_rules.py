"""Secret formats with a clear, unique marker (for example AKIA for AWS keys),
mostly adapted from gitleaks. Formats that are only safe to match next to a
keyword (like "stripe") are in context_rules.py."""
import re

from engine.finding import Finding
from engine.normalize import strip_spaces_for_detection

RULES = [
    ('secret.aws_access_token', re.compile(r'\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b')),
    ('secret.github_pat', re.compile(r'ghp_[0-9a-zA-Z]{36}')),
    ('secret.gitlab_pat', re.compile(r'glpat-[\w-]{20}')),
    ('secret.slack_bot_token', re.compile(r'xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*')),
    ('secret.stripe_key', re.compile(r'\b(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}\b')),
    ('secret.generic_private_key', re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('secret.openai_api_key', re.compile(
        r'sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ'
        r'(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}')),
    ('secret.npm_access_token', re.compile(r'npm_[a-zA-Z0-9]{36}')),
    ('secret.slack_webhook_url', re.compile(
        r'(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}')),
    ('secret.sendgrid_api_key', re.compile(r'SG\.[A-Za-z0-9=_.-]{66}')),
    ('secret.jwt', re.compile(r'\bey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.(?:[a-zA-Z0-9/\\_-]{10,}={0,2})?')),
    ('secret.digitalocean_pat', re.compile(r'\bdop_v1_[a-f0-9]{64}\b')),
    ('secret.databricks_api_token', re.compile(r'\bdapi[a-f0-9]{32}(?:-\d)?\b')),
    ('secret.planetscale_api_token', re.compile(r'\bpscale_tkn_[\w=.-]{32,64}\b')),
    ('secret.postman_api_token', re.compile(r'PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}')),
    ('secret.pypi_upload_token', re.compile(r'pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}')),
    ('secret.square_access_token', re.compile(r'\b(?:EAAA|sq0atp-)[\w-]{22,60}\b')),
    ('secret.shopify_access_token', re.compile(r'shpat_[a-fA-F0-9]{32}')),
    ('secret.shopify_custom_access_token', re.compile(r'shpca_[a-fA-F0-9]{32}')),
    ('secret.shopify_private_app_access_token', re.compile(r'shppa_[a-fA-F0-9]{32}')),
    ('secret.hashicorp_tf_api_token', re.compile(r'(?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}')),
    ('secret.cloudflare_origin_ca_key', re.compile(r'v1\.0-[a-f0-9]{24}-[a-f0-9]{146}')),
    ('secret.grafana_api_key', re.compile(r'(?i)\beyJrIjoi[A-Za-z0-9]{70,400}={0,3}')),
    ('secret.grafana_cloud_api_token', re.compile(r'(?i)\bglc_[A-Za-z0-9+/]{32,400}={0,3}')),
    ('secret.age_secret_key', re.compile(r'AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}')),
    ('secret.gcp_api_key', re.compile(r'\bAIza[\w-]{35}\b')),
    ('secret.linear_api_key', re.compile(r'lin_api_[a-zA-Z0-9]{40}')),
    ('secret.notion_api_token', re.compile(r'\bntn_[0-9]{11}[A-Za-z0-9]{35}\b')),
    ('secret.rubygems_api_token', re.compile(r'\brubygems_[a-f0-9]{48}\b')),
    ('secret.vault_batch_token', re.compile(r'\bhvb\.[\w-]{138,300}\b')),
    ('secret.vault_service_token', re.compile(r'\bhvs\.[\w-]{90,120}\b')),
    # From gitleaks, keeping only the distinctive part of each pattern.
    ('secret.new_relic_insert_key', re.compile(r'NRII-[a-zA-Z0-9-]{32}')),
    ('secret.telegram_bot_token', re.compile(r'\b[0-9]{5,16}:A[a-zA-Z0-9_-]{34}\b')),
    ('secret.twitter_bearer_token', re.compile(r'A{22}[a-zA-Z0-9%]{80,100}')),
    # Anthropic's own keys -- especially on-theme: this tool protects prompts sent
    # to Claude, so it should also catch a Claude API key itself leaking.
    ('secret.anthropic_api_key', re.compile(r'\bsk-ant-api03-[a-zA-Z0-9_-]{93}AA\b')),
    ('secret.anthropic_admin_api_key', re.compile(r'\bsk-ant-admin01-[a-zA-Z0-9_-]{93}AA\b')),
    ('secret.aws_bedrock_api_key', re.compile(r'\bABSK[A-Za-z0-9+/]{109,269}={0,2}')),
    ('secret.onepassword_secret_key', re.compile(
        r'\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b')),
    ('secret.onepassword_service_account_token', re.compile(r'ops_eyJ[a-zA-Z0-9+/]{250,1000}={0,3}')),
    ('secret.artifactory_reference_token', re.compile(r'\bcmVmd[A-Za-z0-9]{59}\b')),
    ('secret.clojars_api_token', re.compile(r'(?i)CLOJARS_[a-z0-9]{60}')),
    ('secret.digitalocean_access_token', re.compile(r'\bdoo_v1_[a-f0-9]{64}\b')),
    ('secret.digitalocean_refresh_token', re.compile(r'(?i)\bdor_v1_[a-f0-9]{64}\b')),
    ('secret.doppler_api_token', re.compile(r'dp\.pt\.[a-zA-Z0-9]{43}')),
    ('secret.dynatrace_api_token', re.compile(r'dt0c01\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{64}')),
    ('secret.easypost_api_token', re.compile(r'\bEZAK[a-zA-Z0-9]{54}\b')),
    # Perplexity/HuggingFace: more AI providers -- same rationale as Anthropic above.
    ('secret.perplexity_api_key', re.compile(r'\bpplx-[a-zA-Z0-9]{48}\b')),
    ('secret.huggingface_access_token', re.compile(r'\bhf_[a-zA-Z]{34}\b')),
    ('secret.github_fine_grained_pat', re.compile(r'github_pat_\w{82}')),
    ('secret.github_oauth', re.compile(r'gho_[0-9a-zA-Z]{36}')),
    ('secret.github_refresh_token', re.compile(r'ghr_[0-9a-zA-Z]{36}')),
    ('secret.gitlab_deploy_token', re.compile(r'gldt-[0-9a-zA-Z_-]{20}')),
    ('secret.grafana_service_account_token', re.compile(r'(?i)\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b')),
    ('secret.planetscale_oauth_token', re.compile(r'\bpscale_oauth_[\w=.-]{32,64}\b')),
    ('secret.planetscale_password', re.compile(r'\bpscale_pw_[\w=.-]{32,64}\b')),
    ('secret.prefect_api_token', re.compile(r'\bpnu_[a-zA-Z0-9]{36}\b')),
    ('secret.pulumi_api_token', re.compile(r'\bpul-[a-f0-9]{40}\b')),
    ('secret.scalingo_api_token', re.compile(r'\btk-us-[\w-]{48}\b')),
    ('secret.shippo_api_token', re.compile(r'\bshippo_(?:live|test)_[a-fA-F0-9]{40}\b')),
    ('secret.shopify_shared_secret', re.compile(r'shpss_[a-fA-F0-9]{32}')),
    # Bounded defensively even though gitleaks' originals used unbounded `+` --
    # not ambiguous here (no overlap with a following literal), but bounding
    # costs nothing and matches this file's general ReDoS-safety discipline.
    ('secret.slack_app_token', re.compile(r'(?i)xapp-\d-[A-Z0-9]{1,50}-\d+-[a-z0-9]{1,50}')),
    ('secret.slack_legacy_token', re.compile(r'xox[os]-\d+-\d+-\d+-[a-fA-F\d]{1,50}')),
    ('secret.slack_user_token', re.compile(r'xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}')),
    # Sourcegraph: dropped gitleaks' third alternative (a bare `[a-fA-F0-9]{40}`
    # with no prefix at all) -- that's indistinguishable from any git commit SHA.
    ('secret.sourcegraph_access_token', re.compile(
        r'sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}')),
    ('secret.typeform_api_token', re.compile(r'tfp_[a-zA-Z0-9\-_.=]{59}')),
    ('secret.yandex_api_key', re.compile(r'AQVN[A-Za-z0-9_-]{35,38}')),
    ('secret.airtable_personal_access_token', re.compile(r'\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b')),
    ('secret.alibaba_access_key_id', re.compile(r'\bLTAI[a-zA-Z0-9]{20}\b')),
    ('secret.atlassian_api_token', re.compile(r'\bATATT3[A-Za-z0-9_=-]{186}\b')),
    ('secret.clickhouse_cloud_api_secret_key', re.compile(r'\b4b1d[A-Za-z0-9]{38}\b')),
    ('secret.defined_networking_api_token', re.compile(r'\bdnkey-[a-zA-Z0-9=_-]{26}-[a-zA-Z0-9=_-]{52}\b')),
    ('secret.duffel_api_token', re.compile(r'duffel_(?:test|live)_[a-zA-Z0-9_=-]{43}')),
    # Length limits here stop slow matching on long text with no email in it
    # (a known regex trap), and match the real email size limits.
    ('pii.email', re.compile(r'[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}')),
    # Batch 3: remaining gitleaks rules with a distinctive-enough standalone
    # marker (fixed prefix/suffix), found by diffing gitleaks.toml's 222 ids
    # against what's already ported here and in context_rules.py.
    ('secret.adobe_client_secret', re.compile(r'\bp8e-[a-zA-Z0-9]{32}\b')),
    ('secret.artifactory_api_key', re.compile(r'\bAKCp[A-Za-z0-9]{69}\b')),
    ('secret.azure_ad_client_secret', re.compile(r'\b[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}\b')),
    ('secret.facebook_page_access_token', re.compile(r'\bEAA[MC][a-zA-Z0-9]{100,300}\b')),
    ('secret.facebook_access_token', re.compile(r'\b\d{15,16}[|%][0-9a-zA-Z_-]{27,40}\b')),
    ('secret.flutterwave_encryption_key', re.compile(r'FLWSECK_TEST-[a-hA-H0-9]{12}\b')),
    ('secret.flutterwave_public_key', re.compile(r'FLWPUBK_TEST-[a-hA-H0-9]{32}-X\b')),
    ('secret.flutterwave_secret_key', re.compile(r'FLWSECK_TEST-[a-hA-H0-9]{32}-X\b')),
    ('secret.flyio_access_token', re.compile(
        r'\bfo1_[\w-]{43}\b|\bfm1[ar]_[a-zA-Z0-9+/]{100,150}={0,3}|\bfm2_[a-zA-Z0-9+/]{100,150}={0,3}')),
    ('secret.frameio_api_token', re.compile(r'fio-u-[a-zA-Z0-9_=-]{64}')),
    ('secret.heroku_api_key_v2', re.compile(r'\bHRKU-AA[0-9a-zA-Z_-]{58}\b')),
    ('secret.huggingface_organization_api_token', re.compile(r'\bapi_org_[a-zA-Z]{34}\b')),
    ('secret.infracost_api_token', re.compile(r'\bico-[a-zA-Z0-9]{32}\b')),
    ('secret.microsoft_teams_webhook', re.compile(
        r'https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}'
        r'@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/'
        r'[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}')),
    ('secret.octopus_deploy_api_key', re.compile(r'\bAPI-[A-Z0-9]{26}\b')),
    ('secret.openshift_user_token', re.compile(r'\bsha256~[\w-]{43}\b')),
    ('secret.readme_api_token', re.compile(r'\brdme_[a-zA-Z0-9]{70}\b')),
    ('secret.sendinblue_api_token', re.compile(r'\bxkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}\b')),
    ('secret.sentry_org_token', re.compile(r'sntrys_eyJpYXQiO[A-Za-z0-9+/]{10,200}_[A-Za-z0-9+/]{43}')),
    ('secret.sentry_user_token', re.compile(r'\bsntryu_[a-f0-9]{64}\b')),
    ('secret.settlemint_application_access_token', re.compile(r'\bsm_aat_[a-zA-Z0-9]{16}\b')),
    ('secret.settlemint_personal_access_token', re.compile(r'\bsm_pat_[a-zA-Z0-9]{16}\b')),
    ('secret.settlemint_service_access_token', re.compile(r'\bsm_sat_[a-zA-Z0-9]{16}\b')),
    ('secret.yandex_aws_access_token', re.compile(r'\bYC[a-zA-Z0-9_-]{38}\b')),
    ('secret.slack_config_access_token', re.compile(r'(?i)xoxe\.xox[bp]-\d-[A-Z0-9]{163,166}')),
    ('secret.slack_config_refresh_token', re.compile(r'(?i)xoxe-\d-[A-Z0-9]{146}')),
    ('secret.slack_legacy_bot_token', re.compile(r'xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}')),
    ('secret.slack_legacy_workspace_token', re.compile(r'xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}')),
    ('secret.gitlab_cicd_job_token', re.compile(r'glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}')),
    ('secret.gitlab_feature_flag_client_token', re.compile(r'glffct-[0-9a-zA-Z_-]{20}')),
    ('secret.gitlab_feed_token', re.compile(r'glft-[0-9a-zA-Z_-]{20}')),
    ('secret.gitlab_incoming_mail_token', re.compile(r'glimt-[0-9a-zA-Z_-]{25}')),
    ('secret.gitlab_kubernetes_agent_token', re.compile(r'glagent-[0-9a-zA-Z_-]{50}')),
    ('secret.gitlab_oauth_app_secret', re.compile(r'gloas-[0-9a-zA-Z_-]{64}')),
    ('secret.gitlab_pat_routable', re.compile(r'\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b')),
    ('secret.gitlab_ptt', re.compile(r'glptt-[0-9a-f]{40}')),
    ('secret.gitlab_rrt', re.compile(r'GR1348941[\w-]{20}')),
    ('secret.gitlab_runner_authentication_token', re.compile(r'glrt-[0-9a-zA-Z_-]{20}')),
    ('secret.gitlab_runner_authentication_token_routable', re.compile(
        r'\bglrt-t\d_[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b')),
    ('secret.gitlab_scim_token', re.compile(r'glsoat-[0-9a-zA-Z_-]{20}')),
    ('secret.gitlab_session_cookie', re.compile(r'_gitlab_session=[0-9a-z]{32}')),
    ('secret.maxmind_license_key', re.compile(r'\b[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk\b')),
    # SSN with dashes or spaces between the 3 groups. Numbers the SSA never
    # issues (000, 666, 900-999, group 00, serial 0000) are left out. Plain
    # 9-digit numbers are too often phone or order numbers; those only count
    # next to a keyword (pii.ssn_context in context_rules.py).
    ('pii.ssn', re.compile(
        r'\b(?!000|666|9\d\d)[0-8]\d{2}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b')),
]

# Number prefixes and lengths of the 6 big card networks. Checked by
# find_credit_cards() below together with the Luhn checksum.
CARD_NETWORK_PATTERNS = [
    re.compile(r'^4\d{12}(?:\d{3}){0,2}$'),  # Visa: 13, 16, or 19 digits
    re.compile(r'^(?:5[1-5]\d{2}|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)\d{12}$'),  # Mastercard: 16
    re.compile(r'^3[47]\d{13}$'),  # Amex: 15
    re.compile(r'^6(?:011|5\d{2}|4[4-9]\d)\d{12}$'),  # Discover: 16
    re.compile(r'^3(?:0[0-5]|[68]\d)\d{11}$'),  # Diners Club: 14
    re.compile(r'^(?:2131|1800|35\d{3})\d{11}$'),  # JCB: 16
]

# 13 to 19 digits, optionally split by single spaces or dashes
# ("4111 1111 1111 1111", "4111-1111-...", or no separators).
_CARD_CANDIDATE_RE = re.compile(r'\b(?:\d[ -]?){12,18}\d\b')

# Categories made by code below instead of the RULES table, listed so the
# "every category has a policy row" test sees them too.
PYTHON_VALIDATED_CATEGORIES = {'pii.credit_card'}


def _luhn_valid(digits: str) -> bool:
    """The mod-10 checksum every real card number passes. About 1 in 10
    random numbers pass it too, so it is only used after the prefix check."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def find_credit_cards(text: str) -> list[Finding]:
    """A card number must match a real network's prefix and length AND pass
    the Luhn checksum. Either check alone flags too many ordinary numbers."""
    findings = []
    for match in _CARD_CANDIDATE_RE.finditer(text):
        digits = re.sub(r'[ -]', '', match.group(0))
        if not any(pattern.match(digits) for pattern in CARD_NETWORK_PATTERNS):
            continue
        if not _luhn_valid(digits):
            continue
        findings.append(Finding(
            span_start=match.start(),
            span_end=match.end(),
            category='pii.credit_card',
            confidence=0.9,
            detector_id='regex.pii.credit_card',
            raw_value=match.group(0),
        ))
    return findings

CONFIDENCE_BY_CATEGORY = {
    'pii.email': 0.7,
    'secret.stripe_key': 0.85,
    'pii.ssn': 0.85,
}

# Catches a key with a space typed or pasted into it (for example
# "AKIA ABCDEF..."). Removing all spaces from the whole message would glue
# ordinary words together and cause false alarms, so this only looks at a
# short stretch right after a distinctive prefix. `\b` is dropped from
# these patterns because it can't see the text around the cut-out stretch.
SPACE_TOLERANT_RULES = [
    ('secret.aws_access_token',
     re.compile(r'A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA'),
     re.compile(r'(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}'), 24),
    ('secret.github_pat', re.compile(r'ghp_'), re.compile(r'ghp_[0-9a-zA-Z]{36}'), 44),
    ('secret.github_fine_grained_pat', re.compile(r'github_pat_'), re.compile(r'github_pat_\w{82}'), 97),
    ('secret.slack_bot_token', re.compile(r'xoxb-'),
     re.compile(r'xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]{0,50}'), 50),
    ('secret.stripe_key', re.compile(r'(?:sk|rk)_(?:test|live|prod)_'),
     re.compile(r'(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}'), 110),
    ('secret.openai_api_key', re.compile(r'sk-'), re.compile(
        r'sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ'
        r'(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}'), 190),
    ('secret.anthropic_api_key', re.compile(r'sk-ant-api03-'),
     re.compile(r'sk-ant-api03-[a-zA-Z0-9_-]{93}AA'), 112),
    ('secret.anthropic_admin_api_key', re.compile(r'sk-ant-admin01-'),
     re.compile(r'sk-ant-admin01-[a-zA-Z0-9_-]{93}AA'), 114),
    ('secret.npm_access_token', re.compile(r'npm_'), re.compile(r'npm_[a-zA-Z0-9]{36}'), 44),
    # More prefixes, those distinctive enough (5+ characters or clearly a
    # brand). Left out on purpose: prefixes that are common words ("pat",
    # "API-"), patterns without a prefix at the start, and very long tokens
    # that are always pasted by programs, not typed. Known gap: a space
    # inside the prefix itself (not after it) is not caught.
    ('secret.gitlab_pat', re.compile(r'glpat-'), re.compile(r'glpat-[\w-]{20}'), 28),
    ('secret.sendgrid_api_key', re.compile(r'SG\.'), re.compile(r'SG\.[A-Za-z0-9=_.-]{66}'), 72),
    ('secret.digitalocean_pat', re.compile(r'dop_v1_'), re.compile(r'dop_v1_[a-f0-9]{64}'), 74),
    ('secret.digitalocean_access_token', re.compile(r'doo_v1_'), re.compile(r'doo_v1_[a-f0-9]{64}'), 74),
    ('secret.digitalocean_refresh_token', re.compile(r'(?i)dor_v1_'),
     re.compile(r'(?i)dor_v1_[a-f0-9]{64}'), 74),
    ('secret.databricks_api_token', re.compile(r'dapi'),
     re.compile(r'dapi[a-f0-9]{32}(?:-\d)?'), 40),
    ('secret.planetscale_api_token', re.compile(r'pscale_tkn_'),
     re.compile(r'pscale_tkn_[\w=.-]{32,64}'), 78),
    ('secret.planetscale_oauth_token', re.compile(r'pscale_oauth_'),
     re.compile(r'pscale_oauth_[\w=.-]{32,64}'), 80),
    ('secret.planetscale_password', re.compile(r'pscale_pw_'),
     re.compile(r'pscale_pw_[\w=.-]{32,64}'), 77),
    ('secret.postman_api_token', re.compile(r'PMAK-'),
     re.compile(r'PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}'), 66),
    ('secret.square_access_token', re.compile(r'EAAA|sq0atp-'),
     re.compile(r'(?:EAAA|sq0atp-)[\w-]{22,60}'), 68),
    ('secret.shopify_access_token', re.compile(r'shpat_'), re.compile(r'shpat_[a-fA-F0-9]{32}'), 40),
    ('secret.shopify_custom_access_token', re.compile(r'shpca_'), re.compile(r'shpca_[a-fA-F0-9]{32}'), 40),
    ('secret.shopify_private_app_access_token', re.compile(r'shppa_'),
     re.compile(r'shppa_[a-fA-F0-9]{32}'), 40),
    ('secret.shopify_shared_secret', re.compile(r'shpss_'), re.compile(r'shpss_[a-fA-F0-9]{32}'), 40),
    ('secret.cloudflare_origin_ca_key', re.compile(r'v1\.0-'),
     re.compile(r'v1\.0-[a-f0-9]{24}-[a-f0-9]{146}'), 178),
    ('secret.age_secret_key', re.compile(r'AGE-SECRET-KEY-1'),
     re.compile(r'AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}'), 78),
    ('secret.gcp_api_key', re.compile(r'AIza'), re.compile(r'AIza[\w-]{35}'), 42),
    ('secret.linear_api_key', re.compile(r'lin_api_'), re.compile(r'lin_api_[a-zA-Z0-9]{40}'), 50),
    ('secret.notion_api_token', re.compile(r'ntn_'),
     re.compile(r'ntn_[0-9]{11}[A-Za-z0-9]{35}'), 52),
    ('secret.rubygems_api_token', re.compile(r'rubygems_'), re.compile(r'rubygems_[a-f0-9]{48}'), 60),
    ('secret.new_relic_insert_key', re.compile(r'NRII-'), re.compile(r'NRII-[a-zA-Z0-9-]{32}'), 40),
    ('secret.twitter_bearer_token', re.compile(r'A{22}'),
     re.compile(r'A{22}[a-zA-Z0-9%]{80,100}'), 125),
    ('secret.aws_bedrock_api_key', re.compile(r'ABSK'),
     re.compile(r'ABSK[A-Za-z0-9+/]{109,269}={0,2}'), 280),
    ('secret.artifactory_reference_token', re.compile(r'cmVmd'),
     re.compile(r'cmVmd[A-Za-z0-9]{59}'), 66),
    ('secret.clojars_api_token', re.compile(r'(?i)CLOJARS_'),
     re.compile(r'(?i)CLOJARS_[a-z0-9]{60}'), 72),
    ('secret.doppler_api_token', re.compile(r'dp\.pt\.'), re.compile(r'dp\.pt\.[a-zA-Z0-9]{43}'), 52),
    ('secret.dynatrace_api_token', re.compile(r'dt0c01\.'),
     re.compile(r'dt0c01\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{64}'), 100),
    ('secret.easypost_api_token', re.compile(r'EZAK'), re.compile(r'EZAK[a-zA-Z0-9]{54}'), 60),
    ('secret.perplexity_api_key', re.compile(r'pplx-'), re.compile(r'pplx-[a-zA-Z0-9]{48}'), 56),
    ('secret.huggingface_access_token', re.compile(r'hf_'), re.compile(r'hf_[a-zA-Z]{34}'), 40),
    ('secret.github_oauth', re.compile(r'gho_'), re.compile(r'gho_[0-9a-zA-Z]{36}'), 42),
    ('secret.github_refresh_token', re.compile(r'ghr_'), re.compile(r'ghr_[0-9a-zA-Z]{36}'), 42),
    ('secret.gitlab_deploy_token', re.compile(r'gldt-'), re.compile(r'gldt-[0-9a-zA-Z_-]{20}'), 28),
    ('secret.grafana_service_account_token', re.compile(r'(?i)glsa_'),
     re.compile(r'(?i)glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}'), 50),
    ('secret.prefect_api_token', re.compile(r'pnu_'), re.compile(r'pnu_[a-zA-Z0-9]{36}'), 42),
    ('secret.pulumi_api_token', re.compile(r'pul-'), re.compile(r'pul-[a-f0-9]{40}'), 46),
    ('secret.scalingo_api_token', re.compile(r'tk-us-'), re.compile(r'tk-us-[\w-]{48}'), 56),
    ('secret.shippo_api_token', re.compile(r'shippo_(?:live|test)_'),
     re.compile(r'shippo_(?:live|test)_[a-fA-F0-9]{40}'), 64),
    ('secret.slack_app_token', re.compile(r'(?i)xapp-'),
     re.compile(r'(?i)xapp-\d-[A-Z0-9]{1,50}-\d+-[a-z0-9]{1,50}'), 120),
    ('secret.slack_legacy_token', re.compile(r'xox[os]-'),
     re.compile(r'xox[os]-\d+-\d+-\d+-[a-fA-F\d]{1,50}'), 100),
    ('secret.slack_user_token', re.compile(r'xox[pe]-'),
     re.compile(r'xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}'), 80),
    ('secret.sourcegraph_access_token', re.compile(r'sgp_'),
     re.compile(r'sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}'), 72),
    ('secret.typeform_api_token', re.compile(r'tfp_'),
     re.compile(r'tfp_[a-zA-Z0-9\-_.=]{59}'), 66),
    ('secret.yandex_api_key', re.compile(r'AQVN'), re.compile(r'AQVN[A-Za-z0-9_-]{35,38}'), 44),
    ('secret.alibaba_access_key_id', re.compile(r'LTAI'), re.compile(r'LTAI[a-zA-Z0-9]{20}'), 26),
    ('secret.atlassian_api_token', re.compile(r'ATATT3'),
     re.compile(r'ATATT3[A-Za-z0-9_=-]{186}'), 196),
    ('secret.clickhouse_cloud_api_secret_key', re.compile(r'4b1d'),
     re.compile(r'4b1d[A-Za-z0-9]{38}'), 44),
    ('secret.defined_networking_api_token', re.compile(r'dnkey-'),
     re.compile(r'dnkey-[a-zA-Z0-9=_-]{26}-[a-zA-Z0-9=_-]{52}'), 90),
    ('secret.duffel_api_token', re.compile(r'duffel_(?:test|live)_'),
     re.compile(r'duffel_(?:test|live)_[a-zA-Z0-9_=-]{43}'), 66),
    ('secret.adobe_client_secret', re.compile(r'p8e-'), re.compile(r'p8e-[a-zA-Z0-9]{32}'), 38),
    ('secret.artifactory_api_key', re.compile(r'AKCp'), re.compile(r'AKCp[A-Za-z0-9]{69}'), 76),
    ('secret.facebook_page_access_token', re.compile(r'EAA[MC]'),
     re.compile(r'EAA[MC][a-zA-Z0-9]{100,300}'), 310),
    ('secret.flutterwave_encryption_key', re.compile(r'FLWSECK_TEST-'),
     re.compile(r'FLWSECK_TEST-[a-hA-H0-9]{12}'), 30),
    ('secret.flutterwave_public_key', re.compile(r'FLWPUBK_TEST-'),
     re.compile(r'FLWPUBK_TEST-[a-hA-H0-9]{32}-X'), 50),
    ('secret.flutterwave_secret_key', re.compile(r'FLWSECK_TEST-'),
     re.compile(r'FLWSECK_TEST-[a-hA-H0-9]{32}-X'), 50),
    ('secret.flyio_access_token', re.compile(r'fo1_'), re.compile(r'fo1_[\w-]{43}'), 50),
    ('secret.frameio_api_token', re.compile(r'fio-u-'), re.compile(r'fio-u-[a-zA-Z0-9_=-]{64}'), 72),
    ('secret.heroku_api_key_v2', re.compile(r'HRKU-AA'), re.compile(r'HRKU-AA[0-9a-zA-Z_-]{58}'), 68),
    ('secret.huggingface_organization_api_token', re.compile(r'api_org_'),
     re.compile(r'api_org_[a-zA-Z]{34}'), 44),
    ('secret.infracost_api_token', re.compile(r'ico-'), re.compile(r'ico-[a-zA-Z0-9]{32}'), 38),
    ('secret.openshift_user_token', re.compile(r'sha256~'), re.compile(r'sha256~[\w-]{43}'), 52),
    ('secret.readme_api_token', re.compile(r'rdme_'), re.compile(r'rdme_[a-zA-Z0-9]{70}'), 78),
    ('secret.sendinblue_api_token', re.compile(r'xkeysib-'),
     re.compile(r'xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}'), 92),
    ('secret.sentry_org_token', re.compile(r'sntrys_eyJpYXQiO'),
     re.compile(r'sntrys_eyJpYXQiO[A-Za-z0-9+/]{10,200}_[A-Za-z0-9+/]{43}'), 270),
    ('secret.sentry_user_token', re.compile(r'sntryu_'), re.compile(r'sntryu_[a-f0-9]{64}'), 74),
    ('secret.settlemint_application_access_token', re.compile(r'sm_aat_'),
     re.compile(r'sm_aat_[a-zA-Z0-9]{16}'), 26),
    ('secret.settlemint_personal_access_token', re.compile(r'sm_pat_'),
     re.compile(r'sm_pat_[a-zA-Z0-9]{16}'), 26),
    ('secret.settlemint_service_access_token', re.compile(r'sm_sat_'),
     re.compile(r'sm_sat_[a-zA-Z0-9]{16}'), 26),
    ('secret.yandex_aws_access_token', re.compile(r'YC'), re.compile(r'YC[a-zA-Z0-9_-]{38}'), 44),
    ('secret.slack_config_access_token', re.compile(r'(?i)xoxe\.xox[bp]-'),
     re.compile(r'(?i)xoxe\.xox[bp]-\d-[A-Z0-9]{163,166}'), 185),
    ('secret.slack_config_refresh_token', re.compile(r'(?i)xoxe-'),
     re.compile(r'(?i)xoxe-\d-[A-Z0-9]{146}'), 160),
    ('secret.slack_legacy_bot_token', re.compile(r'xoxb-'),
     re.compile(r'xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}'), 45),
    ('secret.slack_legacy_workspace_token', re.compile(r'xox[ar]-'),
     re.compile(r'xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}'), 58),
    ('secret.gitlab_cicd_job_token', re.compile(r'glcbt-'),
     re.compile(r'glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}'), 32),
    ('secret.gitlab_feature_flag_client_token', re.compile(r'glffct-'),
     re.compile(r'glffct-[0-9a-zA-Z_-]{20}'), 28),
    ('secret.gitlab_feed_token', re.compile(r'glft-'), re.compile(r'glft-[0-9a-zA-Z_-]{20}'), 26),
    ('secret.gitlab_incoming_mail_token', re.compile(r'glimt-'),
     re.compile(r'glimt-[0-9a-zA-Z_-]{25}'), 32),
    ('secret.gitlab_kubernetes_agent_token', re.compile(r'glagent-'),
     re.compile(r'glagent-[0-9a-zA-Z_-]{50}'), 60),
    ('secret.gitlab_oauth_app_secret', re.compile(r'gloas-'),
     re.compile(r'gloas-[0-9a-zA-Z_-]{64}'), 72),
    ('secret.gitlab_pat_routable', re.compile(r'glpat-'),
     re.compile(r'glpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}'), 320),
    ('secret.gitlab_ptt', re.compile(r'glptt-'), re.compile(r'glptt-[0-9a-f]{40}'), 48),
    ('secret.gitlab_rrt', re.compile(r'GR1348941'), re.compile(r'GR1348941[\w-]{20}'), 30),
    ('secret.gitlab_runner_authentication_token', re.compile(r'glrt-'),
     re.compile(r'glrt-[0-9a-zA-Z_-]{20}'), 26),
    ('secret.gitlab_runner_authentication_token_routable', re.compile(r'glrt-t\d_'),
     re.compile(r'glrt-t\d_[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}'), 320),
    ('secret.gitlab_scim_token', re.compile(r'glsoat-'), re.compile(r'glsoat-[0-9a-zA-Z_-]{20}'), 28),
    ('secret.gitlab_session_cookie', re.compile(r'_gitlab_session='),
     re.compile(r'_gitlab_session=[0-9a-z]{32}'), 50),
]


def run(text: str) -> list[Finding]:
    findings = []
    seen_spans = set()
    for category, pattern in RULES:
        for match in pattern.finditer(text):
            span_start, span_end = match.start(), match.end()
            seen_spans.add((span_start, span_end, category))
            findings.append(Finding(
                span_start=span_start,
                span_end=span_end,
                category=category,
                confidence=CONFIDENCE_BY_CATEGORY.get(category, 0.9),
                detector_id=f'regex.{category}',
                raw_value=match.group(0),
            ))

    for category, anchor_re, value_re, window in SPACE_TOLERANT_RULES:
        for anchor_match in anchor_re.finditer(text):
            window_text = text[anchor_match.start():anchor_match.start() + window]
            if ' ' not in window_text and '\t' not in window_text:
                continue  # already covered by the exact-match pass above
            stripped, index_map = strip_spaces_for_detection(window_text)
            value_match = value_re.match(stripped)
            if value_match is None:
                continue
            span_start = anchor_match.start() + index_map[value_match.start()]
            span_end = anchor_match.start() + index_map[value_match.end() - 1] + 1
            key = (span_start, span_end, category)
            if key in seen_spans:
                continue
            seen_spans.add(key)
            findings.append(Finding(
                span_start=span_start,
                span_end=span_end,
                category=category,
                confidence=CONFIDENCE_BY_CATEGORY.get(category, 0.9),
                detector_id=f'regex.space_tolerant.{category}',
                raw_value=text[span_start:span_end],
            ))

    for finding in find_credit_cards(text):
        key = (finding.span_start, finding.span_end, finding.category)
        if key in seen_spans:
            continue
        seen_spans.add(key)
        findings.append(finding)

    return findings
