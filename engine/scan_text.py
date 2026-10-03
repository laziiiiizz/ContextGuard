"""The detector pipeline for callers outside the proxy (the git hook, file
scanning). Same steps and the same signed policy as proxy/addon.py's
run_pipeline(), loaded by absolute path so it works from any working
directory.
"""
from engine.context_score import adjust_confidence
from engine.detectors import allowlist, context_rules, entropy, regex_rules
from engine.normalize import fold_confusables, normalize
from engine.policy import evaluate, load_policy
from engine.user_settings import is_category_enabled
from proxy.paths import get_app_root


class Scanner:
    def __init__(self):
        policy_dir = get_app_root() / 'policy'
        self.rules = load_policy(str(policy_dir / 'policy.yaml'))  # raises if the signature fails
        self.allowlist = allowlist.load_allowlist(str(policy_dir / 'allowlist.yaml'))

    def scan(self, text: str) -> list:
        content = fold_confusables(normalize(text))
        findings = regex_rules.run(content) + entropy.run(content) + context_rules.run(content)
        findings = allowlist.filter_findings(findings, self.allowlist)
        findings = [adjust_confidence(f, 'public-ai') for f in findings]
        findings = [f for f in findings if is_category_enabled(f.category)]
        return evaluate(findings, self.rules, destination_class='public-ai')

    def blocking_categories(self, text: str) -> list[str]:
        """Categories that would be blocked, deduplicated, in order found."""
        seen = []
        for decision in self.scan(text):
            if decision.action == 'block' and decision.finding.category not in seen:
                seen.append(decision.finding.category)
        return seen
