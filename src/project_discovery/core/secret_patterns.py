"""Single registry of credential value formats shared by detection and redaction.

Every format the secret scanner reports is also removed from report excerpts by
``redact_source_excerpt``. Keeping one registry means a detector can never copy a value
into a report that the redactor does not recognize.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TokenFormat:
    name: str
    pattern: str
    severity: str = "HIGH"
    # Literal substrings at least one of which every match contains. Scanners skip the
    # regex for text without any anchor; an empty tuple means "always run".
    anchors: tuple[str, ...] = ()


# Provider formats with distinctive prefixes or structure (low false-positive rate).
TOKEN_FORMATS: tuple[TokenFormat, ...] = (
    TokenFormat("github_token", r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", anchors=('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_')),
    TokenFormat("github_fine_grained_token", r"\bgithub_pat_[A-Za-z0-9_]{40,}\b", anchors=('github_pat_',)),
    TokenFormat("gitlab_token", r"\bglpat-[A-Za-z0-9_-]{20,}\b", anchors=('glpat-',)),
    TokenFormat("aws_access_key_id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", anchors=('AKIA', 'ASIA')),
    TokenFormat("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", anchors=('AIza',)),
    TokenFormat("google_oauth_client_secret", r"\bGOCSPX-[A-Za-z0-9_-]{28}\b", anchors=('GOCSPX-',)),
    TokenFormat("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b", anchors=('xox',)),
    TokenFormat(
        "slack_webhook_url",
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{6,}/B[A-Za-z0-9_]{6,}/[A-Za-z0-9_]{16,}", anchors=('hooks.slack.com',)),
    TokenFormat("stripe_secret_key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b", anchors=('_live_', '_test_')),
    TokenFormat("sendgrid_api_key", r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b", anchors=('SG.',)),
    TokenFormat("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", anchors=('sk-ant-',)),
    TokenFormat("openai_api_key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b", anchors=('sk-',)),
    TokenFormat("huggingface_token", r"\bhf_[A-Za-z0-9]{30,}\b", anchors=('hf_',)),
    TokenFormat("npm_token", r"\bnpm_[A-Za-z0-9]{30,}\b", anchors=('npm_',)),
    TokenFormat("pypi_token", r"\bpypi-[A-Za-z0-9_-]{40,}\b", anchors=('pypi-',)),
    TokenFormat("docker_pat", r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b", anchors=('dckr_pat_',)),
    TokenFormat("digitalocean_token", r"\bdo[opr]_v1_[a-f0-9]{64}\b", anchors=('_v1_',)),
    TokenFormat("shopify_token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b", anchors=('shpat_', 'shpca_', 'shppa_', 'shpss_')),
    TokenFormat("twilio_api_key", r"\bSK[0-9a-fA-F]{32}\b", anchors=('SK',)),
    TokenFormat("square_token", r"\b(?:sq0atp|sq0csp)-[0-9A-Za-z_-]{22,}\b", anchors=('sq0atp-', 'sq0csp-')),
    TokenFormat("telegram_bot_token", r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b", anchors=(':AA',)),
    TokenFormat(
        "discord_bot_token", r"\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b",
    ),
    TokenFormat("databricks_token", r"\bdapi[a-f0-9]{32}(?:-\d)?\b", anchors=('dapi',)),
    TokenFormat("atlassian_api_token", r"\bATATT3[A-Za-z0-9_=-]{150,}", anchors=('ATATT3',)),
    TokenFormat("linear_api_key", r"\blin_api_[A-Za-z0-9]{40}\b", anchors=('lin_api_',)),
    TokenFormat("postman_api_key", r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b", anchors=('PMAK-',)),
    TokenFormat("grafana_token", r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b|\bglc_[A-Za-z0-9+/]{32,}={0,2}", anchors=('glsa_', 'glc_')),
    TokenFormat("new_relic_key", r"\bNRAK-[A-Z0-9]{27}\b", anchors=('NRAK-',)),
    TokenFormat("hashicorp_vault_token", r"\bhv[sb]\.[A-Za-z0-9_-]{24,}\b", anchors=('hvs.', 'hvb.')),
    TokenFormat("doppler_token", r"\bdp\.(?:pt|st|sa|ct)\.[A-Za-z0-9]{40,}\b", anchors=('dp.',)),
    TokenFormat("age_secret_key", r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b", "CRITICAL", anchors=('AGE-SECRET-KEY-1',)),
    TokenFormat("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", anchors=('eyJ',)),
    # Connection-string secrets: only the value is matched (fixed-width lookbehind).
    TokenFormat("azure_storage_account_key", r"(?<=[Aa]ccount[Kk]ey=)[A-Za-z0-9+/]{40,}={0,2}", anchors=('ccountKey=', 'ccountkey=')),
    TokenFormat("azure_shared_access_key", r"(?<=[Ss]hared[Aa]ccess[Kk]ey=)[A-Za-z0-9+/]{30,}={0,2}", anchors=('ccessKey=', 'ccesskey=')),
    TokenFormat("azure_sas_signature", r"(?<=[?&]sig=)[A-Za-z0-9%+/]{20,}={0,2}", anchors=('sig=',)),
)

# Key names whose literal values the secret scanner reports as credential assignments.
# The excerpt redactor uses this list too (plus a few names it only redacts), so every
# value the scanner reports is also removed from report excerpts.
CREDENTIAL_KEYWORDS = (
    r"api[_-]?key|client[_-]?secret|service[_-]?token|access[_-]?(?:token|key)"
    r"|auth[_-]?token|refresh[_-]?token|password|passwd|passphrase"
    r"|secret[_-]?(?:access[_-]?)?key|secret|token|encryption[_-]?key|signing[_-]?key"
    r"|aws_secret_access_key|database_url"
)
# An optional closing key quote and subscript bracket ("password": / 'password' => /
# env['API_TOKEN'] =), an optional type annotation (password: str = / apiKey: string =),
# then the operator: Go's :=, PHP and Ruby's =>, or : and =. Separators never cross a line.
ASSIGNMENT_OPERATOR = (
    r"""["']?\]?[ \t]*(?::[ \t]*[A-Za-z_][\w.\[\]]*(?:[ \t]*\|[ \t]*[A-Za-z_][\w.\[\]]*)*[ \t]*=(?!=)"""
    r"""|:=|=>|[:=](?!=))[ \t]*"""
)

PRIVATE_KEY_ANCHORS = ("PRIVATE KEY",)
PRIVATE_KEY_MARKER = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
)
# One alternation used by the redactor; detection compiles each format separately so
# findings can name the format.
ANY_TOKEN = re.compile("|".join(f"(?:{item.pattern})" for item in TOKEN_FORMATS))
COMPILED_FORMATS: tuple[tuple[TokenFormat, re.Pattern[str]], ...] = tuple(
    (item, re.compile(item.pattern)) for item in TOKEN_FORMATS
)
