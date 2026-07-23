// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Secret Detection Patterns
// =========================================================================
//
// Port of aegisgate-lens/src/detectors/regex/secrets.js (45 patterns).
// Regex strings are adapted from JavaScript /g flag syntax to Go regexp.
// RE2 does not support lookbehind/lookahead; patterns requiring those
// features have been rewritten or relaxed.
// =========================================================================

package detectors

// SecretsPatterns defines all secret detection patterns.
// Lens parity: secrets.js v0.2.0 (45 patterns).
var SecretsPatterns = []PatternDef{
	{
		Name:        "secret_aws_key",
		Severity:    SeverityCritical,
		Regex:       `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`,
		Description: "AWS access key ID",
	},
	{
		Name:        "secret_github_token",
		Severity:    SeverityCritical,
		Regex:       `\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{80,120}\b`,
		Description: "GitHub personal access token",
	},
	{
		Name:        "secret_gcp_key",
		Severity:    SeverityHigh,
		Regex:       `\bAIza[0-9A-Za-z_-]{30,50}\b`,
		Description: "Google Cloud API key",
	},
	{
		Name:        "secret_azure_key",
		Severity:    SeverityHigh,
		Regex:       `(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{44,88}`,
		Description: "Azure storage account key or SAS",
	},
	{
		Name:        "secret_private_key_pem",
		Severity:    SeverityCritical,
		Regex:       `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`,
		Description: "PEM private key header",
	},
	{
		Name:        "secret_oauth_token",
		Severity:    SeverityHigh,
		Regex:       `\bya29\.[0-9A-Za-z_-]{50,}\b|\b1/[0-9A-Za-z_-]{40,}\b`,
		Description: "OAuth token (Google or generic)",
	},
	{
		Name:        "secret_jwt",
		Severity:    SeverityHigh,
		Regex:       `\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`,
		Description: "JSON Web Token",
	},
	{
		Name:        "secret_api_key_generic",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`,
		Description: "Generic API key or token assignment",
	},
	{
		Name:        "secret_db_connection_string",
		Severity:    SeverityHigh,
		Regex:       `(?:mongodb|postgres|postgresql|mysql|redis|amqp)(?:\+\w+)?:\/\/[\w.-]+:[^\s@]+@[^\s/]+`,
		Description: "Database connection string with credentials",
	},
	{
		Name:        "secret_slack_token",
		Severity:    SeverityHigh,
		Regex:       `\bxox[abprs]-[0-9]+-[0-9]+-[A-Za-z0-9]+\b`,
		Description: "Slack bot/user token",
	},
	{
		Name:        "secret_stripe_key",
		Severity:    SeverityHigh,
		Regex:       `\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b`,
		Description: "Stripe API key",
	},
	{
		Name:        "secret_twilio_key",
		Severity:    SeverityHigh,
		Regex:       `\b(?:SK|AC)[a-fA-F0-9]{32}\b`,
		Description: "Twilio account SID or auth token",
	},
	{
		Name:        "secret_sendgrid_key",
		Severity:    SeverityHigh,
		Regex:       `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`,
		Description: "SendGrid API key",
	},
	{
		Name:        "secret_mailgun_key",
		Severity:    SeverityHigh,
		Regex:       `\bkey-[a-f0-9]{32}\b`,
		Description: "Mailgun API key",
	},
	{
		Name:        "secret_openai_key",
		Severity:    SeverityHigh,
		Regex:       `\bsk-(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{20,}\b`,
		Description: "OpenAI API key",
	},
	{
		Name:        "secret_anthropic_key",
		Severity:    SeverityHigh,
		Regex:       `\bsk-ant-(?:api)?\d{2}-[A-Za-z0-9_-]{20,}\b`,
		Description: "Anthropic API key",
	},
	{
		Name:        "secret_heroku_key",
		Severity:    SeverityMedium,
		Regex:       `\bheroku_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`,
		Description: "Heroku API key",
	},
	{
		Name:        "secret_gitlab_pat",
		Severity:    SeverityCritical,
		Regex:       `\bglpat-[A-Za-z0-9_-]{20,}\b`,
		Description: "GitLab personal access token",
	},
	{
		Name:        "secret_npm_token",
		Severity:    SeverityCritical,
		Regex:       `\bnpm_[A-Za-z0-9]{30,}\b`,
		Description: "npm access token",
	},
	{
		Name:        "secret_pypi_token",
		Severity:    SeverityCritical,
		Regex:       `\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b`,
		Description: "PyPI API token",
	},
	{
		Name:        "secret_slack_legacy",
		Severity:    SeverityHigh,
		Regex:       `\bxox[abprs]-[A-Za-z0-9-]{10,}\b`,
		Description: "Slack legacy token",
	},
	{
		Name:        "secret_github_finegrained",
		Severity:    SeverityCritical,
		Regex:       `\bgithub_pat_[A-Za-z0-9_]{60,}\b`,
		Description: "GitHub fine-grained personal access token",
	},
	{
		Name:        "secret_supabase",
		Severity:    SeverityHigh,
		Regex:       `\beyJ[A-Za-z0-9_-]{50,}\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{40,}\b`,
		Description: "Supabase JWT/API key",
	},
	{
		Name:        "secret_db_url_with_password",
		Severity:    SeverityHigh,
		Regex:       `(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|sqlserver|oracle|jdbc:(?:mysql|postgresql|sqlserver|oracle)|cassandra|influxdb|clickhouse|rabbitmq|mssql|sybase|db2|firebird|hsqldb|derby|sqlite):\/\/[\w.-]+:[^\s@'"]+@[^\s/'"]+`,
		Description: "Database URL with embedded password",
	},
	{
		Name:        "secret_aws_account_id",
		Severity:    SeverityMedium,
		Regex:       `\barn:aws:[a-z0-9-]+:[a-z0-9-]*:(?:aws)?:?(\d{12}):`,
		Description: "AWS ARN with account ID",
	},
	{
		Name:        "secret_github_actions_token",
		Severity:    SeverityCritical,
		Regex:       `\bgh[osur]_[A-Za-z0-9]{30,}\b`,
		Description: "GitHub Actions token",
	},
	{
		Name:        "secret_gitlab_token",
		Severity:    SeverityCritical,
		Regex:       `(?:GLPAT|gitlab_pat)_[A-Za-z0-9]{20,255}`,
		Description: "GitLab token",
	},
	{
		Name:        "secret_bitbucket_token",
		Severity:    SeverityCritical,
		Regex:       `(?:BITBUCKET_TOKEN|BITBUCKET_PAT)\s*[:=]\s*xrp[A-Za-z0-9_]{32,255}`,
		Description: "Bitbucket token",
	},
	{
		Name:        "secret_gitea_token",
		Severity:    SeverityCritical,
		Regex:       `gitea_[A-Za-z0-9]{36,255}`,
		Description: "Gitea token",
	},
	{
		Name:        "secret_circleci_token",
		Severity:    SeverityHigh,
		Regex:       `cici_[A-Za-z0-9]{36,255}`,
		Description: "CircleCI token",
	},
	{
		Name:        "secret_travis_token",
		Severity:    SeverityHigh,
		Regex:       `travis_[A-Za-z0-9]{36,255}`,
		Description: "Travis CI token",
	},
	{
		Name:        "secret_jenkins_token",
		Severity:    SeverityHigh,
		Regex:       `(?:JENKINS_TOKEN|JENKINS_API|JENKINS_PASSWORD)\s*[:=]\s*xrp[A-Za-z0-9_]{32,255}`,
		Description: "Jenkins token",
	},
	{
		Name:        "secret_azure_devops",
		Severity:    SeverityCritical,
		Regex:       `azdo_[A-Za-z0-9]{36,255}`,
		Description: "Azure DevOps token",
	},
	{
		Name:        "secret_digitalocean_token",
		Severity:    SeverityCritical,
		Regex:       `(?:DO_PAT|DIGITALOCEAN_TOKEN|DO_TOKEN)\s*[:=]\s*dop_v1_[A-Za-z0-9]{40,100}`,
		Description: "DigitalOcean token",
	},
	{
		Name:        "secret_linode_token",
		Severity:    SeverityCritical,
		Regex:       `linode_[A-Za-z0-9]{40,80}`,
		Description: "Linode token",
	},
	{
		Name:        "secret_rackspace_token",
		Severity:    SeverityHigh,
		Regex:       `rackspace_[A-Za-z0-9]{32,64}`,
		Description: "Rackspace token",
	},
	{
		Name:        "secret_heroku_token_legacy",
		Severity:    SeverityHigh,
		Regex:       `heroku_[A-Za-z0-9-]{36,50}`,
		Description: "Heroku legacy token",
	},
	{
		Name:        "secret_salesforce_token",
		Severity:    SeverityCritical,
		Regex:       `00D[A-Za-z0-9]{15}![A-Za-z0-9]{64,128}`,
		Description: "Salesforce session/token",
	},
	{
		Name:        "secret_shopify_token",
		Severity:    SeverityHigh,
		Regex:       `sh[a-z]+_[A-Za-z0-9]{20,255}`,
		Description: "Shopify access token",
	},
	{
		Name:        "secret_wordpress_token",
		Severity:    SeverityHigh,
		Regex:       `wordpress_[A-Za-z0-9]{32,64}`,
		Description: "WordPress application password/token",
	},
	{
		Name:        "secret_internal_api_key",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:INTERNAL[_-]?API[_-]?KEY|INTERNAL[_-]?KEY|INTERNAL[_-]?TOKEN)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`,
		Description: "Internal API key assignment",
	},
	{
		Name:        "secret_cursor_key",
		Severity:    SeverityHigh,
		Regex:       `\bcrsr_[A-Za-z0-9]{64}\b`,
		Description: "Cursor API key",
	},
	{
		Name:        "secret_vercel_key",
		Severity:    SeverityHigh,
		Regex:       `\bvck[A-Za-z0-9_-]{32,}\b`,
		Description: "Vercel AI Gateway API key",
	},
	{
		Name:        "secret_groq_key",
		Severity:    SeverityHigh,
		Regex:       `\bgsk_[A-Za-z0-9]{52}\b`,
		Description: "Groq API key",
	},
	{
		Name:        "secret_replicate_key",
		Severity:    SeverityHigh,
		Regex:       `\br8_[A-Za-z0-9]{37}\b`,
		Description: "Replicate API token",
	},
}

// CompiledSecretPatterns holds pre-compiled secret regex patterns.
var CompiledSecretPatterns []compiledPattern

func init() {
	CompiledSecretPatterns = compilePatterns(SecretsPatterns)
}

// DetectSecrets scans text for all secret patterns and returns matches.
func DetectSecrets(text string) []Match {
	return detectWithPatterns(text, CompiledSecretPatterns, string(CategorySecrets))
}
