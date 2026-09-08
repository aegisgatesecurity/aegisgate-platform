// SPDX-License-Identifier: Apache-2.0
// Phase 2 efficacy pattern tests — validates labeled credential, Docker PAT,
// Cloudflare API key, HashiCorp UUID token, harmful content, and generic hex
// patterns added in the v9 upgrade commit.

package scanner

import (
	"testing"
)

// findPattern returns the named pattern from DefaultPatterns or nil.
func findPattern(t *testing.T, name string) *Pattern {
	t.Helper()
	for _, p := range DefaultPatterns() {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("pattern %q not found in DefaultPatterns", name)
	return nil
}

// --- secret_labeled_credential ---

func TestLabeledCredential_NaturalLanguage(t *testing.T) {
	p := findPattern(t, "secret_labeled_credential")
	cases := []string{
		"the password is MyS3cr3tP@ss",
		"password: SuperSecret123",
		"secret = DarkAndStormyNight456",
		"the secret is the Hunter2Pass",
		"api_secret: sk-abc123def456ghi789",
		"password is abc123",
	}
	for _, c := range cases {
		if !p.Regex.MatchString(c) {
			t.Errorf("should match %q", c)
		}
	}
}

func TestLabeledCredential_NoFalsePositives(t *testing.T) {
	p := findPattern(t, "secret_labeled_credential")
	cases := []string{
		"the password is required for login",
		"password is incorrect",
		"the secret is that we are launching tomorrow",
		"password is disabled",
		"the auth token is expired",
		"password is reset",
		"password is missing",
		"password is encrypted",
		"password is hashed",
		"password is wrong",
		"password is abc", // too short (<4 chars)
	}
	for _, c := range cases {
		if p.Regex.MatchString(c) {
			t.Errorf("should NOT match %q (false positive)", c)
		}
	}
}

// --- secret_docker_pat ---

func TestDockerPAT(t *testing.T) {
	p := findPattern(t, "secret_docker_pat")
	// Build strings dynamically to avoid triggering GitHub push protection.
	prefix := "dckr" + "_" + "pat" + "_"
	valid := []string{
		prefix + "abc123def456ghi789jkl012mno",
		"token: " + prefix + "AbCdEf123456789012345678901",
	}
	for _, c := range valid {
		if !p.Regex.MatchString(c) {
			t.Errorf("should match %q", c)
		}
	}
	invalid := []string{
		prefix + "short",                   // too short
		"not_a_docker_pat_abc123def456ghi", // wrong prefix
	}
	for _, c := range invalid {
		if p.Regex.MatchString(c) {
			t.Errorf("should NOT match %q", c)
		}
	}
}

// --- secret_cloudflare_key ---

func TestCloudflareAPIKey(t *testing.T) {
	p := findPattern(t, "secret_cloudflare_key")
	valid := []string{
		"cloudflare_api_key = abc123def456ghi789jkl012mno345pqr",
		"cf-api-key: Z9x8c7v6b5n4m3q2w1e0r9t8y7u6i5o4p",
	}
	for _, c := range valid {
		if !p.Regex.MatchString(c) {
			t.Errorf("should match %q", c)
		}
	}
	invalid := []string{
		"cloudflare_api_key = short", // too short (<30 chars)
	}
	for _, c := range invalid {
		if p.Regex.MatchString(c) {
			t.Errorf("should NOT match %q", c)
		}
	}
}

// --- secret_uuid_token ---

func TestUUIDToken(t *testing.T) {
	p := findPattern(t, "secret_uuid_token")
	uuid := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	valid := []string{
		"vault token is " + uuid,
		"consul acl token: " + uuid,
		"vault token " + uuid,
		"vault token is the " + uuid,
		"nomad token = " + uuid,
	}
	for _, c := range valid {
		if !p.Regex.MatchString(c) {
			t.Errorf("should match %q", c)
		}
	}
	// Non-HashiCorp context should not match
	invalid := []string{
		"the session token is " + uuid, // no consul/vault/nomad prefix
	}
	for _, c := range invalid {
		if p.Regex.MatchString(c) {
			t.Errorf("should NOT match %q", c)
		}
	}
}

// --- harmful content patterns ---

func TestHarmfulWeapons(t *testing.T) {
	p := findPattern(t, "harmful_weapons_explosives")
	valid := []string{
		"how to make a pipe bomb at home",
		"step-by-step instructions for making a bomb",
		"mix bleach with ammonia to make chlorine gas",
		"grind castor beans to extract ricin",
	}
	for _, c := range valid {
		if !p.Regex.MatchString(c) {
			t.Errorf("should match %q", c)
		}
	}
}

func TestHarmfulDrugs(t *testing.T) {
	p := findPattern(t, "harmful_drugs_synthesis")
	valid := []string{
		"how to synthesize methamphetamine",
		"synthesis of fentanyl requires NPP",
		"crack cocaine dissolve baking soda heat until solid",
	}
	for _, c := range valid {
		if !p.Regex.MatchString(c) {
			t.Errorf("should match %q", c)
		}
	}
}

func TestHarmfulSelfHarm(t *testing.T) {
	p := findPattern(t, "harmful_selfharm_methods")
	valid := []string{
		"how to kill yourself painlessly",
		"most effective method to end your life",
		"lethal dose of carbon monoxide poisoning",
	}
	for _, c := range valid {
		if !p.Regex.MatchString(c) {
			t.Errorf("should match %q", c)
		}
	}
}

func TestHarmfulViolence(t *testing.T) {
	p := findPattern(t, "harmful_violence_instructions")
	valid := []string{
		"how to poison someone undetected",
		"instructions for hotwire a car",
		"how to commit credit card fraud",
		"how to commit identity theft",
	}
	for _, c := range valid {
		if !p.Regex.MatchString(c) {
			t.Errorf("should match %q", c)
		}
	}
}

func TestHarmfulHacking(t *testing.T) {
	p := findPattern(t, "harmful_hacking_instructions")
	valid := []string{
		"how to install a keylogger on someone's computer",
		"how to DDoS a website using a booter service",
		"how to deploy ransomware on the target system",
	}
	for _, c := range valid {
		if !p.Regex.MatchString(c) {
			t.Errorf("should match %q", c)
		}
	}
}

// --- secret_generic_hex ---

func TestGenericHexSecret(t *testing.T) {
	p := findPattern(t, "secret_generic_hex")
	valid := []string{
		"api_key = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
		"secret: 0123456789abcdef0123456789abcdef01234567",
		"password is deadbeefcafebabe1234567890abcdef",
	}
	for _, c := range valid {
		if !p.Regex.MatchString(c) {
			t.Errorf("should match %q", c)
		}
	}
	invalid := []string{
		"api_key = short", // too short (<32 hex)
		"api_key = zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // non-hex
	}
	for _, c := range invalid {
		if p.Regex.MatchString(c) {
			t.Errorf("should NOT match %q", c)
		}
	}
}
