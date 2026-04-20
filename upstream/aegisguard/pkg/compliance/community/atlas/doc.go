// Package atlas provides MITRE ATLAS framework compliance checking.
//
// MITRE ATLAS™ (Adversarial Threat Landscape for Artificial-Intelligence Systems)
// is a knowledge base of adversary tactics and techniques based on real-world
// attack observations and realistic demonstrations from AI red teams and security
// groups.
//
// # Features
//
//   - Complete tactic coverage: All 14 ATLAS tactics
//   - Technique detection: 30+ adversarial ML techniques
//   - MITRE ATT&CK mapping: Cross-references to ATT&CK framework
//   - LLM-specific threats: Prompt injection, model extraction, data poisoning
//
// # Usage
//
//	import "github.com/aegisguardsecurity/aegisguard/pkg/compliance/community/atlas"
//
//	checker := atlas.NewAtlasFramework()
//	finding, _ := checker.Check(nil)
//
// # Version
//
// Version: 4.6.0
// ATLAS Version: 4.0.0
// Last Updated: 2024
package atlas
