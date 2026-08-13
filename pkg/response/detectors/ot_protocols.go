// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - OT/ICS Protocol Detection Patterns
// =========================================================================
//
// Detection patterns for Operational Technology (OT) and Industrial Control
// System (ICS) protocols. These patterns identify potential OT protocol
// manipulation in AI prompts, which is a high-risk indicator for:
//   - Manufacturing sector: Modbus function codes
//   - Energy/utilities sector: DNP3 control operations
//   - Cross-sector: OPC-UA method calls
//
// SOC relevance: If a user is prompting an AI with OT protocol commands,
// they may be:
//   1. Testing industrial control manipulation (attack reconnaissance)
//   2. Troubleshooting legitimate OT systems (requires authorization)
//   3. Attempting to bypass OT security controls
//
// These patterns are regex-feasible and operationally useful for SOC
// analysts in manufacturing, energy, and utilities verticals.
// =========================================================================

package detectors

// OTProtocolPatterns defines OT/ICS protocol detection patterns.
// Focused on text-based protocol elements that appear in AI prompts.
var OTProtocolPatterns = []PatternDef{
	// Modbus Function Codes (manufacturing, building automation)
	// Function codes 01-07 are read operations (lower risk)
	// Function codes 05, 06, 15, 16 are write operations (higher risk)
	{
		Name:        "ot_modbus_function_code",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:function\s*code|FC)\s*[:=]?\s*(?:0[1-7]|1[0-6])\b`,
		Description: "Modbus function code (01-16) with label",
	},
	{
		Name:        "ot_modbus_write_single_coil",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:function\s*code|FC)\s*[:=]?\s*05\b`,
		Description: "Modbus function code 05 (Write Single Coil) - potential control manipulation",
	},
	{
		Name:        "ot_modbus_write_single_register",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:function\s*code|FC)\s*[:=]?\s*06\b`,
		Description: "Modbus function code 06 (Write Single Register) - potential control manipulation",
	},
	{
		Name:        "ot_modbus_write_multiple_coils",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:function\s*code|FC)\s*[:=]?\s*(?:15|0?15)\b`,
		Description: "Modbus function code 15 (Write Multiple Coils) - potential control manipulation",
	},
	{
		Name:        "ot_modbus_write_multiple_registers",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:function\s*code|FC)\s*[:=]?\s*(?:16|0?16)\b`,
		Description: "Modbus function code 16 (Write Multiple Registers) - potential control manipulation",
	},
	// DNP3 Control Operations (energy sector, grid control)
	{
		Name:        "ot_dnp3_control_relay",
		Severity:    SeverityHigh,
		Regex:       `(?i)\bDNP3\s+(?:control\s+)?relay\s+(?:output\s+)?(?:block|group)\s*[:=]?\s*12\b`,
		Description: "DNP3 control relay output block (Group 12) - grid control operation",
	},
	{
		Name:        "ot_dnp3_analog_output",
		Severity:    SeverityHigh,
		Regex:       `(?i)\bDNP3\s+analog\s+output\s+(?:block|group)\s*[:=]?\s*4[0-2]\b`,
		Description: "DNP3 analog output block (Groups 40-42) - setpoint manipulation",
	},
	// OPC-UA Method Calls (cross-industry industrial automation)
	{
		Name:        "ot_opcua_method_call",
		Severity:    SeverityMedium,
		Regex:       `(?i)\bOPC[-_]?UA\s+(?:method\s+)?[A-Za-z][A-Za-z0-9_]*\.[A-Za-z][A-Za-z0-9_]*\b`,
		Description: "OPC-UA method call (Namespace.Method format)",
	},
	{
		Name:        "ot_opcua_write_value",
		Severity:    SeverityHigh,
		Regex:       `(?i)\bWriteValue\s*(?:method)?\b`,
		Description: "OPC-UA WriteValue method call - potential control manipulation",
	},
}

// CompiledOTProtocolPatterns holds pre-compiled OT protocol regex patterns.
var CompiledOTProtocolPatterns []compiledPattern

func init() {
	CompiledOTProtocolPatterns = compilePatterns(OTProtocolPatterns)
}

// DetectOTProtocols scans text for OT/ICS protocol patterns and returns matches.
func DetectOTProtocols(text string) []Match {
	return detectWithPatterns(text, CompiledOTProtocolPatterns, "ot_protocol")
}
