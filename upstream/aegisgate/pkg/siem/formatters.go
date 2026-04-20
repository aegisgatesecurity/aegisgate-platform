// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package siem provides event formatters for various SIEM formats.
package siem

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// CEF Formatter (Common Event Format - ArcSight)
// ============================================================================

// CEFFormatter formats events in Common Event Format.
// CEF format: CEF:Version|Vendor|Product|Version|Signature ID|Name|Severity|Extension
type CEFFormatter struct {
	platform Platform
	vendor   string
	product  string
	version  string
}

// CEFOptions contains CEF formatting options.
type CEFOptions struct {
	Vendor  string
	Product string
	Version string
}

// NewCEFFormatter creates a new CEF formatter.
func NewCEFFormatter(platform Platform, opts CEFOptions) *CEFFormatter {
	return &CEFFormatter{
		platform: platform,
		vendor:   orDefault(opts.Vendor, "AegisGate"),
		product:  orDefault(opts.Product, "AI Security Gateway"),
		version:  orDefault(opts.Version, "1.0"),
	}
}

// Format formats a single event in CEF format.
func (f *CEFFormatter) Format(event *Event) ([]byte, error) {
	var buf strings.Builder

	// CEF Header
	buf.WriteString(fmt.Sprintf("CEF:0|%s|%s|%s|",
		cefEscape(f.vendor),
		cefEscape(f.product),
		cefEscape(f.version),
	))

	// Signature ID (use event type or ID)
	signatureID := event.Type
	if signatureID == "" {
		signatureID = event.ID
	}
	buf.WriteString(cefEscape(signatureID))
	buf.WriteRune('|')

	// Event Name
	name := event.Message
	if len(name) > 100 {
		name = name[:100] + "..."
	}
	buf.WriteString(cefEscape(name))
	buf.WriteRune('|')

	// Severity (map to CEF severity 0-10)
	severity := cefSeverity(event.Severity)
	buf.WriteString(severity)
	buf.WriteRune('|')

	// Extension (key=value pairs)
	extensions := f.buildExtensions(event)
	buf.WriteString(extensions)

	return []byte(buf.String()), nil
}

// FormatBatch formats multiple events in CEF format.
func (f *CEFFormatter) FormatBatch(events []*Event) ([]byte, error) {
	var buf strings.Builder
	for i, event := range events {
		data, err := f.Format(event)
		if err != nil {
			return nil, err
		}
		buf.Write(data)
		if i < len(events)-1 {
			buf.WriteByte('\n')
		}
	}
	return []byte(buf.String()), nil
}

// ContentType returns the content type.
func (f *CEFFormatter) ContentType() string {
	return "text/plain"
}

// FileExtension returns the file extension.
func (f *CEFFormatter) FileExtension() string {
	return ".cef"
}

// buildExtensions builds CEF extension key=value pairs.
func (f *CEFFormatter) buildExtensions(event *Event) string {
	ext := make([]string, 0, 20)

	// Standard CEF extensions
	ext = append(ext, fmt.Sprintf("rt=%d", event.Timestamp.Unix()*1000))
	ext = append(ext, fmt.Sprintf("deviceVendor=%s", f.vendor))
	ext = append(ext, fmt.Sprintf("deviceProduct=%s", f.product))

	// Event details
	ext = append(ext, fmt.Sprintf("category=%s", string(event.Category)))
	ext = append(ext, fmt.Sprintf("eventId=%s", event.ID))

	// Source info (from entities)
	for _, entity := range event.Entities {
		switch entity.Type {
		case "src_ip", "source_ip", "ip":
			ext = append(ext, fmt.Sprintf("src=%s", entity.Value))
		case "src_host", "source_host", "host":
			ext = append(ext, fmt.Sprintf("shost=%s", entity.Value))
		case "src_user", "source_user", "user":
			ext = append(ext, fmt.Sprintf("suser=%s", entity.Value))
		case "dst_ip", "dest_ip":
			ext = append(ext, fmt.Sprintf("dst=%s", entity.Value))
		case "dst_host", "dest_host":
			ext = append(ext, fmt.Sprintf("dhost=%s", entity.Value))
		case "dst_user", "dest_user":
			ext = append(ext, fmt.Sprintf("duser=%s", entity.Value))
		}
	}

	// MITRE ATT&CK mappings
	if event.MITRE != nil {
		if event.MITRE.Tactic != "" {
			ext = append(ext, fmt.Sprintf("cs1=%s", event.MITRE.Tactic))
			ext = append(ext, "cs1Label=MitreTactic")
		}
		if event.MITRE.Technique != "" {
			ext = append(ext, fmt.Sprintf("cs2=%s", event.MITRE.Technique))
			ext = append(ext, "cs2Label=MitreTechnique")
		}
	}

	// Additional attributes
	for k, v := range event.Attributes {
		// Map common attributes to CEF extensions
		switch k {
		case "request_method":
			ext = append(ext, fmt.Sprintf("requestMethod=%s", v))
		case "request_url":
			ext = append(ext, fmt.Sprintf("request=%s", v))
		case "response_code":
			ext = append(ext, fmt.Sprintf("outcome=%s", v))
		case "bytes_in":
			ext = append(ext, fmt.Sprintf("in=%s", v))
		case "bytes_out":
			ext = append(ext, fmt.Sprintf("out=%s", v))
		default:
			// Custom extensions
			ext = append(ext, fmt.Sprintf("cs3Label=%s", k))
			ext = append(ext, fmt.Sprintf("cs3=%s", v))
		}
	}

	return strings.Join(ext, " ")
}

// cefEscape escapes special characters for CEF format.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "=", "\\=")
	return s
}

// cefSeverity maps SIEM severity to CEF severity (0-10).
func cefSeverity(sev Severity) string {
	switch sev {
	case SeverityCritical:
		return "10"
	case SeverityHigh:
		return "8"
	case SeverityMedium:
		return "6"
	case SeverityLow:
		return "4"
	default:
		return "2"
	}
}

// ============================================================================
// LEEF Formatter (Log Event Extended Format - QRadar)
// ============================================================================

// LEEFFormatter formats events in LEEF format for QRadar.
// LEEF format: LEEF:Version|Vendor|Product|Version|Event ID|Extension
type LEEFFormatter struct {
	platform Platform
	vendor   string
	product  string
	version  string
}

// LEEFOptions contains LEEF formatting options.
type LEEFOptions struct {
	Vendor  string
	Product string
	Version string
}

// NewLEEFFormatter creates a new LEEF formatter.
func NewLEEFFormatter(platform Platform, opts LEEFOptions) *LEEFFormatter {
	return &LEEFFormatter{
		platform: platform,
		vendor:   orDefault(opts.Vendor, "AegisGate"),
		product:  orDefault(opts.Product, "AI Security Gateway"),
		version:  orDefault(opts.Version, "1.0"),
	}
}

// Format formats a single event in LEEF format.
func (f *LEEFFormatter) Format(event *Event) ([]byte, error) {
	var buf strings.Builder

	// LEEF Header
	buf.WriteString(fmt.Sprintf("LEEF:2.0|%s|%s|%s|",
		leefEscape(f.vendor),
		leefEscape(f.product),
		leefEscape(f.version),
	))

	// Event ID (use event type)
	eventID := event.Type
	if eventID == "" {
		eventID = event.ID
	}
	buf.WriteString(leefEscape(eventID))
	buf.WriteRune('|')

	// Extension (key=value pairs with cat for severity)
	extensions := f.buildExtensions(event)
	buf.WriteString(extensions)

	return []byte(buf.String()), nil
}

// FormatBatch formats multiple events in LEEF format.
func (f *LEEFFormatter) FormatBatch(events []*Event) ([]byte, error) {
	var buf strings.Builder
	for i, event := range events {
		data, err := f.Format(event)
		if err != nil {
			return nil, err
		}
		buf.Write(data)
		if i < len(events)-1 {
			buf.WriteByte('\n')
		}
	}
	return []byte(buf.String()), nil
}

// ContentType returns the content type.
func (f *LEEFFormatter) ContentType() string {
	return "text/plain"
}

// FileExtension returns the file extension.
func (f *LEEFFormatter) FileExtension() string {
	return ".leef"
}

// buildExtensions builds LEEF extension key=value pairs.
func (f *LEEFFormatter) buildExtensions(event *Event) string {
	ext := make([]string, 0, 20)

	// LEEF standard fields
	ext = append(ext, fmt.Sprintf("devTime=%s", event.Timestamp.Format(time.RFC3339)))
	ext = append(ext, fmt.Sprintf("sev=%s", string(event.Severity)))
	ext = append(ext, fmt.Sprintf("cat=%s", string(event.Category)))
	ext = append(ext, fmt.Sprintf("eventName=%s", event.Message))

	// Source info (from entities)
	for _, entity := range event.Entities {
		switch entity.Type {
		case "src_ip", "source_ip", "ip":
			ext = append(ext, fmt.Sprintf("src=%s", entity.Value))
		case "src_port", "source_port":
			ext = append(ext, fmt.Sprintf("srcPort=%s", entity.Value))
		case "src_host", "source_host", "host":
			ext = append(ext, fmt.Sprintf("srcHost=%s", entity.Value))
		case "src_user", "source_user", "user":
			ext = append(ext, fmt.Sprintf("usrName=%s", entity.Value))
		case "dst_ip", "dest_ip":
			ext = append(ext, fmt.Sprintf("dst=%s", entity.Value))
		case "dst_port", "dest_port":
			ext = append(ext, fmt.Sprintf("dstPort=%s", entity.Value))
		case "dst_host", "dest_host":
			ext = append(ext, fmt.Sprintf("dstHost=%s", entity.Value))
		}
	}

	// MITRE ATT&CK mappings
	if event.MITRE != nil {
		if event.MITRE.Tactic != "" {
			ext = append(ext, fmt.Sprintf("mitreTactic=%s", event.MITRE.Tactic))
		}
		if event.MITRE.Technique != "" {
			ext = append(ext, fmt.Sprintf("mitreTechnique=%s", event.MITRE.Technique))
		}
	}

	// Raw event attributes
	for k, v := range event.Attributes {
		ext = append(ext, fmt.Sprintf("%s=%s", k, v))
	}

	return strings.Join(ext, "\t")
}

// leefEscape escapes special characters for LEEF format.
func leefEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "=", "\\=")
	return s
}

// ============================================================================
// Syslog Formatter (RFC 5424)
// ============================================================================

// SyslogFormatter formats events in RFC 5424 syslog format.
type SyslogFormatter struct {
	platform Platform
	facility int
	appName  string
	hostname string
}

// SyslogOptions contains syslog formatting options.
type SyslogOptions struct {
	Facility int
	AppName  string
	Hostname string
}

// NewSyslogFormatter creates a new syslog formatter.
func NewSyslogFormatter(platform Platform, opts SyslogOptions) *SyslogFormatter {
	return &SyslogFormatter{
		platform: platform,
		facility: orDefaultInt(opts.Facility, 1), // user facility
		appName:  orDefault(opts.AppName, "aegisgate"),
		hostname: orDefault(opts.Hostname, getHostname()),
	}
}

// Format formats a single event in syslog format.
func (f *SyslogFormatter) Format(event *Event) ([]byte, error) {
	// Calculate priority
	priority := f.facility*8 + syslogSeverity(event.Severity)

	// Build structured data
	structuredData := f.buildStructuredData(event)

	// RFC 5424 format
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
	msg := fmt.Sprintf("<%d>1 %s %s %s - - %s %s",
		priority,
		event.Timestamp.Format(time.RFC3339),
		f.hostname,
		f.appName,
		structuredData,
		event.Message,
	)

	return []byte(msg), nil
}

// FormatBatch formats multiple events in syslog format.
func (f *SyslogFormatter) FormatBatch(events []*Event) ([]byte, error) {
	var buf strings.Builder
	for i, event := range events {
		data, err := f.Format(event)
		if err != nil {
			return nil, err
		}
		buf.Write(data)
		if i < len(events)-1 {
			buf.WriteByte('\n')
		}
	}
	return []byte(buf.String()), nil
}

// ContentType returns the content type.
func (f *SyslogFormatter) ContentType() string {
	return "text/plain"
}

// FileExtension returns the file extension.
func (f *SyslogFormatter) FileExtension() string {
	return ".log"
}

// buildStructuredData builds RFC 5424 structured data.
func (f *SyslogFormatter) buildStructuredData(event *Event) string {
	var parts []string

	// Event metadata
	eventData := fmt.Sprintf("[event@8732 id=\"%s\" type=\"%s\" category=\"%s\"]",
		event.ID, event.Type, event.Category)
	parts = append(parts, eventData)

	// MITRE ATT&CK data
	if event.MITRE != nil {
		mitreData := fmt.Sprintf("[mitre@8732 tactic=\"%s\" technique=\"%s\"]",
			event.MITRE.Tactic, event.MITRE.Technique)
		parts = append(parts, mitreData)
	}

	// Entities
	if len(event.Entities) > 0 {
		entityPairs := make([]string, len(event.Entities))
		for i, e := range event.Entities {
			entityPairs[i] = fmt.Sprintf("%s=\"%s\"", e.Type, e.Value)
		}
		entityData := fmt.Sprintf("[entities@8732 %s]", strings.Join(entityPairs, " "))
		parts = append(parts, entityData)
	}

	// Additional attributes
	if len(event.Attributes) > 0 {
		attrPairs := make([]string, 0, len(event.Attributes))
		for k, v := range event.Attributes {
			attrPairs = append(attrPairs, fmt.Sprintf("%s=\"%s\"", k, v))
		}
		attrData := fmt.Sprintf("[attrs@8732 %s]", strings.Join(attrPairs, " "))
		parts = append(parts, attrData)
	}

	return strings.Join(parts, "")
}

// syslogSeverity maps SIEM severity to syslog severity.
func syslogSeverity(sev Severity) int {
	switch sev {
	case SeverityCritical:
		return 2 // Critical
	case SeverityHigh:
		return 3 // Error
	case SeverityMedium:
		return 4 // Warning
	case SeverityLow:
		return 5 // Notice
	default:
		return 6 // Informational
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func orDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}

func orDefaultInt(val, def int) int {
	if val == 0 {
		return def
	}
	return val
}

// ============================================================================
// CSV Formatter
// ============================================================================

// CSVFormatter formats events as CSV.
type CSVFormatter struct {
	platform Platform
	headers  []string
}

// NewCSVFormatter creates a new CSV formatter.
func NewCSVFormatter(platform Platform, headers []string) *CSVFormatter {
	if len(headers) == 0 {
		headers = []string{
			"id", "timestamp", "source", "category", "type",
			"severity", "message", "entities", "mitre_tactic", "mitre_technique",
		}
	}
	return &CSVFormatter{
		platform: platform,
		headers:  headers,
	}
}

// Format formats a single event as CSV row.
func (f *CSVFormatter) Format(event *Event) ([]byte, error) {
	row := make([]string, len(f.headers))
	for i, header := range f.headers {
		row[i] = f.getFieldValue(header, event)
	}
	return []byte(strings.Join(row, ",")), nil
}

// FormatBatch formats multiple events as CSV with header row.
func (f *CSVFormatter) FormatBatch(events []*Event) ([]byte, error) {
	var buf strings.Builder

	// Write header
	buf.WriteString(strings.Join(f.headers, ","))
	buf.WriteByte('\n')

	// Write rows
	for _, event := range events {
		row := make([]string, len(f.headers))
		for i, header := range f.headers {
			row[i] = f.getFieldValue(header, event)
		}
		buf.WriteString(strings.Join(row, ","))
		buf.WriteByte('\n')
	}

	return []byte(buf.String()), nil
}

// ContentType returns the content type.
func (f *CSVFormatter) ContentType() string {
	return "text/csv"
}

// FileExtension returns the file extension.
func (f *CSVFormatter) FileExtension() string {
	return ".csv"
}

// getFieldValue extracts a field value from an event.
func (f *CSVFormatter) getFieldValue(field string, event *Event) string {
	// Escape quotes and wrap in quotes
	escape := func(s string) string {
		s = strings.ReplaceAll(s, "\"", "\\\"")
		return fmt.Sprintf("\"%s\"", s)
	}

	switch field {
	case "id":
		return escape(event.ID)
	case "timestamp":
		return event.Timestamp.Format(time.RFC3339)
	case "source":
		return escape(event.Source)
	case "category":
		return escape(string(event.Category))
	case "type":
		return escape(event.Type)
	case "severity":
		return escape(string(event.Severity))
	case "message":
		return escape(event.Message)
	case "entities":
		if len(event.Entities) == 0 {
			return "\"\""
		}
		entities, _ := json.Marshal(event.Entities)
		return escape(string(entities))
	case "mitre_tactic":
		if event.MITRE != nil {
			return escape(event.MITRE.Tactic)
		}
		return "\"\""
	case "mitre_technique":
		if event.MITRE != nil {
			return escape(event.MITRE.Technique)
		}
		return "\"\""
	default:
		// Check attributes
		if val, ok := event.Attributes[field]; ok {
			return escape(val)
		}
		return "\"\""
	}
}
