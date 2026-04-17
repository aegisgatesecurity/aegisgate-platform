// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package webhook provides event filtering functionality.
package webhook

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aegisgatesecurity/aegisgate/pkg/siem"
)

// ============================================================================
// Filter Interface
// ============================================================================

// Filter is the interface for event filters.
type Filter interface {
	// Allow determines if an event should be allowed through
	Allow(event *siem.Event) bool
	// Match determines if an event matches the filter criteria
	Match(event *siem.Event) bool
}

// ============================================================================
// Severity Filter
// ============================================================================

// SeverityFilter filters events based on severity level.
type SeverityFilter struct {
	// Minimum severity required
	MinSeverity siem.Severity
	// Severities to include (empty = all above min)
	IncludeSeverities []siem.Severity
	// Severities to exclude
	ExcludeSeverities []siem.Severity
}

// NewSeverityFilter creates a new severity filter.
func NewSeverityFilter() *SeverityFilter {
	return &SeverityFilter{}
}

// WithMinSeverity sets the minimum severity.
func (f *SeverityFilter) WithMinSeverity(severity siem.Severity) *SeverityFilter {
	f.MinSeverity = severity
	return f
}

// WithIncludeSeverities sets the severities to include.
func (f *SeverityFilter) WithIncludeSeverities(severities ...siem.Severity) *SeverityFilter {
	f.IncludeSeverities = severities
	return f
}

// WithExcludeSeverities sets the severities to exclude.
func (f *SeverityFilter) WithExcludeSeverities(severities ...siem.Severity) *SeverityFilter {
	f.ExcludeSeverities = severities
	return f
}

// Allow implements Filter interface.
func (f *SeverityFilter) Allow(event *siem.Event) bool {
	if event == nil {
		return false
	}
	return f.Match(event)
}

// Match implements Filter interface.
func (f *SeverityFilter) Match(event *siem.Event) bool {
	if event == nil {
		return false
	}

	severity := event.Severity

	// Check excluded severities
	for _, excl := range f.ExcludeSeverities {
		if severity == excl {
			return false
		}
	}

	// If include list is set, check it
	if len(f.IncludeSeverities) > 0 {
		for _, incl := range f.IncludeSeverities {
			if severity == incl {
				return true
			}
		}
		return false
	}

	// Check minimum severity
	if f.MinSeverity != "" {
		return meetsMinSeverity(severity, f.MinSeverity)
	}

	return true
}

// ============================================================================
// Category Filter
// ============================================================================

// CategoryFilter filters events based on category.
type CategoryFilter struct {
	// Categories to include (empty = all)
	IncludeCategories []siem.EventCategory
	// Categories to exclude
	ExcludeCategories []siem.EventCategory
}

// NewCategoryFilter creates a new category filter.
func NewCategoryFilter() *CategoryFilter {
	return &CategoryFilter{}
}

// WithIncludeCategories sets the categories to include.
func (f *CategoryFilter) WithIncludeCategories(categories ...siem.EventCategory) *CategoryFilter {
	f.IncludeCategories = categories
	return f
}

// WithExcludeCategories sets the categories to exclude.
func (f *CategoryFilter) WithExcludeCategories(categories ...siem.EventCategory) *CategoryFilter {
	f.ExcludeCategories = categories
	return f
}

// Allow implements Filter interface.
func (f *CategoryFilter) Allow(event *siem.Event) bool {
	if event == nil {
		return false
	}
	return f.Match(event)
}

// Match implements Filter interface.
func (f *CategoryFilter) Match(event *siem.Event) bool {
	if event == nil {
		return false
	}

	category := event.Category

	// Check excluded categories
	for _, excl := range f.ExcludeCategories {
		if category == excl {
			return false
		}
	}

	// If include list is set, check it
	if len(f.IncludeCategories) > 0 {
		for _, incl := range f.IncludeCategories {
			if category == incl {
				return true
			}
		}
		return false
	}

	return true
}

// ============================================================================
// Source Filter
// ============================================================================

// SourceFilter filters events based on source.
type SourceFilter struct {
	// Sources to include (empty = all)
	IncludeSources []string
	// Sources to exclude
	ExcludeSources []string
	// Use regex for matching
	UseRegex bool
	// Case sensitive matching
	CaseSensitive bool
}

// NewSourceFilter creates a new source filter.
func NewSourceFilter() *SourceFilter {
	return &SourceFilter{
		CaseSensitive: true,
	}
}

// WithIncludeSources sets the sources to include.
func (f *SourceFilter) WithIncludeSources(sources ...string) *SourceFilter {
	f.IncludeSources = sources
	return f
}

// WithExcludeSources sets the sources to exclude.
func (f *SourceFilter) WithExcludeSources(sources ...string) *SourceFilter {
	f.ExcludeSources = sources
	return f
}

// WithRegex enables regex matching.
func (f *SourceFilter) WithRegex(useRegex bool) *SourceFilter {
	f.UseRegex = useRegex
	return f
}

// WithCaseSensitive sets case sensitivity.
func (f *SourceFilter) WithCaseSensitive(sensitive bool) *SourceFilter {
	f.CaseSensitive = sensitive
	return f
}

// Allow implements Filter interface.
func (f *SourceFilter) Allow(event *siem.Event) bool {
	if event == nil {
		return false
	}
	return f.Match(event)
}

// Match implements Filter interface.
func (f *SourceFilter) Match(event *siem.Event) bool {
	if event == nil {
		return false
	}

	source := event.Source

	// Check excluded sources
	for _, excl := range f.ExcludeSources {
		if f.matchString(source, excl) {
			return false
		}
	}

	// If include list is set, check it
	if len(f.IncludeSources) > 0 {
		for _, incl := range f.IncludeSources {
			if f.matchString(source, incl) {
				return true
			}
		}
		return false
	}

	return true
}

// matchString performs string matching with regex/case options.
func (f *SourceFilter) matchString(str, pattern string) bool {
	if f.UseRegex {
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return false
		}
		return matched
	}

	if f.CaseSensitive {
		return str == pattern
	}
	return strings.EqualFold(str, pattern)
}

// ============================================================================
// Event Type Filter
// ============================================================================

// EventTypeFilter filters events based on event type.
type EventTypeFilter struct {
	// Event types to include (empty = all)
	IncludeTypes []string
	// Event types to exclude
	ExcludeTypes []string
	// Use regex for matching
	UseRegex bool
	// Case sensitive matching
	CaseSensitive bool
}

// NewEventTypeFilter creates a new event type filter.
func NewEventTypeFilter() *EventTypeFilter {
	return &EventTypeFilter{
		CaseSensitive: true,
	}
}

// WithIncludeTypes sets the event types to include.
func (f *EventTypeFilter) WithIncludeTypes(types ...string) *EventTypeFilter {
	f.IncludeTypes = types
	return f
}

// WithExcludeTypes sets the event types to exclude.
func (f *EventTypeFilter) WithExcludeTypes(types ...string) *EventTypeFilter {
	f.ExcludeTypes = types
	return f
}

// WithRegex enables regex matching.
func (f *EventTypeFilter) WithRegex(useRegex bool) *EventTypeFilter {
	f.UseRegex = useRegex
	return f
}

// WithCaseSensitive sets case sensitivity.
func (f *EventTypeFilter) WithCaseSensitive(sensitive bool) *EventTypeFilter {
	f.CaseSensitive = sensitive
	return f
}

// Allow implements Filter interface.
func (f *EventTypeFilter) Allow(event *siem.Event) bool {
	if event == nil {
		return false
	}
	return f.Match(event)
}

// Match implements Filter interface.
func (f *EventTypeFilter) Match(event *siem.Event) bool {
	if event == nil {
		return false
	}

	eventType := event.Type

	// Check excluded types
	for _, excl := range f.ExcludeTypes {
		if f.matchString(eventType, excl) {
			return false
		}
	}

	// If include list is set, check it
	if len(f.IncludeTypes) > 0 {
		for _, incl := range f.IncludeTypes {
			if f.matchString(eventType, incl) {
				return true
			}
		}
		return false
	}

	return true
}

// matchString performs string matching with regex/case options.
func (f *EventTypeFilter) matchString(str, pattern string) bool {
	if f.UseRegex {
		matched, err := regexp.MatchString(pattern, str)
		if err != nil {
			return false
		}
		return matched
	}

	if f.CaseSensitive {
		return str == pattern
	}
	return strings.EqualFold(str, pattern)
}

// ============================================================================
// Attribute Filter
// ============================================================================

// AttributeFilter filters events based on attributes.
type AttributeFilter struct {
	// Conditions for attribute matching
	Conditions []AttributeCondition
}

// AttributeCondition defines a condition for attribute matching.
type AttributeCondition struct {
	// Attribute key
	Key string
	// Operator (eq, ne, contains, regex, gt, lt, gte, lte, exists)
	Operator string
	// Value to compare
	Value interface{}
	// Case sensitive matching
	CaseSensitive bool
}

// NewAttributeFilter creates a new attribute filter.
func NewAttributeFilter() *AttributeFilter {
	return &AttributeFilter{}
}

// WithCondition adds a condition.
func (f *AttributeFilter) WithCondition(key, operator string, value interface{}) *AttributeFilter {
	f.Conditions = append(f.Conditions, AttributeCondition{
		Key:      key,
		Operator: operator,
		Value:    value,
	})
	return f
}

// Allow implements Filter interface.
func (f *AttributeFilter) Allow(event *siem.Event) bool {
	if event == nil {
		return false
	}
	return f.Match(event)
}

// Match implements Filter interface.
func (f *AttributeFilter) Match(event *siem.Event) bool {
	if event == nil {
		return false
	}

	for _, cond := range f.Conditions {
		if !f.matchCondition(event, cond) {
			return false
		}
	}

	return true
}

// matchCondition checks if an event matches an attribute condition.
func (f *AttributeFilter) matchCondition(event *siem.Event, cond AttributeCondition) bool {
	// Get attribute value
	var attrValue interface{}
	if event.Attributes != nil {
		attrValue = event.Attributes[cond.Key]
	}

	// Also check raw data
	if attrValue == nil && event.Raw != nil {
		attrValue = event.Raw[cond.Key]
	}

	switch cond.Operator {
	case "exists":
		return attrValue != nil
	case "eq":
		return compareEqual(attrValue, cond.Value, cond.CaseSensitive)
	case "ne":
		return !compareEqual(attrValue, cond.Value, cond.CaseSensitive)
	case "contains":
		return contains(attrValue, cond.Value, cond.CaseSensitive)
	case "regex":
		return matchRegex(attrValue, cond.Value)
	case "gt", "lt", "gte", "lte":
		return compareNumeric(attrValue, cond.Value, cond.Operator)
	}

	return false
}

// ============================================================================
// Composite Filter
// ============================================================================

// CompositeFilter combines multiple filters.
type CompositeFilter struct {
	// Filters to combine
	filters []Filter
	// Combine mode (and, or)
	mode string
}

// NewCompositeFilter creates a new composite filter.
func NewCompositeFilter() *CompositeFilter {
	return &CompositeFilter{
		mode: "and",
	}
}

// WithFilters adds filters.
func (f *CompositeFilter) WithFilters(filters ...Filter) *CompositeFilter {
	f.filters = append(f.filters, filters...)
	return f
}

// WithMode sets the combine mode.
func (f *CompositeFilter) WithMode(mode string) *CompositeFilter {
	f.mode = mode
	return f
}

// Allow implements Filter interface.
func (f *CompositeFilter) Allow(event *siem.Event) bool {
	if len(f.filters) == 0 {
		return true
	}

	switch f.mode {
	case "or":
		for _, filter := range f.filters {
			if filter.Allow(event) {
				return true
			}
		}
		return false
	default: // "and"
		for _, filter := range f.filters {
			if !filter.Allow(event) {
				return false
			}
		}
		return true
	}
}

// Match implements Filter interface.
func (f *CompositeFilter) Match(event *siem.Event) bool {
	return f.Allow(event)
}

// ============================================================================
// Filter Builder
// ============================================================================

// FilterBuilder provides a fluent interface for building filters.
type FilterBuilder struct {
	filters []Filter
}

// NewFilterBuilder creates a new filter builder.
func NewFilterBuilder() *FilterBuilder {
	return &FilterBuilder{}
}

// WithSeverityFilter adds a severity filter.
func (b *FilterBuilder) WithSeverityFilter(minSeverity siem.Severity) *FilterBuilder {
	f := NewSeverityFilter().WithMinSeverity(minSeverity)
	b.filters = append(b.filters, f)
	return b
}

// WithCategoryFilter adds a category filter.
func (b *FilterBuilder) WithCategoryFilter(include []siem.EventCategory, exclude []siem.EventCategory) *FilterBuilder {
	f := NewCategoryFilter()
	if len(include) > 0 {
		f.WithIncludeCategories(include...)
	}
	if len(exclude) > 0 {
		f.WithExcludeCategories(exclude...)
	}
	b.filters = append(b.filters, f)
	return b
}

// WithSourceFilter adds a source filter.
func (b *FilterBuilder) WithSourceFilter(include []string, exclude []string) *FilterBuilder {
	f := NewSourceFilter()
	if len(include) > 0 {
		f.WithIncludeSources(include...)
	}
	if len(exclude) > 0 {
		f.WithExcludeSources(exclude...)
	}
	b.filters = append(b.filters, f)
	return b
}

// WithEventTypeFilter adds an event type filter.
func (b *FilterBuilder) WithEventTypeFilter(include []string, exclude []string) *FilterBuilder {
	f := NewEventTypeFilter()
	if len(include) > 0 {
		f.WithIncludeTypes(include...)
	}
	if len(exclude) > 0 {
		f.WithExcludeTypes(exclude...)
	}
	b.filters = append(b.filters, f)
	return b
}

// WithFilter adds a custom filter.
func (b *FilterBuilder) WithFilter(filter Filter) *FilterBuilder {
	b.filters = append(b.filters, filter)
	return b
}

// Build builds the filter.
func (b *FilterBuilder) Build() Filter {
	if len(b.filters) == 0 {
		return NewCompositeFilter()
	}
	if len(b.filters) == 1 {
		return b.filters[0]
	}
	return NewCompositeFilter().WithFilters(b.filters...).WithMode("and")
}

// BuildOr builds an OR filter.
func (b *FilterBuilder) BuildOr() Filter {
	return NewCompositeFilter().WithFilters(b.filters...).WithMode("or")
}

// ============================================================================
// Event Matcher
// ============================================================================

// EventMatcher matches events against trigger conditions.
type EventMatcher struct {
	filters map[string]Filter
}

// NewEventMatcher creates a new event matcher.
func NewEventMatcher() *EventMatcher {
	return &EventMatcher{
		filters: make(map[string]Filter),
	}
}

// AddFilter adds a filter with a name.
func (m *EventMatcher) AddFilter(name string, filter Filter) {
	m.filters[name] = filter
}

// RemoveFilter removes a filter.
func (m *EventMatcher) RemoveFilter(name string) {
	delete(m.filters, name)
}

// Match checks if an event matches any registered filter.
func (m *EventMatcher) Match(event *siem.Event) bool {
	for _, filter := range m.filters {
		if filter.Match(event) {
			return true
		}
	}
	return false
}

// MatchAll checks if an event matches all registered filters.
func (m *EventMatcher) MatchAll(event *siem.Event) bool {
	for _, filter := range m.filters {
		if !filter.Match(event) {
			return false
		}
	}
	return true
}

// MatchNamed checks if an event matches a specific named filter.
func (m *EventMatcher) MatchNamed(event *siem.Event, name string) bool {
	if filter, ok := m.filters[name]; ok {
		return filter.Match(event)
	}
	return false
}

// MatchTriggers checks if an event matches trigger conditions.
func (m *EventMatcher) MatchTriggers(event *siem.Event, triggers []TriggerCondition) bool {
	if len(triggers) == 0 {
		return true
	}

	for _, trigger := range triggers {
		if m.matchTrigger(event, trigger) {
			return true
		}
	}
	return false
}

// matchTrigger checks if an event matches a single trigger condition.
func (m *EventMatcher) matchTrigger(event *siem.Event, trigger TriggerCondition) bool {
	// Check minimum severity
	if trigger.MinSeverity != "" && !meetsMinSeverity(event.Severity, trigger.MinSeverity) {
		return false
	}

	// Check excluded severities
	for _, sev := range trigger.ExcludeSeverities {
		if event.Severity == sev {
			return false
		}
	}

	// Check categories
	if len(trigger.Categories) > 0 {
		found := false
		for _, cat := range trigger.Categories {
			if event.Category == cat {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check excluded categories
	for _, cat := range trigger.ExcludeCategories {
		if event.Category == cat {
			return false
		}
	}

	// Check sources
	if len(trigger.Sources) > 0 {
		found := false
		for _, src := range trigger.Sources {
			if event.Source == src {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check excluded sources
	for _, src := range trigger.ExcludeSources {
		if event.Source == src {
			return false
		}
	}

	// Check event types
	if len(trigger.EventTypes) > 0 {
		found := false
		for _, t := range trigger.EventTypes {
			if event.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check excluded event types
	for _, t := range trigger.ExcludeEventTypes {
		if event.Type == t {
			return false
		}
	}

	return true
}

// BuildFilterFromTrigger builds a filter from a trigger condition.
func BuildFilterFromTrigger(trigger TriggerCondition) Filter {
	builder := NewFilterBuilder()

	if trigger.MinSeverity != "" {
		builder.WithSeverityFilter(trigger.MinSeverity)
	}

	if len(trigger.Categories) > 0 || len(trigger.ExcludeCategories) > 0 {
		builder.WithCategoryFilter(trigger.Categories, trigger.ExcludeCategories)
	}

	if len(trigger.Sources) > 0 || len(trigger.ExcludeSources) > 0 {
		builder.WithSourceFilter(trigger.Sources, trigger.ExcludeSources)
	}

	if len(trigger.EventTypes) > 0 || len(trigger.ExcludeEventTypes) > 0 {
		builder.WithEventTypeFilter(trigger.EventTypes, trigger.ExcludeEventTypes)
	}

	return builder.Build()
}

// ============================================================================
// Helper Functions
// ============================================================================

// meetsMinSeverity checks if an event severity meets the minimum threshold.
func meetsMinSeverity(eventSev, minSev siem.Severity) bool {
	severityOrder := map[siem.Severity]int{
		siem.SeverityCritical: 5,
		siem.SeverityHigh:     4,
		siem.SeverityMedium:   3,
		siem.SeverityLow:      2,
		siem.SeverityInfo:     1,
		"":                    0,
	}

	eventLevel := severityOrder[eventSev]
	minLevel := severityOrder[minSev]

	return eventLevel >= minLevel
}

// compareEqual compares two values for equality.
func compareEqual(a, b interface{}, caseSensitive bool) bool {
	if a == nil || b == nil {
		return a == b
	}

	// Convert to strings and compare
	strA := toString(a)
	strB := toString(b)

	if caseSensitive {
		return strA == strB
	}
	return strings.EqualFold(strA, strB)
}

// contains checks if a contains b.
func contains(a, b interface{}, caseSensitive bool) bool {
	if a == nil || b == nil {
		return false
	}

	strA := toString(a)
	strB := toString(b)

	if caseSensitive {
		return strings.Contains(strA, strB)
	}
	return strings.Contains(strings.ToLower(strA), strings.ToLower(strB))
}

// matchRegex matches a value against a regex pattern.
func matchRegex(value, pattern interface{}) bool {
	if value == nil || pattern == nil {
		return false
	}

	strValue := toString(value)
	strPattern := toString(pattern)

	matched, err := regexp.MatchString(strPattern, strValue)
	if err != nil {
		return false
	}
	return matched
}

// compareNumeric compares two numeric values.
func compareNumeric(a, b interface{}, op string) bool {
	floatA, okA := toFloat64(a)
	floatB, okB := toFloat64(b)

	if !okA || !okB {
		return false
	}

	switch op {
	case "gt":
		return floatA > floatB
	case "lt":
		return floatA < floatB
	case "gte":
		return floatA >= floatB
	case "lte":
		return floatA <= floatB
	}

	return false
}

// toString converts a value to string.
func toString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	case fmt.Stringer:
		return val.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}

// toFloat64 converts a value to float64.
func toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case int:
		return float64(val), true
	case int32:
		return float64(val), true
	case int64:
		return float64(val), true
	case uint:
		return float64(val), true
	case uint32:
		return float64(val), true
	case uint64:
		return float64(val), true
	case float32:
		return float64(val), true
	case float64:
		return val, true
	default:
		return 0, false
	}
}
