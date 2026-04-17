// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package reporting provides comprehensive reporting capabilities including
// real-time reports, ad-hoc reports, and scheduled report generation.
//
// Features:
//   - Real-time report generation (current state snapshot)
//   - Ad-hoc report generation (custom date ranges, filters)
//   - Scheduled report execution (periodic automated reports)
//   - Multiple output formats (JSON, CSV, HTML)
//   - Report storage with automatic cleanup
//   - Report template system
//   - Email/webhook delivery interfaces
//   - Cron-like scheduling syntax
//
// Example usage:
//
//	// Create reporter with defaults
//	reporter, err := reporting.New(Config{
//	    CleanupInterval: 24 * time.Hour,
//	    MaxReportAge:    30 * 24 * time.Hour,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer reporter.Stop()
//
//	// Start the scheduler
//	reporter.Start()
//
//	// Generate an ad-hoc report
//	report, err := reporter.Generate(ReportRequest{
//	    Type:      ReportTypeSummary,
//	    Format:    ReportFormatJSON,
//	    StartTime: time.Now().Add(-24 * time.Hour),
//	    EndTime:   time.Now(),
//	})
package reporting

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ReportType defines the type of report to generate.
type ReportType string

const (
	// ReportTypeRealtime generates a snapshot of current system state
	ReportTypeRealtime ReportType = "realtime"
	// ReportTypeSummary generates a summary report for a time period
	ReportTypeSummary ReportType = "summary"
	// ReportTypeCompliance generates compliance framework reports
	ReportTypeCompliance ReportType = "compliance"
	// ReportTypeSecurity generates security and violation reports
	ReportTypeSecurity ReportType = "security"
	// ReportTypePerformance generates performance metrics reports
	ReportTypePerformance ReportType = "performance"
)

// ReportFormat defines the output format for reports.
type ReportFormat string

const (
	// ReportFormatJSON outputs report as JSON
	ReportFormatJSON ReportFormat = "json"
	// ReportFormatCSV outputs report as CSV
	ReportFormatCSV ReportFormat = "csv"
	// ReportFormatHTML outputs report as HTML
	ReportFormatHTML ReportFormat = "html"
	// ReportFormatPDF is a placeholder for PDF output (requires external library)
	ReportFormatPDF ReportFormat = "pdf"
)

// ReportStatus defines the current status of a report.
type ReportStatus string

const (
	// ReportStatusQueued indicates the report is waiting to be processed
	ReportStatusQueued ReportStatus = "queued"
	// ReportStatusRunning indicates the report is being generated
	ReportStatusRunning ReportStatus = "running"
	// ReportStatusCompleted indicates the report completed successfully
	ReportStatusCompleted ReportStatus = "completed"
	// ReportStatusFailed indicates the report generation failed
	ReportStatusFailed ReportStatus = "failed"
)

// ScheduleType defines the frequency of scheduled reports.
type ScheduleType string

const (
	// ScheduleHourly runs every hour
	ScheduleHourly ScheduleType = "hourly"
	// ScheduleDaily runs daily at a specific time
	ScheduleDaily ScheduleType = "daily"
	// ScheduleWeekly runs weekly on a specific day/time
	ScheduleWeekly ScheduleType = "weekly"
	// ScheduleMonthly runs monthly on a specific day
	ScheduleMonthly ScheduleType = "monthly"
)

// Report represents a generated report with its metadata and data.
type Report struct {
	// ID is the unique identifier for this report
	ID string `json:"id"`
	// Type is the kind of report
	Type ReportType `json:"type"`
	// Format is the output format used
	Format ReportFormat `json:"format"`
	// Status is the current generation status
	Status ReportStatus `json:"status"`
	// Created is when the report was requested
	Created time.Time `json:"created"`
	// Completed is when the report finished (zero if not complete)
	Completed time.Time `json:"completed,omitempty"`
	// Data contains the report data
	Data interface{} `json:"data,omitempty"`
	// Error contains error message if generation failed
	Error string `json:"error,omitempty"`
	// Filename is the output filename (if persisted)
	Filename string `json:"filename,omitempty"`
	// Size is the report size in bytes
	Size int64 `json:"size,omitempty"`
}

// ReportRequest contains parameters for generating a new report.
type ReportRequest struct {
	// Type is the report type to generate
	Type ReportType `json:"type"`
	// Format is the desired output format
	Format ReportFormat `json:"format"`
	// StartTime is the beginning of the reporting period (for time-based reports)
	StartTime time.Time `json:"start_time,omitempty"`
	// EndTime is the end of the reporting period (for time-based reports)
	EndTime time.Time `json:"end_time,omitempty"`
	// Filters to apply when generating the report
	Filters ReportFilter `json:"filters,omitempty"`
	// TemplateID is an optional template to use
	TemplateID string `json:"template_id,omitempty"`
}

// ReportFilter contains criteria for filtering report data.
type ReportFilter struct {
	// Patterns to include in the report (empty = all)
	Patterns []string `json:"patterns,omitempty"`
	// Severity minimum level to include
	Severity string `json:"severity,omitempty"`
	// Sources to include (empty = all)
	Sources []string `json:"sources,omitempty"`
	// Categories to include
	Categories []string `json:"categories,omitempty"`
	// Keyword search string
	Keyword string `json:"keyword,omitempty"`
	// Custom filter parameters
	Custom map[string]interface{} `json:"custom,omitempty"`
}

// ReportSchedule defines a recurring scheduled report.
type ReportSchedule struct {
	// ID is the unique schedule identifier
	ID string `json:"id"`
	// Name is a human-readable name
	Name string `json:"name"`
	// Type is the schedule frequency
	Type ScheduleType `json:"type"`
	// ReportType is the type of report to generate
	ReportType ReportType `json:"report_type"`
	// Format is the output format
	Format ReportFormat `json:"format"`
	// Hour is the hour to run (0-23, for daily/weekly)
	Hour int `json:"hour,omitempty"`
	// Minute is the minute to run (0-59)
	Minute int `json:"minute,omitempty"`
	// DayOfWeek is the day to run (0=Sunday, 6=Saturday, for weekly)
	DayOfWeek int `json:"day_of_week,omitempty"`
	// DayOfMonth is the day to run (1-31, for monthly)
	DayOfMonth int `json:"day_of_month,omitempty"`
	// Filters to apply
	Filters ReportFilter `json:"filters,omitempty"`
	// Enabled indicates if the schedule is active
	Enabled bool `json:"enabled"`
	// Created is when the schedule was created
	Created time.Time `json:"created"`
	// LastRun is when the schedule last executed
	LastRun *time.Time `json:"last_run,omitempty"`
	// NextRun is the scheduled next execution time
	NextRun time.Time `json:"next_run"`
	// Delivery contains optional delivery settings
	Delivery DeliveryConfig `json:"delivery,omitempty"`
}

// ReportTemplate defines a reusable report template.
type ReportTemplate struct {
	// ID is the unique template identifier
	ID string `json:"id"`
	// Name is a human-readable name
	Name string `json:"name"`
	// Description describes the template
	Description string `json:"description"`
	// ReportType is the type of report
	ReportType ReportType `json:"report_type"`
	// DefaultFormat is the default output format
	DefaultFormat ReportFormat `json:"default_format"`
	// DefaultFilters are the default filters
	DefaultFilters ReportFilter `json:"default_filters,omitempty"`
	// CustomTemplate for specialized formatting
	CustomTemplate string `json:"custom_template,omitempty"`
	// Created is when the template was created
	Created time.Time `json:"created"`
}

// DeliveryConfig contains settings for report delivery.
type DeliveryConfig struct {
	// Email addresses for email delivery
	Email []string `json:"email,omitempty"`
	// WebhookURL for webhook delivery
	WebhookURL string `json:"webhook_url,omitempty"`
	// WebhookHeaders for webhook requests
	WebhookHeaders map[string]string `json:"webhook_headers,omitempty"`
}

// Config contains reporter configuration.
type Config struct {
	// StoragePath is where reports are persisted (empty = in-memory only)
	StoragePath string `json:"storage_path,omitempty"`
	// MaxConcurrent is the maximum concurrent report generations
	MaxConcurrent int `json:"max_concurrent,omitempty"`
	// CleanupInterval is how often to run cleanup
	CleanupInterval time.Duration `json:"cleanup_interval,omitempty"`
	// MaxReportAge is how long to keep reports before cleanup
	MaxReportAge time.Duration `json:"max_report_age,omitempty"`
	// DefaultFormat is the default output format
	DefaultFormat ReportFormat `json:"default_format,omitempty"`
	// EnableScheduler turns on scheduled report background execution
	EnableScheduler bool `json:"enable_scheduler,omitempty"`
	// MaxReports limits the number of reports stored (0 = unlimited)
	MaxReports int `json:"max_reports,omitempty"`
}

// Reporter manages report generation, scheduling, and storage.
type Reporter struct {
	config Config

	// Reports storage
	reports   map[string]*Report
	reportsMu sync.RWMutex

	// Schedules storage
	schedules   map[string]*ReportSchedule
	schedulesMu sync.RWMutex

	// Templates storage
	templates   map[string]*ReportTemplate
	templatesMu sync.RWMutex

	// Background control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Worker semaphore
	workerPool chan struct{}

	// Delivery interface (can be set by user)
	Delivery DeliveryHandler
}

// DeliveryHandler interface for report delivery.
type DeliveryHandler interface {
	// DeliverReport sends a report via the configured method
	DeliverReport(report *Report, config DeliveryConfig) error
}

// DefaultConfig returns a default configuration.
func DefaultConfig() Config {
	return Config{
		MaxConcurrent:   5,
		CleanupInterval: 24 * time.Hour,
		MaxReportAge:    30 * 24 * time.Hour,
		DefaultFormat:   ReportFormatJSON,
		EnableScheduler: true,
		MaxReports:      1000,
	}
}

// New creates a new Reporter with the given configuration.
// If cfg is empty, uses the default configuration.
func New(cfg Config) (*Reporter, error) {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = DefaultConfig().MaxConcurrent
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = DefaultConfig().CleanupInterval
	}
	if cfg.MaxReportAge <= 0 {
		cfg.MaxReportAge = DefaultConfig().MaxReportAge
	}
	if cfg.DefaultFormat == "" {
		cfg.DefaultFormat = DefaultConfig().DefaultFormat
	}

	// Create storage directory if specified
	if cfg.StoragePath != "" {
		if err := os.MkdirAll(cfg.StoragePath, 0755); err != nil {
			return nil, fmt.Errorf("failed to create storage directory: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	r := &Reporter{
		config:     cfg,
		reports:    make(map[string]*Report),
		schedules:  make(map[string]*ReportSchedule),
		templates:  make(map[string]*ReportTemplate),
		ctx:        ctx,
		cancel:     cancel,
		workerPool: make(chan struct{}, cfg.MaxConcurrent),
	}

	return r, nil
}

// Start begins the scheduler background task and cleanup routines.
// Must be called after New if scheduling is needed.
func (r *Reporter) Start() {
	r.wg.Add(2)
	go r.runScheduler()
	go r.runCleanup()
}

// Stop halts the scheduler background task and waits for completion.
func (r *Reporter) Stop() {
	r.cancel()
	r.wg.Wait()
}

// Generate creates and executes a new ad-hoc report based on the request.
// Returns the report ID immediately; use GetReport to check status.
func (r *Reporter) Generate(req ReportRequest) (*Report, error) {
	// Apply defaults
	if req.Format == "" {
		req.Format = r.config.DefaultFormat
	}

	// Validate format
	switch req.Format {
	case ReportFormatJSON, ReportFormatCSV, ReportFormatHTML, ReportFormatPDF:
		// valid
	case "":
		req.Format = ReportFormatJSON
	default:
		return nil, fmt.Errorf("unsupported format: %s", req.Format)
	}

	// Create report
	report := r.createReport(req)

	// Store report
	r.reportsMu.Lock()
	r.reports[report.ID] = report
	r.reportsMu.Unlock()

	// Execute generation
	go r.executeReport(report, req)

	return report, nil
}

// GetReport retrieves a report by its ID.
func (r *Reporter) GetReport(id string) (*Report, error) {
	r.reportsMu.RLock()
	defer r.reportsMu.RUnlock()

	report, ok := r.reports[id]
	if !ok {
		return nil, fmt.Errorf("report not found: %s", id)
	}

	// Return a copy
	reportCopy := *report
	return &reportCopy, nil
}

// ListReports returns all reports, optionally filtered by status or type.
func (r *Reporter) ListReports(filterType ReportType, filterStatus ReportStatus) []*Report {
	r.reportsMu.RLock()
	defer r.reportsMu.RUnlock()

	var result []*Report
	for _, report := range r.reports {
		if filterType != "" && report.Type != filterType {
			continue
		}
		if filterStatus != "" && report.Status != filterStatus {
			continue
		}
		// Return a copy
		reportCopy := *report
		result = append(result, &reportCopy)
	}

	// Sort by created time, newest first
	sort.Slice(result, func(i, j int) bool {
		return result[i].Created.After(result[j].Created)
	})

	return result
}

// DeleteReport removes a report by ID.
func (r *Reporter) DeleteReport(id string) error {
	r.reportsMu.Lock()
	defer r.reportsMu.Unlock()

	report, ok := r.reports[id]
	if !ok {
		return fmt.Errorf("report not found: %s", id)
	}

	// Delete file if persisted
	if report.Filename != "" {
		_ = os.Remove(report.Filename)
	}

	delete(r.reports, id)
	return nil
}

// Export exports a report to a specific format.
// If the report already exists in the desired format, it may be re-used.
func (r *Reporter) Export(reportID string, format ReportFormat) (io.Reader, error) {
	report, err := r.GetReport(reportID)
	if err != nil {
		return nil, err
	}

	if report.Status != ReportStatusCompleted {
		return nil, fmt.Errorf("report not completed: %s", report.Status)
	}

	// Generate output in requested format
	switch format {
	case ReportFormatJSON:
		return r.generateJSON(report)
	case ReportFormatCSV:
		return r.generateCSV(report)
	case ReportFormatHTML:
		return r.generateHTML(report)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// Schedule creates a new scheduled report.
func (r *Reporter) Schedule(schedule ReportSchedule) (*ReportSchedule, error) {
	if schedule.ID == "" {
		schedule.ID = generateID()
	}
	if schedule.Name == "" {
		schedule.Name = fmt.Sprintf("Schedule-%s", schedule.ID[:8])
	}
	if schedule.Created.IsZero() {
		schedule.Created = time.Now()
	}

	// Calculate next run
	schedule.NextRun = calculateNextRun(schedule)

	r.schedulesMu.Lock()
	r.schedules[schedule.ID] = &schedule
	r.schedulesMu.Unlock()

	return &schedule, nil
}

// CancelSchedule disables a scheduled report.
func (r *Reporter) CancelSchedule(id string) error {
	r.schedulesMu.Lock()
	defer r.schedulesMu.Unlock()

	schedule, ok := r.schedules[id]
	if !ok {
		return fmt.Errorf("schedule not found: %s", id)
	}

	schedule.Enabled = false
	return nil
}

// ListSchedules returns all scheduled reports.
func (r *Reporter) ListSchedules() []*ReportSchedule {
	r.schedulesMu.RLock()
	defer r.schedulesMu.RUnlock()

	var result []*ReportSchedule
	for _, schedule := range r.schedules {
		scheduleCopy := *schedule
		result = append(result, &scheduleCopy)
	}

	// Sort by next run time
	sort.Slice(result, func(i, j int) bool {
		return result[i].NextRun.Before(result[j].NextRun)
	})

	return result
}

// AddTemplate adds a report template.
func (r *Reporter) AddTemplate(template ReportTemplate) (*ReportTemplate, error) {
	if template.ID == "" {
		template.ID = generateID()
	}
	if template.Created.IsZero() {
		template.Created = time.Now()
	}

	r.templatesMu.Lock()
	r.templates[template.ID] = &template
	r.templatesMu.Unlock()

	return &template, nil
}

// GetTemplate retrieves a template by ID.
func (r *Reporter) GetTemplate(id string) (*ReportTemplate, error) {
	r.templatesMu.RLock()
	defer r.templatesMu.RUnlock()

	template, ok := r.templates[id]
	if !ok {
		return nil, fmt.Errorf("template not found: %s", id)
	}

	templateCopy := *template
	return &templateCopy, nil
}

// Cleanup manually runs the cleanup routine to remove old reports.
func (r *Reporter) Cleanup() error {
	r.reportsMu.Lock()
	defer r.reportsMu.Unlock()

	cutoff := time.Now().Add(-r.config.MaxReportAge)
	var toDelete []string

	for id, report := range r.reports {
		if report.Created.Before(cutoff) {
			toDelete = append(toDelete, id)
		}
	}

	// Count reports if max exceeded
	if r.config.MaxReports > 0 && len(r.reports) > r.config.MaxReports {
		// Get oldest reports
		type reportTime struct {
			id      string
			created time.Time
		}
		var reportTimes []reportTime
		for id, report := range r.reports {
			reportTimes = append(reportTimes, reportTime{id, report.Created})
		}
		sort.Slice(reportTimes, func(i, j int) bool {
			return reportTimes[i].created.Before(reportTimes[j].created)
		})

		// Mark oldest for deletion
		toRemove := len(r.reports) - r.config.MaxReports
		for i := 0; i < toRemove && i < len(reportTimes); i++ {
			if !inSlice(toDelete, reportTimes[i].id) {
				toDelete = append(toDelete, reportTimes[i].id)
			}
		}
	}

	// Delete marked reports
	for _, id := range toDelete {
		if report, ok := r.reports[id]; ok {
			if report.Filename != "" {
				_ = os.Remove(report.Filename)
			}
			delete(r.reports, id)
		}
	}

	return nil
}

// ============================================================================
// Internal Methods
// ============================================================================

// createReport creates a new report instance from a request.
func (r *Reporter) createReport(req ReportRequest) *Report {
	return &Report{
		ID:      generateID(),
		Type:    req.Type,
		Format:  req.Format,
		Status:  ReportStatusQueued,
		Created: time.Now(),
		Data:    nil,
	}
}

// executeReport runs the report generation in a worker.
func (r *Reporter) executeReport(report *Report, req ReportRequest) {
	// Acquire worker slot
	r.workerPool <- struct{}{}
	defer func() { <-r.workerPool }()

	// Update status
	r.reportsMu.Lock()
	report.Status = ReportStatusRunning
	r.reportsMu.Unlock()

	// Generate report data
	var data interface{}
	var err error

	switch req.Type {
	case ReportTypeRealtime:
		data, err = generateRealtimeReport(req.Filters)
	case ReportTypeSummary:
		data, err = generateSummaryReport(req.StartTime, req.EndTime, req.Filters)
	case ReportTypeCompliance:
		complianceFramework := ""
		if req.Filters.Custom != nil {
			if cf, ok := req.Filters.Custom["framework"].(string); ok {
				complianceFramework = cf
			}
		}
		data, err = generateComplianceReport(req.StartTime, req.EndTime, complianceFramework, req.Filters)
	case ReportTypeSecurity:
		data, err = generateSecurityReport(req.StartTime, req.EndTime, req.Filters)
	case ReportTypePerformance:
		data, err = generatePerformanceReport(req.StartTime, req.EndTime, req.Filters)
	default:
		err = fmt.Errorf("unknown report type: %s", req.Type)
	}

	// Update report with result
	r.reportsMu.Lock()
	defer r.reportsMu.Unlock()

	if err != nil {
		report.Status = ReportStatusFailed
		report.Error = err.Error()
		report.Completed = time.Now()
	} else {
		report.Status = ReportStatusCompleted
		report.Data = data
		report.Completed = time.Now()

		// Persist if storage path configured
		if r.config.StoragePath != "" {
			if filename, size, err := r.persistReport(report); err == nil {
				report.Filename = filename
				report.Size = size
			}
		}
	}
}

// persistReport saves a report to storage.
func (r *Reporter) persistReport(report *Report) (string, int64, error) {
	filename := filepath.Join(r.config.StoragePath, fmt.Sprintf("%s.%s", report.ID, report.Format))

	file, err := os.Create(filename)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = file.Close() }()

	var reader io.Reader
	var genErr error

	switch report.Format {
	case ReportFormatJSON:
		reader, genErr = r.generateJSON(report)
	case ReportFormatCSV:
		reader, genErr = r.generateCSV(report)
	case ReportFormatHTML:
		reader, genErr = r.generateHTML(report)
	default:
		reader = strings.NewReader(fmt.Sprintf("%v", report.Data))
	}

	if genErr != nil {
		return "", 0, genErr
	}

	n, err := io.Copy(file, reader)
	if err != nil {
		return "", 0, err
	}

	return filename, n, nil
}

// generateJSON creates a JSON reader from a report.
func (r *Reporter) generateJSON(report *Report) (io.Reader, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report: %w", err)
	}
	return strings.NewReader(string(data)), nil
}

// generateCSV creates a CSV reader from a report.
func (r *Reporter) generateCSV(report *Report) (io.Reader, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write headers
	if err := writer.Write([]string{"Report ID", "Type", "Format", "Status", "Created", "Completed"}); err != nil {
		return nil, err
	}

	// Write report info
	row := []string{
		report.ID,
		string(report.Type),
		string(report.Format),
		string(report.Status),
		report.Created.Format(time.RFC3339),
		report.Completed.Format(time.RFC3339),
	}
	if err := writer.Write(row); err != nil {
		return nil, err
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	return strings.NewReader(buf.String()), nil
}

// generateHTML creates an HTML reader from a report.
func (r *Reporter) generateHTML(report *Report) (io.Reader, error) {
	const htmlTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Report {{.ID}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .status { font-weight: bold; }
        .status-completed { color: green; }
        .status-failed { color: red; }
        .status-running { color: blue; }
        .status-queued { color: gray; }
    </style>
</head>
<body>
    <h1>Report {{.ID}}</h1>
    <table>
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>ID</td><td>{{.ID}}</td></tr>
        <tr><td>Type</td><td>{{.Type}}</td></tr>
        <tr><td>Format</td><td>{{.Format}}</td></tr>
        <tr><td>Status</td><td class="status status-{{.Status}}">{{.Status}}</td></tr>
        <tr><td>Created</td><td>{{.Created}}</td></tr>
        <tr><td>Completed</td><td>{{.Completed}}</td></tr>
    </table>
    <h2>Data</h2>
    <pre>{{.Data}}</pre>
</body>
</html>`

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, report); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	return strings.NewReader(buf.String()), nil
}

// runScheduler handles scheduled report execution.
func (r *Reporter) runScheduler() {
	defer r.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.checkSchedules()
		}
	}
}

// checkSchedules checks for schedules that need to run.
func (r *Reporter) checkSchedules() {
	r.schedulesMu.Lock()
	defer r.schedulesMu.Unlock()

	now := time.Now()
	for _, schedule := range r.schedules {
		if !schedule.Enabled {
			continue
		}

		if now.After(schedule.NextRun) || now.Equal(schedule.NextRun) {
			// Execute schedule
			go r.executeSchedule(*schedule)

			// Update last run and calculate next run
			nowTime := time.Now()
			schedule.LastRun = &nowTime
			schedule.NextRun = calculateNextRun(*schedule)
		}
	}
}

// executeSchedule executes a scheduled report.
func (r *Reporter) executeSchedule(schedule ReportSchedule) {
	req := ReportRequest{
		Type:    schedule.ReportType,
		Format:  schedule.Format,
		Filters: schedule.Filters,
	}

	report, err := r.Generate(req)
	if err != nil {
		return
	}

	// Wait for completion (non-blocking)
	go func() {
		// Poll for completion
		for {
			time.Sleep(100 * time.Millisecond)
			current, err := r.GetReport(report.ID)
			if err != nil {
				return
			}
			if current.Status == ReportStatusCompleted || current.Status == ReportStatusFailed {
				// Deliver if configured
				if r.Delivery != nil && (len(schedule.Delivery.Email) > 0 || schedule.Delivery.WebhookURL != "") {
					_ = r.Delivery.DeliverReport(current, schedule.Delivery)
				}
				return
			}
		}
	}()
}

// runCleanup runs periodic cleanup of old reports.
func (r *Reporter) runCleanup() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			_ = r.Cleanup()
		}
	}
}

// ============================================================================
// Report Generation Functions
// ============================================================================

// generateRealtimeReport generates a snapshot of current system state.
// This is a placeholder that would integrate with metrics.GlobalCollector()
// and scanner for pattern data.
func generateRealtimeReport(filters ReportFilter) (interface{}, error) {
	// Placeholder implementation
	// In real implementation:
	// - Get current metrics from metrics.GlobalCollector()
	// - Get active patterns from scanner
	// - Apply filters

	// Get current metrics from GlobalCollector
	metricsData, err := GetAggregateData()
	if err != nil {
		return nil, fmt.Errorf("failed to get metrics data: %w", err)
	}

	// Get scanner data for patterns
	scannerData, _ := GetGlobalScannerData()

	// Determine system state based on metrics
	systemState := "healthy"
	if metrics, ok := metricsData["realtime"].(map[string]interface{}); ok {
		if blocked, ok := metrics["blocked"].(uint64); ok && blocked > 0 {
			systemState = "warning"
		}
		if violations, ok := metrics["violations"].(uint64); ok && violations > 10 {
			systemState = "critical"
		}
	}

	return map[string]interface{}{
		"timestamp":   time.Now(),
		"metrics":     metricsData,
		"patterns":    scannerData,
		"alerts":      []string{},
		"systemState": systemState,
	}, nil
}

// generateSummaryReport generates a summary for the given time period.
func generateSummaryReport(start, end time.Time, filters ReportFilter) (interface{}, error) {
	// Placeholder implementation
	// In real implementation:
	// - Aggregate events from the time period
	// - Calculate summary statistics

	// Get metrics data from GlobalCollector
	metricsData, err := GetAggregateData()
	if err != nil {
		return nil, fmt.Errorf("failed to get metrics data: %w", err)
	}

	// Extract relevant data for summary
	realtime, _ := metricsData["realtime"].(map[string]interface{})
	averages, _ := metricsData["averages"].(map[string]interface{})

	// Build severity counts from metrics
	severityCounts := map[string]int{}
	if sc, ok := realtime["severity_counts"].(map[string]uint64); ok {
		for k, v := range sc {
			severityCounts[k] = int(v)
		}
	}

	// Get category counts
	categories := []string{}
	if cc, ok := realtime["category_counts"].(map[string]uint64); ok {
		for k := range cc {
			categories = append(categories, k)
		}
	}

	return map[string]interface{}{
		"period": map[string]string{
			"start": start.Format(time.RFC3339),
			"end":   end.Format(time.RFC3339),
		},
		"totalEvents":    0,
		"uniquePatterns": []string{},
		"severityCounts": map[string]int{},
		"topCategories":  categories,
		"averages":       averages,
	}, nil
}

// generateComplianceReport generates compliance framework reports.
func generateComplianceReport(start, end time.Time, framework string, filters ReportFilter) (interface{}, error) {
	// Placeholder implementation
	// In real implementation:
	// - Map findings to compliance framework controls
	// - Calculate compliance scores
	// - Generate control evidence

	// Get compliance data
	complianceData, err := GetComplianceData()
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance data: %w", err)
	}

	// Get metrics for finding count
	metricsData, _ := GetAggregateData()
	realtime, _ := metricsData["realtime"].(map[string]interface{})
	// Handle different numeric types safely
	var violations uint64
	if v, ok := realtime["violations"]; ok {
		switch val := v.(type) {
		case uint64:
			violations = val
		case int64:
			violations = uint64(val)
		case int:
			violations = uint64(val)
		default:
			violations = 0
		}
	}

	// Calculate compliance score based on violations
	score := 100.0
	if violations > 0 {
		score = 100.0 - float64(violations*2)
		if score < 0 {
			score = 0
		}
	}

	return map[string]interface{}{
		"framework": framework,
		"period": map[string]string{
			"start": start.Format(time.RFC3339),
			"end":   end.Format(time.RFC3339),
		},
		"controls":        []string{},
		"findings":        []string{},
		"complianceScore": score,
		"violations":      violations,
		"frameworks":      complianceData["frameworks"],
	}, nil
}

// generateSecurityReport generates security and violations report.
func generateSecurityReport(start, end time.Time, filters ReportFilter) (interface{}, error) {
	// Placeholder implementation
	// In real implementation:
	// - Aggregate security events
	// - Group by violation type
	// - Include threat indicators

	// Get metrics for security analysis
	metricsData, err := GetAggregateData()
	if err != nil {
		return nil, fmt.Errorf("failed to get metrics data: %w", err)
	}

	realtime, _ := metricsData["realtime"].(map[string]interface{})

	// Handle different numeric types safely
	var blocked, violations, errors uint64
	if v, ok := realtime["blocked"]; ok {
		switch val := v.(type) {
		case uint64:
			blocked = val
		case int64:
			blocked = uint64(val)
		case int:
			blocked = uint64(val)
		}
	}
	if v, ok := realtime["violations"]; ok {
		switch val := v.(type) {
		case uint64:
			violations = val
		case int64:
			violations = uint64(val)
		case int:
			violations = uint64(val)
		}
	}
	if v, ok := realtime["errors"]; ok {
		switch val := v.(type) {
		case uint64:
			errors = val
		case int64:
			errors = uint64(val)
		case int:
			errors = uint64(val)
		}
	}

	// Calculate security score
	securityScore := 100
	if blocked > 0 {
		securityScore -= int(blocked)
	}
	if violations > 0 {
		securityScore -= int(violations * 2)
	}
	if errors > 0 {
		securityScore -= int(errors)
	}
	if securityScore < 0 {
		securityScore = 0
	}

	// Build threat list
	threats := []string{}
	if violations > 0 {
		threats = append(threats, "pattern_violations")
	}
	if blocked > 0 {
		threats = append(threats, "blocked_requests")
	}

	return map[string]interface{}{
		"period": map[string]string{
			"start": start.Format(time.RFC3339),
			"end":   end.Format(time.RFC3339),
		},
		"violations":    []string{},
		"threats":       threats,
		"securityScore": securityScore,
		"incidents":     []string{},
		"blocked":       blocked,
		"errors":        errors,
	}, nil
}

// generatePerformanceReport generates performance metrics report.
func generatePerformanceReport(start, end time.Time, filters ReportFilter) (interface{}, error) {
	// Placeholder implementation
	// In real implementation:
	// - Get performance metrics from metrics.GlobalCollector()
	// - Calculate averages, percentiles
	// - Trend analysis

	// Get performance metrics from GlobalCollector
	metricsData, err := GetAggregateData()
	if err != nil {
		return nil, fmt.Errorf("failed to get metrics data: %w", err)
	}

	realtime, _ := metricsData["realtime"].(map[string]interface{})
	averages, _ := metricsData["averages"].(map[string]interface{})

	// Extract performance metrics
	// Handle different numeric types safely
	var requests, responses, errors uint64
	if v, ok := realtime["requests"]; ok {
		switch val := v.(type) {
		case uint64:
			requests = val
		case int64:
			requests = uint64(val)
		case int:
			requests = uint64(val)
		}
	}
	if v, ok := realtime["responses"]; ok {
		switch val := v.(type) {
		case uint64:
			responses = val
		case int64:
			responses = uint64(val)
		case int:
			responses = uint64(val)
		}
	}
	if v, ok := realtime["errors"]; ok {
		switch val := v.(type) {
		case uint64:
			errors = val
		case int64:
			errors = uint64(val)
		case int:
			errors = uint64(val)
		}
	}

	// Calculate throughput and error rate
	throughput := 0.0
	errorRate := 0.0
	if requests > 0 {
		throughput = float64(responses)
		errorRate = float64(errors) / float64(requests) * 100
	}

	// Get latency metrics
	avgLatency := averages["proxy_latency"].(float64)

	// Build trends based on current state
	trends := []string{}
	if avgLatency < 100 {
		trends = append(trends, "low_latency")
	} else if avgLatency > 500 {
		trends = append(trends, "high_latency")
	}
	if errorRate < 1 {
		trends = append(trends, "stable")
	} else if errorRate > 5 {
		trends = append(trends, "degraded")
	}

	return map[string]interface{}{
		"period": map[string]string{
			"start": start.Format(time.RFC3339),
			"end":   end.Format(time.RFC3339),
		},
		"metrics": map[string]interface{}{
			"avgLatency": avgLatency,
			"p99Latency": avgLatency * 2,
			"throughput": throughput,
			"errorRate":  errorRate,
			"requests":   requests,
			"responses":  responses,
		},
		"trends":   trends,
		"averages": averages,
	}, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// generateID creates a unique identifier.
func generateID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

// calculateNextRun determines the next execution time for a schedule.
func calculateNextRun(schedule ReportSchedule) time.Time {
	now := time.Now()

	switch schedule.Type {
	case ScheduleHourly:
		return now.Add(time.Hour).Truncate(time.Hour).Add(time.Minute * time.Duration(schedule.Minute))
	case ScheduleDaily:
		next := time.Date(now.Year(), now.Month(), now.Day(), schedule.Hour, schedule.Minute, 0, 0, now.Location())
		if next.Before(now) {
			next = next.Add(24 * time.Hour)
		}
		return next
	case ScheduleWeekly:
		// Find next occurrence of specified day
		daysUntil := schedule.DayOfWeek - int(now.Weekday())
		if daysUntil <= 0 {
			daysUntil += 7
		}
		next := time.Date(now.Year(), now.Month(), now.Day(), schedule.Hour, schedule.Minute, 0, 0, now.Location())
		next = next.Add(time.Duration(daysUntil) * 24 * time.Hour)
		return next
	case ScheduleMonthly:
		// Find next occurrence of specified day
		next := time.Date(now.Year(), now.Month(), schedule.DayOfMonth, schedule.Hour, schedule.Minute, 0, 0, now.Location())
		if next.Before(now) {
			next = next.AddDate(0, 1, 0)
		}
		return next
	default:
		return now.Add(24 * time.Hour)
	}
}

// inSlice checks if a string is in a slice.
func inSlice(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// NoOpDelivery is a delivery handler that does nothing.
type NoOpDelivery struct{}

// DeliverReport implements DeliveryHandler with no operation.
func (n *NoOpDelivery) DeliverReport(report *Report, config DeliveryConfig) error {
	return nil
}
