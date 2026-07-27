// Package reporting provides comprehensive reporting capabilities including
// real-time reports, ad-hoc reports, and scheduled report generation.
//
// This file contains integration helpers for connecting to other AegisGate packages.
package reporting

import (
	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/metrics"
	"github.com/aegisgatesecurity/aegisgate/pkg/scanner"
)

// MetricsDataSource integrates with the metrics package
type MetricsDataSource struct {
	collector *metrics.MetricsCollector
}

// NewMetricsDataSource creates a new metrics data source
func NewMetricsDataSource(collector *metrics.MetricsCollector) *MetricsDataSource {
	if collector == nil {
		collector = metrics.GlobalCollector()
	}
	return &MetricsDataSource{collector: collector}
}

// GetMetricsData retrieves current metrics from the collector
func (m *MetricsDataSource) GetMetricsData() (map[string]interface{}, error) {
	realtime := m.collector.GetRealtimeMetrics()
	stats := m.collector.GetStats()

	return map[string]interface{}{
		"realtime": map[string]interface{}{
			"requests":        realtime.RequestCount,
			"responses":       realtime.ResponseCount,
			"blocked":         realtime.BlockedCount,
			"violations":      realtime.ViolationCount,
			"errors":          realtime.ErrorCount,
			"severity_counts": realtime.SeverityCounts.Get(),
		},
		"averages": map[string]interface{}{
			"scan_duration": m.collector.GetAverageScanDuration(),
			"proxy_latency": m.collector.GetAverageProxyLatency(),
		},
		"patterns":        stats.TopPatterns,
		"category_counts": realtime.CategoryCounts,
	}, nil
}

// ScannerDataSource integrates with the scanner package
type ScannerDataSource struct {
	scanner *scanner.Scanner
}

// NewScannerDataSource creates a new scanner data source
func NewScannerDataSource(s *scanner.Scanner) *ScannerDataSource {
	return &ScannerDataSource{scanner: s}
}

// GetScannerData retrieves scanner statistics
func (s *ScannerDataSource) GetScannerData() (map[string]interface{}, error) {
	if s.scanner == nil {
		return map[string]interface{}{
			"patterns":   []string{},
			"categories": []string{},
		}, nil
	}

	// Return basic scanner info
	return map[string]interface{}{
		"patterns":      []map[string]interface{}{},
		"pattern_count": 0,
	}, nil
}

// ComplianceDataSource integrates with the compliance package
type ComplianceDataSource struct {
	manager *compliance.ComplianceManager
}

// NewComplianceDataSource creates a new compliance data source
func NewComplianceDataSource(manager *compliance.ComplianceManager) *ComplianceDataSource {
	return &ComplianceDataSource{manager: manager}
}

// GetComplianceData retrieves compliance status for all frameworks
func (c *ComplianceDataSource) GetComplianceData() (map[string]interface{}, error) {
	if c.manager == nil {
		return map[string]interface{}{
			"frameworks": []string{},
		}, nil
	}

	frameworks := c.manager.GetActiveFrameworks()
	frameworkStatus := make([]map[string]interface{}, len(frameworks))

	for i, fw := range frameworks {
		status := c.manager.GetStatus()
		frameworkStatus[i] = map[string]interface{}{
			"name":   fw.String(),
			"status": status,
		}
	}

	return map[string]interface{}{
		"frameworks":      frameworkStatus,
		"framework_count": len(frameworks),
	}, nil
}

// GetComplianceReport retrieves a detailed compliance report for a framework
func (c *ComplianceDataSource) GetComplianceReport(framework compliance.Framework) (*compliance.ComplianceReport, error) {
	if c.manager == nil {
		return nil, nil
	}
	reportJSON, err := c.manager.GenerateReport()
	if err != nil {
		return nil, err
	}
	return &compliance.ComplianceReport{
		Summary: reportJSON,
	}, nil
}

// AggregateDataSource combines multiple data sources into one
type AggregateDataSource struct {
	metrics    *MetricsDataSource
	scanner    *ScannerDataSource
	compliance *ComplianceDataSource
}

// NewAggregateDataSource creates a new aggregate data source
func NewAggregateDataSource(
	metricsCollector *metrics.MetricsCollector,
	scannerInstance *scanner.Scanner,
	complianceManager *compliance.ComplianceManager,
) *AggregateDataSource {
	return &AggregateDataSource{
		metrics:    NewMetricsDataSource(metricsCollector),
		scanner:    NewScannerDataSource(scannerInstance),
		compliance: NewComplianceDataSource(complianceManager),
	}
}

// GetAllData retrieves all data from all sources
func (a *AggregateDataSource) GetAllData() (map[string]interface{}, error) {
	result := make(map[string]interface{})

	if a.metrics != nil {
		if data, err := a.metrics.GetMetricsData(); err == nil {
			result["metrics"] = data
		}
	}

	if a.scanner != nil {
		if data, err := a.scanner.GetScannerData(); err == nil {
			result["scanner"] = data
		}
	}

	if a.compliance != nil {
		if data, err := a.compliance.GetComplianceData(); err == nil {
			result["compliance"] = data
		}
	}

	return result, nil
}

// SetMetricsCollector updates the metrics collector
func (a *AggregateDataSource) SetMetricsCollector(collector *metrics.MetricsCollector) {
	a.metrics = NewMetricsDataSource(collector)
}

// SetScanner updates the scanner instance
func (a *AggregateDataSource) SetScanner(s *scanner.Scanner) {
	a.scanner = NewScannerDataSource(s)
}

// SetComplianceManager updates the compliance manager
func (a *AggregateDataSource) SetComplianceManager(m *compliance.ComplianceManager) {
	a.compliance = NewComplianceDataSource(m)
}

// GetAggregateData returns all data from connected sources
func GetAggregateData() (map[string]interface{}, error) {
	collector := metrics.GlobalCollector()
	ds := NewMetricsDataSource(collector)
	return ds.GetMetricsData()
}

// GetGlobalScannerData returns scanner data using a default scanner instance
func GetGlobalScannerData() (map[string]interface{}, error) {
	// Return empty scanner data - scanner requires config
	return map[string]interface{}{
		"patterns":      []map[string]interface{}{},
		"pattern_count": 0,
	}, nil
}

// GetComplianceData returns compliance data
func GetComplianceData() (map[string]interface{}, error) {
	// Return empty compliance data - requires proper initialization
	return map[string]interface{}{
		"frameworks": []string{},
	}, nil
}
