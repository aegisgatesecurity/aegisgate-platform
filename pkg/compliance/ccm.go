// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Continuous Control Monitoring (CCM)
// =========================================================================
//
// v1 scope: scheduler + status + history. Drift detection is in ccm_drift.go.
// RunOnStart is bool (default false). User must explicitly opt in.
// =========================================================================

package compliance

import (
	"context"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

type CCMSchedule struct {
	Interval   time.Duration
	RunOnStart bool
}

type CCMDriftCallback func(regressions []CCMRegression)

type CCMScheduler struct {
	mu          sync.Mutex
	scanner     *Scanner
	schedule    CCMSchedule
	historyMax  int
	lastReport  *ScanReport
	scanHistory []*ScanReport
	onDrift     CCMDriftCallback
	running     bool
	stopCh      chan struct{}
}

func NewCCMScheduler(scanner *Scanner, schedule CCMSchedule) *CCMScheduler {
	if schedule.Interval == 0 {
		schedule.Interval = 24 * time.Hour
	}
	return &CCMScheduler{
		scanner:    scanner,
		schedule:   schedule,
		historyMax: 90,
		stopCh:     make(chan struct{}),
	}
}

func (s *CCMScheduler) SetOnDriftCallback(cb CCMDriftCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onDrift = cb
}

func (s *CCMScheduler) Start(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	if s.schedule.RunOnStart {
		go s.runScan(ctx)
	}
	go s.loop(ctx)
}

func (s *CCMScheduler) loop(ctx context.Context) {
	ticker := time.NewTicker(s.schedule.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.runScan(ctx)
		}
	}
}

func (s *CCMScheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)
	s.stopCh = make(chan struct{})
	s.mu.Unlock()
}

func (s *CCMScheduler) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *CCMScheduler) runScan(ctx context.Context) {
	s.mu.Lock()
	scanner := s.scanner
	if scanner == nil {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	report, err := scanner.Scan(ctx, s.syntheticLicense())
	if err != nil {
		return
	}

	s.mu.Lock()
	prior := s.lastReport
	s.lastReport = report
	s.scanHistory = append(s.scanHistory, report)
	if len(s.scanHistory) > s.historyMax {
		s.scanHistory = s.scanHistory[len(s.scanHistory)-s.historyMax:]
	}
	cb := s.onDrift
	s.mu.Unlock()

	if prior != nil && cb != nil {
		regressions := s.driftDetector().Compare(prior, report)
		if len(regressions) > 0 {
			cb(regressions)
		}
	}
}

func (s *CCMScheduler) syntheticLicense() *license.ValidationResult {
	return &license.ValidationResult{
		Valid: true,
		Tier:  tier.TierEnterprise,
	}
}

func (s *CCMScheduler) driftDetector() *CCMDriftDetector {
	return defaultCCMDriftDetector
}

var defaultCCMDriftDetector = &CCMDriftDetector{}

type CCMStatus struct {
	Running              bool            `json:"running"`
	IntervalSec          int             `json:"interval_sec"`
	LastScanAt           time.Time       `json:"last_scan_at"`
	HistorySize          int             `json:"history_size"`
	LastReport           *ScanReport     `json:"last_report,omitempty"`
	PriorReport          *ScanReport     `json:"prior_report,omitempty"`
	TotalControls        int             `json:"total_controls"`
	CompliantControls    int             `json:"compliant_controls"`
	OverallScore         float64         `json:"overall_score"`
	OverallCompliancePct float64         `json:"overall_compliance_pct"`
	Regressions          []CCMRegression `json:"regressions,omitempty"`
}

func (s *CCMScheduler) GetStatus() CCMStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := CCMStatus{
		Running:     s.running,
		IntervalSec: int(s.schedule.Interval.Seconds()),
	}
	if s.lastReport != nil {
		status.LastReport = s.lastReport
		status.LastScanAt = s.lastReport.GeneratedAt
		status.OverallScore = s.lastReport.OverallScore
		status.OverallCompliancePct = s.lastReport.OverallCompliancePct
		for _, fw := range s.lastReport.Frameworks {
			status.TotalControls += fw.ControlsTotal
			status.CompliantControls += fw.ControlsEnforced
		}
		if len(s.scanHistory) >= 2 {
			status.PriorReport = s.scanHistory[len(s.scanHistory)-2]
		}
	}
	status.HistorySize = len(s.scanHistory)
	if status.PriorReport != nil && status.LastReport != nil {
		status.Regressions = defaultCCMDriftDetector.Compare(
			status.PriorReport, status.LastReport,
		)
	}
	return status
}

func (s *CCMScheduler) GetHistory() []*ScanReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*ScanReport, len(s.scanHistory))
	copy(out, s.scanHistory)
	return out
}

func (s *CCMScheduler) RunNow(ctx context.Context) {
	s.runScan(ctx)
}
