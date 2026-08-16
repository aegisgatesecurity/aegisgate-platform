// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Posture Check (v3.3.0 Phase 6.5)
//
// check.go collects data from existing subsystems (license, compliance
// gating, uptime, version) and produces a posture.Report. The Checker
// is dependency-injected so the test suite can substitute mock
// implementations of any subsystem without touching globals.
//
// v3.3.0 Phase 6.5.

package posture

import (
	"context"
	"fmt"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// HealthStatus is the per-subsystem health verdict.
type HealthStatus string

const (
	// StatusHealthy means the subsystem is operating as expected.
	StatusHealthy HealthStatus = "healthy"
	// StatusDegraded means the subsystem is operating but with caveats
	// (e.g., grace-period license, missing implementation, near quota).
	StatusDegraded HealthStatus = "degraded"
	// StatusUnhealthy means the subsystem is broken or misconfigured.
	StatusUnhealthy HealthStatus = "unhealthy"
	// StatusUnknown means we could not determine the status (e.g., a
	// dependency is nil and we have no data). Different from unhealthy:
	// unknown is "we don't know", unhealthy is "we know it's bad".
	StatusUnknown HealthStatus = "unknown"
)

// GatingFunc is the signature of the compliance gating function. We
// declare it here so the Checker can be tested without importing
// pkg/compliance.
type GatingFunc func(framework string, lic *license.ValidationResult) compliance.GatingDecision

// Deps is the set of dependencies the Checker needs to assemble a
// posture report. Every field is optional - nil values degrade the
// report gracefully (the corresponding subsystem shows as StatusUnknown
// with a clear explanation).
type Deps struct {
	// License is the active license manager. Used to determine tier,
	// modules, and expiration. Optional.
	License *license.Manager

	// GatingFunc is the compliance framework gating function. Defaults
	// to compliance.EvaluateGating if nil.
	GatingFunc GatingFunc

	// StartTime is when the platform process started. Used to compute
	// uptime. Optional (uptime shows as unknown if nil).
	StartTime time.Time

	// Version is the platform version string (e.g., "v3.3.0-beta.2").
	Version string

	// Commit is the git commit SHA the binary was built from. Optional.
	Commit string

	// Mode is the operation mode (production, demo, staging). Used to
	// surface demo/staging mode prominently in the report.
	Mode string

	// Now is the time function. Defaults to time.Now if nil. Injectable
	// for deterministic tests.
	Now func() time.Time
}

// SubsystemReport is the per-subsystem health summary.
type SubsystemReport struct {
	Name    string       `json:"name"`
	Status  HealthStatus `json:"status"`
	Summary string       `json:"summary"`
	Details []string     `json:"details,omitempty"` // optional key-value-ish lines
}

// Report is the top-level posture check output.
type Report struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Version     string            `json:"version"`
	Commit      string            `json:"commit,omitempty"`
	Mode        string            `json:"mode,omitempty"`
	Overall     HealthStatus      `json:"overall_status"`
	Uptime      string            `json:"uptime,omitempty"`
	License     *LicenseBlock     `json:"license,omitempty"`
	Compliance  []ComplianceBlock `json:"compliance,omitempty"`
	Subsystems  []SubsystemReport `json:"subsystems"`
}

// LicenseBlock is the license section of the posture report.
type LicenseBlock struct {
	Tier         string    `json:"tier"`
	DisplayName  string    `json:"display_name"`
	Valid        bool      `json:"valid"`
	GracePeriod  bool      `json:"grace_period,omitempty"`
	Expired      bool      `json:"expired,omitempty"`
	Customer     string    `json:"customer,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	ModulesOwned []string  `json:"modules_owned,omitempty"`
	Message      string    `json:"message,omitempty"`
}

// ComplianceBlock describes a single compliance framework's posture.
type ComplianceBlock struct {
	Framework         string `json:"framework"`
	DisplayName       string `json:"display_name"`
	Enforced          bool   `json:"enforced"`
	HasImplementation bool   `json:"has_implementation"`
	RequiredTier      string `json:"required_tier,omitempty"`
	Reason            string `json:"reason,omitempty"`
}

// Checker is the posture-check orchestrator. It is safe to share across
// goroutines - it has no mutable state of its own.
type Checker struct {
	deps Deps
}

// NewChecker returns a Checker wired to the provided dependencies.
// It is safe to pass a partially-populated Deps - missing dependencies
// are reported as StatusUnknown in the resulting Report.
func NewChecker(deps Deps) *Checker {
	if deps.GatingFunc == nil {
		deps.GatingFunc = compliance.EvaluateGating
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	return &Checker{deps: deps}
}

// Check assembles a posture Report. The provided context is used only
// for cancellation - the underlying subsystem reads are non-blocking.
func (c *Checker) Check(ctx context.Context) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("posture check cancelled: %w", err)
	}

	now := c.deps.Now().UTC()
	report := &Report{
		GeneratedAt: now,
		Version:     c.deps.Version,
		Commit:      c.deps.Commit,
		Mode:        c.deps.Mode,
		Subsystems:  []SubsystemReport{},
	}

	// 1. Uptime
	if !c.deps.StartTime.IsZero() {
		uptime := now.Sub(c.deps.StartTime)
		report.Uptime = formatDuration(uptime)
		report.Subsystems = append(report.Subsystems, SubsystemReport{
			Name:    "uptime",
			Status:  StatusHealthy,
			Summary: fmt.Sprintf("Process running for %s", report.Uptime),
		})
	} else {
		report.Subsystems = append(report.Subsystems, SubsystemReport{
			Name:    "uptime",
			Status:  StatusUnknown,
			Summary: "Start time not provided",
		})
	}

	// 2. License
	report.License = c.checkLicense(now)
	report.Subsystems = append(report.Subsystems, licenseSubsystem(report.License))

	// 3. Compliance gating
	report.Compliance = c.checkCompliance()
	report.Subsystems = append(report.Subsystems, complianceSubsystem(report.Compliance))

	// 4. Compute overall status
	report.Overall = computeOverall(report.Subsystems)

	return report, nil
}

// checkLicense reads the license via the injected manager. It is
// tolerant of nil/invalid managers and returns a LicenseBlock that
// reflects the situation.
func (c *Checker) checkLicense(now time.Time) *LicenseBlock {
	if c.deps.License == nil {
		return &LicenseBlock{
			Tier:        "unknown",
			DisplayName: "Unknown",
			Valid:       false,
			Message:     "license manager not configured",
		}
	}

	key := c.deps.License.GetLicenseKey()
	result := c.deps.License.Validate(key)
	block := &LicenseBlock{
		Tier:        result.Tier.String(),
		DisplayName: result.Tier.DisplayName(),
		Valid:       result.Valid,
		GracePeriod: result.GracePeriod,
		Expired:     result.Expired,
		Message:     result.Message,
	}
	if result.Valid {
		block.Customer = result.Payload.Customer
		block.ExpiresAt = result.Payload.ExpiresAt
		block.ModulesOwned = result.Payload.Modules
	}
	return block
}

// checkCompliance evaluates every known compliance framework's gating
// against the current license. Returns nil if gating is unavailable
// (no GatingFunc at all).
//
// The GatingDecision struct from pkg/compliance has the fields:
//
//	Enforced, Framework, RequiredTier, LicenseTier, ModuleOwned,
//	Reason (GatingReason), MissingUpgradeTo, MissingTierTo,
//	HasImplementation. It does NOT have a DisplayName field - the
//
// display name is the framework name, formatted by us. We also cast
// the typed GatingReason back to a plain string for the JSON output.
//
// If License is nil (no manager), we pass a zero-value
// ValidationResult to the GatingFunc. The real EvaluateGating handles
// nil-license correctly (returns tier_too_low for everything).
func (c *Checker) checkCompliance() []ComplianceBlock {
	if c.deps.GatingFunc == nil {
		return nil
	}
	var validationResult *license.ValidationResult
	if c.deps.License != nil {
		key := c.deps.License.GetLicenseKey()
		v := c.deps.License.Validate(key)
		validationResult = &v
	}

	frameworks := knownFrameworks()
	blocks := make([]ComplianceBlock, 0, len(frameworks))
	for _, fw := range frameworks {
		decision := c.deps.GatingFunc(fw, validationResult)
		blocks = append(blocks, ComplianceBlock{
			Framework:         decision.Framework,
			DisplayName:       displayNameForFramework(decision.Framework),
			Enforced:          decision.Enforced,
			HasImplementation: decision.HasImplementation,
			RequiredTier:      decision.RequiredTier.String(),
			Reason:            string(decision.Reason),
		})
	}
	return blocks
}

// displayNameForFramework returns the human-readable name for a
// framework code. Sourced from pkg/compliance/gating.go's
// moduleRequirements map (DisplayName field). Kept here as a
// private helper to avoid a circular import and to give posture
// its own controlled vocabulary.
func displayNameForFramework(fw string) string {
	switch fw {
	case "hipaa":
		return "HIPAA"
	case "pci":
		return "PCI-DSS"
	case "soc2":
		return "SOC 2"
	case "iso42001":
		return "ISO 42001"
	case "fedramp":
		return "FedRAMP"
	case "fips":
		return "FIPS 140"
	case "eu_ai_act":
		return "EU AI Act"
	default:
		return fw
	}
}

// knownFrameworks returns the list of compliance framework names
// accepted by compliance.EvaluateGating. Sourced from
// pkg/compliance/gating.go's moduleRequirements map.
func knownFrameworks() []string {
	return []string{
		"hipaa",
		"pci",
		"soc2",
		"iso42001",
		"fedramp",
		"fips",
		"eu_ai_act",
	}
}

// licenseSubsystem summarizes the license state for the Subsystems list.
//
// Distinguishes three cases:
//  1. LicenseBlock is nil (no manager configured): StatusUnknown
//  2. License is present but invalid (expired, malformed, etc): StatusUnhealthy
//  3. License is present and valid: StatusHealthy (or Degraded if in grace period)
func licenseSubsystem(lic *LicenseBlock) SubsystemReport {
	if lic == nil {
		return SubsystemReport{Name: "license", Status: StatusUnknown, Summary: "no license manager configured"}
	}
	// A non-nil LicenseBlock with a Tier of "unknown" and Valid=false
	// indicates we have a manager but no key was supplied. That is
	// also "we dont know" rather than "we know its bad".
	if !lic.Valid && lic.Tier == "unknown" {
		return SubsystemReport{Name: "license", Status: StatusUnknown, Summary: "no license key provided"}
	}
	if !lic.Valid {
		return SubsystemReport{
			Name:    "license",
			Status:  StatusUnhealthy,
			Summary: fmt.Sprintf("license invalid: %s", lic.Message),
		}
	}
	if lic.GracePeriod {
		return SubsystemReport{
			Name:    "license",
			Status:  StatusDegraded,
			Summary: fmt.Sprintf("license in grace period (tier=%s, customer=%s)", lic.Tier, lic.Customer),
		}
	}
	return SubsystemReport{
		Name:    "license",
		Status:  StatusHealthy,
		Summary: fmt.Sprintf("license valid (tier=%s, customer=%s, modules=%d)", lic.Tier, lic.Customer, len(lic.ModulesOwned)),
	}
}

// complianceSubsystem summarizes the compliance state. The posture is
// degraded if any enforced framework lacks implementation; unhealthy
// is reserved for future use (e.g., compliance subsystem panics).
func complianceSubsystem(blocks []ComplianceBlock) SubsystemReport {
	if len(blocks) == 0 {
		return SubsystemReport{Name: "compliance", Status: StatusUnknown, Summary: "no compliance frameworks evaluated"}
	}
	var enforced, missingImpl int
	for _, b := range blocks {
		if b.Enforced {
			enforced++
			if !b.HasImplementation {
				missingImpl++
			}
		}
	}
	status := StatusHealthy
	summary := fmt.Sprintf("%d frameworks evaluated, %d enforced", len(blocks), enforced)
	if missingImpl > 0 {
		status = StatusDegraded
		summary = fmt.Sprintf("%d frameworks enforced but %d missing implementation", enforced, missingImpl)
	}
	return SubsystemReport{Name: "compliance", Status: status, Summary: summary}
}

// computeOverall reduces per-subsystem statuses to a single overall
// verdict. Rules:
//   - any unhealthy => overall unhealthy
//   - any degraded  => overall degraded
//   - any unknown   => overall unknown (if no other signal)
//   - all healthy   => overall healthy
func computeOverall(subs []SubsystemReport) HealthStatus {
	hasHealthy, hasDegraded, hasUnhealthy, hasUnknown := false, false, false, false
	for _, s := range subs {
		switch s.Status {
		case StatusHealthy:
			hasHealthy = true
		case StatusDegraded:
			hasDegraded = true
		case StatusUnhealthy:
			hasUnhealthy = true
		case StatusUnknown:
			hasUnknown = true
		}
	}
	switch {
	case hasUnhealthy:
		return StatusUnhealthy
	case hasDegraded:
		return StatusDegraded
	case hasUnknown && !hasHealthy:
		return StatusUnknown
	default:
		return StatusHealthy
	}
}

// formatDuration renders a duration in a human-readable form. Days are
// shown as Nd, hours as Hh, minutes as Mm, seconds as Ss. We do not
// break the duration into weeks or months because posture is an
// operator signal, not a calendar.
func formatDuration(d time.Duration) string {
	if d < 0 {
		return "0s"
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	case hours > 0:
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	case minutes > 0:
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}
