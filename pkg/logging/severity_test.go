package logging

import (
	"testing"
)

func TestSeverityConstants(t *testing.T) {
	severities := []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}

	expected := []string{"critical", "high", "medium", "low", "info"}

	for i, sev := range severities {
		if string(sev) != expected[i] {
			t.Errorf("Severity %d = %v, want %v", i, sev, expected[i])
		}
	}
}

func TestSyslogFacilityConstants(t *testing.T) {
	if SyslogFacilityLocal0 != 16 {
		t.Errorf("SyslogFacilityLocal0 = %d, want 16", SyslogFacilityLocal0)
	}
	if SyslogFacilityLocal7 != 23 {
		t.Errorf("SyslogFacilityLocal7 = %d, want 23", SyslogFacilityLocal7)
	}
}

func TestSyslogSeverityConstants(t *testing.T) {
	if SyslogSeverityEmergency != 0 {
		t.Error("SyslogSeverityEmergency should be 0")
	}
	if SyslogSeverityDebug != 7 {
		t.Errorf("SyslogSeverityDebug = %d, want 7", SyslogSeverityDebug)
	}
}

func TestGetSupportedMSGIDs(t *testing.T) {
	ids := GetSupportedMSGIDs()
	if len(ids) == 0 {
		t.Error("GetSupportedMSGIDs returned empty slice")
	}
}
