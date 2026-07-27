package reporting

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxConcurrent != 5 {
		t.Errorf("expected MaxConcurrent 5, got %d", cfg.MaxConcurrent)
	}
}

func TestNew(t *testing.T) {
	reporter, err := New(Config{})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if reporter == nil {
		t.Fatal("reporter is nil")
	}
}

func TestReporterStartStop(t *testing.T) {
	reporter, _ := New(Config{EnableScheduler: false})
	reporter.Start()
	reporter.Stop()
}

func TestGenerate(t *testing.T) {
	reporter, _ := New(Config{})
	req := ReportRequest{Type: ReportTypeRealtime, Format: ReportFormatJSON}
	report, err := reporter.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if report == nil {
		t.Fatal("report is nil")
	}
}

func TestGetReport(t *testing.T) {
	reporter, _ := New(Config{})
	report, _ := reporter.Generate(ReportRequest{Type: ReportTypeRealtime})
	getReport, err := reporter.GetReport(report.ID)
	if err != nil {
		t.Fatalf("GetReport failed: %v", err)
	}
	if getReport.ID != report.ID {
		t.Error("report ID mismatch")
	}
}

func TestListReports(t *testing.T) {
	reporter, _ := New(Config{})
	reporter.Generate(ReportRequest{Type: ReportTypeRealtime})
	time.Sleep(50 * time.Millisecond)
	reports := reporter.ListReports("", "")
	if len(reports) < 1 {
		t.Errorf("expected at least 1 report, got %d", len(reports))
	}
}

func TestDeleteReport(t *testing.T) {
	reporter, _ := New(Config{})
	report, _ := reporter.Generate(ReportRequest{Type: ReportTypeRealtime})
	err := reporter.DeleteReport(report.ID)
	if err != nil {
		t.Fatalf("DeleteReport failed: %v", err)
	}
}

func TestSchedule(t *testing.T) {
	reporter, _ := New(Config{})
	schedule := ReportSchedule{Type: ScheduleDaily, ReportType: ReportTypeRealtime, Enabled: true}
	sched, err := reporter.Schedule(schedule)
	if err != nil {
		t.Fatalf("Schedule failed: %v", err)
	}
	if sched.ID == "" {
		t.Error("schedule ID is empty")
	}
}

func TestAddTemplate(t *testing.T) {
	reporter, _ := New(Config{})
	template := ReportTemplate{Name: "Test", ReportType: ReportTypeRealtime}
	tmpl, err := reporter.AddTemplate(template)
	if err != nil {
		t.Fatalf("AddTemplate failed: %v", err)
	}
	if tmpl.ID == "" {
		t.Error("template ID is empty")
	}
}

func TestCleanup(t *testing.T) {
	reporter, _ := New(Config{MaxReportAge: time.Hour})
	err := reporter.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
}

func TestNoOpDelivery(t *testing.T) {
	delivery := &NoOpDelivery{}
	err := delivery.DeliverReport(&Report{}, DeliveryConfig{})
	if err != nil {
		t.Errorf("NoOpDelivery failed: %v", err)
	}
}

func TestReportTypes(t *testing.T) {
	if ReportTypeRealtime != "realtime" {
		t.Error("unexpected ReportTypeRealtime")
	}
}

func TestReportFormats(t *testing.T) {
	if ReportFormatJSON != "json" {
		t.Error("unexpected ReportFormatJSON")
	}
}

func TestScheduleTypes(t *testing.T) {
	if ScheduleHourly != "hourly" {
		t.Error("unexpected ScheduleHourly")
	}
}
