module github.com/aegisguardsecurity/aegisguard/pkg/unified-audit

go 1.25

require (
	github.com/aegisguardsecurity/aegisguard/shared/unified-audit v0.0.0
	github.com/sirupsen/logrus v1.9.3
)

replace github.com/aegisguardsecurity/aegisguard/shared/unified-audit => ../../shared/unified-audit