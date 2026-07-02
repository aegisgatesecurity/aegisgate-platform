module github.com/aegisgatesecurity/aegisguard

go 1.25.0

require (
	github.com/prometheus/client_golang v1.18.0
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.53.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/sys v0.46.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

replace github.com/aegisgatesecurity/aegisguard/pkg/unified-audit => ./pkg/unified-audit

replace github.com/aegisgatesecurity/aegisguard/shared/unified-audit => ./shared/unified-audit

replace github.com/aegisgatesecurity/aegisguard/pkg/compliance => ./pkg/compliance

replace github.com/aegisgatesecurity/aegisguard/pkg/bridge => ./pkg/bridge

replace github.com/aegisgatesecurity/aegisguard/pkg/observability => ./pkg/observability

replace github.com/aegisgatesecurity/aegisguard/pkg/audit => ./pkg/audit

replace github.com/aegisgatesecurity/aegisguard/pkg/mcp => ./pkg/mcp
