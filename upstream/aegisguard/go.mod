module github.com/aegisguardsecurity/aegisguard

go 1.25.0

require (
	github.com/aegisguardsecurity/aegisguard/shared/unified-audit v0.0.0
	github.com/go-redis/redis/v8 v8.11.5
	github.com/lib/pq v1.12.0
	github.com/prometheus/client_golang v1.18.0
	github.com/redis/go-redis/v9 v9.18.0
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.49.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

replace github.com/aegisguardsecurity/aegisguard/pkg/unified-audit => ./pkg/unified-audit

replace github.com/aegisguardsecurity/aegisguard/shared/unified-audit => ./shared/unified-audit

replace github.com/aegisguardsecurity/aegisguard/pkg/compliance => ./pkg/compliance

replace github.com/aegisguardsecurity/aegisguard/pkg/bridge => ./pkg/bridge

replace github.com/aegisguardsecurity/aegisguard/pkg/observability => ./pkg/observability

replace github.com/aegisguardsecurity/aegisguard/pkg/audit => ./pkg/audit

replace github.com/aegisguardsecurity/aegisguard/pkg/mcp => ./pkg/mcp
