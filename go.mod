module github.com/aegisgatesecurity/aegisgate-platform

go 1.25.9

replace (
	// Vendored upstream modules — self-contained, no external repo needed
	github.com/aegisgatesecurity/aegisgate => ./upstream/aegisgate

	// AegisGate subpackages (resolve from vendored upstream)
	github.com/aegisgatesecurity/aegisgate/pkg/resilience => ./upstream/aegisgate/pkg/resilience
	github.com/aegisgatesecurity/aegisgate/pkg/resilience/ratelimit => ./upstream/aegisgate/pkg/resilience/ratelimit
	github.com/aegisguardsecurity/aegisguard => ./upstream/aegisguard
)

require (
	github.com/aegisgatesecurity/aegisgate v0.0.0-00010101000000-000000000000
	github.com/aegisguardsecurity/aegisguard v0.0.0-00010101000000-000000000000
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/google/go-cmp v0.7.0
	github.com/prometheus/client_golang v1.18.0
	github.com/stretchr/testify v1.11.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aegisgatesecurity/aegisgate/pkg/resilience v0.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)
