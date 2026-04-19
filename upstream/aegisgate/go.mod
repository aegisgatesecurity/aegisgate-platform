module github.com/aegisgatesecurity/aegisgate

go 1.25.9

require (
	github.com/aegisgatesecurity/aegisgate/pkg/resilience v0.0.0
	github.com/google/uuid v1.6.0
	github.com/prometheus/client_golang v1.18.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.46.0
	golang.org/x/net v0.48.0
	golang.org/x/oauth2 v0.34.0
	google.golang.org/grpc v1.79.3
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)

replace github.com/aegisgatesecurity/aegisgate/pkg/core/license => ./pkg/core/license

replace github.com/aegisgatesecurity/aegisgate/pkg/resilience => ./pkg/resilience

replace github.com/aegisgatesecurity/aegisgate/pkg/core => ./pkg/core

replace github.com/aegisgatesecurity/aegisgate/pkg/middleware => ./pkg/middleware

replace github.com/aegisgatesecurity/aegisgate/pkg/proxy => ./pkg/proxy

replace github.com/aegisgatesecurity/aegisgate/pkg/grpc => ./pkg/grpc

replace github.com/aegisgatesecurity/aegisgate/pkg/dashboard => ./pkg/dashboard

replace github.com/aegisgatesecurity/aegisgate/pkg/crypto/enhanced => ./pkg/crypto/enhanced

replace github.com/aegisgatesecurity/aegisgate/pkg/tls => ./pkg/tls
