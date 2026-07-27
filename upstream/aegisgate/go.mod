module github.com/aegisgatesecurity/aegisgate

go 1.26.5

require (
	github.com/aegisgatesecurity/aegisgate/pkg/resilience v0.0.0
	github.com/google/uuid v1.6.0
	github.com/prometheus/client_golang v1.18.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.56.0
	golang.org/x/oauth2 v0.36.0
	google.golang.org/grpc v1.82.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.10.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.22.0 // indirect
)

require (
	github.com/aegisgatesecurity/aegisgate-platform v0.0.0
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
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

replace github.com/aegisgatesecurity/aegisgate-platform => ../../
