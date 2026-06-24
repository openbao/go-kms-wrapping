module github.com/openbao/go-kms-wrapping/v2/examples/plugin-cli

go 1.25.0

replace github.com/openbao/go-kms-wrapping/v2 => ../../

replace github.com/openbao/go-kms-wrapping/plugin/v2 => ../../plugin

require (
	github.com/hashicorp/go-hclog v1.6.3
	github.com/hashicorp/go-plugin v1.7.0
	github.com/openbao/go-kms-wrapping/plugin/v2 v2.0.0-20240219184625-e8f4fba40bca
	github.com/openbao/go-kms-wrapping/v2 v2.8.0
)

require (
	github.com/fatih/color v1.18.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.2.0 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/oklog/run v1.2.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	go.opentelemetry.io/otel/metric v1.39.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251222181119-0a764e51fe1b // indirect
	google.golang.org/grpc v1.78.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
