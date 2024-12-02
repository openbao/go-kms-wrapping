module github.com/openbao/go-kms-wrapping/wrappers/kmip/v2

go 1.22.1

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/gemalto/kmip-go v0.0.10
	github.com/google/uuid v1.3.0
	github.com/openbao/go-kms-wrapping/v2 v2.0.0-00010101000000-000000000000
)

require (
	github.com/ansel1/merry v1.6.2 // indirect
	github.com/ansel1/merry/v2 v2.0.1 // indirect
	github.com/gemalto/flume v0.13.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	go.uber.org/zap v1.21.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.3.8 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

retract [v2.0.0, v2.0.2]
