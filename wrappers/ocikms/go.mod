module github.com/openbao/go-kms-wrapping/wrappers/ocikms/v2

go 1.24.0

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/openbao/go-kms-wrapping/v2 v2.2.0
	github.com/oracle/oci-go-sdk/v60 v60.0.0
	golang.org/x/net v0.34.0
)

require (
	github.com/fatih/color v1.13.0 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.9 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.6 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/sony/gobreaker v0.5.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	golang.org/x/sys v0.29.0 // indirect
	google.golang.org/protobuf v1.36.4 // indirect
)

retract [v2.0.0, v2.0.8]
