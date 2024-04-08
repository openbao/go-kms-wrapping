module github.com/openbao/go-kms-wrapping/wrappers/ocikms/v2

go 1.22.1

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/openbao/go-kms-wrapping/v2 v2.0.0-00010101000000-000000000000
	github.com/oracle/oci-go-sdk/v60 v60.0.0
	golang.org/x/net v0.17.0
)

require (
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/sony/gobreaker v0.5.0 // indirect
	github.com/stretchr/objx v0.1.1 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

retract [v2.0.0, v2.0.8]
